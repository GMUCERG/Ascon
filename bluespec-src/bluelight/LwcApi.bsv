package LwcApi;

import FIFO::*;
import FIFOF::*;
import SpecialFIFOs :: * ;
import GetPut :: *;

import Bus :: *;
import CryptoCore :: *;

// typedef enum {
//   ACTKEY  = 4'b111, // -> 01 CoreOpType::OpKey  
//   ENC     = 4'b010, // -> 10 CoreOpType::OpEnc  
//   DEC     = 4'b011, // -> 11 CoreOpType::OpDec  
//   HASH    = 4'b000  // -> 00 CoreOpType::OpHash 
// } LwcApiPdiOpcodeLSB deriving (Bits, Eq);

typedef DataLast#(CoreWord) CoreWordWithLast;

interface LwcIfc;
  interface BusRecv#(CoreWord) pdi;
  interface BusRecv#(CoreWord) sdi;
  (* prefix = "do" *)
  interface BusSendWL#(CoreWord) do_;
endinterface

typedef enum {
  GetPdiInstruction,
  GetSdiInstruction,
  GetPdiHeader,
  GetSdiHeader,
  GetPdiData,
  GetTagHeader,
  GetTagData,
  EnqTagHeader,
  GetSdiData
} InputState deriving (Bits, Eq, FShow);

typedef enum {
  SendHeader,
  SendData,
  VerifyTag,
  SendStatus
} OutputState deriving (Bits, Eq, FShow);

// Segment header
typedef UInt#(32) Header;
function Header make_header(SegmentType t, Bool eot, Bool last, Bit#(16) len) = unpack({pack(t) , 1'b0, 1'b0, pack(eot), pack(last), 8'b0, len});
function SegmentType headerType(Header w) = unpack(pack(w)[31:28]);
function Bit#(16) headerLen(Header w) = pack(w)[15:0];
function Bool headerLast(Header w) = unpack(pack(w)[24]);
function Bool headerEoT(Header w) = unpack(pack(w)[25]);
function Bool headerEoI(Header w) = unpack(pack(w)[26]);


module mkLwc#(CryptoCoreIfc cryptoCore, Bool ccIsLittleEndian, Bool ccPadsOutput) (LwcIfc);
  function Bit#(n) lwcSwapEndian(Bit#(n) word) provisos (Mul#(nbytes, 8, n), Div#(n, 8, nbytes));
    return ccIsLittleEndian ? swapEndian(word) : word;
  endfunction

  // should be synthesized out when ccPadsOutput is True TODO: verify QoR
  function CoreWord lwcPadWord(CoreWord word, Bit#(2) padarg);
    return tpl_2(padWord(word, padarg, False));
  endfunction


  BusReceiver#(CoreWord) pdiReceiver <- mkPipelineBusReceiver;
  BusReceiver#(CoreWord) sdiReceiver <- mkPipelineBusReceiver;

  let pdiGet = fifoToGet(pdiReceiver.out).get;
  let sdiGet = fifoToGet(sdiReceiver.out).get;

  Reg#(Bit#(14)) inWordCounter    <- mkRegU;
  Reg#(Bit#(14)) outCounter       <- mkRegU;
  Reg#(Bit#(2))  finalRemainBytes <- mkRegU;
  Reg#(Bit#(2))  outRemainder     <- mkRegU;

  Reg#(Bool) inSegLast   <- mkRegU; // last segment
  Reg#(Bool) outSegLast  <- mkRegU; // last segment
  Reg#(Bool) inSegEoT    <- mkRegU; // last segment of its type
  Reg#(Bool) statFailure <- mkReg(False); // status use in output

  Reg#(SegmentType) inSegType   <- mkRegU;
  Reg#(SegmentType) outSegType  <- mkRegU;

  FIFO#(Header) headersFifo <- mkPipelineFIFO;
  FIFO#(CoreWord) tagFifo <- mkPipelineFIFO;

  let inState  <- mkReg(GetPdiInstruction);
  let outState <- mkReg(SendHeader);

  let doSender <- mkBusSenderWL(?);

  let inWordCounterMsbZero = inWordCounter[13:1] == 0;
  let outCounterMsbZero = outCounter[13:1] == 0;

  // TODO abstract Instruction type
  function Bool instructionIsActKey(CoreWord w); // only CoreWord needed for Instruction
    Bit#(4) opcode = truncateLSB(w); // only need 3 LSB bits of the opcode
    // thrid bit 1, on pdi, it's ACTKEY! (LDKEY is on sdi only)
    return opcode[2] == 1'b1;
  endfunction


  (* fire_when_enabled *)
  rule rl_pdi_instruction if (inState == GetPdiInstruction);
    let w <- pdiGet;
    inState <= instructionIsActKey(w) ? GetSdiInstruction : GetPdiHeader;
  endrule

  (* fire_when_enabled *)
  rule rl_get_sdi_inst if (inState == GetSdiInstruction);
    let w <- sdiGet;
    inState <= GetSdiHeader;
  endrule

  (* fire_when_enabled *)
  rule rl_get_sdi_hdr if (inState == GetSdiHeader);
    let w <- sdiGet;
    Header hdr = unpack(w);
    let len = headerLen(hdr);

    match {.hi, .lo} = split(len);
    inWordCounter    <= hi;
    finalRemainBytes <= lo;
    inSegLast        <= True;
    inSegEoT         <= True;

    cryptoCore.process(headerType(hdr), len == 0);
    inState <= GetSdiData;
  endrule

  (* fire_when_enabled *)
  rule rl_get_pdi_hdr if (inState == GetPdiHeader);
    let w <- pdiGet;
    Header hdr = unpack(w);
    let typ  = headerType(hdr);
    let len  = headerLen(hdr);
    let last = headerLast(hdr);
    let eot  = headerEoT(hdr);

    inSegType <= typ;
    inSegEoT  <= eot;

    // $display("Got header: typ: ", fshow(typ), ", len: ", len, " eot:", eot, " last:", last);

    inWordCounter    <= len[15:2];
    finalRemainBytes <= len[1:0]; 
    inSegLast        <= last;

    case (typ) matches
      Ciphertext:
        headersFifo.enq(make_header(Plaintext,  eot,  True,  len));
      Plaintext:
        headersFifo.enq(make_header(Ciphertext, eot,  False, len));
      HashMessage &&& last:
        headersFifo.enq(make_header(Digest, True, True, fromInteger(crypto_hash_bytes)));
    endcase

    let empty = len == 0;
    cryptoCore.process(typ, empty);
    
    if (empty)
    begin
      if(eot && typ == Ciphertext)
        inState <= GetTagHeader;
      else if (last)
        inState <= (typ == Plaintext) ? EnqTagHeader : GetPdiInstruction;
      // if !last: get more PDI headers
    end
    else
      inState <= GetPdiData;

  endrule

  let last_of_seg = inWordCounterMsbZero && ((inWordCounter[0] == 0) || (finalRemainBytes == 0));

  (* fire_when_enabled *)
  rule rl_feed_core_sdi if (inState == GetSdiData);
    let w <- sdiGet;
    // $displayh("rl_feed_core_SDI: got (key) w=", w);
    inWordCounter <= inWordCounter - 1;

    let lot = last_of_seg && inSegEoT;

    cryptoCore.bdi.enq( BdIO {word: lwcSwapEndian(w), lot: lot, padarg: finalRemainBytes} ); // 0 -> no padding 1 -> 3, 2-> 2, 3-> 1

    if (last_of_seg) inState <=  GetPdiInstruction;
  endrule

  (* fire_when_enabled *)
  rule rl_feed_core_pdi if (inState == GetPdiData);
    let w <- pdiGet;
    // $displayh("rl_feed_core: got w=", w);
    inWordCounter <= inWordCounter - 1;

    let last_of_seg = inWordCounterMsbZero && ((inWordCounter[0] == 0) || (finalRemainBytes == 0));
    let lot = last_of_seg && inSegEoT;

    cryptoCore.bdi.enq( BdIO {word: lwcSwapEndian(w), lot: lot, padarg: finalRemainBytes} ); // 0 -> no padding 1 -> 3, 2-> 2, 3-> 1

    if (last_of_seg) begin
      if (inSegEoT && inSegType == Plaintext)
        inState <= EnqTagHeader;
      else
        if (inSegEoT && inSegType == Ciphertext)
          inState <= GetTagHeader;
        else
          inState <= inSegLast ? GetPdiInstruction : GetPdiHeader;
    end
  endrule

  (* fire_when_enabled *)
  rule rl_get_tag_hdr if (inState == GetTagHeader);
    let w      <- pdiGet;
    Header hdr = unpack(w);
    let len    = headerLen(hdr);

    inWordCounter <= len[15:2];

    inState <= GetTagData;

    // $display("GetTagHeader Got header: ", ", len: ", len);
  endrule

  (* fire_when_enabled *)
  rule rl_get_tag_data if (inState == GetTagData);
    let w <- pdiGet;
    // $displayh("rl_feed_core: got w=", w);
    inWordCounter <= inWordCounter - 1;
    tagFifo.enq(w);

    if (inWordCounterMsbZero)
      inState <= GetPdiInstruction;
  endrule

  (* fire_when_enabled *)
  rule rl_enq_tag if (inState == EnqTagHeader); // only in encrypt, after last Plaintext was read
    headersFifo.enq(make_header(Tag, True, True, fromInteger(crypto_abytes)));
    inState <= GetPdiInstruction;
  endrule

  /// output ///

  rule rl_out_header if (outState == SendHeader);
    headersFifo.deq;
    let h = headersFifo.first;
    let len = headerLen(h);
    let typ = headerType(h);
    let eot = headerEoT(h);
    let last = headerLast(h);
    doSender.in.enq(CoreWordWithLast { data: pack(h), last: False } );

    outSegType <= typ;
    outSegLast <= last;

    match {.hi, .lo} = split(len);
    outRemainder <= lo;

    if (len != 0) begin
      outCounter <= hi;
      outState   <= SendData;
    end
    else if (typ == Plaintext) begin
      outState  <= VerifyTag;
      outCounter <= 4; //FIXME from core/inputs
    end
    else if (last)
      outState <= SendStatus;
  endrule

  (* fire_when_enabled *)
  rule rl_verify_tag if (outState == VerifyTag);
    tagFifo.deq;
    cryptoCore.bdo.deq;
    let intag = tagFifo.first;
    match tagged BdIO {word:.word, lot:.lot} = cryptoCore.bdo.first;
    outCounter <= outCounter - 1;

    let sw = lwcSwapEndian(word);

    // $display("Verifytag got tag:%h core:%h", intag, sw);

    if (intag != sw) begin
      // $displayh("Tag mismatch: %h != %h ", intag, sw);
      statFailure <= True;
    end
    
    if (outCounterMsbZero)
      outState <= SendStatus;
  endrule

  (* fire_when_enabled *)
  rule rl_sendout_data if (outState == SendData);
    cryptoCore.bdo.deq;
    
    match tagged BdIO {word:.word, lot:.lot, padarg: .padarg} = cryptoCore.bdo.first;
    let pw = lot ? lwcPadWord(word, padarg) : word;
    doSender.in.enq(CoreWordWithLast { data: pw, last: False} );
    let last_of_seg = outCounterMsbZero && ((outCounter[0] == 0) || (outRemainder == 0));
    if (last_of_seg) begin
      if (outSegLast)
        if (outSegType == Plaintext) begin
          outCounter <= 4;
          outState <= VerifyTag;
        end
        else 
          outState <= SendStatus;
      else
        outState <= SendHeader; // more headers
    end else
      outCounter <= outCounter - 1;
  endrule

  (* fire_when_enabled *)
  rule rl_out_status if (outState == SendStatus);
    doSender.in.enq(CoreWordWithLast { data: {3'b111, pack(statFailure), 28'b0}, last: True });
    statFailure <= False;
    outState <= SendHeader;
  endrule
  
  interface pdi = pdiReceiver.in;
  interface sdi = sdiReceiver.in;
  interface do_ = doSender.out;
  
endmodule

endpackage : LwcApi