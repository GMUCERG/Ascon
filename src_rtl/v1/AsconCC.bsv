package AsconCC;

import Vector::*;
import GetPut::*;

import Asconp::*;
import SIPO::*;
import PISO::*;
import CryptoCore::*;

typedef enum {
  IDLE,
  ABSORB_BDI, // waiting on process command
  ZERO_FILL,  // recieve from bdi
  FULL
//  SQUEEZE
} InState_t deriving(Bits, Eq);

typedef enum {
  ABSORB_SQUEEZE,
  PERMUTE,
  OUTPUT_TAG
//  SQUEEZE
} XState_t deriving(Bits, Eq);

typedef TMul#((TDiv#(SizeOf#(AsconLane),SizeOf#(CoreWord))), NumLanes) NumCoreWords;
//(* synthesize *)
module mkAsconCC(CryptoCoreIfc);
    SIPO#(4, CoreWord) sipo <- mkSIPO;
    PISO#(4, CoreWord) piso <- mkPISO;

    // FSMs
    Reg#(InState_t) inState <- mkReg(IDLE);
    Reg#(XState_t) xState <- mkReg(ABSORB_SQUEEZE);
    // rule rl_idle if (state == IDLE);

    // Registers
    Reg#(SegmentType) inRecvType <- mkRegU;

    Reg#(Bit#(KeySize)) keyR <- mkRegU;
    Reg#(Bit#(NpubSize)) npubR <- mkRegU;

    Reg#(AsconState) asconState <- mkRegU;
    Reg#(UInt#(2)) counter <- mkRegU;

    Reg#(UInt#(TLog#(AsconRounds))) roundCounter <- mkRegU;

    Reg#(Bool) initStep <- mkRegU;
    Reg#(Bool) finalADStep <- mkRegU;
    Reg#(Bool) emitTag <- mkRegU;
    Reg#(Bool) inLastOfType <- mkRegU;
    Reg#(Bool) inLastBlockPadded <- mkRegU;
    Reg#(Bool) inPaddedBlockZero <- mkRegU;
    Reg#(Bool) inEmptyType <- mkRegU;
    Reg#(Bool) squeeze <- mkReg(False);
    Reg#(CountType#(4)) bdiValidBytes <- mkRegU;
    Reg#(Bit#(2)) inPadarg  <- mkRegU;
    Reg#(Bit#(2)) outPadarg <- mkRegU;
    let sipoCount = sipo.count;
    let sipoCount4 = pack(sipoCount)[1] == 1 && pack(sipoCount)[0] == 1;
   // let sipoCount8 = pack(sipoCount)[2] == 1 && sipoCount4;
    let inRecvKey = inRecvType == Key;
    let inRecvNpub = inRecvType == Npub;

    let decrypt = inRecvType == Ciphertext;


    /*
     *  
     */
    (* fire_when_enabled *)
    rule rl_absorb_squeeze if (inState == FULL && xState == ABSORB_SQUEEZE);
      $display("ABSORB SQUEEZE ", $time);
      let sipo_data = pack(sipo.data);
      let newState = asconState;
      let bdoValidBytes = 0;
      case(inRecvType)
        Key: begin
          keyR <= sipo_data;
          inState <= IDLE;
        end
        Npub: begin
          initStep <= True;
          newState = AsconState{x0:initialVector, x1:keyR[127:64], x2:keyR[63:0], x3:sipo_data[127:64], x4:sipo_data[63:0]};
          roundCounter <= fromInteger(valueOf(Pa));
          xState <= PERMUTE;
          inState <= IDLE;
        end
        AD: begin
          if(inEmptyType) begin
            $display("Domain sep - Empty AD ", $time);
            $display(print_state("DSB ", asconState));
            newState = domainSep(asconState);
            $display(print_state("DSA ", newState));
            finalADStep <= False;
            inState <= IDLE;
          end else begin
            roundCounter <= fromInteger(valueOf(Pb));
            xState <= PERMUTE;
            newState = rXOR(asconState, sipo_data);
            if(inLastOfType) begin
              if(inLastBlockPadded) begin
                $display("Last AD " ,$time);
                finalADStep <= True;
                inPaddedBlockZero <= False;
                inState <= IDLE;
              end else begin
                $display("Last AD block is FULL " ,$time);
                inState <= ZERO_FILL;
              end
            end else begin
              inState <= ABSORB_BDI;
            end
          end
        end
        Plaintext, Ciphertext: begin
          if(inEmptyType) begin
            $display("Empty PT/CT ", $time);
            newState = keyXOR(rXOR(newState, sipo_data), keyR);
            roundCounter <= fromInteger(valueOf(Pa));
            emitTag <= True;
            inState <= IDLE;
            xState <= PERMUTE;
          end else begin
            newState = rXOR(asconState, sipo_data);
            
            xState <= PERMUTE;
            if(inLastOfType) begin
              if(inLastBlockPadded) begin
                $display("Last PT/CT " , $time);
                emitTag <= True;
                roundCounter <= fromInteger(valueOf(Pa));
                newState = keyXOR(newState, keyR);
                inState <= IDLE;
                bdoValidBytes = inPaddedBlockZero ? 0 : bdiValidBytes;
                inPaddedBlockZero <= False;
                outPadarg <= inPadarg;
              end else begin
                emitTag <= False;
                roundCounter <= fromInteger(valueOf(Pb));
                bdoValidBytes =  4;
                inState <= ZERO_FILL;
              end
            end else begin
              emitTag <= False;
              roundCounter <= fromInteger(valueOf(Pb));
              inState <= ABSORB_BDI;
              bdoValidBytes = 4;
            end
          end
        end
        default: begin
          inState <= IDLE;
        end
      endcase
      

      piso.enq(toChunks({newState.x0, newState.x1}), bdoValidBytes);
      if(decrypt && !inLastBlockPadded) begin
        newState.x0 = sipo_data[127:64];
        newState.x1 = sipo_data[63:0];
      end
      asconState <= newState;
      
      sipo.deq;
    endrule
     /* if(inLastOfType) begin
        case (inRecvType)
          Key: begin
            keyR <= sipo_data;
          end
          Npub: begin
            initStep <= True;
            newState = AsconState{x0:initialVector, x1:keyR[127:64], x2:keyR[63:0], x3:sipo_data[127:64], x4:sipo_data[63:0]};
            roundCounter <= fromInteger(valueOf(Pa));
            xState <= PERMUTE;
          end
          AD: begin
            if(inEmptyType) begin
              $display("Domain sep - Empty AD ", $time);
              $display(print_state("DSB ", asconState));
              newState = domainSep(asconState);
              $display(print_state("DSA ", newState));
              finalADStep <= False;
            end else begin
              $display("Absorb Last AD ", $time);
              newState = rXOR(asconState, pack(sipo.data));
              roundCounter <= fromInteger(valueOf(Pb));
              xState <= PERMUTE;
              finalADStep <= True;
            end
          end
          Plaintext, Ciphertext: begin
            if(inEmptyType) begin
              $display("Empty PT/CT ", $time);
              newState = keyXOR(newState, keyR);
              roundCounter <= fromInteger(valueOf(Pa));
              emitTag <= True;
              
              xState <= PERMUTE;
              sipoValidFlags <= 0;
            end
          end
          default: begin
        //    inState <= IDLE;
          end
        endcase
        inState <= IDLE;
        sipo.deq;
      end
    //  end
    let outState = asconState;
  //    piso.enq(toChunks({outState.x3, outState.x4}), sipoValidFlags);
      asconState <= newState;
      //  emitTag <= emitTag_o;
    //    asconState <= toChunks({iv,keyR, pack(sipo.data[9]), pack(sipo.data[8]), pack(sipo.data[7]), pack(sipo.data[6])});
     //   $display("SQUEEZE ", $time);
     //   xState <= PERMUTE;

    //  end
*/
   // endrule

    (* fire_when_enabled *)
    rule rl_output_tag if (xState == OUTPUT_TAG);
      let outState = cXOR(asconState, keyR);
      piso.enq(toChunks({asconState.x3, asconState.x4}), 4);
      outPadarg <= 0;
      xState <= ABSORB_SQUEEZE;
    endrule

    (* fire_when_enabled *)
    rule rl_permute if (xState == PERMUTE);
      
      
      if (roundCounter == 2 && !(initStep || finalADStep || emitTag)) begin
        xState <= ABSORB_SQUEEZE;
        let newState = asconRound2(asconState, roundCounter - 1);
        
        asconState <= newState;
        roundCounter <= roundCounter - 2;
      end else if(roundCounter == 0) begin
        if(initStep) begin
          $display("INIT STEP ", $time);
          let newState = cXOR(asconState, keyR);
          asconState <= newState;
          initStep <= False; 
          xState <= ABSORB_SQUEEZE;
          $display(print_state("Initiatiozation ", newState));
        end else if(finalADStep) begin
          $display("Domain Sep ", $time);
          finalADStep <= False;
          let newState = domainSep(asconState);
          asconState <= newState;
          xState <= ABSORB_SQUEEZE;
        end else if(emitTag) begin
            $display("Emit Tag ", $time);
            let newState = cXOR(asconState, keyR);
            emitTag <= False;
           // outputTag <= True;
            asconState <= newState;
            xState <= OUTPUT_TAG;
        end else begin
          xState <= ABSORB_SQUEEZE;
        end
       
        $display("Done ", $time);
        
      
      end
      else begin
        let newState = asconRound2(asconState, roundCounter - 1);
        
        asconState <= newState;
        roundCounter <= roundCounter - 2;
      end
    endrule

    (* fire_when_enabled *)
    rule rl_fill_zero if (inState == ZERO_FILL);
      if(sipoCount4) begin
        inState <= FULL;
      end

      if(sipo.isEmpty || (inLastOfType && !inLastBlockPadded)) begin
        sipo.enq({1, 31'b0});
       // outPadarg <= {'0};
        inLastBlockPadded <= True;
        inPaddedBlockZero <= !inEmptyType && sipo.isEmpty;
      end else begin
        sipo.enq(0);
      end
    endrule

    method Action process(SegmentType typ, Bool empty) if (inState == IDLE);
     // initStep <= False;
      inRecvType <= typ;
      inState <= empty ? ZERO_FILL : ABSORB_BDI;
      inEmptyType <= empty;
    endmethod
    
    interface FifoIn bdi;
      method Action enq(i) if (inState == ABSORB_BDI);
        match tagged BdIO {word: .word, lot: .lot, padarg: .padarg} = i;
        match {.padded, .pw} = padWord(word, padarg, True);
        inPadarg <= padarg;
        sipo.enq(lot ? pw : word);
        inLastOfType <= lot;
        inLastBlockPadded <= padded && lot;
        bdiValidBytes <= sipo.count + 1;
        if(sipoCount4) begin
          inState <= FULL;
        end else if(lot) begin
          inState <= ZERO_FILL;
        end

      endmethod
    endinterface





    interface FifoOut bdo;
      method deq = piso.deq;
      method first;
        let lot = (piso.count == 1) && inLastOfType;
        return BdIO {word: piso.first, lot: lot, padarg: outPadarg} ;
      endmethod
      method notEmpty = piso.notEmpty;
    endinterface

endmodule

endpackage : AsconCC