package CryptoCore;

import GetPut::*;
import FIFOF::*;
import Vector::*;

`ifndef IO_WIDTH
`define IO_WIDTH 32
`endif

typedef Bit#(`IO_WIDTH) CoreWord;

// TODO FIXME as cryptoCore parameter or constant? `define?
// used in LwcApi
Integer crypto_abytes = 16;     // size of tag in bytes
Integer crypto_hash_bytes = 32; // size of hash digest in bytes

interface FifoOut#(type a);
  method Action deq;
  (* always_ready *)
  method Bool notEmpty;
  (* always_ready *)
  method a first;
endinterface

interface FifoIn#(type a);
  method Action enq(a el);
endinterface

function FifoOut#(a) fifofToFifoOut(FIFOF#(a) fifo);
return
  interface FifoOut#(a);
    method Action deq if (fifo.notEmpty);
      fifo.deq;
    endmethod
    method Bool notEmpty = fifo.notEmpty;
    method a first = fifo.first;
  endinterface;
endfunction

function Tuple2#(Bool, CoreWord) padWord(CoreWord word, Bit#(2) padarg, Bool padOne);
  return case (padarg)
    2'd0    : tuple2(False, word);
    2'd1    : tuple2(True, {word[31:24], pack(padOne), '0});
    2'd2    : tuple2(True, {word[31:16], pack(padOne), '0});
    default : tuple2(True, {word[31:8], pack(padOne), '0});
  endcase;
endfunction

typedef Bit#(8) Byte;


typedef enum {
  AD          = 4'b0001,
  Plaintext   = 4'b0100,
  Ciphertext  = 4'b0101,
  Tag         = 4'b1000,
  Key         = 4'b1100,
  Npub        = 4'b1101,
  HashMessage = 4'b0111,
  Digest      = 4'b1001
} SegmentType deriving (Bits, Eq, FShow);

typedef enum {
  OpKey  = 2'b01,
  OpEnc  = 2'b10,
  OpDec  = 2'b11,
  OpHash = 2'b00
} CoreOpType deriving (Bits, Eq, FShow);

typedef struct {
  Bool lot;       // last word of the type
  Bit#(2) padarg; // padding argument, number of valid bytes or 0 all valid
  CoreWord word;  // data word
} BdIO deriving (Bits, Eq);

interface CryptoCoreIfc;
  // after fire, words of type `typ` will be sent to CryptoCore, if not empty
  // typ:   type of segment to be received (if note empty) and processed
  // empty: no bdi will be sent afterwards
  method Action process(SegmentType typ, Bool empty);
  
  // input to CryptoCore
  interface FifoIn#(BdIO)  bdi;

  // output from CryptoCore
  interface FifoOut#(BdIO) bdo;
endinterface

function Bit#(n) swapEndian(Bit#(n) word) provisos (Mul#(nbytes, 8, n), Div#(n, 8, nbytes));
    Vector#(nbytes, Byte) v = toChunks(word);
    return pack(reverse(v));
endfunction

endpackage : CryptoCore