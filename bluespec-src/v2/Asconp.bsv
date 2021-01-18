package Asconp;

import Vector :: *;
import CryptoCore :: *;


typedef 12 AsconRounds;
typedef 12 Pa; // Number of initialization permutation rounds
typedef 8 Pb; // Number of intermediate permutation rounds

typedef 64 LaneWidth;
typedef Bit#(LaneWidth) AsconLane;

typedef 5 NumLanes;

typedef struct {
  AsconLane x0;
  AsconLane x1;
  AsconLane x2;
  AsconLane x3;
  AsconLane x4;
} AsconState deriving(Bits,Eq);

//typedef Vector#(NumLanes, AsconLane) AsconState;

typedef Vector#(10, Vector#(4, Reg#(Byte))) AsconStateReg;

typedef 128 KeySize;
typedef 128 NpubSize;


Bit#(8) roundConst[valueOf(AsconRounds)] = {'h4b, 'h5a, 'h69, 'h78, 'h87, 'h96, 'ha5, 'hb4, 'hc3, 'hd2, 'he1, 'hf0}; //{'hF0, 'hE1, 'hd2, 'hc3,'hb4, 'ha5,'h96, 'h87,'h78, 'h69,'h5a, 'h4b};


Bit#(5) sBox[32] = {5'h04, 5'h0b, 5'h1f, 5'h14, 5'h1a, 5'h15, 5'h09, 5'h02, 5'h1b, 5'h05, 5'h08, 5'h12, 5'h1d, 5'h03, 5'h06, 5'h1c, 5'h1e, 5'h13, 5'h07, 5'h0e, 5'h00, 5'h0d, 5'h11, 5'h18, 5'h10, 5'h0c, 5'h01, 5'h19, 5'h16, 5'h0a, 5'h0f, 5'h17};

Bit#(64) initialVector = 64'h80800c0800000000;

function Action print_state(String msg, AsconState state);
  action
    $write("%s\n", msg);
    $write("%08x %08x\n", state.x0[63:32], state.x0[31:0]);
    $write("%08x %08x\n", state.x1[63:32], state.x1[31:0]);
    $write("%08x %08x\n", state.x2[63:32], state.x2[31:0]);
    $write("%08x %08x\n", state.x3[63:32], state.x3[31:0]);
    $write("%08x %08x\n", state.x4[63:32], state.x4[31:0]);
    $write("-");
    $display("");
  endaction
endfunction

function Action print_lane(String msg, AsconLane lane);
  action
    $write("%s\n", msg);
    $write("%08x %08x\n", lane[63:32], lane[31:0]);
    $write("-");
    $display("");
  endaction
endfunction

function AsconLane pc(AsconLane x2, UInt#(TLog#(AsconRounds)) roundn);
    x2[7:0] = x2[7:0] ^ roundConst[roundn];
    return x2;
endfunction

function AsconState ps(AsconState state);




  state.x0 = state.x0 ^ state.x4;
  state.x4 = state.x4 ^ state.x3;
  state.x2 = state.x2 ^ state.x1;
  let t0 = state.x0;
  let t1 = state.x1;
  state.x0 = state.x0 ^ (~state.x1 & state.x2);
  state.x1 = state.x1 ^ (~state.x2 & state.x3);
  state.x2 = state.x2 ^ (~state.x3 & state.x4);
  state.x3 = state.x3 ^ (~state.x4 & t0);
  state.x4 = state.x4 ^ (~t0 & t1);

  state.x1 = state.x1 ^ state.x0;
  state.x3 = state.x3 ^ state.x2;
  state.x0 = state.x0 ^ state.x4;
  state.x2 = ~state.x2;
  /*
  for(Integer i = 0; i < valueOf(LaneWidth); i = i + 1) begin
    let t = {state.x0[i], state.x1[i], state.x2[i], state.x3[i], state.x4[i]};
    t = sBox[t];
  
    state.x0[i] = t[4];
    state.x1[i] = t[3];
    state.x2[i] = t[2];
    state.x3[i] = t[1];
    state.x4[i] = t[0];
  end*/
  return state;
endfunction
function AsconState pl(AsconState state);
  state.x0 = state.x0 ^ ({state.x0[18:0], state.x0[63:19]} ^ {state.x0[27:0], state.x0[63:28]});
  state.x1 = state.x1 ^ ({state.x1[60:0], state.x1[63:61]} ^ {state.x1[38:0], state.x1[63:39]});
  state.x2 = state.x2 ^ ({state.x2[0:0], state.x2[63:1]} ^ {state.x2[5:0], state.x2[63:6]});
  state.x3 = state.x3 ^ ({state.x3[9:0], state.x3[63:10]} ^ {state.x3[16:0], state.x3[63:17]});
  state.x4 = state.x4 ^ ({state.x4[6:0], state.x4[63:7]} ^ {state.x4[40:0], state.x4[63:41]});
  return state;
endfunction

function AsconState cXOR(AsconState state, Bit#(KeySize) data);
  state.x3 = state.x3 ^ data[128-1:64];
  state.x4 = state.x4 ^ data[63:0];
  return state;
endfunction

function AsconState keyXOR(AsconState state, Bit#(KeySize) key);
  state.x2 = state.x2 ^ key[128-1:64];
  state.x3 = state.x3 ^ key[63:0];
  return state;
endfunction

function AsconState rXOR(AsconState state, Bit#(128) data);
  state.x0 = state.x0 ^ data[128-1:64];
  state.x1 = state.x1 ^ data[63:0];
  return state;
endfunction
function AsconState domainSep(AsconState state);
  state.x4[0] = state.x4[0] ^ 1;
  return state;
endfunction


function AsconState asconRound(AsconState state, UInt#(TLog#(AsconRounds)) roundn);
    // pc - Add round constant
    state.x2 = pc(state.x2, roundn);

    // ps - sbox
    state = ps(state);

    // pl - linear layer
    state = pl(state);


    return state;
endfunction

function AsconState asconRound2(AsconState state, UInt#(TLog#(AsconRounds)) roundn);
    let s = asconRound(state, roundn);
    return asconRound(s, roundn-1);
endfunction

function AsconState asconRound4(AsconState state, UInt#(TLog#(AsconRounds)) roundn);
    let s = asconRound2(state, roundn);
    return asconRound2(s, roundn-2);
endfunction


function Bit#(32) setBytes(Bit#(32) x, Bit#(32) bytes, Bit#(2) padarg);
  return case(padarg)
    2'd0: bytes;
    2'd1: {bytes[31:24], x[23:0]};
    2'd2: {bytes[31:16], x[15:0]};
    default : {bytes[31:8], x[7:0]};
  endcase;
endfunction
endpackage : Asconp