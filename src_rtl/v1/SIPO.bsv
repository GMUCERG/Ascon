package SIPO;

import Vector::*;
import PISO::*;

export SIPO::*;
export Vector::*;

interface SIPO #(numeric type size, type el_type);
  method Action enq(el_type in_data); 
  method Action deq;
  (* always_ready *)
  method CountType#(size) count;
  (* always_ready *)
  method Bool isFull;
  (* always_ready *)
  method Bool notFull;
  (* always_ready *)
  method Bool isEmpty;
  (* always_ready *)
  method Vector#(size, el_type) data;
endinterface

// Pipelined SIPO (Serial In, Parallel Out)
// if full enq can happen simultanously with deq of first element 
module mkPipelineSIPO (SIPO#(size, el_type)) provisos (Bits#(el_type, el_type_sz));
  Reg#(Vector#(size, el_type)) vec <- mkRegU;
  Reg#(CountType#(size)) count_reg <- mkReg(0);
  RWire#(el_type) rwEnq <- mkRWire();
  let pwDeq <- mkPulseWire();

  Bool full = count_reg == fromInteger(valueOf(size));
  Bool empty = count_reg == 0;
  (* fire_when_enabled, no_implicit_conditions *)
  rule update if (isValid(rwEnq.wget) || pwDeq);
    case (rwEnq.wget) matches
      tagged Valid .v:
        begin
          vec <= shiftInAt0(vec, v);
          if (pwDeq) // simultanous enq & deq
            count_reg <= 1;
          else // enq only
            count_reg <= count_reg + 1;
        end
      tagged Invalid: // deq only
        count_reg <= 0;
    endcase
  endrule

  method Action enq(el_type el) if (!full || pwDeq);
    rwEnq.wset(el);
  endmethod
        
  method Action deq if (full);
    pwDeq.send();
  endmethod

  method Vector#(size, el_type) data;
    return vec;
  endmethod

  method CountType#(size) count;
    return count_reg;
  endmethod

  method Bool isFull;
    return full;
  endmethod

  method Bool notFull;
    return !full;
  endmethod

  method Bool isEmpty;
    return empty;
  endmethod
endmodule : mkPipelineSIPO


module mkSIPO (SIPO#(size, el_type)) provisos (Bits#(el_type, el_type_sz));
  Reg#(Vector#(size, el_type)) vec <- mkRegU;
  Reg#(CountType#(size)) count_reg <- mkReg(0);

  Bool full = count_reg == fromInteger(valueOf(size));
  Bool empty = count_reg == 0;
  
  method Action enq(el_type v) if (!full);
    vec <= shiftInAt0(vec, v);
    count_reg <= count_reg + 1;
  endmethod
        
  method Action deq if (full);
    count_reg <= 0;
  endmethod

  method Vector#(size, el_type) data;
    return vec;
  endmethod

  method CountType#(size) count;
    return count_reg;
  endmethod

  method Bool isFull;
    return full;
  endmethod

  method Bool notFull;
    return !full;
  endmethod

  method Bool isEmpty;
    return empty;
  endmethod
endmodule : mkSIPO



interface MyShiftReg #(numeric type size, type el_type);
  (* always_ready *)
  method Action enq(el_type in_data); 
  (* always_ready *)
  method Vector#(size, el_type) data;
endinterface

module mkMyShiftReg (MyShiftReg#(size, el_type)) provisos (Bits#(el_type, el_type_sz));
  Reg#(Vector#(size, el_type)) vec <- mkRegU;

  method Action enq(el_type v);
    vec <= shiftInAt0(vec, v);
  endmethod
  method Vector#(size, el_type) data;
    return vec;
  endmethod
endmodule : mkMyShiftReg

// with set-one
interface MyShiftRegWSO #(numeric type size, type el_type);
  (* always_ready *)
  method Action enq(el_type in_data); 
  (* always_ready *)
  method Action setOne; // has priority over enq
  (* always_ready *)
  method Vector#(size, el_type) data;
endinterface

module mkMyShiftRegWSO (MyShiftRegWSO#(size, el_type)) provisos (Bits#(el_type, el_type_sz), PrimUpdateable#(el_type, a__), SizedLiteral#(a__, 1));
  Reg#(Vector#(size, el_type)) vec <- mkRegU;

  let doSetOne <- mkPulseWire;
  let enqData <- mkRWire;

  (* fire_when_enabled, no_implicit_conditions *)
  rule rl_update_vec;
    if (doSetOne) // setOne has priority over enq
      vec[0][0] <= 1'b1;
    else if (enqData.wget matches tagged Valid .v)
      vec <= shiftInAt0(vec, v);
  endrule

  method Action setOne;
    doSetOne.send;
  endmethod

  method Action enq(el_type v);
    enqData.wset(v);
  endmethod

  method Vector#(size, el_type) data;
    return vec;
  endmethod
endmodule : mkMyShiftRegWSO

endpackage : SIPO