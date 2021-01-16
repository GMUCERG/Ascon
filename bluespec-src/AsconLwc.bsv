package AsconLwc;

import LwcApi :: *;
import AsconCC :: *;


`ifndef TOP_MODULE_NAME
`define TOP_MODULE_NAME lwc
`endif

(* default_clock_osc = "clk",
   default_reset = "rst" *)
module `TOP_MODULE_NAME (LwcIfc);
  let ascon <- mkAsconCC;
  let lwc <- mkLwc(ascon, False, False);
  return lwc;
endmodule

endpackage : AsconLwc