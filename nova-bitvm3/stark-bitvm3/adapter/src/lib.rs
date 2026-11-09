//! Thin lowering to the repository's existing Boolean/garbling engine.
//! Default features on the parent crate are disabled, including SP1 soldering.
use garbled_snark_verifier::{CircuitContext, Gate, WireId, circuit::{FALSE_WIRE, TRUE_WIRE}};
use stwo_bitvm3_core::Gates;

pub struct Repo<'a, C: CircuitContext>(pub &'a mut C);
impl<C: CircuitContext> Gates for Repo<'_, C> {
    type W = WireId;
    fn constant(&mut self, bit: bool) -> WireId {
        if bit { TRUE_WIRE } else { FALSE_WIRE }
    }
    fn xor(&mut self, a: WireId, b: WireId) -> WireId {
        if a == FALSE_WIRE { return b; }
        if b == FALSE_WIRE { return a; }
        if a == b { return FALSE_WIRE; }
        let out = self.0.issue_wire();
        self.0.add_gate(Gate::xor(a, b, out));
        out
    }
    fn and(&mut self, a: WireId, b: WireId) -> WireId {
        if a == FALSE_WIRE || b == FALSE_WIRE { return FALSE_WIRE; }
        if a == TRUE_WIRE { return b; }
        if b == TRUE_WIRE || a == b { return a; }
        let out = self.0.issue_wire();
        self.0.add_gate(Gate::and(a, b, out));
        out
    }
}
