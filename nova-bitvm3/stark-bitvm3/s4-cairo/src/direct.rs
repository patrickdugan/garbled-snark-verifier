//! Value-oblivious-topology Boolean evaluation without retaining the gate DAG.
//! Wire identity, rather than its private bit, controls constant folding.
use stwo_bitvm3_core::Gates;
use stwo_bitvm3_lowering::{Program, Value};

/// A wire is an identity and the bit it carries. Identities 0 and 1 are the constants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wire {
    id: u64,
    bit: bool,
}
#[allow(dead_code)]
impl Wire {
    /// A wire with a caller-chosen identity (at least 2), for inputs whose identity must be the same in
    /// every piece of a lowering.
    pub fn new(id: u64, bit: bool) -> Self {
        assert!(id >= 2, "identities 0 and 1 are the constants");
        Self { id, bit }
    }
    pub fn constant(bit: bool) -> Self {
        Self { id: u64::from(bit), bit }
    }
    pub fn id(&self) -> u64 {
        self.id
    }
    pub fn bit(&self) -> bool {
        self.bit
    }
    pub fn is_constant(&self) -> bool {
        self.id < 2
    }
}

pub struct Direct {
    next: u64,
    pub ands: u64,
    pub xors: u64,
}
impl Direct {
    pub fn new() -> Self {
        Self::with_first_id(2)
    }
    /// Issues wire identities from `first` upward, so that several lowerings never share one.
    pub fn with_first_id(first: u64) -> Self {
        assert!(first >= 2);
        Self { next: first, ands: 0, xors: 0 }
    }
    fn issue(&mut self, bit: bool) -> Wire {
        let w = Wire { id: self.next, bit };
        self.next += 1;
        w
    }
    pub fn inputs(&mut self, values: &[Value]) -> Vec<Wire> {
        values.iter().flatten().flat_map(|&v| (0..32).map(move |i| (v >> i) & 1 != 0)).map(|bit| self.issue(bit)).collect()
    }
}
impl Gates for Direct {
    type W = Wire;
    fn constant(&mut self, bit: bool) -> Wire {
        Wire::constant(bit)
    }
    fn xor(&mut self, a: Wire, b: Wire) -> Wire {
        if a.id == 0 { return b; }
        if b.id == 0 { return a; }
        if a.id == b.id { return self.constant(false); }
        self.xors += 1;
        self.issue(a.bit ^ b.bit)
    }
    fn and(&mut self, a: Wire, b: Wire) -> Wire {
        if a.id == 0 || b.id == 0 { return self.constant(false); }
        if a.id == 1 { return b; }
        if b.id == 1 || a.id == b.id { return a; }
        self.ands += 1;
        assert!(self.ands <= 4_000_000_000, "non-free-gate budget exceeded");
        self.issue(a.bit & b.bit)
    }
}
pub fn run(program: &Program, values: &[Value]) -> anyhow::Result<(bool, u64, u64)> {
    let mut backend = Direct::new();
    let raw = backend.inputs(values);
    let result = program.lower(&mut backend, &raw)?;
    Ok((result.bit, backend.ands, backend.xors))
}
