//! Counting-only Boolean backend: the same constant folding as the S2 direct backend
//! (wire identity, not private bit value, decides folding), without tracking bits.
use stwo_bitvm3_core::Gates;
use stwo_bitvm3_lowering::{Program, Value};

pub struct Count {
    next: u64,
    pub ands: u64,
    pub xors: u64,
}
impl Count {
    pub fn new() -> Self { Self { next: 2, ands: 0, xors: 0 } }
    fn issue(&mut self) -> u64 { let w = self.next; self.next += 1; w }
}
impl Gates for Count {
    type W = u64;
    fn constant(&mut self, bit: bool) -> u64 { u64::from(bit) }
    fn xor(&mut self, a: u64, b: u64) -> u64 {
        if a == 0 { return b; }
        if b == 0 { return a; }
        if a == b { return 0; }
        self.xors += 1;
        self.issue()
    }
    fn and(&mut self, a: u64, b: u64) -> u64 {
        if a == 0 || b == 0 { return 0; }
        if a == 1 { return b; }
        if b == 1 || a == b { return a; }
        self.ands += 1;
        self.issue()
    }
}
/// Boolean gate counts of `program`, obtained by running its checked lowering on fresh input wires.
pub fn count(program: &Program) -> anyhow::Result<(u64, u64)> {
    let mut backend = Count::new();
    let raw: Vec<u64> = (0..program.input_bits()).map(|_| backend.issue()).collect();
    let _accept = program.lower(&mut backend, &raw)?;
    Ok((backend.ands, backend.xors))
}
#[allow(dead_code)]
pub fn unused(_: &Value) {}

use std::collections::HashMap;
use stwo_bitvm3_lowering::{Constraint, Limits};

/// Exact Boolean gate counts without materializing the value table: every constraint is
/// lowered on its own small program (identical operand pattern, fresh input wires), once per
/// distinct shape, and the per-variable canonical decoding and per-binding equality are measured
/// the same way. The result is validated against the monolithic `count` on the final verifier.
pub fn analytic(program: &Program) -> anyhow::Result<(u64, u64)> {
    let limits = Limits { max_vars: 1 << 20, max_constraints: 1 << 20,
        max_permutation: 1 << 22, max_permutation_work: usize::MAX / 4 };
    let measure = |n_vars: usize, constraints: Vec<Constraint>, bindings: Vec<(usize, Value)>|
        -> anyhow::Result<(u64, u64)> {
        let p = Program::new(n_vars, constraints, bindings, limits)?;
        count(&p)
    };
    // Per-variable decode and canonicality: slope between two sizes with no constraints.
    let base = measure(3, vec![], vec![])?;
    let big = measure(1003, vec![], vec![])?;
    let decode = ((big.0 - base.0) / 1000, (big.1 - base.1) / 1000);
    anyhow::ensure!(base.0 + decode.0 * 1000 == big.0 && base.1 + decode.1 * 1000 == big.1, "decode is not linear");
    // Per-binding equality (value pin on a non-base slot).
    let with_binding = measure(4, vec![], vec![(3, [1, 2, 3, 4])])?;
    let without = measure(4, vec![], vec![])?;
    let bind = (with_binding.0 - without.0, with_binding.1 - without.1);
    let n_bound = program.bindings().len() as u64 - 3;
    let mut total = (base.0 - 3 * decode.0, base.1 - 3 * decode.1);
    total.0 += decode.0 * program.n_vars() as u64 + bind.0 * n_bound;
    total.1 += decode.1 * program.n_vars() as u64 + bind.1 * n_bound;
    // Constraints, by shape. A shape is the gate kind plus which operand indices coincide.
    let mut shapes: HashMap<String, (u64, (u64, u64))> = HashMap::new();
    for c in program.constraints() {
        let (key, vars): (String, Vec<usize>) = match c {
            Constraint::Add { a, b, out } => ("add".into(), vec![*a, *b, *out]),
            Constraint::Sub { a, b, out } => ("sub".into(), vec![*a, *b, *out]),
            Constraint::Mul { a, b, out } => ("mul".into(), vec![*a, *b, *out]),
            Constraint::PointwiseMul { a, b, out } => ("pmul".into(), vec![*a, *b, *out]),
            Constraint::Eq { a, b } => ("eq".into(), vec![*a, *b]),
            Constraint::TripleXor { inputs, out } => ("txor".into(), vec![inputs[0], inputs[1], inputs[2], *out]),
            Constraint::M31ToU32 { input, out } => ("m2u".into(), vec![*input, *out]),
            Constraint::BlakeG { inputs, outputs } => ("blake".into(), inputs.iter().chain(outputs).copied().collect()),
            Constraint::Permutation { inputs, outputs } => (format!("perm{}", inputs.len()), inputs.iter().chain(outputs).copied().collect()),
            Constraint::Output { .. } => continue,
        };
        // Shape key: first-occurrence numbering of operand indices, with base slots kept distinct.
        let mut seen: Vec<usize> = Vec::new();
        let pattern: Vec<usize> = vars.iter().map(|v| {
            if *v < 3 { return *v; }
            let at = seen.iter().position(|x| x == v).unwrap_or_else(|| { seen.push(*v); seen.len() - 1 });
            3 + at
        }).collect();
        let shape = format!("{key}:{pattern:?}");
        if let Some(entry) = shapes.get_mut(&shape) { entry.0 += 1; continue; }
        let renumbered = |v: &usize| -> usize { if *v < 3 { *v } else { pattern[vars.iter().position(|x| x == v).unwrap()] } };
        let one = match c {
            Constraint::Add { a, b, out } => Constraint::Add { a: renumbered(a), b: renumbered(b), out: renumbered(out) },
            Constraint::Sub { a, b, out } => Constraint::Sub { a: renumbered(a), b: renumbered(b), out: renumbered(out) },
            Constraint::Mul { a, b, out } => Constraint::Mul { a: renumbered(a), b: renumbered(b), out: renumbered(out) },
            Constraint::PointwiseMul { a, b, out } => Constraint::PointwiseMul { a: renumbered(a), b: renumbered(b), out: renumbered(out) },
            Constraint::Eq { a, b } => Constraint::Eq { a: renumbered(a), b: renumbered(b) },
            Constraint::TripleXor { inputs, out } => Constraint::TripleXor { inputs: inputs.map(|v| renumbered(&v)), out: renumbered(out) },
            Constraint::M31ToU32 { input, out } => Constraint::M31ToU32 { input: renumbered(input), out: renumbered(out) },
            Constraint::BlakeG { inputs, outputs } => Constraint::BlakeG { inputs: inputs.map(|v| renumbered(&v)), outputs: outputs.map(|v| renumbered(&v)) },
            Constraint::Permutation { inputs, outputs } => Constraint::Permutation {
                inputs: inputs.iter().map(|v| renumbered(v)).collect(), outputs: outputs.iter().map(|v| renumbered(v)).collect() },
            Constraint::Output { .. } => unreachable!(),
        };
        let n_vars = 3 + seen.len();
        let with = measure(n_vars, vec![one], vec![])?;
        let without = measure(n_vars, vec![], vec![])?;
        shapes.insert(shape, (1, (with.0 - without.0, with.1 - without.1)));
    }
    for (_, (n, unit)) in shapes {
        total.0 += n * unit.0;
        total.1 += n * unit.1;
    }
    Ok(total)
}
