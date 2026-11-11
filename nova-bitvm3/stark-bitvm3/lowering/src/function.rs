//! Function form of a trusted, finalized upstream circuit.
//!
//! `Program` checks a relation: every variable of the circuit is a witness input and every gate is a
//! constraint between inputs. That is the right shape for a witness checker and the wrong one for a
//! garbled circuit whose input labels must be authenticated, because the input is the whole execution
//! (hundreds of millions of bits for a STARK verifier). `Function` is the same circuit read as a
//! computation: its only inputs are the variables upstream *guessed*, each with the type upstream's
//! finalization gave it, and every other variable is computed by the gate that defines it.
//!
//! Upstream marks a guessed variable `v` with exactly one self-referential gate when the context is
//! finalized (`Context::finalize_guessed_vars` at the pinned revision):
//!   * `M31ToU32 { input: v, out: v }`   a 16-bit unsigned integer (one 16-bit limb, the rest zero);
//!   * `PointwiseMul { v, one, v }`       a base-field element (one 31-bit limb, the rest zero);
//!   * `Add { v, zero, v }`               an unrestricted QM31 element.
//! Those gates hold by construction once the input has that type, so they become the input's type and
//! are not lowered. A variable that is neither a pinned constant, a typed guess, nor computed by a gate
//! is refused: nothing is left for a prover to choose silently.
//!
//! A permutation gate does not say which permutation its outputs are; upstream fills them in natively and
//! is not asked to justify the choice. When the outputs have no value yet, this form computes them: the
//! inputs sorted ascending as 124-bit integers (fourth limb most significant). That is always sound, since
//! a sorted copy is a permutation, and it accepts whenever the rest of the circuit accepts that order.
//! The pinned Stwo verifier permutes `value + key * u` with distinct keys and then requires the keys to
//! ascend, so the order it accepts is exactly this one. A permutation gate whose outputs already have
//! values is checked as a multiset equality, as in relation form.
//!
//! Acceptance is one wire: every input limb canonical, every `Eq`, permutation and domain check, and
//! every gate whose output already had a value agreeing with it. `Output` gates carry no check here;
//! the statement of a verifier circuit enters through its guessed inputs.
use crate::program::{blake_g, pack, qeq, sorted, word, xor, zeros};
use crate::{Constraint, Error, Limits, Value};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};
use stwo_bitvm3_core::{self as s, Bits, Gates, Qm, P};

/// The type upstream's finalization gave a guessed variable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    U16,
    M31,
    Qm31,
}
impl Kind {
    /// Number of input bits.
    pub fn bits(self) -> usize {
        match self {
            Kind::U16 => 16,
            Kind::M31 => 31,
            Kind::Qm31 => 124,
        }
    }
}

/// One gate in evaluation order. Bit `i` of `fresh` says that output `i` is defined by this step; a clear
/// bit means the output already has a value and the step compares against it. A permutation gate defines
/// all of its outputs (`fresh == 1`) or none (`fresh == 0`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub gate: Constraint,
    pub fresh: u8,
}

impl Step {
    /// Variables whose value the step needs: what its gate reads, and any output it only compares against.
    pub fn reads(&self) -> Vec<usize> {
        let (mut reads, writes) = shape(&self.gate);
        if matches!(self.gate, Constraint::Permutation { .. }) {
            if self.fresh == 0 { reads.extend(writes); }
        } else {
            reads.extend(writes.into_iter().enumerate().filter(|(slot, _)| self.fresh & (1 << slot) == 0).map(|(_, var)| var));
        }
        reads
    }
    /// Variables the step defines.
    pub fn defines(&self) -> Vec<usize> {
        let writes = shape(&self.gate).1;
        if matches!(self.gate, Constraint::Permutation { .. }) {
            return if self.fresh != 0 { writes } else { Vec::new() };
        }
        writes.into_iter().enumerate().filter(|(slot, _)| self.fresh & (1 << slot) != 0).map(|(_, var)| var).collect()
    }
}

/// Where a lowering keeps the wires of variables. `get` is only called for variables that have a value.
pub trait Env<W> {
    fn get(&self, var: usize) -> Qm<W>;
    fn set(&mut self, var: usize, value: Qm<W>);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Function {
    n_vars: usize,
    constants: BTreeMap<usize, Value>,
    inputs: Vec<(usize, Kind)>,
    offsets: Vec<usize>,
    input_bits: usize,
    steps: Vec<Step>,
    outputs: Vec<usize>,
}

fn marker(gate: &Constraint) -> Option<(usize, Kind)> {
    match gate {
        Constraint::M31ToU32 { input, out } if input == out => Some((*out, Kind::U16)),
        Constraint::PointwiseMul { a, b, out } if (a == out && *b == 1) || (b == out && *a == 1) => Some((*out, Kind::M31)),
        Constraint::Add { a, b, out } if (a == out && *b == 0) || (b == out && *a == 0) => Some((*out, Kind::Qm31)),
        _ => None,
    }
}
/// (variables read, variables written) of a gate.
fn shape(gate: &Constraint) -> (Vec<usize>, Vec<usize>) {
    match gate {
        Constraint::Add { a, b, out } | Constraint::Sub { a, b, out } | Constraint::Mul { a, b, out }
        | Constraint::PointwiseMul { a, b, out } => (vec![*a, *b], vec![*out]),
        Constraint::Eq { a, b } => (vec![*a, *b], vec![]),
        Constraint::TripleXor { inputs, out } => (inputs.to_vec(), vec![*out]),
        Constraint::M31ToU32 { input, out } => (vec![*input], vec![*out]),
        Constraint::BlakeG { inputs, outputs } => (inputs.to_vec(), outputs.to_vec()),
        Constraint::Permutation { inputs, outputs } => (inputs.clone(), outputs.clone()),
        Constraint::Output { input } => (vec![*input], vec![]),
    }
}

impl Function {
    /// `constants` are the trusted constants of the circuit (upstream's constant table). The three base
    /// slots (zero, one, `u`) are always pinned.
    pub fn new(n_vars: usize, constraints: Vec<Constraint>, constants: Vec<(usize, Value)>, limits: Limits) -> Result<Self, Error> {
        if n_vars < 3 { return Err(Error::InvalidShape); }
        if n_vars > limits.max_vars || constraints.len() > limits.max_constraints || n_vars.checked_mul(128).is_none() {
            return Err(Error::Budget);
        }
        let mut pins = BTreeMap::from([(0, [0, 0, 0, 0]), (1, [1, 0, 0, 0]), (2, [0, 0, 1, 0])]);
        for (idx, value) in constants {
            if idx >= n_vars { return Err(Error::ReferenceOutOfRange(idx)); }
            if value.iter().any(|&x| x >= P) { return Err(Error::NonCanonicalBinding(idx)); }
            if let Some(old) = pins.insert(idx, value) {
                if old != value { return Err(Error::ConflictingBinding(idx)); }
            }
        }
        // Shapes and budgets first, then the typed inputs.
        let mut permutation_work = 0usize;
        let mut kinds: BTreeMap<usize, Kind> = BTreeMap::new();
        let mut gates: Vec<Constraint> = Vec::with_capacity(constraints.len());
        let mut outputs = Vec::new();
        for gate in constraints {
            let (reads, writes) = shape(&gate);
            for idx in reads.iter().chain(&writes) {
                if *idx >= n_vars { return Err(Error::ReferenceOutOfRange(*idx)); }
            }
            if let Constraint::Permutation { inputs, outputs } = &gate {
                if inputs.len() != outputs.len() { return Err(Error::InvalidShape); }
                if inputs.len() > limits.max_permutation { return Err(Error::Budget); }
                let width = inputs.len().max(1).checked_next_power_of_two().ok_or(Error::Budget)?;
                let log = width.trailing_zeros() as usize;
                let work = width.checked_mul(log + 1).and_then(|x| x.checked_mul(log + 1))
                    .and_then(|x| x.checked_mul(2)).ok_or(Error::Budget)?;
                permutation_work = permutation_work.checked_add(work).ok_or(Error::Budget)?;
                if permutation_work > limits.max_permutation_work { return Err(Error::Budget); }
            }
            match (&gate, marker(&gate)) {
                (Constraint::Output { input }, _) => outputs.push(*input),
                // A self-referential gate on a constant is an ordinary (and trivially true) gate.
                (_, Some((var, kind))) if !pins.contains_key(&var) => {
                    if kinds.insert(var, kind).is_some() { return Err(Error::InvalidShape); }
                }
                _ => gates.push(gate),
            }
        }

        // Evaluation order: a gate runs once everything it reads has a value. Among runnable gates the
        // one with the smallest largest variable index goes first, which follows upstream's
        // construction order (variables are numbered as they are created) and keeps related gates close.
        let mut known = vec![false; n_vars];
        for idx in pins.keys().chain(kinds.keys()) { known[*idx] = true; }
        let mut waiting: Vec<Vec<u32>> = vec![Vec::new(); n_vars];
        let mut missing = vec![0u32; gates.len()];
        let mut ready = BinaryHeap::new();
        let key = |gate: &Constraint| { let (r, w) = shape(gate); r.into_iter().chain(w).max().unwrap_or(0) };
        for (i, gate) in gates.iter().enumerate() {
            let (reads, _) = shape(gate);
            for var in reads {
                if !known[var] { waiting[var].push(i as u32); missing[i] += 1; }
            }
            if missing[i] == 0 { ready.push(Reverse((key(gate), i))); }
        }
        let mut order: Vec<(usize, u8)> = Vec::with_capacity(gates.len());
        while let Some(Reverse((_, i))) = ready.pop() {
            let (_, writes) = shape(&gates[i]);
            let permutation = matches!(gates[i], Constraint::Permutation { .. });
            if permutation {
                // All outputs computed, or all compared; nothing in between.
                let have = writes.iter().filter(|var| known[**var]).count();
                if have != 0 && have != writes.len() { return Err(Error::InvalidShape); }
            }
            let mut fresh = 0u8;
            for (slot, var) in writes.into_iter().enumerate() {
                if known[var] { continue; }
                fresh |= if permutation { 1 } else { 1 << slot };
                known[var] = true;
                for j in std::mem::take(&mut waiting[var]) {
                    let j = j as usize;
                    missing[j] -= 1;
                    if missing[j] == 0 { ready.push(Reverse((key(&gates[j]), j))); }
                }
            }
            order.push((i, fresh));
        }
        if order.len() != gates.len() {
            // Some gate reads a variable that is not a constant, not a typed guess and not computed.
            let var = (0..gates.len()).filter(|i| missing[*i] > 0)
                .flat_map(|i| shape(&gates[i]).0).find(|v| !known[*v]).unwrap_or(0);
            return Err(Error::Undetermined(var));
        }
        for var in &outputs {
            if !known[*var] { return Err(Error::Undetermined(*var)); }
        }
        let mut slots: Vec<Option<Constraint>> = gates.into_iter().map(Some).collect();
        let steps = order.into_iter().map(|(i, fresh)| Step { gate: slots[i].take().expect("each gate once"), fresh }).collect();

        let inputs: Vec<(usize, Kind)> = kinds.into_iter().collect();
        let mut offsets = Vec::with_capacity(inputs.len());
        let mut input_bits = 0usize;
        for (_, kind) in &inputs {
            offsets.push(input_bits);
            input_bits += kind.bits();
        }
        Ok(Self { n_vars, constants: pins, inputs, offsets, input_bits, steps, outputs })
    }

    pub fn n_vars(&self) -> usize { self.n_vars }
    pub fn constants(&self) -> &BTreeMap<usize, Value> { &self.constants }
    /// Typed inputs in variable order; input `i` occupies `kind.bits()` bits from `offset(i)`.
    pub fn inputs(&self) -> &[(usize, Kind)] { &self.inputs }
    pub fn offset(&self, input: usize) -> usize { self.offsets[input] }
    pub fn input_bits(&self) -> usize { self.input_bits }
    pub fn steps(&self) -> &[Step] { &self.steps }
    /// Variables named by upstream `Output` gates, in gate order. They are computed, not checked.
    pub fn outputs(&self) -> &[usize] { &self.outputs }

    /// The input bits a full assignment carries: the low bits of the first limb for `U16` and `M31`, all
    /// four 31-bit limbs for `Qm31`. Nothing is checked; the lowering checks canonical form.
    pub fn encode(&self, values: &[Value]) -> Result<Vec<bool>, Error> {
        if values.len() != self.n_vars {
            return Err(Error::WitnessLength { expected: self.n_vars, actual: values.len() });
        }
        let mut bits = Vec::with_capacity(self.input_bits);
        for (var, kind) in &self.inputs {
            let value = values[*var];
            match kind {
                Kind::U16 => bits.extend((0..16).map(|i| (value[0] >> i) & 1 != 0)),
                Kind::M31 => bits.extend((0..31).map(|i| (value[0] >> i) & 1 != 0)),
                Kind::Qm31 => bits.extend(value.iter().flat_map(|limb| (0..31).map(move |i| (limb >> i) & 1 != 0))),
            }
        }
        Ok(bits)
    }

    /// Wires of a constant.
    pub fn constant<B: Gates>(b: &mut B, value: &Value) -> Qm<B::W> {
        std::array::from_fn(|i| s::constant(b, value[i] as u64, 31))
    }

    /// Wires of a typed input, without the canonical check. For a lowering in pieces, where an input read
    /// by several pieces is checked in one of them.
    pub fn place<B: Gates>(b: &mut B, kind: Kind, raw: &[B::W]) -> Qm<B::W> {
        assert_eq!(raw.len(), kind.bits());
        let zero = b.constant(false);
        let empty = || vec![zero; 31];
        match kind {
            Kind::U16 | Kind::M31 => {
                let mut low = raw.to_vec();
                low.resize(31, zero);
                [low, empty(), empty(), empty()]
            }
            Kind::Qm31 => std::array::from_fn(|i| raw[31 * i..31 * (i + 1)].to_vec()),
        }
    }

    /// Wires of a typed input and the wire saying its limbs are canonical (a 31-bit limb is canonical
    /// unless it is P itself; a 16-bit input always is).
    pub fn input<B: Gates>(b: &mut B, kind: Kind, raw: &[B::W]) -> (Qm<B::W>, B::W) {
        let value = Self::place(b, kind, raw);
        let zero = b.constant(false);
        let limbs = match kind { Kind::U16 => 0, Kind::M31 => 1, Kind::Qm31 => 4 };
        let mut ok = b.constant(true);
        for limb in value.iter().take(limbs) {
            let mut raw32 = limb.clone();
            raw32.push(zero);
            let (_, valid) = s::decode_m31(b, &raw32);
            ok = b.and(ok, valid);
        }
        (value, ok)
    }

    /// Lowers one step and returns its check wire (constant true when the step only defines values).
    pub fn apply<B: Gates, E: Env<B::W>>(b: &mut B, step: &Step, env: &mut E) -> B::W {
        let mut ok = b.constant(true);
        let put = |b: &mut B, env: &mut E, ok: &mut B::W, slot: usize, var: usize, value: Qm<B::W>| {
            if step.fresh & (1 << slot) != 0 {
                env.set(var, value);
            } else {
                let same = qeq(b, &value, &env.get(var));
                *ok = b.and(*ok, same);
            }
        };
        match &step.gate {
            Constraint::Add { a, b: other, out } => {
                let r = s::qm31_add(b, &env.get(*a), &env.get(*other));
                put(b, env, &mut ok, 0, *out, r);
            }
            Constraint::Sub { a, b: other, out } => {
                let r = s::qm31_sub(b, &env.get(*a), &env.get(*other));
                put(b, env, &mut ok, 0, *out, r);
            }
            Constraint::Mul { a, b: other, out } => {
                let r = s::qm31_mul(b, &env.get(*a), &env.get(*other));
                put(b, env, &mut ok, 0, *out, r);
            }
            Constraint::PointwiseMul { a, b: other, out } => {
                let (x, y) = (env.get(*a), env.get(*other));
                let r = std::array::from_fn(|i| s::m31_mul(b, &x[i], &y[i]));
                put(b, env, &mut ok, 0, *out, r);
            }
            Constraint::Eq { a, b: other } => {
                let same = qeq(b, &env.get(*a), &env.get(*other));
                ok = b.and(ok, same);
            }
            Constraint::TripleXor { inputs, out } => {
                let w: [Bits<B::W>; 3] = std::array::from_fn(|i| {
                    let (w, valid) = word(b, &env.get(inputs[i]));
                    ok = b.and(ok, valid);
                    w
                });
                let r = xor(b, &w[0], &w[1]);
                let r = xor(b, &r, &w[2]);
                let r = pack(b, &r);
                put(b, env, &mut ok, 0, *out, r);
            }
            Constraint::M31ToU32 { input, out } => {
                let v = env.get(*input);
                let base = zeros(b, v[1..].iter().flatten().copied());
                ok = b.and(ok, base);
                let mut w = v[0].clone();
                w.push(b.constant(false));
                let r = pack(b, &w);
                put(b, env, &mut ok, 0, *out, r);
            }
            Constraint::BlakeG { inputs, outputs } => {
                let w: [Bits<B::W>; 6] = std::array::from_fn(|i| {
                    let (w, valid) = word(b, &env.get(inputs[i]));
                    ok = b.and(ok, valid);
                    w
                });
                let result = blake_g(b, &w);
                for (slot, (w, var)) in result.iter().zip(outputs).enumerate() {
                    let r = pack(b, w);
                    put(b, env, &mut ok, slot, *var, r);
                }
            }
            Constraint::Permutation { inputs, outputs } => {
                let a = sorted(b, inputs.iter().map(|&i| env.get(i).concat()).collect());
                if step.fresh != 0 {
                    // The padding sentinels sort last; the first `outputs.len()` rows are the inputs.
                    for (var, row) in outputs.iter().zip(&a) {
                        env.set(*var, std::array::from_fn(|limb| row[31 * limb..31 * (limb + 1)].to_vec()));
                    }
                } else {
                    let c = sorted(b, outputs.iter().map(|&i| env.get(i).concat()).collect());
                    let same = s::equal(b, &a.concat(), &c.concat());
                    ok = b.and(ok, same);
                }
            }
            Constraint::Output { .. } => unreachable!("Output gates are not steps"),
        }
        ok
    }

    /// Lowers the whole function at once: the acceptance wire and the wires of every variable. Meant for
    /// small circuits and tests; large circuits are lowered step range by step range with their own `Env`.
    pub fn lower<B: Gates>(&self, b: &mut B, raw: &[B::W]) -> Result<(B::W, Vec<Qm<B::W>>), Error> {
        if raw.len() != self.input_bits {
            return Err(Error::WitnessLength { expected: self.input_bits, actual: raw.len() });
        }
        struct All<W>(Vec<Option<Qm<W>>>);
        impl<W: Copy> Env<W> for All<W> {
            fn get(&self, var: usize) -> Qm<W> { self.0[var].clone().expect("evaluation order") }
            fn set(&mut self, var: usize, value: Qm<W>) { self.0[var] = Some(value); }
        }
        let mut env = All(vec![None; self.n_vars]);
        for (idx, value) in &self.constants {
            env.0[*idx] = Some(Self::constant(b, value));
        }
        let mut ok = b.constant(true);
        for (i, (var, kind)) in self.inputs.iter().enumerate() {
            let (value, valid) = Self::input(b, *kind, &raw[self.offsets[i]..self.offsets[i] + kind.bits()]);
            ok = b.and(ok, valid);
            env.0[*var] = Some(value);
        }
        for step in &self.steps {
            let valid = Self::apply(b, step, &mut env);
            ok = b.and(ok, valid);
        }
        // A variable no gate reads or writes has no wires; give it zeros so the result is total.
        let zero = Self::constant(b, &[0, 0, 0, 0]);
        Ok((ok, env.0.into_iter().map(|v| v.unwrap_or_else(|| zero.clone())).collect()))
    }
}
