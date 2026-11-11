//! S6: the final verifier garbled as a function of its typed inputs.
//!
//! The plan of `func.rs` is run on the half-gates engine. As in S5 every piece is garbled under one seed
//! (one delta, one hasher key) in its own gate-number range, and a last piece ANDs the check wires. What
//! is new is that pieces hand wires to each other: a variable computed in one piece enters a later piece
//! with the label pair it left with. The only labels that come from outside are those of the typed inputs,
//! one pair per input bit, derived from a key and the bit's position.
//!
//! Per piece: a counting pass fixes the shape (which handed-on bits are constants, which are the same
//! wire, the largest fan-out, the AND count); the engine garbles; the engine evaluates once per witness;
//! and every handed-on wire is checked: the evaluator's label must be the garbler's label for the bit the
//! evaluator computed, and the bits must spell the value upstream's own witness has for that variable.
use crate::func::{INPUT_ID_BASE, Plan, Store, first_id, lower_piece, run_dag};
use crate::garble::{Carried, and_all, evaluate_all, garble, input_label0};
use anyhow::{Result, ensure};
use garbled_snark_verifier::{
    EvaluatedWire, GarbleMode, GarbledWire, GateHasher, S, WireId,
    circuit::{CiphertextHandler, CiphertextSource, CircuitInput, CircuitMode, EncodeInput, EvaluateMode, FALSE_WIRE, TRUE_WIRE},
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use stwo_bitvm3_adapter::Repo;
use stwo_bitvm3_core::{Gates, Qm};
use stwo_bitvm3_lowering::Value;

/// Witnesses evaluated per garbling: the honest one and one changed proof.
pub const WITNESSES: usize = 2;
const STRIDE_LOG: u32 = 36;

/// One bit of a variable handed from piece to piece.
#[derive(Clone)]
enum Bit {
    Const(bool),
    /// `gid` identifies the wire across pieces; `g0` is the garbler's zero label; `e` the evaluator's wire
    /// for each witness.
    Wire { gid: u64, g0: S, e: [EvaluatedWire; WITNESSES] },
}
type VarBits = Vec<Bit>;

/// Counting backend with dense local wire numbers: 0 and 1 are the constants, then the wires that enter
/// the piece, then the wires its gates create. Folds exactly like the engine adapter.
struct Shape {
    reads: Vec<u32>,
    ands: u64,
}
impl Shape {
    fn external(&mut self) -> u32 {
        self.reads.push(0);
        self.reads.len() as u32 + 1
    }
    fn gate(&mut self, a: u32, b: u32) -> u32 {
        // The engine does not count reads of the two constant wires.
        if a > 1 { self.reads[a as usize - 2] += 1; }
        if b > 1 { self.reads[b as usize - 2] += 1; }
        self.reads.push(0);
        self.reads.len() as u32 + 1
    }
}
impl Gates for Shape {
    type W = u32;
    fn constant(&mut self, bit: bool) -> u32 {
        u32::from(bit)
    }
    fn xor(&mut self, a: u32, b: u32) -> u32 {
        if a == 0 { return b; }
        if b == 0 { return a; }
        if a == b { return 0; }
        self.gate(a, b)
    }
    fn and(&mut self, a: u32, b: u32) -> u32 {
        if a == 0 || b == 0 { return 0; }
        if a == 1 { return b; }
        if b == 1 || a == b { return a; }
        self.ands += 1;
        self.gate(a, b)
    }
}

/// A wire that enters a piece.
enum Source {
    /// Bit `usize` of the function input.
    Input(usize),
    Carried { g0: S, e: [EvaluatedWire; WITNESSES] },
}
struct External {
    gid: u64,
    source: Source,
}

/// Garbler's side of the wires entering a piece.
struct Entering<'a> {
    wires: &'a [External],
    key: &'a [u8; 32],
}
impl CircuitInput for Entering<'_> {
    type WireRepr = Vec<WireId>;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Vec<WireId> {
        (0..self.wires.len()).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Vec<WireId>) -> Vec<WireId> {
        w.clone()
    }
}
impl<H: GateHasher, T: CiphertextHandler> EncodeInput<GarbleMode<H, T>> for Entering<'_> {
    fn encode(&self, w: &Vec<WireId>, mode: &mut GarbleMode<H, T>) {
        let probe = mode.issue_garbled_wire();
        let delta = probe.label0 ^ &probe.label1;
        for (id, wire) in w.iter().zip(self.wires) {
            let label0 = match &wire.source {
                Source::Input(bit) => input_label0(self.key, *bit, 0),
                Source::Carried { g0, .. } => *g0,
            };
            mode.feed_wire(*id, GarbledWire { label0, label1: label0 ^ &delta });
        }
    }
}
/// Evaluator's side: one active label per entering wire.
struct Arriving<'a>(&'a [EvaluatedWire]);
impl CircuitInput for Arriving<'_> {
    type WireRepr = Vec<WireId>;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Vec<WireId> {
        (0..self.0.len()).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Vec<WireId>) -> Vec<WireId> {
        w.clone()
    }
}
impl<H: GateHasher, T: CiphertextSource> EncodeInput<EvaluateMode<H, T>> for Arriving<'_> {
    fn encode(&self, w: &Vec<WireId>, mode: &mut EvaluateMode<H, T>) {
        for (id, wire) in w.iter().zip(self.0) {
            mode.feed_wire(*id, wire.clone());
        }
    }
}

struct PieceOutcome {
    ciphertexts: u64,
    gates: u64,
    hash: [u8; 32],
    /// The piece's check wire: a constant, or the garbler's pair and the evaluator's wire per witness.
    ok: Result<(GarbledWire, [EvaluatedWire; WITNESSES]), bool>,
    handed_on_wires: u64,
    compared: u64,
    mismatches: u64,
    worst_fanout: u32,
}

pub struct Outcome {
    pub pieces: usize,
    pub ciphertexts: u64,
    pub gates: u64,
    pub commitment: [u8; 32],
    /// Per witness: verdict, rejecting pieces, and whether the output label is the garbler's label for it.
    pub verdicts: Vec<(bool, usize, bool)>,
    /// Wires handed between pieces whose evaluator label was checked against the garbler's pair.
    pub handed_on_wires: u64,
    /// Handed-on variables compared with the reference assignments, and how many differed.
    pub compared: u64,
    pub mismatches: u64,
    pub worst_fanout: u32,
    pub seconds: f64,
}

fn value_of(bits: &[Bit], witness: usize) -> Value {
    std::array::from_fn(|limb| {
        (0..31).fold(0u32, |x, j| {
            let bit = match &bits[31 * limb + j] {
                Bit::Const(b) => *b,
                Bit::Wire { e, .. } => e[witness].value,
            };
            x | (u32::from(bit) << j)
        })
    })
}

/// Garbles the function once and evaluates it on `inputs[k]` for each witness `k`. `references[k]` is the
/// full assignment upstream computed for that witness; every handed-on variable is compared with it.
pub fn run(plan: &Plan, inputs: [&[bool]; WITNESSES], references: [&[Value]; WITNESSES], threads: usize, seed: u64) -> Result<Outcome> {
    let start = Instant::now();
    let f = plan.f;
    for input in inputs {
        ensure!(input.len() == f.input_bits(), "input length");
    }
    let key = *blake3::hash(format!("stwo-bitvm3 S6 function input labels, seed {seed}").as_bytes()).as_bytes();
    let store: Store<VarBits> = Store::new(plan);
    let deps: Vec<Vec<usize>> = plan.pieces.iter().map(|p| p.deps.clone()).collect();

    let pieces = run_dag(&deps, threads, |p| -> Result<PieceOutcome> {
        let spec = &plan.pieces[p];
        // Wires that enter the piece, in a fixed order: the bits of its typed inputs, then every distinct
        // wire among the variables it was handed.
        let held: Vec<(usize, Arc<VarBits>)> = spec.carried.iter().map(|v| (*v, store.get(*v))).collect();
        let mut external: Vec<External> = Vec::new();
        let mut index: HashMap<u64, u32> = HashMap::new();
        for i in &spec.inputs {
            let (_, kind) = f.inputs()[*i as usize];
            for bit in f.offset(*i as usize)..f.offset(*i as usize) + kind.bits() {
                index.insert(INPUT_ID_BASE + bit as u64, external.len() as u32);
                external.push(External { gid: INPUT_ID_BASE + bit as u64, source: Source::Input(bit) });
            }
        }
        for (_, bits) in &held {
            for bit in bits.iter() {
                if let Bit::Wire { gid, g0, e } = bit {
                    if !index.contains_key(gid) {
                        index.insert(*gid, external.len() as u32);
                        external.push(External { gid: *gid, source: Source::Carried { g0: *g0, e: e.clone() } });
                    }
                }
            }
        }
        let carried_bits: HashMap<usize, &VarBits> = held.iter().map(|(v, bits)| (*v, &**bits)).collect();
        // The wires of an entering variable on a backend whose constants and entering wires are given.
        fn enter<W: Copy>(bits: &VarBits, zero: W, one: W, wire: impl Fn(u64) -> W) -> Qm<W> {
            std::array::from_fn(|limb| {
                bits[31 * limb..31 * (limb + 1)]
                    .iter()
                    .map(|bit| match bit {
                        Bit::Const(b) => if *b { one } else { zero },
                        Bit::Wire { gid, .. } => wire(*gid),
                    })
                    .collect()
            })
        }
        let input_range = |i: u32| {
            let (_, kind) = f.inputs()[i as usize];
            f.offset(i as usize)..f.offset(i as usize) + kind.bits()
        };

        // Shape pass.
        let mut shape = Shape { reads: Vec::new(), ands: 0 };
        for _ in &external {
            shape.external();
        }
        let local = |gid: u64| index[&gid] + 2;
        let (shape_ok, shape_env) = lower_piece(
            &mut shape, f, spec,
            |i| input_range(i).map(|bit| local(INPUT_ID_BASE + bit as u64)).collect(),
            |v| enter(carried_bits[&v], 0u32, 1u32, local),
        );
        // Wires that leave the piece: every distinct non-constant bit of the variables it hands on, then
        // its check wire. Each costs the engine one more read.
        let mut leaving: Vec<u32> = Vec::new();
        let mut position: HashMap<u32, usize> = HashMap::new();
        let mut leave = |id: u32| {
            if id > 1 && !position.contains_key(&id) {
                position.insert(id, leaving.len());
                leaving.push(id);
            }
        };
        for v in &spec.writes {
            shape_env.map[v].iter().flatten().for_each(|id| leave(*id));
        }
        leave(shape_ok);
        for id in &leaving {
            shape.reads[*id as usize - 2] += 1;
        }
        // The engine adds one read to every entering wire and counts in 16 bits.
        let worst_fanout = shape.reads.iter().copied().max().unwrap_or(0) + 1;
        ensure!(worst_fanout < u16::MAX as u32, "a wire is read {worst_fanout} times; use smaller pieces");

        // The same lowering on the engine; wires leave in the order fixed above. From here on the piece's
        // tables are only read, by reference, so that the evaluation threads below can share them.
        let n_leaving = leaving.len();
        let (index, carried_bits, shape_env, position, input_range) = (&index, &carried_bits, &shape_env, &position, &input_range);
        macro_rules! lower_on_engine {
            () => {
                |c, w: &Vec<WireId>| -> Vec<WireId> {
                    let mut repo = Repo(c);
                    let (ok, env) = lower_piece(
                        &mut repo, f, spec,
                        |i| input_range(i).map(|bit| w[index[&(INPUT_ID_BASE + bit as u64)] as usize]).collect(),
                        |v| enter(carried_bits[&v], FALSE_WIRE, TRUE_WIRE, |gid| w[index[&gid] as usize]),
                    );
                    let mut out = vec![FALSE_WIRE; n_leaving];
                    for v in &spec.writes {
                        for (wire, id) in env.map[v].iter().flatten().zip(shape_env.map[v].iter().flatten()) {
                            if let Some(at) = position.get(id) {
                                out[*at] = *wire;
                            }
                        }
                    }
                    if let Some(at) = position.get(&shape_ok) {
                        out[*at] = ok;
                    }
                    out
                }
            };
        }
        // Initial size of the engine's wire table; it grows on demand.
        let capacity = (2 * external.len() + (1 << 14)).next_power_of_two();
        let first_gate = p << STRIDE_LOG;
        let g = garble(Entering { wires: &external, key: &key }, capacity, seed, first_gate, lower_on_engine!()).result;
        let (ciphertexts, hash) = g.ciphertext_handler_result;
        ensure!(ciphertexts.len() as u64 == shape.ands, "engine and counting pass disagree on the AND count");
        ensure!(ciphertexts.len() as u64 == g.gate_count.nonfree_gate_count(), "ciphertext count differs from the non-free gate count");
        ensure!(g.gate_count.total_gate_count() < 1 << STRIDE_LOG, "piece overflows its gate index range");
        ensure!(g.output_value.len() == n_leaving, "the engine returned a different number of leaving wires");
        let constants = (g.true_wire_constant.select(true), g.false_wire_constant.select(false));
        let ciphertexts = Arc::new(ciphertexts);

        // The evaluations for the witnesses are independent of each other and run side by side.
        let (pairs_in, pairs_out) = (&g.input_wire_values, &g.output_value);
        let evaluated: Vec<Vec<EvaluatedWire>> = std::thread::scope(|scope| {
            let runs: Vec<_> = (0..WITNESSES)
                .map(|k| {
                    let ciphertexts = ciphertexts.clone();
                    let external = &external;
                    scope.spawn(move || -> Result<Vec<EvaluatedWire>> {
                        let arriving: Vec<EvaluatedWire> = external
                            .iter()
                            .zip(pairs_in)
                            .map(|(wire, pair)| match &wire.source {
                                Source::Input(bit) => EvaluatedWire::new_from_garbled(pair, inputs[k][*bit]),
                                Source::Carried { e, .. } => e[k].clone(),
                            })
                            .collect();
                        let out = evaluate_all(Arriving(&arriving), capacity, seed, first_gate, constants, ciphertexts, lower_on_engine!())?;
                        ensure!(out.len() == n_leaving, "the evaluator returned a different number of leaving wires");
                        for (wire, pair) in out.iter().zip(pairs_out) {
                            ensure!(wire.active_label == pair.select(wire.value), "a leaving wire carries the wrong label");
                            ensure!(wire.active_label != pair.select(!wire.value), "a leaving wire's label is ambiguous");
                        }
                        Ok(out)
                    })
                })
                .collect();
            runs.into_iter().map(|run| run.join().unwrap_or_else(|_| Err(anyhow::anyhow!("an evaluation panicked")))).collect::<Result<Vec<_>>>()
        })?;

        // Hand the variables on, with a global identity per wire, and compare them with upstream.
        let wire_gid = |id: u32| -> u64 {
            let at = id as usize - 2;
            if at < external.len() { external[at].gid } else { first_id(p) + (at - external.len()) as u64 }
        };
        let (mut compared, mut mismatches) = (0u64, 0u64);
        for v in &spec.writes {
            let bits: VarBits = shape_env.map[v]
                .iter()
                .flatten()
                .map(|id| match *id {
                    0 => Bit::Const(false),
                    1 => Bit::Const(true),
                    id => {
                        let at = position[&id];
                        Bit::Wire {
                            gid: wire_gid(id),
                            g0: g.output_value[at].label0,
                            e: std::array::from_fn(|k| evaluated[k][at].clone()),
                        }
                    }
                })
                .collect();
            for k in 0..WITNESSES {
                compared += 1;
                mismatches += u64::from(value_of(&bits, k) != references[k][*v]);
            }
            store.put(*v, bits);
        }
        let ok = match shape_ok {
            0 => Err(false),
            1 => Err(true),
            id => {
                let at = position[&id];
                Ok((g.output_value[at].clone(), std::array::from_fn(|k| evaluated[k][at].clone())))
            }
        };
        for v in &spec.carried {
            store.release(*v);
        }
        Ok(PieceOutcome {
            ciphertexts: ciphertexts.len() as u64,
            gates: g.gate_count.total_gate_count(),
            hash,
            ok,
            handed_on_wires: (n_leaving * WITNESSES) as u64,
            compared,
            mismatches,
            worst_fanout,
        })
    })?;

    // The combining piece: one AND chain over the non-constant check wires.
    let constant_false = pieces.iter().filter(|p| matches!(p.ok, Err(false))).count();
    let checks: Vec<&(GarbledWire, [EvaluatedWire; WITNESSES])> = pieces.iter().filter_map(|p| p.ok.as_ref().ok()).collect();
    let pairs: Vec<GarbledWire> = checks.iter().map(|c| c.0.clone()).collect();
    let capacity = (pairs.len() + (1 << 10)).next_power_of_two();
    let first_gate = plan.pieces.len() << STRIDE_LOG;
    let g = garble(Carried(&pairs), capacity, seed, first_gate, |c, w: &Vec<WireId>| and_all(c, w)).result;
    let (ciphertexts, combiner_hash) = g.ciphertext_handler_result;
    let constants = (g.true_wire_constant.select(true), g.false_wire_constant.select(false));
    let ciphertexts = Arc::new(ciphertexts);
    let accept = g.output_value[0].clone();
    let mut verdicts = Vec::new();
    for k in 0..WITNESSES {
        let arriving: Vec<EvaluatedWire> = checks.iter().map(|c| c.1[k].clone()).collect();
        let rejecting = arriving.iter().filter(|w| !w.value).count() + constant_false;
        let out = evaluate_all(Carried(&arriving), capacity, seed, first_gate, constants, ciphertexts.clone(), |c, w: &Vec<WireId>| and_all(c, w))?;
        let wire = &out[0];
        let label_ok = wire.active_label == accept.select(wire.value) && wire.active_label != accept.select(!wire.value);
        verdicts.push((wire.value && constant_false == 0, rejecting, label_ok));
    }
    let mut commitment = blake3::Hasher::new();
    for piece in &pieces {
        commitment.update(&piece.hash);
    }
    commitment.update(&combiner_hash);
    Ok(Outcome {
        pieces: plan.pieces.len() + 1,
        ciphertexts: pieces.iter().map(|p| p.ciphertexts).sum::<u64>() + ciphertexts.len() as u64,
        gates: pieces.iter().map(|p| p.gates).sum::<u64>() + g.gate_count.total_gate_count(),
        commitment: *commitment.finalize().as_bytes(),
        verdicts,
        handed_on_wires: pieces.iter().map(|p| p.handed_on_wires).sum(),
        compared: pieces.iter().map(|p| p.compared).sum(),
        mismatches: pieces.iter().map(|p| p.mismatches).sum(),
        worst_fanout: pieces.iter().map(|p| p.worst_fanout).max().unwrap_or(0),
        seconds: start.elapsed().as_secs_f64(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo_bitvm3_lowering::{Function, Limits, fixture::function_fixture, testing::evaluate};

    #[test]
    fn function_pieces_form_one_garbled_circuit() {
        let (n, gates, constants, values) = function_fixture();
        let f = Function::new(n, gates, constants, Limits::default()).unwrap();
        let honest = f.encode(&values).unwrap();
        let (ok, reference) = evaluate(&f, &honest);
        assert!(ok);
        // A changed input that breaks a check, and one that only changes computed values.
        let mut rejected = None;
        let mut accepted = None;
        for bit in 0..honest.len() {
            let mut input = honest.clone();
            input[bit] = !input[bit];
            let (ok, computed) = evaluate(&f, &input);
            if ok && accepted.is_none() && computed != reference { accepted = Some((input, computed)); }
            else if !ok && rejected.is_none() { rejected = Some((input, computed)); }
        }
        let (bad_input, bad_reference) = rejected.expect("some flip is rejected");
        let (other_input, other_reference) = accepted.expect("some flip is accepted with other values");
        let mut commitments = Vec::new();
        for (budget, max_steps, layers) in [(1, 1, 128), (1, 3, 2), (u64::MAX, usize::MAX, 1)] {
            let plan = Plan::layered(&f, budget, max_steps, layers).unwrap();
            let out = run(&plan, [&honest, &bad_input], [&reference, &bad_reference], 2, 7).unwrap();
            assert_eq!(out.verdicts[0], (true, 0, true), "honest, budget {budget} steps {max_steps}");
            assert!(!out.verdicts[1].0 && out.verdicts[1].1 > 0 && out.verdicts[1].2, "rejected input");
            assert_eq!(out.mismatches, 0);
            // An accepted input with other values: accept label again, and its own values on the wires.
            let again = run(&plan, [&other_input, &honest], [&other_reference, &reference], 2, 7).unwrap();
            assert_eq!((again.verdicts[0], again.verdicts[1], again.mismatches), ((true, 0, true), (true, 0, true), 0));
            // One garbling serves every input: the ciphertexts do not depend on what is evaluated.
            assert_eq!(again.commitment, out.commitment);
            assert_eq!(again.ciphertexts, out.ciphertexts);
            commitments.push((out.commitment, out.ciphertexts));
        }
        // Cutting the function differently changes the gate numbering but not the number of gates.
        assert_eq!(commitments[0].1, commitments[2].1);
        let plan = Plan::layered(&f, 1, 3, 2).unwrap();
        let other_seed = run(&plan, [&honest, &bad_input], [&reference, &bad_reference], 1, 8).unwrap();
        assert_ne!(other_seed.commitment, commitments[1].0);
        // The wrong reference is noticed: the comparison has teeth.
        let wrong = run(&plan, [&honest, &bad_input], [&bad_reference, &bad_reference], 1, 7).unwrap();
        assert!(wrong.mismatches > 0 || wrong.compared == 0);
    }
}
