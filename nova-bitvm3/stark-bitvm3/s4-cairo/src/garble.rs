//! S5: the whole final verifier as one garbled circuit, produced and evaluated piece by piece.
//!
//! The Boolean program is cut into the same pieces as the direct check (`shard.rs`). Every piece is garbled
//! with the repository's half-gates engine under one seed, so all pieces share Δ, the constant labels and
//! the hasher key, and three rules make the pieces one circuit rather than many:
//!   * each raw input bit has a single label pair, derived from a key and its global position, so a
//!     variable read by several pieces carries the same label in all of them;
//!   * each piece numbers its gates in its own range, so no gate tweak is used twice;
//!   * a last piece ANDs the acceptance wires of all pieces into the single output wire.
//! Ciphertexts of a piece are hashed, evaluated against each witness and dropped, so nothing is stored.
//!
//! Laboratory conventions, as in S2: fixed randomness, and the evaluator's input labels are selected
//! directly from the garbler's pairs (no oblivious transfer, no Bitcoin commitment).
use crate::direct;
use crate::shard::{Piece, Plan, for_each_piece};
use anyhow::{Result, ensure};
use garbled_snark_verifier::{
    AesCcrGateHasher, Blake3AccumulatingHash, CircuitContext, EvaluatedWire, GarbleMode, GarbledWire, GateHasher, S,
    WireId,
    circuit::{
        CiphertextHandler, CiphertextSource, CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, EvaluateMode,
        StreamingResult, TRUE_WIRE,
    },
};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use std::{sync::Arc, time::Instant};
use stwo_bitvm3_adapter::Repo;
use stwo_bitvm3_core::Gates;
use stwo_bitvm3_lowering::{Program, Value};

/// Each piece owns the gate indices `[index << STRIDE_LOG, (index + 1) << STRIDE_LOG)`.
const STRIDE_LOG: u32 = 36;
type Hasher = AesCcrGateHasher;

/// The zero label of a raw input bit, a function of the key and the bit's global position only.
fn input_label0(key: &[u8; 32], global_var: usize, bit: usize) -> S {
    let mut message = [0u8; 16];
    message[..8].copy_from_slice(&(global_var as u64).to_le_bytes());
    message[8..].copy_from_slice(&(bit as u64).to_le_bytes());
    let hash = blake3::keyed_hash(key, &message);
    S::from_u128(u128::from_le_bytes(hash.as_bytes()[..16].try_into().unwrap()))
}

/// Garbler's inputs of a piece: one wire per raw bit of each local variable, labelled by global position.
struct GlobalInputs<'a> {
    globals: &'a [usize],
    key: &'a [u8; 32],
}
impl CircuitInput for GlobalInputs<'_> {
    type WireRepr = Vec<WireId>;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Vec<WireId> {
        (0..self.globals.len() * 128).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Vec<WireId>) -> Vec<WireId> {
        w.clone()
    }
}
impl<H: GateHasher, T: CiphertextHandler> EncodeInput<GarbleMode<H, T>> for GlobalInputs<'_> {
    fn encode(&self, w: &Vec<WireId>, mode: &mut GarbleMode<H, T>) {
        // Any wire the mode issues exposes Δ to the garbler as the difference of its two labels.
        let probe = mode.issue_garbled_wire();
        let delta = probe.label0 ^ &probe.label1;
        for (i, id) in w.iter().enumerate() {
            let label0 = input_label0(self.key, self.globals[i / 128], i % 128);
            mode.feed_wire(*id, GarbledWire { label0, label1: label0 ^ &delta });
        }
    }
}

/// Evaluator's inputs of a piece: the active label of every raw bit of the witness.
struct WitnessInputs<'a> {
    labels: &'a [GarbledWire],
    values: &'a [Value],
}
impl CircuitInput for WitnessInputs<'_> {
    type WireRepr = Vec<WireId>;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Vec<WireId> {
        (0..self.values.len() * 128).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Vec<WireId>) -> Vec<WireId> {
        w.clone()
    }
}
impl<H: GateHasher, T: CiphertextSource> EncodeInput<EvaluateMode<H, T>> for WitnessInputs<'_> {
    fn encode(&self, w: &Vec<WireId>, mode: &mut EvaluateMode<H, T>) {
        assert_eq!(w.len(), self.labels.len());
        for (i, id) in w.iter().enumerate() {
            let word = self.values[i / 128][(i % 128) / 32];
            let bit = (word >> (i % 32)) & 1 != 0;
            mode.feed_wire(*id, EvaluatedWire::new_from_garbled(&self.labels[i], bit));
        }
    }
}

/// Inputs that are wires of earlier pieces (the acceptance wires fed to the combining piece).
struct Carried<'a, W>(&'a [W]);
impl<W> CircuitInput for Carried<'_, W> {
    type WireRepr = Vec<WireId>;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Vec<WireId> {
        (0..self.0.len()).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Vec<WireId>) -> Vec<WireId> {
        w.clone()
    }
}
impl<H: GateHasher, T: CiphertextHandler> EncodeInput<GarbleMode<H, T>> for Carried<'_, GarbledWire> {
    fn encode(&self, w: &Vec<WireId>, mode: &mut GarbleMode<H, T>) {
        for (id, wire) in w.iter().zip(self.0) {
            mode.feed_wire(*id, wire.clone());
        }
    }
}
impl<H: GateHasher, T: CiphertextSource> EncodeInput<EvaluateMode<H, T>> for Carried<'_, EvaluatedWire> {
    fn encode(&self, w: &Vec<WireId>, mode: &mut EvaluateMode<H, T>) {
        for (id, wire) in w.iter().zip(self.0) {
            mode.feed_wire(*id, wire.clone());
        }
    }
}

#[derive(Default)]
struct MemorySink {
    ciphertexts: Vec<S>,
    hash: Blake3AccumulatingHash,
}
impl CiphertextHandler for MemorySink {
    type Result = (Vec<S>, [u8; 32]);
    fn handle(&mut self, ct: S) {
        self.ciphertexts.push(ct);
        self.hash.update(ct);
    }
    fn finalize(self) -> Self::Result {
        (self.ciphertexts, self.hash.finalize())
    }
}
struct MemorySource {
    ciphertexts: Arc<Vec<S>>,
    position: usize,
}
impl CiphertextSource for MemorySource {
    /// Number of ciphertexts consumed.
    type Result = usize;
    fn recv(&mut self) -> Option<S> {
        let ct = self.ciphertexts.get(self.position).copied();
        if ct.is_some() {
            self.position += 1;
        }
        ct
    }
    fn finalize(self) -> usize {
        self.position
    }
}

fn evaluation_hasher(seed: u64) -> Hasher {
    // The garbler draws the hasher key first from the same seeded generator (`GarbleMode::new`).
    Hasher::from_rng(&mut ChaChaRng::seed_from_u64(seed))
}

struct Garbled<I: CircuitInput> {
    result: StreamingResult<GarbleMode<Hasher, MemorySink>, I, Vec<GarbledWire>>,
}
fn garble<I, F>(inputs: I, capacity: usize, seed: u64, first_gate: usize, build: F) -> Garbled<I>
where
    I: CircuitInput<WireRepr = Vec<WireId>> + EncodeInput<GarbleMode<Hasher, MemorySink>>,
    F: Fn(&mut garbled_snark_verifier::circuit::StreamingMode<GarbleMode<Hasher, MemorySink>>, &Vec<WireId>) -> Vec<WireId>,
{
    let mode = GarbleMode::<Hasher, MemorySink>::new(capacity, seed, MemorySink::default()).with_first_gate_index(first_gate);
    Garbled { result: CircuitBuilder::run_streaming(inputs, mode, build) }
}
fn evaluate<I, F>(
    inputs: I, capacity: usize, seed: u64, first_gate: usize, constants: (S, S), ciphertexts: Arc<Vec<S>>, build: F,
) -> Result<EvaluatedWire>
where
    I: CircuitInput<WireRepr = Vec<WireId>> + EncodeInput<EvaluateMode<Hasher, MemorySource>>,
    F: Fn(&mut garbled_snark_verifier::circuit::StreamingMode<EvaluateMode<Hasher, MemorySource>>, &Vec<WireId>) -> Vec<WireId>,
{
    let expected = ciphertexts.len();
    let source = MemorySource { ciphertexts, position: 0 };
    let mode = EvaluateMode::new(evaluation_hasher(seed), capacity, constants.0, constants.1, source)
        .with_first_gate_index(first_gate);
    let e: StreamingResult<EvaluateMode<Hasher, MemorySource>, I, Vec<EvaluatedWire>> =
        CircuitBuilder::run_streaming(inputs, mode, build);
    ensure!(e.ciphertext_handler_result == expected, "the evaluator consumed {} of {expected} ciphertexts", e.ciphertext_handler_result);
    ensure!(e.output_value.len() == 1, "one output wire expected");
    Ok(e.output_value[0].clone())
}

fn lower_piece<C: CircuitContext>(c: &mut C, w: &[WireId], program: &Program) -> Vec<WireId> {
    vec![program.lower(&mut Repo(c), w).expect("validated piece")]
}
fn and_all<C: CircuitContext>(c: &mut C, w: &[WireId]) -> Vec<WireId> {
    let mut repo = Repo(c);
    let mut all = TRUE_WIRE;
    for wire in w {
        all = repo.and(all, *wire);
    }
    vec![all]
}

/// Counts how often each wire is read, with the same folding rules as the garbling adapter. The garbling
/// engine tracks remaining reads in a 16-bit counter that wraps silently in release builds, so a piece is
/// only garbled after its largest fan-out is known to fit.
struct Fanout {
    reads: Vec<u32>,
}
impl Gates for Fanout {
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
        self.gate(a, b)
    }
}
impl Fanout {
    fn gate(&mut self, a: u32, b: u32) -> u32 {
        // Reads of the two constant wires are not tracked by the engine either.
        if a > 1 { self.reads[a as usize] += 1; }
        if b > 1 { self.reads[b as usize] += 1; }
        self.reads.push(0);
        (self.reads.len() - 1) as u32
    }
}
/// Returns (largest fan-out, number of wires above the 16-bit limit, index of the widest wire, input wires).
pub fn max_fanout(program: &Program) -> Result<(u32, usize, usize, usize)> {
    let inputs = program.input_bits();
    let mut backend = Fanout { reads: vec![0; inputs + 2] };
    let raw: Vec<u32> = (2..inputs as u32 + 2).collect();
    program.lower(&mut backend, &raw)?;
    let (widest, max) = backend.reads.iter().enumerate().max_by_key(|(_, r)| **r).map(|(i, r)| (i, *r)).unwrap_or((0, 0));
    let over = backend.reads.iter().filter(|r| **r > u16::MAX as u32).count();
    Ok((max, over, widest, inputs))
}

struct PieceOutcome {
    ciphertexts: u64,
    gates: u64,
    hash: [u8; 32],
    output: GarbledWire,
    /// One evaluated acceptance wire per witness.
    evaluated: Vec<EvaluatedWire>,
}

fn run_piece(index: usize, piece: &Piece, witnesses: &[&[Value]], seed: u64, key: &[u8; 32]) -> Result<PieceOutcome> {
    let program = &piece.program;
    // The engine's per-wire read counter is 16 bits wide; the root pass adds one read per input.
    let (fanout, _, _, _) = max_fanout(program)?;
    ensure!(fanout < u16::MAX as u32 - 1, "piece {index} has a wire read {fanout} times; use smaller pieces");
    let capacity = (program.input_bits() + (1 << 18)).next_power_of_two();
    let first_gate = index << STRIDE_LOG;
    let g = garble(GlobalInputs { globals: &piece.globals, key }, capacity, seed, first_gate, |c, w| lower_piece(c, w, program)).result;
    let (ciphertexts, hash) = g.ciphertext_handler_result;
    ensure!(ciphertexts.len() as u64 == g.gate_count.nonfree_gate_count(), "ciphertext count differs from the non-free gate count");
    ensure!(g.gate_count.total_gate_count() < 1 << STRIDE_LOG, "piece {index} overflows its gate index range");
    ensure!(g.output_value.len() == 1, "one output wire expected");
    let output = g.output_value[0].clone();
    let constants = (g.true_wire_constant.select(true), g.false_wire_constant.select(false));
    let ciphertexts = Arc::new(ciphertexts);
    let mut evaluated = Vec::with_capacity(witnesses.len());
    for values in witnesses {
        let local = piece.values(values);
        let (expected, ands, _) = direct::run(program, &local)?;
        ensure!(ands == ciphertexts.len() as u64, "garbled and direct AND counts differ in piece {index}");
        let wire = evaluate(
            WitnessInputs { labels: &g.input_wire_values, values: &local }, capacity, seed, first_gate, constants,
            ciphertexts.clone(), |c, w| lower_piece(c, w, program),
        )?;
        ensure!(wire.value == expected, "garbled and direct verdicts differ in piece {index}");
        ensure!(wire.active_label == output.select(expected), "wrong acceptance label in piece {index}");
        ensure!(wire.active_label != output.select(!expected), "ambiguous acceptance label in piece {index}");
        evaluated.push(wire);
    }
    Ok(PieceOutcome { ciphertexts: ciphertexts.len() as u64, gates: g.gate_count.total_gate_count(), hash, output, evaluated })
}

pub struct Outcome {
    pub pieces: usize,
    pub ciphertexts: u64,
    pub gates: u64,
    /// BLAKE3 over the per-piece ciphertext hashes in piece order, the combining piece last.
    pub commitment: [u8; 32],
    /// Per witness: the plaintext verdict, the number of rejecting pieces, and whether the evaluator's output
    /// label is exactly the garbler's label for that verdict.
    pub verdicts: Vec<(bool, usize, bool)>,
    pub seconds: f64,
}

/// Garbles every piece of `program` once and evaluates it for each witness.
pub fn run(program: &Program, witnesses: &[&[Value]], shard_size: usize, threads: usize, seed: u64) -> Result<Outcome> {
    let start = Instant::now();
    for values in witnesses {
        ensure!(values.len() == program.n_vars(), "witness length");
    }
    let key = *blake3::hash(format!("stwo-bitvm3 S5 input labels, seed {seed}").as_bytes()).as_bytes();
    let plan = Plan::new(program, shard_size);
    let pieces = for_each_piece(plan.len(), threads, |i| run_piece(i, &plan.piece(i)?, witnesses, seed, &key))?;

    // The combining piece: one AND chain over the acceptance wires, in its own gate index range.
    let outputs: Vec<GarbledWire> = pieces.iter().map(|p| p.output.clone()).collect();
    let capacity = (outputs.len() + (1 << 10)).next_power_of_two();
    let first_gate = plan.len() << STRIDE_LOG;
    let g = garble(Carried(&outputs), capacity, seed, first_gate, |c, w| and_all(c, w)).result;
    let (ciphertexts, combiner_hash) = g.ciphertext_handler_result;
    let constants = (g.true_wire_constant.select(true), g.false_wire_constant.select(false));
    let ciphertexts = Arc::new(ciphertexts);
    let accept = g.output_value[0].clone();
    let mut verdicts = Vec::new();
    for k in 0..witnesses.len() {
        let carried: Vec<EvaluatedWire> = pieces.iter().map(|p| p.evaluated[k].clone()).collect();
        let rejecting = carried.iter().filter(|w| !w.value).count();
        let wire = evaluate(Carried(&carried), capacity, seed, first_gate, constants, ciphertexts.clone(), |c, w| and_all(c, w))?;
        ensure!(wire.value == (rejecting == 0), "combining piece disagrees with the pieces");
        let label_ok = wire.active_label == accept.select(wire.value) && wire.active_label != accept.select(!wire.value);
        verdicts.push((wire.value, rejecting, label_ok));
    }

    let mut commitment = blake3::Hasher::new();
    for piece in &pieces {
        commitment.update(&piece.hash);
    }
    commitment.update(&combiner_hash);
    Ok(Outcome {
        pieces: plan.len() + 1,
        ciphertexts: pieces.iter().map(|p| p.ciphertexts).sum::<u64>() + ciphertexts.len() as u64,
        gates: pieces.iter().map(|p| p.gates).sum::<u64>() + g.gate_count.total_gate_count(),
        commitment: *commitment.finalize().as_bytes(),
        verdicts,
        seconds: start.elapsed().as_secs_f64(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo_bitvm3_core::P;
    use stwo_bitvm3_lowering::fixture::all_gate_fixture;

    #[test]
    fn pieces_form_one_garbled_circuit() {
        let (program, good) = all_gate_fixture();
        let (whole, whole_ands, _) = direct::run(&program, &good).unwrap();
        assert!(whole);
        // A handful of rejected witnesses and one that only changes a value the relation ignores, if any.
        let mut bad: Vec<Vec<Value>> = Vec::new();
        for i in (0..good.len()).step_by(3) {
            let mut w = good.clone();
            w[i][0] = (w[i][0] + 1) % P;
            bad.push(w);
        }
        let mut alias = good.clone();
        alias[0][0] = P;
        bad.push(alias);
        let mut witnesses: Vec<&[Value]> = vec![&good];
        witnesses.extend(bad.iter().map(|w| w.as_slice()));
        let expected: Vec<bool> = witnesses.iter().map(|w| direct::run(&program, w).unwrap().0).collect();
        assert!(expected.iter().any(|v| !*v), "no rejected witness in the test set");

        let mut commitments = Vec::new();
        for shard_size in [1, 3, 1000] {
            let out = run(&program, &witnesses, shard_size, 2, 7).unwrap();
            for (k, (verdict, rejecting, label_ok)) in out.verdicts.iter().enumerate() {
                assert_eq!(*verdict, expected[k], "witness {k}, shard size {shard_size}");
                assert_eq!(*rejecting == 0, expected[k]);
                assert!(*label_ok, "output label mismatch for witness {k}, shard size {shard_size}");
            }
            if shard_size == 1000 {
                // One piece holding every constraint: the same ANDs as the monolithic program, no combining gate.
                assert_eq!(out.ciphertexts, whole_ands);
            }
            commitments.push(out.commitment);
        }
        // Garbling is deterministic for a seed, and the seed matters.
        let again = run(&program, &witnesses, 3, 1, 7).unwrap();
        assert_eq!(again.commitment, commitments[1]);
        let other = run(&program, &witnesses, 3, 1, 8).unwrap();
        assert_ne!(other.commitment, commitments[1]);
    }

    #[test]
    fn input_labels_depend_only_on_global_position() {
        let key = [3u8; 32];
        assert_eq!(input_label0(&key, 5, 9).to_u128(), input_label0(&key, 5, 9).to_u128());
        assert_ne!(input_label0(&key, 5, 9).to_u128(), input_label0(&key, 9, 5).to_u128());
        assert_ne!(input_label0(&key, 5, 9).to_u128(), input_label0(&[4u8; 32], 5, 9).to_u128());
    }
}
