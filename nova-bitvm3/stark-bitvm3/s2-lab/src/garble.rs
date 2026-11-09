//! Full-template garble/evaluate experiment. Fixed randomness, direct input-label
//! selection, and repeated evaluation are laboratory-only conventions.
use anyhow::{ensure, Result};
use garbled_snark_verifier::{
    AesCcrGateHasher, Blake3AccumulatingHash, CircuitContext, EvaluatedWire,
    GarbleMode, GarbledWire, GateHasher, S, WireId,
    circuit::{CiphertextHandler, CiphertextSource, CircuitBuilder, CircuitInput,
        CircuitMode, EncodeInput, EvaluateMode, FileSource, StreamingResult},
};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use serde_json::{json, Value as Json};
use std::{fs::{self, File}, io::{BufWriter, Write}, path::Path, time::Instant};
use stwo_bitvm3_adapter::Repo;
use stwo_bitvm3_lowering::{Program, Value};

struct GIn(usize);
impl CircuitInput for GIn {
    type WireRepr = Vec<WireId>;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (0..self.0).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<WireId> { w.clone() }
}
impl<H: GateHasher, T: CiphertextHandler> EncodeInput<GarbleMode<H,T>> for GIn {
    fn encode(&self, w: &Self::WireRepr, mode: &mut GarbleMode<H,T>) {
        for id in w { let label = mode.issue_garbled_wire(); mode.feed_wire(*id,label); }
    }
}
struct EIn<'a> { labels: &'a [GarbledWire], values: &'a [Value] }
impl CircuitInput for EIn<'_> {
    type WireRepr = Vec<WireId>;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (0..self.values.len()*128).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<WireId> { w.clone() }
}
impl<H: GateHasher, T: CiphertextSource> EncodeInput<EvaluateMode<H,T>> for EIn<'_> {
    fn encode(&self, w: &Self::WireRepr, mode: &mut EvaluateMode<H,T>) {
        assert_eq!(w.len(), self.labels.len());
        for (i,id) in w.iter().enumerate() {
            let word = self.values[i/128][(i%128)/32];
            let bit = (word >> (i%32)) & 1 != 0;
            mode.feed_wire(*id, EvaluatedWire::new_from_garbled(&self.labels[i],bit));
        }
    }
}
struct DiskSink {
    writer: BufWriter<File>,
    count: u64,
    hash: Blake3AccumulatingHash,
}
impl CiphertextHandler for DiskSink {
    type Result = (u64, [u8;32]);
    fn handle(&mut self, ct: S) {
        self.count += 1;
        assert!(self.count <= 150_000_000, "S2 ciphertext budget exceeded");
        self.writer.write_all(&ct.to_u128().to_be_bytes()).expect("write laboratory ciphertext");
        self.hash.update(ct);
    }
    fn finalize(mut self) -> Self::Result {
        self.writer.flush().expect("flush laboratory ciphertext");
        (self.count, self.hash.finalize())
    }
}
fn build<C: CircuitContext>(c: &mut C, w: &[WireId], program: &Program) -> Vec<WireId> {
    vec![program.lower(&mut Repo(c), w).expect("validated fixed template")]
}

pub fn run(program: &Program, good: &[Value], bad: &[Value], expected_ands: u64,
           scratch: &Path) -> Result<Json> {
    ensure!(good.len() == program.n_vars() && bad.len() == good.len(), "witness shape");
    ensure!(expected_ands <= 150_000_000, "garbling budget");
    let cap = program.input_bits().checked_add(1<<18).and_then(usize::checked_next_power_of_two)
        .ok_or_else(|| anyhow::anyhow!("live-wire budget overflow"))?;
    ensure!(cap <= 1<<24, "live-wire capacity exceeds experiment cap");
    let sink = DiskSink { writer: BufWriter::with_capacity(4<<20, File::create(scratch)?),
        count: 0, hash: Blake3AccumulatingHash::default() };
    let seed = 117u64;
    let start = Instant::now();
    let g: StreamingResult<GarbleMode<AesCcrGateHasher,DiskSink>,_,Vec<GarbledWire>> =
        CircuitBuilder::streaming_garbling(GIn(program.input_bits()), cap, seed, sink,
            |c,w| build(c,w,program));
    let garble_seconds = start.elapsed().as_secs_f64();
    let (count, hash) = g.ciphertext_handler_result;
    ensure!(count == expected_ands && count == g.gate_count.nonfree_gate_count(), "gate-count disagreement");
    ensure!(fs::metadata(scratch)?.len() == count*16, "ciphertext length disagreement");
    println!("S2 full garble ciphertexts={count} bytes={} seconds={garble_seconds:.3}",count*16);
    let mut cases = Vec::new();
    for (name, values, expected) in [("authentic",good,true),("trace_auth_path",bad,false)] {
        let start = Instant::now();
        let mut rng = ChaChaRng::seed_from_u64(seed);
        let hasher = AesCcrGateHasher::from_rng(&mut rng);
        let source = FileSource::from_path(scratch)?;
        let e: StreamingResult<EvaluateMode<AesCcrGateHasher,FileSource>,_,Vec<EvaluatedWire>> =
            CircuitBuilder::streaming_evaluation(
                EIn { labels: &g.input_wire_values, values }, cap,
                g.true_wire_constant.select(true).to_u128(),
                g.false_wire_constant.select(false).to_u128(), hasher, source,
                |c,w| build(c,w,program));
        ensure!(e.output_value.len() == 1 && g.output_value.len() == 1, "acceptance output shape");
        ensure!(e.output_value[0].active_label == g.output_value[0].select(expected), "wrong output label: {name}");
        ensure!(e.output_value[0].active_label != g.output_value[0].select(!expected), "ambiguous output label: {name}");
        ensure!(e.ciphertext_handler_result == hash, "ciphertext transcript mismatch");
        ensure!(e.gate_count.nonfree_gate_count() == count, "evaluation gate count");
        let seconds = start.elapsed().as_secs_f64();
        println!("S2 full evaluation {name} accepted={expected} seconds={seconds:.3}");
        cases.push(json!({"case":name,"accepted":expected,"seconds":seconds,
            "output_label_checked":true,"opposite_label_rejected":true,"ciphertext_hash_checked":true}));
    }
    fs::remove_file(scratch)?;
    Ok(json!({"ciphertexts":count,"ciphertext_bytes":count*16,
        "ciphertext_blake3":hex::encode(hash),"live_wire_capacity":cap,
        "garble_seconds":garble_seconds,"cases":cases,"test_only_label_selection":true,
        "bitcoin_dispute_tested":false}))
}
