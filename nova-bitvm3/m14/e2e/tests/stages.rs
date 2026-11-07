//! Stage-by-stage checks of the circuit verifier on the committed v2 final proof (c4) against
//! SP1's own verifier code.
use garbled_snark_verifier::{
    WireId,
    circuit::{CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, ExecuteMode, StreamingResult},
};
use m14_circuit::hash::Transcript;
use m14_e2e::{
    native::{self, Item, F, GC},
    verifier::{self, Inputs, Shape},
};
use slop_algebra::AbstractField;
use slop_challenger::{CanObserve, IopCtx, VariableLengthChallenger};
use sp1_hypercube::{air::MachineAir, LogUpGkrVerifier};

const CAP: usize = 1 << 24;

struct Plain(Vec<bool>);
impl CircuitInput for Plain {
    type WireRepr = Vec<WireId>;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (0..self.0.len()).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<WireId> {
        w.clone()
    }
}
impl EncodeInput<ExecuteMode> for Plain {
    fn encode(&self, w: &Self::WireRepr, mode: &mut ExecuteMode) {
        for (id, v) in w.iter().zip(&self.0) {
            mode.feed_wire(*id, *v);
        }
    }
}

/// Observed bytes of the recorded native verification of the c4 v2 proof.
fn native_observed() -> Vec<u8> {
    let raw = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../circuit/fixtures/c4-v2-transcript.bin")).unwrap();
    let (mut at, mut out) = (0, Vec::new());
    while at < raw.len() {
        let n = u32::from_le_bytes(raw[at + 1..at + 5].try_into().unwrap()) as usize;
        if raw[at] == 0 {
            out.extend_from_slice(&raw[at + 5..at + 5 + n]);
        }
        at += 5 + n;
    }
    out
}

fn bytes_of(bits: &[bool]) -> Vec<u8> {
    bits.chunks(8).map(|c| c.iter().enumerate().fold(0u8, |a, (i, &b)| a | ((b as u8) << i))).collect()
}

fn stage_logup(items: &[Item], shape: &Shape) -> (bool, Vec<u8>, usize) {
    let input = native::bits(items);
    let n = input.len();
    let r: StreamingResult<ExecuteMode, _, Vec<bool>> = CircuitBuilder::streaming_execute(Plain(input), CAP, |c, w| {
        let mut t = Transcript::new(verifier::DOMAIN_V2);
        let mut inp = Inputs::new(w);
        verifier::preamble(c, &mut t, shape, &mut inp);
        let out = verifier::logup(c, &mut t, shape, &mut inp);
        assert_eq!(inp.used(), n, "inputs consumed");
        let mut o = vec![out.ok];
        o.extend(t.log.iter().copied());
        o
    });
    let gates = r.gate_count.nonfree_gate_count() as usize;
    (r.output_value[0], bytes_of(&r.output_value[1..]), gates)
}

#[test]
fn logup_gkr_matches_sp1_on_the_real_proof() {
    let proof = native::load(native::FIXTURE_V2);
    let machine = native::machine();
    let shard = &proof.proof;

    // SP1 natively: the same preamble, then its LogUp-GKR verifier.
    let mut ch = GC::default_challenger();
    proof.vk.observe_into(&mut ch);
    <m13_verify::ctx::Blake3ChallengerV2 as VariableLengthChallenger<F, m13_verify::ctx::Digest>>::observe_constant_length_extension_slice::<F>(&mut ch, &shard.public_values);
    ch.observe(shard.main_commitment);
    ch.observe(F::from_canonical_usize(shard.opened_values.chips.len()));
    for (name, cv) in shard.opened_values.chips.iter() {
        let acc = cv.degree.iter().fold(F::zero(), |acc, &x| x + F::two() * acc);
        ch.observe(acc);
        ch.observe(F::from_canonical_usize(name.len()));
        name.as_bytes().iter().for_each(|b| ch.observe(F::from_canonical_u8(*b)));
    }
    let chips = native::shard_chips(&machine, shard);
    let degrees = shard.opened_values.chips.iter().map(|(n, c)| (n.clone(), c.degree.clone())).collect();
    LogUpGkrVerifier::<GC, m13_verify::Blake3WrapSCV2>::verify_logup_gkr(
        &chips,
        &degrees,
        sp1_verifier::compressed::RECURSION_MAX_LOG_ROW_COUNT,
        &shard.logup_gkr_proof,
        &shard.public_values,
        &mut ch,
    )
    .expect("SP1 accepts the real proof's LogUp-GKR");

    // The circuit.
    let shape = Shape::new(&machine, &proof.vk, shard);
    eprintln!(
        "chips {} interactions {} niv {} beta_seed_dim {} public values {}",
        shape.chips.len(),
        shape.num_interactions,
        shape.niv,
        shape.beta_seed_dim,
        shape.num_pv
    );
    assert!(chips.iter().map(|c| c.name()).eq(shape.chips.iter().map(|c| c.name())));
    let items = native::items_logup(&machine, shard);
    let (ok, observed, gates) = stage_logup(&items, &shape);
    eprintln!("M14-E2E logup stage: {} input items, {gates} gates", items.len());
    let want = native_observed();
    assert_eq!(observed[..], want[..observed.len()], "circuit observations differ from SP1's transcript");
    assert!(ok, "circuit rejects the real LogUp-GKR");

    // A changed round message is rejected.
    let mut bad = items.clone();
    let k = items.len() - 40;
    if let Item::Ext(v) = &mut bad[k] {
        v[0] = (v[0] + 1) % 0x7f00_0001;
    } else {
        panic!("item {k} is not an extension element");
    }
    assert!(!stage_logup(&bad, &shape).0, "changed opening accepted");
}
