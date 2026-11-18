//! Small CPU-only regressions for seed entropy and the public evaluator boundary.
use garbled_snark_verifier::{
    AesCcrGateHasher, Delta, EvaluatedWire, GarbleMode, GarbledWire, Gate, GateHasher, S, WireId,
    circuit::{
        CiphertextHandler, CiphertextSource, CircuitBuilder, CircuitContext, CircuitInput,
        CircuitMode, EncodeInput, EvaluateMode, FALSE_WIRE, StreamingResult, TRUE_WIRE,
    },
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;

const CAPACITY: usize = 64;

struct FreshInputs;

impl CircuitInput for FreshInputs {
    type WireRepr = [WireId; 3];

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        std::array::from_fn(|_| issue())
    }

    fn collect_wire_ids(wires: &Self::WireRepr) -> Vec<WireId> {
        wires.to_vec()
    }
}

impl<H: GateHasher, CTH: CiphertextHandler> EncodeInput<GarbleMode<H, CTH>> for FreshInputs {
    fn encode(&self, wires: &Self::WireRepr, mode: &mut GarbleMode<H, CTH>) {
        for wire in wires {
            let labels = mode.issue_garbled_wire();
            mode.feed_wire(*wire, labels);
        }
    }
}

struct SelectedInputs([EvaluatedWire; 3]);

impl CircuitInput for SelectedInputs {
    type WireRepr = [WireId; 3];

    fn allocate(&self, issue: impl FnMut() -> WireId) -> Self::WireRepr {
        FreshInputs.allocate(issue)
    }

    fn collect_wire_ids(wires: &Self::WireRepr) -> Vec<WireId> {
        wires.to_vec()
    }
}

impl<H: GateHasher, SRC: CiphertextSource> EncodeInput<EvaluateMode<H, SRC>> for SelectedInputs {
    fn encode(&self, wires: &Self::WireRepr, mode: &mut EvaluateMode<H, SRC>) {
        for (wire, selected) in wires.iter().zip(&self.0) {
            mode.feed_wire(*wire, selected.clone());
        }
    }
}

#[derive(Default)]
struct Ciphertexts(Vec<S>);

impl CiphertextHandler for Ciphertexts {
    type Result = Vec<S>;

    fn handle(&mut self, ciphertext: S) {
        self.0.push(ciphertext);
    }

    fn finalize(self) -> Self::Result {
        self.0
    }
}

struct CiphertextReader(std::vec::IntoIter<S>);

impl CiphertextSource for CiphertextReader {
    type Result = ();

    fn recv(&mut self) -> Option<S> {
        self.0.next()
    }

    fn finalize(self) {
        assert_eq!(self.0.len(), 0, "evaluator must consume the whole stream");
    }
}

#[derive(Debug, PartialEq, Eq)]
struct PublicParameters {
    salt: [u8; 16],
    true_label: [u8; 16],
    false_label: [u8; 16],
}

type GarbledResult =
    StreamingResult<GarbleMode<AesCcrGateHasher, Ciphertexts>, FreshInputs, Vec<GarbledWire>>;

fn circuit(ctx: &mut impl CircuitContext, inputs: &[WireId; 3]) -> Vec<WireId> {
    let conjunction = ctx.issue_wire();
    ctx.add_gate(Gate::and(inputs[0], inputs[1], conjunction));
    let result = ctx.issue_wire();
    ctx.add_gate(Gate::xor(conjunction, inputs[2], result));
    let with_true = ctx.issue_wire();
    ctx.add_gate(Gate::and(result, TRUE_WIRE, with_true));
    let with_false = ctx.issue_wire();
    ctx.add_gate(Gate::or(result, FALSE_WIRE, with_false));
    vec![with_true, with_false]
}

fn garble(mode: GarbleMode<AesCcrGateHasher, Ciphertexts>) -> (PublicParameters, GarbledResult) {
    let public = PublicParameters {
        salt: mode.gate_hasher_seed().to_le_bytes(),
        true_label: mode.true_value().select(true).to_le_bytes(),
        false_label: mode.false_value().select(false).to_le_bytes(),
    };
    let result = CircuitBuilder::run_streaming(FreshInputs, mode, circuit);
    (public, result)
}

fn full_seed(seed: [u8; 32]) -> (PublicParameters, GarbledResult) {
    garble(GarbleMode::new_with_seed(
        CAPACITY,
        seed,
        Ciphertexts::default(),
    ))
}

fn assert_same_artifact(a: &GarbledResult, b: &GarbledResult) {
    assert_eq!(a.input_wire_values, b.input_wire_values);
    assert_eq!(a.output_value, b.output_value);
    assert_eq!(a.ciphertext_handler_result, b.ciphertext_handler_result);
    assert_eq!(
        a.gate_count.nonfree_gate_count(),
        b.gate_count.nonfree_gate_count()
    );
}

#[test]
fn full_seed_is_deterministic() {
    let (public_a, a) = full_seed([0x42; 32]);
    let (public_b, b) = full_seed([0x42; 32]);
    assert_eq!(public_a, public_b);
    assert_same_artifact(&a, &b);
    assert!(!a.ciphertext_handler_result.is_empty());
}

#[test]
fn every_seed_byte_above_u64_changes_garbling() {
    let seed = [0x42; 32];
    let (public, baseline) = full_seed(seed);
    let baseline_delta =
        baseline.input_wire_values[0].label0 ^ &baseline.input_wire_values[0].label1;
    for index in 0..32 {
        let mut changed = seed;
        changed[index] ^= 1;
        let (changed_public, changed_result) = full_seed(changed);
        assert_ne!(public.salt, changed_public.salt, "seed byte {index}");
        assert_ne!(
            baseline.input_wire_values, changed_result.input_wire_values,
            "seed byte {index}"
        );
        let changed_delta = changed_result.input_wire_values[0].label0
            ^ &changed_result.input_wire_values[0].label1;
        assert_ne!(baseline_delta, changed_delta, "seed byte {index}");
        assert_ne!(
            baseline.ciphertext_handler_result, changed_result.ciphertext_handler_result,
            "seed byte {index}"
        );
    }
}

struct ScriptedRng<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl RngCore for ScriptedRng<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut out = [0u8; 4];
        self.fill_bytes(&mut out);
        u32::from_le_bytes(out)
    }

    fn next_u64(&mut self) -> u64 {
        let mut out = [0u8; 8];
        self.fill_bytes(&mut out);
        u64::from_le_bytes(out)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            *byte = self.bytes.get(self.offset).copied().unwrap_or(0);
            self.offset += 1;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[test]
fn delta_generation_rejects_zero_and_redacts_debug() {
    let mut scripted = [0u8; 32];
    scripted[16] = 0x5a;
    let mut rng = ScriptedRng {
        bytes: &scripted,
        offset: 0,
    };
    let delta = Delta::generate(&mut rng);
    assert_eq!(
        *delta,
        S::from_le_bytes([0x5a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    );
    assert_eq!(format!("{delta:?}"), "Delta([REDACTED])");
}

#[test]
#[should_panic(expected = "RNG failed to produce a non-zero Free-XOR delta")]
fn delta_generation_panics_on_all_zero_rng() {
    let mut rng = ScriptedRng {
        bytes: &[],
        offset: 0,
    };
    let _ = Delta::generate(&mut rng);
}

#[test]
fn legacy_u64_uses_the_same_chacha_seed_expansion() {
    for seed in [0, 7, u64::MAX] {
        let (legacy_public, legacy) =
            garble(GarbleMode::new(CAPACITY, seed, Ciphertexts::default()));
        let expanded_seed = ChaChaRng::seed_from_u64(seed).get_seed();
        let (full_public, full) = full_seed(expanded_seed);
        assert_eq!(legacy_public, full_public);
        assert_same_artifact(&legacy, &full);
    }
}

#[test]
fn evaluation_needs_only_public_parameters_and_selected_labels() {
    for pattern in 0u8..8 {
        let mut seed = [0x29; 32];
        seed[31] = pattern;
        let (public, garbled) = full_seed(seed);
        let bits: [bool; 3] = std::array::from_fn(|index| (pattern >> index) & 1 == 1);
        let selected = SelectedInputs(std::array::from_fn(|index| {
            EvaluatedWire::new(
                garbled.input_wire_values[index].select(bits[index]),
                bits[index],
            )
        }));
        // This boundary transfers no private seed, RNG, delta, or label pairs.
        let evaluated: StreamingResult<_, _, Vec<EvaluatedWire>> =
            CircuitBuilder::streaming_evaluation(
                selected,
                CAPACITY,
                S::from_le_bytes(public.true_label).to_u128(),
                S::from_le_bytes(public.false_label).to_u128(),
                AesCcrGateHasher::from_seed(S::from_le_bytes(public.salt)),
                CiphertextReader(garbled.ciphertext_handler_result.into_iter()),
                circuit,
            );
        let expected = (bits[0] & bits[1]) ^ bits[2];
        for (output, labels) in evaluated.output_value.iter().zip(&garbled.output_value) {
            assert_eq!(output.value, expected);
            assert_eq!(output.active_label, labels.select(expected));
        }
    }
}
