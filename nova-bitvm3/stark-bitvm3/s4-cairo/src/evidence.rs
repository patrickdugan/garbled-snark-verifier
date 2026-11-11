//! Evidence for a 1-to-1 circuit-proof verifier: upstream's committed production-sized proof of the
//! privacy Cairo-verifier circuit (`test_data/multiverifier/proof_cairo.bin`), its mutations, native
//! acceptance and Boolean acceptance. The configuration (PCS config, preprocessed layout, preprocessed
//! root and output digest) is taken from upstream's own fixture constants, never from the proof.
use anyhow::{Context as _, Result, ensure};
use circuit_prover::test_utils::{
    PCS_CONFIG, PRIVACY_CAIRO_VERIFIER_OUTPUT_DIGEST, PRIVACY_CAIRO_VERIFIER_PREPROCESSED_ROOT,
    multiverifier_preprocessed_column_log_sizes,
};
use circuit_serialize::deserialize::deserialize_proof_with_config;
use circuit_verifier::multiverifier::{CircuitVerifierInput, SharedConfig, build_multiverifier_circuit, shared_config};
use circuits::{blake::HashValue, context::FinalizedContext, ivalue::NoValue};
use circuits_stark_verifier::proof::{Proof, empty_proof};
use std::path::Path;
use stwo::core::fields::qm31::QM31;
use stwo_bitvm3_lowering::Value;

pub struct Fixture {
    pub shared: SharedConfig,
    pub proof: Proof<QM31>,
}

/// The shared configuration of the committed fixture: log blowup 3, 23 queries, 27 proof-of-work bits,
/// trace log size 21, and the 45-column preprocessed layout of the padded Cairo-verifier circuit.
pub fn fixture_shared() -> SharedConfig {
    shared_config(multiverifier_preprocessed_column_log_sizes(), PCS_CONFIG)
}

/// The proof-independent 1-to-1 verifier circuit of the fixture configuration.
pub fn fixture_template() -> FinalizedContext<NoValue> {
    let shared = fixture_shared();
    let input = CircuitVerifierInput::<NoValue> {
        proof: empty_proof(&shared.proof_config),
        preprocessed_root: HashValue::no_value(),
        output_digest: HashValue::no_value(),
    };
    build_multiverifier_circuit::<NoValue>(vec![input], &shared)
}

/// Loads the committed proof, deserialized against the pinned proof configuration, requiring that every
/// byte is consumed.
pub fn load(dir: &Path) -> Result<Fixture> {
    let shared = fixture_shared();
    let bytes = std::fs::read(dir.join("proof_cairo.bin")).context("proof_cairo.bin")?;
    let mut slice: &[u8] = &bytes;
    let proof = deserialize_proof_with_config(&mut slice, &shared.proof_config)
        .map_err(|e| anyhow::anyhow!("deserialize: {e:?}"))?;
    ensure!(slice.is_empty(), "trailing bytes after the proof: {}", slice.len());
    Ok(Fixture { shared, proof })
}

pub fn context(f: &Fixture, proof: &Proof<QM31>) -> FinalizedContext<QM31> {
    let input = CircuitVerifierInput::<QM31> {
        proof: proof.clone(),
        preprocessed_root: HashValue::<QM31>::from(PRIVACY_CAIRO_VERIFIER_PREPROCESSED_ROOT),
        output_digest: HashValue::from(PRIVACY_CAIRO_VERIFIER_OUTPUT_DIGEST),
    };
    build_multiverifier_circuit::<QM31>(vec![input], &f.shared)
}

pub fn values(c: &FinalizedContext<QM31>) -> Vec<Value> {
    c.values().iter().map(|v| v.to_m31_array().map(|x| x.0)).collect()
}
