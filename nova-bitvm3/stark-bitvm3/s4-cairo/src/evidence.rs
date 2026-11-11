//! Evidence for a 1-to-1 circuit-proof verifier. Two sources of proofs, each with its configuration taken
//! from pinned constants rather than from the proof:
//!   * the fixture: upstream's committed production-sized proof of the privacy Cairo-verifier circuit
//!     (`test_data/multiverifier/proof_cairo.bin`, blowup 3, 23 queries);
//!   * the production recursion proof produced by upstream's `privacy_recursive_prove` (blowup 2,
//!     35 queries, root `PRIVACY_RECURSION_CIRCUIT_PREPROCESSED_ROOT`), stored by the `s4-prove` binary.
use anyhow::{Context as _, Result, ensure};
use circuit_prover::test_utils::{
    PCS_CONFIG, PRIVACY_CAIRO_VERIFIER_OUTPUT_DIGEST, PRIVACY_CAIRO_VERIFIER_PREPROCESSED_ROOT,
    multiverifier_preprocessed_column_log_sizes,
};
use circuit_serialize::deserialize::deserialize_proof_with_config;
use circuit_verifier::multiverifier::{CircuitVerifierInput, SharedConfig, build_multiverifier_circuit, shared_config};
use circuits::{blake::HashValue, context::FinalizedContext, ivalue::NoValue};
use circuits_stark_verifier::proof::{Proof, empty_proof};
use privacy_circuit_verify::get_recursive_circuit_config;
use privacy_common::consts::PRIVACY_RECURSION_CIRCUIT_PREPROCESSED_ROOT as PRODUCTION_ROOT;
use std::path::Path;
use stwo::core::{fields::qm31::QM31, vcs::blake2_hash::Blake2sHash};
use stwo_bitvm3_lowering::Value;

pub struct Fixture {
    pub label: &'static str,
    pub shared: SharedConfig,
    pub proof: Proof<QM31>,
    pub root: [u32; 8],
    pub digest: HashValue<QM31>,
}

/// The shared configuration of the committed fixture: log blowup 3, 23 queries, 27 proof-of-work bits,
/// trace log size 21, and the 45-column preprocessed layout of the padded Cairo-verifier circuit.
pub fn fixture_shared() -> SharedConfig {
    shared_config(multiverifier_preprocessed_column_log_sizes(), PCS_CONFIG)
}

/// The shared configuration of the production recursion circuit.
pub fn production_shared() -> Result<SharedConfig> {
    let config = get_recursive_circuit_config(&PRODUCTION_ROOT).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(shared_config(config.preprocessed_column_log_sizes, config.config))
}

/// The proof-independent 1-to-1 verifier circuit of a shared configuration.
pub fn template(shared: &SharedConfig) -> FinalizedContext<NoValue> {
    let input = CircuitVerifierInput::<NoValue> {
        proof: empty_proof(&shared.proof_config),
        preprocessed_root: HashValue::no_value(),
        output_digest: HashValue::no_value(),
    };
    build_multiverifier_circuit::<NoValue>(vec![input], shared)
}
pub fn fixture_template() -> FinalizedContext<NoValue> {
    template(&fixture_shared())
}

fn parse(bytes: &[u8], shared: &SharedConfig) -> Result<Proof<QM31>> {
    let mut slice: &[u8] = bytes;
    let proof = deserialize_proof_with_config(&mut slice, &shared.proof_config)
        .map_err(|e| anyhow::anyhow!("deserialize: {e:?}"))?;
    ensure!(slice.is_empty(), "trailing bytes after the proof: {}", slice.len());
    Ok(proof)
}

/// Upstream's committed proof, deserialized against the pinned proof configuration.
pub fn load_fixture(dir: &Path) -> Result<Fixture> {
    let shared = fixture_shared();
    let proof = parse(&std::fs::read(dir.join("proof_cairo.bin")).context("proof_cairo.bin")?, &shared)?;
    Ok(Fixture {
        label: "committed fixture proof_cairo.bin (blowup 3, 23 queries)",
        shared,
        proof,
        root: PRIVACY_CAIRO_VERIFIER_PREPROCESSED_ROOT,
        digest: HashValue::from(PRIVACY_CAIRO_VERIFIER_OUTPUT_DIGEST),
    })
}

/// A recursion proof from `privacy_recursive_prove`: the decompressed `CircuitSerialize` bytes and the
/// hex of the Blake2s digest of the bootloader output preimage. The root is the production constant.
pub fn load_production(raw: &Path, digest_hex: &str) -> Result<Fixture> {
    let shared = production_shared()?;
    let proof = parse(&std::fs::read(raw).context("recursion proof")?, &shared)?;
    let bytes: [u8; 32] = hex::decode(digest_hex.trim()).context("digest hex")?.try_into().map_err(|_| anyhow::anyhow!("digest must be 32 bytes"))?;
    Ok(Fixture {
        label: "production recursion proof (blowup 2, 35 queries)",
        shared,
        proof,
        root: PRODUCTION_ROOT,
        digest: HashValue::<QM31>::from(Blake2sHash(bytes)),
    })
}

pub fn context(f: &Fixture, proof: &Proof<QM31>) -> FinalizedContext<QM31> {
    let input = CircuitVerifierInput::<QM31> {
        proof: proof.clone(),
        preprocessed_root: HashValue::<QM31>::from(f.root),
        output_digest: f.digest.clone(),
    };
    build_multiverifier_circuit::<QM31>(vec![input], &f.shared)
}

pub fn values(c: &FinalizedContext<QM31>) -> Vec<Value> {
    c.values().iter().map(|v| v.to_m31_array().map(|x| x.0)).collect()
}
