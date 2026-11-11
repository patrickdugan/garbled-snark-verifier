//! Evidence for a 1-to-1 circuit-proof verifier. Three sources of proofs, each with its configuration taken
//! from pinned constants rather than from the proof:
//!   * the fixture: upstream's committed production-sized proof of the privacy Cairo-verifier circuit
//!     (`test_data/multiverifier/proof_cairo.bin`, blowup 3, 23 queries);
//!   * the production recursion proof produced by upstream's `privacy_recursive_prove` (blowup 2,
//!     35 queries, root `PRIVACY_RECURSION_CIRCUIT_PREPROCESSED_ROOT`), stored by the `s4-prove` binary;
//!   * the laboratory profile L21 recursion proof of the Shinigami bootloader task (`lab_config.rs`).
//! The statement of a proof is two public values: the preprocessed root of the verified circuit and the
//! eight-word output digest. The final verifier's own eight output words follow from the statement alone.
use crate::lab_config;
use anyhow::{Context as _, Result, ensure};
use circuit_cairo_verifier::verify::build_cairo_verifier_circuit;
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::test_utils::{
    PCS_CONFIG, PRIVACY_CAIRO_VERIFIER_OUTPUT_DIGEST, PRIVACY_CAIRO_VERIFIER_PREPROCESSED_ROOT, leaf_circuit_hash,
    multiverifier_preprocessed_column_log_sizes, native_blake_u32s,
};
use circuit_serialize::deserialize::deserialize_proof_with_config;
use circuit_verifier::multiverifier::{CircuitVerifierInput, SharedConfig, build_multiverifier_circuit, shared_config};
use circuits::{blake::HashValue, context::FinalizedContext, ivalue::NoValue, utils::le_u32s_from_bytes};
use circuits_stark_verifier::proof::{Proof, empty_proof};
use privacy_circuit_verify::get_recursive_circuit_config;
use privacy_common::compute_privacy_bootloader_output_hash;
use privacy_common::consts::PRIVACY_RECURSION_CIRCUIT_PREPROCESSED_ROOT as PRODUCTION_ROOT;
use starknet_types_core::felt::Felt;
use std::path::Path;
use stwo::core::{fields::qm31::QM31, fri::FriConfig, pcs::PcsConfig};
use stwo_bitvm3_lowering::Value;

pub struct Fixture {
    pub label: &'static str,
    pub shared: SharedConfig,
    pub proof: Proof<QM31>,
    /// Statement, part 1: preprocessed root of the verified circuit.
    pub root: [u32; 8],
    /// Statement, part 2: the verified circuit's output digest.
    pub digest: [u32; 8],
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

/// The Cairo-verifier circuit of laboratory profile L21, derived from the pinned profile alone.
pub fn lab_preprocessed() -> Result<PreprocessedCircuit> {
    let vcfg = lab_config::cairo_verifier_config().map_err(anyhow::Error::msg)?;
    let mut circuit = build_cairo_verifier_circuit(&vcfg);
    Ok(PreprocessedCircuit::preprocess_circuit(&mut circuit))
}

/// The shared configuration of the final verifier for laboratory profile L21. Nothing here is read from a
/// proof: the layout of the verified circuit follows from the pinned Cairo-verifier configuration.
pub fn lab_shared() -> Result<SharedConfig> {
    let preprocessed = lab_preprocessed()?;
    let pcs = PcsConfig::from_fri_config(FriConfig { params: lab_config::CIRCUIT_FRI, trace_log_size: preprocessed.trace_log_size() });
    Ok(shared_config(preprocessed.preprocessed_trace.log_sizes(), pcs))
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

fn digest_from_hex(digest_hex: &str) -> Result<[u32; 8]> {
    let bytes: [u8; 32] =
        hex::decode(digest_hex.trim()).context("digest hex")?.try_into().map_err(|_| anyhow::anyhow!("digest must be 32 bytes"))?;
    Ok(le_u32s_from_bytes(bytes))
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
        digest: PRIVACY_CAIRO_VERIFIER_OUTPUT_DIGEST,
    })
}

/// A recursion proof from `privacy_recursive_prove`: the decompressed `CircuitSerialize` bytes and the
/// hex of the Blake2s digest of the bootloader output preimage. The root is the production constant.
pub fn load_production(raw: &Path, digest_hex: &str) -> Result<Fixture> {
    let shared = production_shared()?;
    let proof = parse(&std::fs::read(raw).context("recursion proof")?, &shared)?;
    Ok(Fixture {
        label: "production recursion proof (blowup 2, 35 queries)",
        shared,
        proof,
        root: PRODUCTION_ROOT,
        digest: digest_from_hex(digest_hex)?,
    })
}

/// What a Shinigami receipt statement says, read from the bootloader output preimage.
pub struct Receipt {
    pub program_hash: Felt,
    pub words: Vec<Felt>,
}

/// Parses and checks the privacy bootloader's output preimage for one task:
/// `[1, 2 + n, program_hash, n task output words]`, with the pinned Shinigami program hash.
pub fn receipt_from_preimage(preimage: &[Felt]) -> Result<Receipt> {
    ensure!(preimage.len() >= 3, "preimage too short");
    ensure!(preimage[0] == Felt::ONE, "the bootloader must have run exactly one task");
    ensure!(preimage[1] == Felt::from(preimage.len() - 1), "task output size word does not match the preimage length");
    let expected = Felt::from_hex(lab_config::SHINIGAMI_PROGRAM_HASH).map_err(|e| anyhow::anyhow!("pinned hash: {e}"))?;
    ensure!(preimage[2] == expected, "the task's program hash is not the pinned Shinigami executable");
    Ok(Receipt { program_hash: preimage[2], words: preimage[3..].to_vec() })
}

/// A recursion proof of the L21 Cairo-verifier circuit for the Shinigami bootloader task. The statement is
/// derived here: the root is the pinned profile constant and the digest is recomputed from the bootloader
/// output preimage, whose program hash must be the pinned Shinigami executable.
pub fn load_lab(raw: &Path, preimage_json: &str) -> Result<(Fixture, Receipt)> {
    let preimage: Vec<Felt> = serde_json::from_str(preimage_json).context("output preimage")?;
    let receipt = receipt_from_preimage(&preimage)?;
    let digest = le_u32s_from_bytes(compute_privacy_bootloader_output_hash(&preimage).0);
    let shared = lab_shared()?;
    let proof = parse(&std::fs::read(raw).context("recursion proof")?, &shared)?;
    let fixture = Fixture {
        label: "Shinigami under the privacy bootloader, laboratory profile L21",
        shared,
        proof,
        root: lab_config::CIRCUIT_PREPROCESSED_ROOT,
        digest,
    };
    Ok((fixture, receipt))
}

/// The final verifier's eight public output words for a statement, computed without any proof: Blake2s
/// over the verified circuit's hash (its configuration and preprocessed root) followed by the digest.
/// This mirrors upstream's `test_verify_circuit_single_input_output_digest`.
pub fn statement_words(shared: &SharedConfig, root: [u32; 8], digest: [u32; 8]) -> [u32; 8] {
    let payload: Vec<u32> = leaf_circuit_hash(root.into(), shared).into_iter().chain(digest).collect();
    native_blake_u32s(&payload)
}

/// The same eight words as the circuit holds them (two 16-bit limbs per word).
pub fn statement_outputs(shared: &SharedConfig, root: [u32; 8], digest: [u32; 8]) -> Vec<Value> {
    HashValue::<QM31>::from(statement_words(shared, root, digest))
        .into_iter()
        .map(|w| w.raw().to_m31_array().map(|x| x.0))
        .collect()
}

pub fn context_for(f: &Fixture, proof: &Proof<QM31>, digest: [u32; 8]) -> FinalizedContext<QM31> {
    let input = CircuitVerifierInput::<QM31> {
        proof: proof.clone(),
        preprocessed_root: HashValue::<QM31>::from(f.root),
        output_digest: HashValue::<QM31>::from(digest),
    };
    build_multiverifier_circuit::<QM31>(vec![input], &f.shared)
}
pub fn context(f: &Fixture, proof: &Proof<QM31>) -> FinalizedContext<QM31> {
    context_for(f, proof, f.digest)
}

pub fn values(c: &FinalizedContext<QM31>) -> Vec<Value> {
    c.values().iter().map(|v| v.to_m31_array().map(|x| x.0)).collect()
}
