//! Laboratory profile L21: the pinned configuration under which the full Shinigami executable is proved as
//! a task of upstream's privacy bootloader and recursed into a 1-to-1 circuit proof.
//!
//! It differs from upstream's production privacy profile in three pinned ways, none read from a proof:
//!   * the Cairo trace may reach 2^21 rows (production: 2^20), because the bootloader must load and hash
//!     the 169,856-word executable;
//!   * the Cairo proof uses blowup 2 with 35 queries and 26 proof-of-work bits (production: blowup 3,
//!     23 queries, 27 bits); both are upstream's `privacy_pcs_config` parameter pairs for its 96-bit target;
//!   * the component set drops the Pedersen and Poseidon families, which this task never touches.
//! The bootloader program, the preprocessed trace variant, the interaction proof-of-work bits, the circuit
//! FRI parameters and the zero-knowledge blinding rule are upstream's production values.
//!
//! This file is shared by `s4-cairo` (the Boolean checker) and `s4-prove` (the prover).
use cairo_air::verifier::INTERACTION_POW_BITS;
use circuit_cairo_verifier::all_components::all_components;
use circuit_cairo_verifier::verify::{CairoVerifierConfig, NON_QUERY_INFO_LEAK};
use circuits::ivalue::NoValue;
use circuits_stark_verifier::proof::ProofConfig;
use privacy_common::get_privacy_bootloader_program;
use std::sync::Arc;
use stwo::core::fri::{FriConfig, FriParams};
use stwo::core::pcs::PcsConfig;
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTraceVariant;
use stwo_cairo_common::prover_types::cpu::Felt252;

pub const CAIRO_TRACE_LOG_SIZE: u32 = 21;
pub const CAIRO_FRI: FriParams =
    FriParams { pow_bits: 26, log_blowup_factor: 2, log_last_layer_degree_bound: 0, n_queries: 35, fold_step: 4 };
pub const CAIRO_PCS: PcsConfig =
    PcsConfig::from_fri_config(FriConfig { params: CAIRO_FRI, trace_log_size: CAIRO_TRACE_LOG_SIZE });
/// The circuit prover's FRI parameters: upstream's production `CIRCUIT_FRI_CONFIG.params`.
pub const CIRCUIT_FRI: FriParams =
    FriParams { pow_bits: 26, log_blowup_factor: 2, log_last_layer_degree_bound: 0, n_queries: 35, fold_step: 4 };
pub const VARIANT: PreProcessedTraceVariant = PreProcessedTraceVariant::CanonicalSmall;

/// Components of the Cairo AIR that the Shinigami bootloader task enables, in `all_components` order.
pub const COMPONENTS: &[&str] = &[
    "add_opcode",
    "add_opcode_small",
    "add_ap_opcode",
    "assert_eq_opcode",
    "assert_eq_opcode_imm",
    "assert_eq_opcode_double_deref",
    "blake_compress_opcode",
    "call_opcode_abs",
    "call_opcode_rel_imm",
    "jnz_opcode_non_taken",
    "jnz_opcode_taken",
    "jump_opcode_abs",
    "jump_opcode_double_deref",
    "jump_opcode_rel",
    "jump_opcode_rel_imm",
    "mul_opcode",
    "mul_opcode_small",
    "ret_opcode",
    "verify_instruction",
    "blake_round",
    "blake_g",
    "blake_round_sigma",
    "triple_xor_32",
    "verify_bitwise_xor_12",
    "bitwise_builtin",
    "range_check_builtin",
    "memory_address_to_id",
    "memory_id_to_big",
    "memory_id_to_small",
    "range_check_6",
    "range_check_8",
    "range_check_11",
    "range_check_12",
    "range_check_18",
    "range_check_20",
    "range_check_4_3",
    "range_check_4_4",
    "range_check_9_9",
    "range_check_7_2_5",
    "range_check_3_6_6_3",
    "range_check_4_4_4_4",
    "range_check_3_3_3_3_3",
    "verify_bitwise_xor_4",
    "verify_bitwise_xor_7",
    "verify_bitwise_xor_8",
    "verify_bitwise_xor_9",
];

/// Merkle root of the canonical-small preprocessed trace committed with blowup 2 and lifted to 2^23.
/// Upstream's table (`get_preprocessed_root`) only covers trace log size 20; this value is what the
/// pinned prover commits to and is recomputable from the preprocessed trace alone.
pub const CAIRO_PREPROCESSED_ROOT: [u32; 8] =
    [3179307202, 1157159835, 453510509, 2593092033, 3795335427, 2895299845, 1780569295, 460461011];

/// Preprocessed root of the Cairo-verifier circuit of this profile (the circuit the final verifier checks).
/// `s4-cairo lab-root` recomputes it from this file's constants alone.
pub const CIRCUIT_PREPROCESSED_ROOT: [u32; 8] =
    [268396719, 2599903103, 1868538018, 1647113170, 245116028, 3068642296, 2008906235, 2577474101];

/// Blake program hash (the bootloader's `compute_program_hash_chain`, version 0) of the Bootloader
/// entrypoint of `shinigami_bitvm3_receipt.executable.json`: 169,856 words, builtins output, range_check
/// and bitwise, built by Scarb 2.18.0 from the pinned S3 sources. `s4-prove lab-bind` recomputes it.
#[allow(dead_code)]
pub const SHINIGAMI_PROGRAM_HASH: &str = "0x35d865e3a2c16e04032630546acb93f8d1b883cbb6fb688eb4e1afd1dc42f8";

pub fn enabled_bits() -> Vec<bool> {
    all_components::<NoValue>().keys().map(|name| COMPONENTS.contains(name)).collect()
}

/// The fixed configuration of the Cairo-verifier circuit for this profile.
pub fn cairo_verifier_config() -> Result<CairoVerifierConfig, String> {
    let all = all_components::<NoValue>();
    for name in COMPONENTS {
        if !all.contains_key(name) {
            return Err(format!("unknown component {name}"));
        }
    }
    let enabled = all.into_iter().filter(|(name, _)| COMPONENTS.contains(name)).collect();
    let proof_config = ProofConfig::new(&enabled, VARIANT.n_columns(), &CAIRO_PCS, INTERACTION_POW_BITS);
    let bootloader = get_privacy_bootloader_program().map_err(|e| e.to_string())?;
    let program = bootloader
        .iter_data()
        .map(|value| value.get_int().map(|felt| Felt252::from(felt).get_limbs()).ok_or("non-integer program cell"))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CairoVerifierConfig {
        proof_config,
        enabled_bits: enabled_bits(),
        program: Arc::from(program.as_slice()),
        preprocessed_root: CAIRO_PREPROCESSED_ROOT.into(),
        preprocessed_trace_variant: VARIANT,
        zk_blinding_amount: Some(CIRCUIT_FRI.n_queries + NON_QUERY_INFO_LEAK),
    })
}
