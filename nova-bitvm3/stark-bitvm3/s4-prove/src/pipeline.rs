//! The production privacy recursive prover, generalized from a Cairo PIE to any bootloader task.
//!
//! This reproduces `privacy_prove::privacy_recursive_prove` at the pinned revision step for step (privacy
//! bootloader run, Cairo proof under the production Cairo profile, Cairo-verifier circuit, recursion proof
//! under the production circuit profile); only the task handed to the bootloader differs. The upstream
//! function takes a PIE and keeps its helpers private, so the body is repeated here.
use anyhow::{Result, anyhow, bail};
use cairo_program_runner_lib::types::{HashFunc, PrivacySimpleBootloaderInput, SimpleBootloaderInput};
use cairo_program_runner_lib::{ProgramInput, Task, TaskSpec, cairo_run_program};
use circuit_cairo_verifier::verify::{build_and_fill_cairo_verifier_circuit, prepare_cairo_proof_for_circuit_verifier};
use circuit_common::finalize::pad_context;
use circuit_prover::prover::{prepare_circuit_proof_for_circuit_verifier, prove_circuit_with_precompute};
use circuit_serialize::serialize::CircuitSerialize;
use privacy_common::{compute_privacy_bootloader_output_hash, get_privacy_bootloader_program};
use privacy_prove::RecursiveProverPrecomputes;
use privacy_prove::consts::{CAIRO_PROVER_PARAMS, CAIRO_RUN_CONFIG};
use starknet_types_core::felt::Felt;
use std::{fs::read_to_string, rc::Rc, time::Instant};
use stwo::core::utils::MaybeOwned;
use stwo_cairo_adapter::adapter::adapt;
use stwo_cairo_prover::prover::prove_cairo_with_precompute;
use tempfile::NamedTempFile;

/// Returns the raw (decompressed) recursion proof bytes and the bootloader output preimage.
pub fn prove_task(task: Task, pre: &RecursiveProverPrecomputes, log: &mut impl FnMut(String)) -> Result<(Vec<u8>, Vec<Felt>)> {
    let start = Instant::now();
    let preimage_file = NamedTempFile::new()?;
    // The program-hash function is a bootloader input; its cost scales with the program length.
    let hash = match std::env::var("S4_HASH").as_deref() {
        Ok("poseidon") => HashFunc::Poseidon,
        Ok("pedersen") => HashFunc::Pedersen,
        _ => HashFunc::Blake,
    };
    log(format!("program hash function: {:?}", std::env::var("S4_HASH").unwrap_or_else(|_| "blake".into())));
    let spec = TaskSpec { task: Rc::new(task), program_hash_function: hash };
    let input = PrivacySimpleBootloaderInput {
        simple_bootloader_input: SimpleBootloaderInput { fact_topologies_path: None, single_page: true, tasks: vec![spec] },
        output_preimage_dump_path: preimage_file.path().to_path_buf(),
    };
    let bootloader = get_privacy_bootloader_program().map_err(|e| anyhow!("{e}"))?;
    let runner = cairo_run_program(&bootloader, Some(ProgramInput::Value(Box::new(input))), CAIRO_RUN_CONFIG, None)
        .map_err(|e| anyhow!("bootloader run: {e}"))?;
    let preimage: Vec<Felt> = serde_json::from_str(&read_to_string(preimage_file.path())?)?;
    log(format!("bootloader executed, output preimage {} felts ({:.1}s)", preimage.len(), start.elapsed().as_secs_f64()));
    let prover_input = adapt(&runner).map_err(|e| anyhow!("adapt: {e}"))?;
    log(format!("prover input adapted ({:.1}s)", start.elapsed().as_secs_f64()));
    let by = &prover_input.state_transitions.casm_states_by_opcode;
    log(format!(
        "dims: steps by opcode: generic {} add_ap {} add {} add_small {} assert_eq {} assert_eq_dd {} assert_eq_imm {} call_abs {} call_rel_imm {} jnz_nt {} jnz_t {} jump_rel_imm {} jump_rel {} jump_dd {} jump_abs {} mul_small {} mul {} ret {} blake {} qm31 {}",
        by.generic_opcode.len(), by.add_ap_opcode.len(), by.add_opcode.len(), by.add_opcode_small.len(), by.assert_eq_opcode.len(),
        by.assert_eq_opcode_double_deref.len(), by.assert_eq_opcode_imm.len(), by.call_opcode_abs.len(), by.call_opcode_rel_imm.len(),
        by.jnz_opcode_non_taken.len(), by.jnz_opcode_taken.len(), by.jump_opcode_rel_imm.len(), by.jump_opcode_rel.len(),
        by.jump_opcode_double_deref.len(), by.jump_opcode_abs.len(), by.mul_opcode_small.len(), by.mul_opcode.len(), by.ret_opcode.len(),
        by.blake_compress_opcode.len(), by.qm_31_add_mul_opcode.len()
    ));
    log(format!(
        "dims: memory address_to_id {} f252_values {} small_values {} pc_count {} public_memory_addresses {} builtin_segments {:?}",
        prover_input.memory.address_to_id.len(), prover_input.memory.f252_values.len(), prover_input.memory.small_values.len(),
        prover_input.pc_count, prover_input.public_memory_addresses.len(), prover_input.builtin_segments
    ));
    if std::env::var("S4_DIMS_ONLY").is_ok() {
        bail!("dimensions printed; proving skipped (S4_DIMS_ONLY)");
    }

    let cairo_proof = prove_cairo_with_precompute(
        &pre.base_column_pool,
        &pre.twiddles,
        pre.cairo_preprocessed_trace.clone(),
        MaybeOwned::Borrowed(&pre.cairo_preprocessed_tree),
        prover_input,
        CAIRO_PROVER_PARAMS,
    )
    .map_err(|e| anyhow!("cairo proof: {e:?}"))?;
    log(format!("cairo proof produced ({:.1}s)", start.elapsed().as_secs_f64()));
    let (proof, aux) = prepare_cairo_proof_for_circuit_verifier(&cairo_proof);
    let output_hash = compute_privacy_bootloader_output_hash(&preimage);
    let mut context = build_and_fill_cairo_verifier_circuit(&pre.cairo_verifier_config, proof, aux, output_hash);
    if !context.is_circuit_valid() {
        bail!("the Cairo-verifier circuit rejected the Cairo proof");
    }
    pad_context(&mut context);
    log(format!("Cairo-verifier circuit valid ({:.1}s)", start.elapsed().as_secs_f64()));
    let circuit_proof = prove_circuit_with_precompute(
        &pre.base_column_pool,
        &pre.twiddles,
        &pre.preprocessed_circuit,
        MaybeOwned::Borrowed(&pre.circuit_preprocessed_tree),
        context.values(),
        pre.circuit_config.config,
    )
    .map_err(|e| anyhow!("circuit proof: {e:?}"))?;
    let (qm31s, _public) = prepare_circuit_proof_for_circuit_verifier(circuit_proof);
    let mut bytes = vec![];
    qm31s.serialize(&mut bytes);
    log(format!("recursion proof produced ({:.1}s)", start.elapsed().as_secs_f64()));
    Ok((bytes, preimage))
}
