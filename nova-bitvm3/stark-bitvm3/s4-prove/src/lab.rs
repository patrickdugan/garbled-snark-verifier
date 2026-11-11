//! Laboratory profile L21 prover (see `lab_config.rs`), staged so that the Cairo proof and the recursion
//! proof never share a process:
//!   lab-cairo    privacy bootloader run of one task, Cairo proof, native Cairo verification
//!   lab-recurse  Cairo-verifier circuit of the pinned profile, its proof, native 1-to-1 verification
//!   lab-bind     recompute the task's program hash and locate it and the task output in the preimage
use crate::lab_config as cfg;
use crate::pipeline;
use anyhow::{Context as _, Result, anyhow, ensure};
use cairo_air::utils::{binary_deserialize_from_file, binary_serialize_to_file};
use cairo_air::verifier::verify_cairo_ex;
use cairo_air::CairoProof;
use cairo_program_runner_lib::types::HashFunc;
use cairo_program_runner_lib::{Task, compute_program_hash_chain};
use circuit_cairo_verifier::all_components::all_components;
use circuit_cairo_verifier::verify::{
    build_and_fill_cairo_verifier_circuit, build_cairo_verifier_circuit, prepare_cairo_proof_for_circuit_verifier,
};
use circuit_common::finalize::pad_context;
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::prover::{BaseColumnPool, SimdBackend, prepare_circuit_proof_for_circuit_verifier, prove_circuit_assignment};
use circuit_serialize::serialize::CircuitSerialize;
use circuit_verifier::verify::{CircuitConfig, verify_circuit};
use circuits::ivalue::NoValue;
use circuits::utils::le_u32s_from_bytes;
use privacy_common::compute_privacy_bootloader_output_hash;
use starknet_types_core::felt::Felt;
use std::{fs::File, path::Path, sync::Arc, time::Instant};
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::CommitmentTreeProver;
use stwo::prover::poly::circle::PolyOps;
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTraceVariant;
use stwo_cairo_prover::prover::warm_pedersen_pp_trace;
use stwo_cairo_prover::witness::preprocessed_trace::gen_trace;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::PcsConfig;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo_cairo_prover::prover::{ChannelHash, LiftingSizePolicy, ProverParameters, prove_cairo};

fn words(hash: &[u8; 32]) -> [u32; 8] {
    le_u32s_from_bytes(*hash)
}

pub fn cairo(task: Task, out: &Path, log: &mut impl FnMut(String)) -> Result<()> {
    let start = Instant::now();
    let (prover_input, preimage) = pipeline::run_bootloader(task, log)?;
    std::fs::write(out.join("output_preimage.json"), serde_json::to_string(&preimage)?)?;
    let params = ProverParameters {
        channel_hash: ChannelHash::Blake2s,
        fri_params: cfg::CAIRO_FRI,
        preprocessed_trace_variant: cfg::VARIANT,
        channel_salt: 0,
        // Recomputing coefficients costs time and saves memory; the proof does not depend on it.
        store_polynomials_coefficients: false,
        include_all_preprocessed_columns: true,
        opt_n_id_to_big_components: Some(1),
        lifting_size_policy: LiftingSizePolicy::Fixed(cfg::CAIRO_PCS.trace_lifting_log_size),
    };
    let proof: CairoProof<Blake2sMerkleHasher> =
        prove_cairo::<Blake2sMerkleChannel>(prover_input, params).map_err(|e| anyhow!("cairo proof: {e:?}"))?;
    log(format!("cairo proof produced ({:.1}s)", start.elapsed().as_secs_f64()));

    let flat = proof.claim.flatten_claim();
    let names: Vec<&'static str> = all_components::<NoValue>().keys().copied().collect();
    ensure!(names.len() == flat.component_enable_bits.len(), "component list length");
    let enabled: Vec<&str> =
        names.iter().zip(&flat.component_enable_bits).filter(|(_, on)| **on).map(|(n, _)| *n).collect();
    log(format!("enabled components ({}): {}", enabled.len(), enabled.join(",")));
    log(format!("component log sizes: {:?}", flat.component_log_sizes));
    log(format!("pcs config: {:?}", proof.extended_stark_proof.proof.config));
    log(format!("cairo preprocessed root words: {:?}", words(&proof.extended_stark_proof.proof.commitments[0].0)));
    log(format!("matches pinned component set: {}", flat.component_enable_bits == cfg::enabled_bits()));

    binary_serialize_to_file(&proof, &File::create(out.join("cairo_proof.bin"))?)?;
    log(format!(
        "cairo proof stored: {} bytes compressed ({:.1}s)",
        std::fs::metadata(out.join("cairo_proof.bin"))?.len(),
        start.elapsed().as_secs_f64()
    ));
    // The proof carries every preprocessed column (the circuit verifier needs a fixed column count).
    verify_cairo_ex::<Blake2sMerkleChannel>(proof.into(), true).map_err(|e| anyhow!("native Cairo verifier rejected: {e:?}"))?;
    log(format!("native Cairo verifier accepted ({:.1}s)", start.elapsed().as_secs_f64()));
    Ok(())
}

pub fn recurse(out: &Path, log: &mut impl FnMut(String)) -> Result<()> {
    let start = Instant::now();
    let proof: CairoProof<Blake2sMerkleHasher> =
        binary_deserialize_from_file(&File::open(out.join("cairo_proof.bin")).context("cairo_proof.bin")?)?;
    let preimage: Vec<Felt> = serde_json::from_str(&std::fs::read_to_string(out.join("output_preimage.json"))?)?;

    // Everything the circuit fixes comes from the pinned profile; the proof must match it.
    let vcfg = cfg::cairo_verifier_config().map_err(|e| anyhow!(e))?;
    let flat = proof.claim.flatten_claim();
    ensure!(flat.component_enable_bits == vcfg.enabled_bits, "the proof's component set differs from the pinned profile");
    ensure!(proof.extended_stark_proof.proof.config == cfg::CAIRO_PCS, "the proof's PCS configuration differs from the pinned profile");
    ensure!(
        words(&proof.extended_stark_proof.proof.commitments[0].0) == cfg::CAIRO_PREPROCESSED_ROOT,
        "the proof's preprocessed root differs from the pinned profile"
    );

    let mut template = build_cairo_verifier_circuit(&vcfg);
    let preprocessed = PreprocessedCircuit::preprocess_circuit(&mut template);
    log(format!(
        "Cairo-verifier circuit template: stats {:?}, trace log size {} ({:.1}s)",
        template.stats(), preprocessed.trace_log_size(), start.elapsed().as_secs_f64()
    ));

    let (stark_proof, aux) = prepare_cairo_proof_for_circuit_verifier(&proof);
    drop(proof);
    let output_hash = compute_privacy_bootloader_output_hash(&preimage);
    let mut context = build_and_fill_cairo_verifier_circuit(&vcfg, stark_proof, aux, output_hash);
    ensure!(context.is_circuit_valid(), "the Cairo-verifier circuit rejected the Cairo proof");
    pad_context(&mut context);
    ensure!(context.circuit() == template.circuit(), "the filled circuit differs from the proof-independent template");
    drop(template);
    log(format!("Cairo-verifier circuit accepted the Shinigami Cairo proof ({:.1}s)", start.elapsed().as_secs_f64()));

    let pcs = PcsConfig::from_fri_config(FriConfig { params: cfg::CIRCUIT_FRI, trace_log_size: preprocessed.trace_log_size() });
    let circuit_proof = prove_circuit_assignment(context.values(), &preprocessed, &BaseColumnPool::<SimdBackend>::new(), pcs)
        .map_err(|e| anyhow!("circuit proof: {e:?}"))?;
    drop(context);
    log(format!("recursion proof produced ({:.1}s)", start.elapsed().as_secs_f64()));

    let root = circuit_proof.stark_proof.proof.commitments[0];
    let layout: Vec<(String, u32)> =
        preprocessed.preprocessed_trace.log_sizes().into_iter().map(|(id, log)| (id.id, log)).collect();
    let circuit_config = CircuitConfig { config: pcs, preprocessed_column_log_sizes: preprocessed.preprocessed_trace.log_sizes() };
    let (proof_q, public) = prepare_circuit_proof_for_circuit_verifier(circuit_proof);
    let mut raw = vec![];
    proof_q.serialize(&mut raw);
    verify_circuit(circuit_config, root.into(), proof_q, public).map_err(|e| anyhow!("1-to-1 verifier rejected: {e}"))?;
    log(format!("native 1-to-1 circuit verifier accepted ({:.1}s)", start.elapsed().as_secs_f64()));

    std::fs::write(out.join("recursion_raw.bin"), &raw)?;
    std::fs::write(out.join("output_digest.hex"), hex::encode(output_hash.0))?;
    let layout_json = serde_json::json!({
        "circuit_trace_log_size": preprocessed.trace_log_size(),
        "circuit_preprocessed_root": words(&root.0),
        "matches_pinned_circuit_root": words(&root.0) == cfg::CIRCUIT_PREPROCESSED_ROOT,
        "preprocessed_column_log_sizes": layout,
    });
    std::fs::write(out.join("lab_layout.json"), serde_json::to_string_pretty(&layout_json)?)?;
    log(format!(
        "sizes: raw recursion proof {} bytes, circuit root words {:?}, pinned root match {}, digest {}",
        raw.len(), words(&root.0), words(&root.0) == cfg::CIRCUIT_PREPROCESSED_ROOT, hex::encode(output_hash.0)
    ));
    Ok(())
}

/// Shows what the bootloader output preimage commits to: the task's program hash, recomputed here from
/// the executable alone, and the task's own output words.
pub fn bind(task: &Task, out: &Path, log: &mut impl FnMut(String)) -> Result<()> {
    let preimage: Vec<Felt> = serde_json::from_str(&std::fs::read_to_string(out.join("output_preimage.json"))?)?;
    let program = match task {
        Task::Cairo1Program(exe) => &exe.program,
        Task::Cairo0Program(exe) => &exe.program,
        Task::Pie(_) => anyhow::bail!("lab-bind needs an executable task"),
    };
    let stripped = program.get_stripped_program().map_err(|e| anyhow!("stripped program: {e}"))?;
    let hash = compute_program_hash_chain(&stripped, 0, HashFunc::Blake).map_err(|e| anyhow!("program hash: {e:?}"))?;
    log(format!("task program: {} words, builtins {:?}, Blake program hash {:#x}", stripped.data.len(), stripped.builtins, hash));
    log(format!("output preimage ({} felts): {}", preimage.len(), preimage.iter().map(|f| format!("{f:#x}")).collect::<Vec<_>>().join(" ")));
    let position = preimage.iter().position(|f| *f == hash);
    log(format!("program hash position in the preimage: {position:?}"));
    ensure!(position.is_some(), "the recomputed program hash is not in the output preimage");
    let digest = compute_privacy_bootloader_output_hash(&preimage);
    log(format!("output digest (the final verifier's public value): {}", hex::encode(digest.0)));
    let report = serde_json::json!({
        "program_words": stripped.data.len(),
        "program_hash_blake": format!("{hash:#x}"),
        "program_hash_position": position,
        "output_preimage": preimage.iter().map(|f| format!("{f:#x}")).collect::<Vec<_>>(),
        "output_digest": hex::encode(digest.0),
    });
    std::fs::write(out.join("binding.json"), serde_json::to_string_pretty(&report)?)?;
    Ok(())
}

fn cairo_preprocessed_root(variant: PreProcessedTraceVariant, log_blowup: u32, lifting: u32) -> [u32; 8] {
    let trace = Arc::new(variant.to_preprocessed_trace());
    warm_pedersen_pp_trace(variant);
    let twiddles = SimdBackend::precompute_twiddles(CanonicCoset::new(lifting).circle_domain().half_coset);
    let polys = SimdBackend::interpolate_columns(gen_trace(trace), &twiddles);
    let tree = CommitmentTreeProver::<SimdBackend, Blake2sMerkleChannel>::new(
        polys, log_blowup, &twiddles, false, lifting, &BaseColumnPool::<SimdBackend>::new(),
    );
    words(&tree.commitment.root().0)
}

/// Recomputes the pinned Cairo preprocessed root from the preprocessed trace alone, after showing that the
/// same procedure reproduces upstream's own table entry for its production profile.
pub fn roots(log: &mut impl FnMut(String)) -> Result<()> {
    let upstream: [u32; 8] = [2271225220, 1855536874, 1802924152, 654143153, 3715309987, 1517124483, 206973071, 750452746];
    let control = cairo_preprocessed_root(cfg::VARIANT, 3, 23);
    log(format!("control (blowup 3, lifting 23) reproduces upstream get_preprocessed_root(23): {}", control == upstream));
    ensure!(control == upstream, "the recomputation procedure does not reproduce upstream's root");
    let lab = cairo_preprocessed_root(cfg::VARIANT, cfg::CAIRO_FRI.log_blowup_factor, cfg::CAIRO_PCS.preprocessed_lifting_log_size);
    log(format!("L21 Cairo preprocessed root (blowup 2, lifting 23): {lab:?}"));
    log(format!("matches pinned CAIRO_PREPROCESSED_ROOT: {}", lab == cfg::CAIRO_PREPROCESSED_ROOT));
    ensure!(lab == cfg::CAIRO_PREPROCESSED_ROOT, "pinned Cairo preprocessed root differs from the recomputed one");
    Ok(())
}
