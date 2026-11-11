//! Runs the production privacy pipeline (privacy bootloader, Cairo proof, Cairo-verifier circuit, recursion
//! proof under the production circuit configuration) on one bootloader task, verifies the result with
//! upstream's own verifier, and stores what the S4 Boolean check needs:
//!   recursion_raw.bin   the decompressed recursion proof (CircuitSerialize bytes)
//!   output_digest.hex   the 32-byte Blake2s digest of the bootloader output preimage
//!   output_preimage.json the bootloader output preimage (felts)
//!   proof_full.bin      the proof exactly as upstream emits it (35-byte header plus zstd body)
//!   run.txt             timings and sizes
//! Usage: s4-prove TASK OUT_DIR [ARGS_FILE]
//!   TASK ending in .zip is a Cairo PIE; otherwise a Scarb `.executable.json` (its Bootloader entrypoint)
//!   with ARGS_FILE a JSON array of hex felts.
mod pipeline;
use anyhow::{Context as _, Result, ensure};
use cairo_program_runner_lib::Task;
use cairo_program_runner_lib::tasks::{create_cairo1_program_task, create_pie_task};
use circuits::utils::bytes_from_le_u32s;
use privacy_circuit_verify::verify_recursive_circuit;
use privacy_common::consts::PRIVACY_RECURSION_CIRCUIT_PREPROCESSED_ROOT;
use privacy_common::utils::{ProofHeader, Version};
use privacy_common::{PrivacyProofOutput, compute_privacy_bootloader_output_hash};
use privacy_prove::prepare_recursive_prover_precomputes;
use std::{fmt::Write as _, path::PathBuf, time::Instant};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    ensure!(args.len() == 3 || args.len() == 4, "usage: s4-prove TASK OUT_DIR [ARGS_FILE]");
    let (task_path, out) = (PathBuf::from(&args[1]), PathBuf::from(&args[2]));
    std::fs::create_dir_all(&out)?;
    let start = Instant::now();
    let mut log = String::new();
    let mut note = |line: String| {
        println!("{line}");
        writeln!(log, "{line}").ok();
    };

    let task: Task = if task_path.extension().is_some_and(|e| e == "zip") {
        create_pie_task(&task_path).map_err(|e| anyhow::anyhow!("pie: {e}"))?
    } else {
        let args_file = args.get(3).map(PathBuf::from);
        create_cairo1_program_task(&task_path, None, args_file).map_err(|e| anyhow::anyhow!("cairo1 task: {e}"))?
    };
    note(format!("task loaded: {} ({:.1}s)", task_path.display(), start.elapsed().as_secs_f64()));
    let precomputes = prepare_recursive_prover_precomputes().map_err(|e| anyhow::anyhow!("{e}"))?;
    note(format!("precomputes ready ({:.1}s)", start.elapsed().as_secs_f64()));
    let (raw, preimage) = pipeline::prove_task(task, &precomputes, &mut note)?;

    // Re-wrap exactly as upstream emits the proof, then run upstream's verifier on it.
    let header = ProofHeader {
        version: Version::current(),
        preprocessed_root: bytes_from_le_u32s(PRIVACY_RECURSION_CIRCUIT_PREPROCESSED_ROOT),
    };
    let mut full = header.serialize().to_vec();
    full.extend(zstd::encode_all(&raw[..], 3)?);
    let output = PrivacyProofOutput { proof: full, output_preimage: preimage };
    verify_recursive_circuit(&output).map_err(|e| anyhow::anyhow!("upstream verifier rejected: {e}"))?;
    note(format!("upstream verify_recursive_circuit accepted ({:.1}s)", start.elapsed().as_secs_f64()));

    let digest = compute_privacy_bootloader_output_hash(&output.output_preimage);
    std::fs::write(out.join("proof_full.bin"), &output.proof)?;
    std::fs::write(out.join("recursion_raw.bin"), &raw)?;
    std::fs::write(out.join("output_digest.hex"), hex::encode(digest.0))?;
    std::fs::write(out.join("output_preimage.json"), serde_json::to_string(&output.output_preimage).context("preimage")?)?;
    note(format!(
        "sizes: emitted {} bytes, raw recursion proof {} bytes, output preimage {} felts, digest {}",
        output.proof.len(), raw.len(), output.output_preimage.len(), hex::encode(digest.0)
    ));
    std::fs::write(out.join("run.txt"), log)?;
    Ok(())
}
