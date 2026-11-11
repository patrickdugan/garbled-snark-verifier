//! Provers for the S4 Boolean check.
//!
//! Production profile (upstream's privacy pipeline, unchanged parameters):
//!   s4-prove TASK OUT_DIR [ARGS_FILE]
//!     privacy bootloader, Cairo proof, Cairo-verifier circuit, recursion proof, upstream verification.
//!     Writes recursion_raw.bin, output_digest.hex, output_preimage.json, proof_full.bin, run.txt.
//!
//! Laboratory profile L21 (`../s4-cairo/src/lab_config.rs`), one stage per process:
//!   s4-prove lab-cairo TASK OUT_DIR [ARGS_FILE]
//!   s4-prove lab-recurse OUT_DIR
//!   s4-prove lab-bind TASK OUT_DIR [ARGS_FILE]
//!   s4-prove lab-roots OUT_DIR
//!
//! TASK ending in .zip is a Cairo PIE; otherwise a Scarb `.executable.json` (its Bootloader entrypoint)
//! with ARGS_FILE a JSON array of hex felts.
mod lab;
#[path = "../../s4-cairo/src/lab_config.rs"]
mod lab_config;
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

fn load_task(task_path: &PathBuf, args_file: Option<PathBuf>) -> Result<Task> {
    if task_path.extension().is_some_and(|e| e == "zip") {
        create_pie_task(task_path).map_err(|e| anyhow::anyhow!("pie: {e}"))
    } else {
        create_cairo1_program_task(task_path, None, args_file).map_err(|e| anyhow::anyhow!("cairo1 task: {e}"))
    }
}

fn main() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mode = match args.first().map(String::as_str) {
        Some("lab-cairo" | "lab-recurse" | "lab-bind" | "lab-roots") => args.remove(0),
        _ => "prod".to_string(),
    };
    let start = Instant::now();
    let mut text = String::new();
    let mut note = |line: String| {
        println!("{line}");
        writeln!(text, "{line}").ok();
    };
    let out = match mode.as_str() {
        "lab-recurse" | "lab-roots" => {
            ensure!(args.len() == 1, "usage: s4-prove lab-recurse|lab-roots OUT_DIR");
            let out = PathBuf::from(&args[0]);
            std::fs::create_dir_all(&out)?;
            if mode == "lab-roots" { lab::roots(&mut note)? } else { lab::recurse(&out, &mut note)? }
            out
        }
        _ => {
            ensure!(args.len() == 2 || args.len() == 3, "usage: s4-prove [lab-cairo|lab-bind] TASK OUT_DIR [ARGS_FILE]");
            let (task_path, out) = (PathBuf::from(&args[0]), PathBuf::from(&args[1]));
            std::fs::create_dir_all(&out)?;
            let task = load_task(&task_path, args.get(2).map(PathBuf::from))?;
            note(format!("task loaded: {} ({:.1}s)", task_path.display(), start.elapsed().as_secs_f64()));
            match mode.as_str() {
                "lab-cairo" => lab::cairo(task, &out, &mut note)?,
                "lab-bind" => lab::bind(&task, &out, &mut note)?,
                _ => production(task, &out, &mut note, start)?,
            }
            out
        }
    };
    let name = match mode.as_str() {
        "prod" => "run.txt".to_string(),
        other => format!("{other}.txt"),
    };
    std::fs::write(out.join(name), text)?;
    Ok(())
}

fn production(task: Task, out: &PathBuf, note: &mut impl FnMut(String), start: Instant) -> Result<()> {
    let precomputes = prepare_recursive_prover_precomputes().map_err(|e| anyhow::anyhow!("{e}"))?;
    note(format!("precomputes ready ({:.1}s)", start.elapsed().as_secs_f64()));
    let (raw, preimage) = pipeline::prove_task(task, &precomputes, note)?;

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
    Ok(())
}
