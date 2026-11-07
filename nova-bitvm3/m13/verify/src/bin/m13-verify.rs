//! m13-verify verify WRAP.bin EXPECT.json
//!     The complete final verifier, run once on one thread: wall time,
//!     BLAKE3 compressions per role and (with the `opcount` feature and
//!     patched p3-koala-bear) every KoalaBear operation.
use std::{collections::BTreeMap, time::Instant};

use anyhow::{bail, ensure, Result};
use m13_verify::{ctx, opcount, verify_final, Blake3WrapProof, FinalStatement};

fn main() -> Result<()> {
    // One rayon thread: a parallel reduction adds one partial sum per extra
    // thread, so counts taken with more threads vary with the thread count
    // and between runs. Single-threaded counts are deterministic and are the
    // work of the sequential verifier, which is what a circuit evaluates.
    std::env::set_var("RAYON_NUM_THREADS", "1");
    let a: Vec<String> = std::env::args().collect();
    ensure!(a.len() == 4 && a[1] == "verify", "usage: m13-verify verify WRAP.bin EXPECT.json");
    let bytes = std::fs::read(&a[2])?;
    let wrap: Blake3WrapProof = bincode::deserialize(&bytes)?;
    let expect: FinalStatement = serde_json::from_slice(&std::fs::read(&a[3])?)?;
    let proof_bytes = bincode::serialize(&wrap.proof)?.len();
    ctx::reset_counters();
    opcount::reset();
    let t = Instant::now();
    let got = match verify_final(&wrap, &expect) {
        Ok(s) => s,
        Err(e) => bail!("refused: {e:#}"),
    };
    let secs = t.elapsed().as_secs_f64();
    let ops = opcount::snapshot();
    let counts = ctx::read_counters();
    let by_role: BTreeMap<_, _> = ctx::ROLE_NAMES.iter().zip(counts.iter()).map(|(k, v)| (*k, *v)).collect();
    let total: u64 = counts.iter().map(|c| c.compressions).sum();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "verified", "seconds": secs, "statement": got,
            "wrap_file_bytes": bytes.len(), "wrap_proof_bytes": proof_bytes,
            "public_values_len": wrap.proof.public_values.len(),
            "blake3": by_role, "blake3_compressions_total": total,
            "koalabear_ops": ops,
        }))?
    );
    Ok(())
}
