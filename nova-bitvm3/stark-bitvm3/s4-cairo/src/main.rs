//! S4: Boolean size of the pinned Stwo circuit verifiers, imported through the S1 lowering.
//! A template depends only on its verifier configuration, never on a proof.
mod count;
mod direct;
mod evidence;
mod lab_config;
mod shard;
use anyhow::{bail, Context as _, Result};
use circuit_cairo_verifier::verify::build_cairo_verifier_circuit;
use circuits::{context::FinalizedContext, ivalue::NoValue};
use privacy_circuit_verify::get_cairo_verifier_config;
use std::time::Instant;
use stwo_bitvm3_lowering::{Limits, Program};
use stwo_bitvm3_upstream::import_finalized;

fn report(name: &str, template: &FinalizedContext<NoValue>, with_boolean: bool, analytic: bool) -> Result<()> {
    let start = Instant::now();
    println!("[{name}] stats: {:?}", template.stats());
    let c = template.circuit();
    println!(
        "[{name}] gates: add={} sub={} mul={} pointwise_mul={} eq={} triple_xor={} m31_to_u32={} blake_g={} permutation={} output={} n_vars={}",
        c.add.len(), c.sub.len(), c.mul.len(), c.pointwise_mul.len(), c.eq.len(), c.triple_xor.len(),
        c.m31_to_u32.len(), c.blake_g_gate.len(), c.permutation.len(), c.output.len(), c.n_vars,
    );
    let widest = c.permutation.iter().map(|p| p.inputs.len()).max().unwrap_or(0);
    let total_perm: usize = c.permutation.iter().map(|p| p.inputs.len()).sum();
    println!("[{name}] permutation widest={widest} total_width={total_perm}");
    // Output gates must be pinned; for a size measurement their values are placeholders.
    let pins: Vec<(usize, [u32; 4])> = c.output.iter().filter(|g| g.in0 > 2).map(|g| (g.in0, [0, 0, 0, 0])).collect();
    let limits = Limits {
        max_vars: 64_000_000, max_constraints: 64_000_000,
        max_permutation: 1 << 22, max_permutation_work: usize::MAX / 4,
    };
    let program: Program = import_finalized(template, &pins, limits).context("import")?;
    println!(
        "[{name}] program: n_vars={} constraints={} input_bits={} bindings={}",
        program.n_vars(), program.constraints().len(), program.input_bits(), program.bindings().len()
    );
    if with_boolean {
        let (ands, xors) = count::count(&program)?;
        println!("[{name}] boolean (monolithic): non_free_AND={ands} XOR={xors} ({:.1}s)", start.elapsed().as_secs_f64());
    }
    if analytic {
        let (ands, xors) = count::analytic(&program)?;
        println!("[{name}] boolean (per-shape, exact): non_free_AND={ands} XOR={xors} ({:.1}s)", start.elapsed().as_secs_f64());
    }
    Ok(())
}

fn final_verifier_template() -> Result<FinalizedContext<NoValue>> {
    Ok(evidence::template(&evidence::production_shared()?))
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let boolean = args.iter().any(|a| a == "--boolean");
    // `--light` keeps acceptance and the statement mutations and skips the six proof mutations.
    let light = args.iter().any(|a| a == "--light");
    let analytic = args.iter().any(|a| a == "--analytic");
    match args.get(1).map(String::as_str) {
        Some("final") => report("final-1to1", &final_verifier_template()?, boolean, analytic),
        Some("cairo") => {
            let mut config = get_cairo_verifier_config().map_err(|e| anyhow::anyhow!("{e}"))?;
            // Optional: replace the fixed program by N zero cells to measure the per-word cost of public memory.
            if let Some(n) = args.iter().position(|a| a == "--program-words").and_then(|i| args.get(i + 1)) {
                let n: usize = n.parse()?;
                let zero = num_traits::Zero::zero();
                config.program = std::sync::Arc::from(vec![[<stwo::core::fields::m31::M31 as num_traits::Zero>::zero(); 28]; n].as_slice());
                let _: stwo::core::fields::m31::M31 = zero;
            }
            println!(
                "cairo config: components={} program_words={} zk_blinding={:?}",
                config.enabled_bits.iter().filter(|b| **b).count(), config.program.len(), config.zk_blinding_amount
            );
            report("cairo", &build_cairo_verifier_circuit(&config), boolean, analytic)
        }
        Some("final-fixture") => report("final-1to1-fixture-config", &evidence::fixture_template(), boolean, analytic),
        Some("check") => check(evidence::load_fixture(std::path::Path::new(args.get(2).context("fixture directory")?))?, light),
        Some("check-prod") => check(evidence::load_production(
            std::path::Path::new(args.get(2).context("recursion_raw.bin")?),
            &std::fs::read_to_string(args.get(3).context("output_digest.hex")?)?,
        )?, light),
        Some("final-lab") => report("final-1to1-lab-L21", &evidence::template(&evidence::lab_shared()?), boolean, analytic),
        Some("check-lab") => {
            let (fixture, receipt) = evidence::load_lab(
                std::path::Path::new(args.get(2).context("recursion_raw.bin")?),
                &std::fs::read_to_string(args.get(3).context("output_preimage.json")?)?,
            )?;
            let n = receipt.words.len();
            anyhow::ensure!(n >= 8, "receipt too short");
            println!("check: statement: Shinigami program hash {:#x} (pinned), receipt of {n} words", receipt.program_hash);
            println!(
                "check: statement: domain {:#x} schema {:#x} scope {:#x} flags {:#x} accepted {:#x} error {:#x} txid {:#x}{:032x}",
                receipt.words[0], receipt.words[1], receipt.words[2], receipt.words[3],
                receipt.words[n - 4], receipt.words[n - 3], receipt.words[n - 1], receipt.words[n - 2]
            );
            check(fixture, light)
        }
        Some("lab-root") => {
            // Recompute the L21 Cairo-verifier circuit's preprocessed root from the pinned profile alone.
            let preprocessed = evidence::lab_preprocessed()?;
            let root = circuits::utils::le_u32s_from_bytes(preprocessed.preprocessed_root(lab_config::CIRCUIT_FRI.log_blowup_factor).0);
            println!("lab-root: circuit trace log size {} recomputed root {:?}", preprocessed.trace_log_size(), root);
            println!("lab-root: matches pinned CIRCUIT_PREPROCESSED_ROOT: {}", root == lab_config::CIRCUIT_PREPROCESSED_ROOT);
            anyhow::ensure!(root == lab_config::CIRCUIT_PREPROCESSED_ROOT, "pinned circuit root differs from the recomputed one");
            Ok(())
        }
        _ => bail!("usage: s4 final|final-fixture|final-lab|cairo [--boolean] [--analytic] | check FIXTURE_DIR | check-prod RAW DIGEST_FILE | check-lab RAW PREIMAGE_JSON [--light] | lab-root"),
    }
}

/// Native acceptance, Boolean acceptance and mutation rejection for a proof of the privacy Cairo-verifier circuit.
fn check(fixture: evidence::Fixture, light: bool) -> Result<()> {
    use circuits_stark_verifier::proof::Proof;
    use stwo::core::fields::qm31::QM31;
    let start = Instant::now();
    let one = QM31::from_u32_unchecked(1, 0, 0, 0);
    println!("check: proof under test: {}", fixture.label);
    let valid = evidence::context(&fixture, &fixture.proof);
    anyhow::ensure!(valid.is_circuit_valid(), "the native relation rejected the proof");
    println!("check: native relation accepted the proof ({:.1}s)", start.elapsed().as_secs_f64());

    let template = evidence::template(&fixture.shared);
    anyhow::ensure!(valid.circuit() == template.circuit(), "the proof-bearing circuit differs from the template");
    let good = evidence::values(&valid);
    // Public values are never read from the witness: the eight output words follow from the statement
    // (pinned configuration, preprocessed root, output digest) alone.
    let limits = Limits {
        max_vars: 64_000_000, max_constraints: 64_000_000,
        max_permutation: 1 << 22, max_permutation_work: usize::MAX / 4,
    };
    let pins_for = |root: [u32; 8], digest: [u32; 8]| -> Result<Vec<(usize, [u32; 4])>> {
        let outputs = evidence::statement_outputs(&fixture.shared, root, digest);
        let gates: Vec<usize> = template.circuit().output.iter().map(|g| g.in0).filter(|v| *v > 2).collect();
        let start = circuits::context::OUTPUT_START;
        anyhow::ensure!(gates == (start..start + outputs.len()).collect::<Vec<_>>(), "unexpected output gate layout");
        Ok(gates.into_iter().zip(outputs).collect())
    };
    let pins = pins_for(fixture.root, fixture.digest)?;
    println!(
        "check: statement: root {:08x?} digest {:08x?} gives public output words {:08x?}",
        fixture.root, fixture.digest, evidence::statement_words(&fixture.shared, fixture.root, fixture.digest)
    );
    let program = import_finalized(&template, &pins, limits).context("import")?;
    println!(
        "check: program n_vars={} constraints={} public output pins={} (derived from the statement)",
        program.n_vars(), program.constraints().len(), pins.len()
    );
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).min(16);
    let shard_size = 2000;
    let (ok, shards, ands) = shard::run(&program, &good, shard_size, threads)?;
    println!(
        "check: Boolean relation accepted={ok} over {shards} shards on {threads} threads, summed non-free ANDs {ands} ({:.1}s)",
        start.elapsed().as_secs_f64()
    );
    anyhow::ensure!(ok, "the Boolean relation rejected the proof");

    // Mutations: every internal value is re-derived for the changed proof against the same trusted template.
    let mut cases: Vec<(&str, Proof<QM31>)> = Vec::new();
    let p = &fixture.proof;
    let mut m = p.clone(); m.trace_at_oods[0] += one; cases.push(("trace_at_oods[0]+1", m));
    let mut m = p.clone(); m.claimed_sums[0] += one; cases.push(("claimed_sums[0]+1", m));
    let mut m = p.clone(); m.fri.commit.last_layer_coefs[0] += one; cases.push(("fri_last_layer_coef+1", m));
    let mut m = p.clone(); m.oods_pow_nonce += one; cases.push(("oods_pow_nonce+1", m));
    let mut m = p.clone();
    if let Some(x) = m.fri.witness.0.iter_mut().flatten().flatten().next() { *x += one; }
    cases.push(("fri_witness_first+1", m));
    let mut m = p.clone(); m.channel_salt += one; cases.push(("channel_salt+1", m));
    if light {
        cases.clear();
        println!("check: proof mutations skipped (--light)");
    }
    for (name, bad) in cases {
        let built = std::panic::catch_unwind(|| evidence::context(&fixture, &bad));
        let Ok(ctx) = built else {
            println!("check: mutation {name}: witness synthesis panicked (rejected before any gate check)");
            continue;
        };
        anyhow::ensure!(ctx.circuit() == template.circuit(), "mutation changed the graph: {name}");
        let native_ok = ctx.is_circuit_valid();
        let raw = evidence::values(&ctx);
        let (boolean_ok, _, _) = shard::run(&program, &raw, shard_size, threads)?;
        println!("check: mutation {name}: native_accepts={native_ok} boolean_accepts={boolean_ok}");
        anyhow::ensure!(!native_ok && !boolean_ok, "mutation accepted: {name}");
    }
    // Statement mutations: the honest witness must not satisfy the relation pinned to another statement,
    // and a witness synthesized for another digest must not satisfy the relation pinned to this one.
    let mut other_digest = fixture.digest;
    other_digest[0] ^= 1;
    let mut other_root = fixture.root;
    other_root[0] ^= 1;
    for (name, root, digest) in [("statement digest bit", fixture.root, other_digest), ("statement root bit", other_root, fixture.digest)] {
        let wrong = import_finalized(&template, &pins_for(root, digest)?, limits).context("import")?;
        let (accepted, _, _) = shard::run(&wrong, &good, shard_size, threads)?;
        println!("check: {name} flipped in the pinned statement, honest witness: boolean_accepts={accepted}");
        anyhow::ensure!(!accepted, "a wrong statement was accepted: {name}");
    }
    let ctx = evidence::context_for(&fixture, &fixture.proof, other_digest);
    let native_ok = ctx.is_circuit_valid();
    let (boolean_ok, _, _) = shard::run(&program, &evidence::values(&ctx), shard_size, threads)?;
    println!("check: witness synthesized for another digest: native_accepts={native_ok} boolean_accepts={boolean_ok}");
    anyhow::ensure!(!native_ok && !boolean_ok, "a witness for another digest was accepted");

    // Non-canonical alias: a variable holding p instead of 0 must be rejected by the Boolean relation.
    let mut alias = good.clone();
    alias[0][0] = stwo_bitvm3_core::P;
    let (alias_ok, _, _) = shard::run(&program, &alias, shard_size, threads)?;
    anyhow::ensure!(!alias_ok, "noncanonical zero alias accepted");
    println!("check: noncanonical zero alias rejected; all checks passed in {:.1}s", start.elapsed().as_secs_f64());
    Ok(())
}
