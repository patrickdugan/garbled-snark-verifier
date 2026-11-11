//! S4: Boolean size of the pinned Stwo circuit verifiers, imported through the S1 lowering.
//! A template depends only on its verifier configuration, never on a proof.
mod count;
mod direct;
mod evidence;
mod func;
#[cfg(feature = "garbled")]
mod garble;
#[cfg(feature = "garbled")]
mod gfunc;
mod lab_config;
mod shard;

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anyhow::{bail, Context as _, Result};
use circuit_cairo_verifier::verify::build_cairo_verifier_circuit;
use circuits::{context::FinalizedContext, ivalue::NoValue};
use privacy_circuit_verify::get_cairo_verifier_config;
use std::time::Instant;
use stwo_bitvm3_lowering::{Limits, Program};
use stwo_bitvm3_upstream::{import_finalized, import_function};

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
        #[cfg(feature = "garbled")]
        Some("fanout") => {
            // Diagnostic: the largest wire fan-out of each piece of the production final verifier.
            let template = final_verifier_template()?;
            let pins: Vec<(usize, [u32; 4])> = template.circuit().output.iter().filter(|g| g.in0 > 2).map(|g| (g.in0, [0, 0, 0, 0])).collect();
            let limits = Limits { max_vars: 64_000_000, max_constraints: 64_000_000, max_permutation: 1 << 22, max_permutation_work: usize::MAX / 4 };
            let program = import_finalized(&template, &pins, limits).context("import")?;
            let size: usize = args.get(2).and_then(|a| a.parse().ok()).unwrap_or(2000);
            let plan = shard::Plan::new(&program, size);
            let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).min(16);
            let rows = shard::for_each_piece(plan.len(), threads, |i| {
                let piece = plan.piece(i)?;
                let (max, over, widest, inputs) = garble::max_fanout(&piece.program)?;
                let what = if widest >= 2 && widest < inputs + 2 { format!("input bit {} of global var {}", (widest - 2) % 128, piece.globals[(widest - 2) / 128]) } else { "internal wire".to_string() };
                Ok((max, over, what, piece.program.n_vars(), piece.program.constraints().len()))
            })?;
            let worst = rows.iter().map(|r| r.0).max().unwrap_or(0);
            let bad = rows.iter().filter(|r| r.1 > 0).count();
            println!("fanout: shard size {size}: {} pieces, worst fan-out {worst}, pieces with a wire above 65535: {bad}", rows.len());
            for (i, r) in rows.iter().enumerate().filter(|(i, r)| r.1 > 0 || *i < 3).take(12) {
                println!("fanout: piece {i}: max {} over-limit wires {} widest {} vars {} constraints {}", r.0, r.1, r.2, r.3, r.4);
            }
            Ok(())
        }
        #[cfg(feature = "garbled")]
        Some("garble-func") => garble_function(evidence::load_fixture(std::path::Path::new(args.get(2).context("fixture directory")?))?),
        #[cfg(feature = "garbled")]
        Some("garble-func-lab") => {
            let (fixture, _receipt) = evidence::load_lab(
                std::path::Path::new(args.get(2).context("recursion_raw.bin")?),
                &std::fs::read_to_string(args.get(3).context("output_preimage.json")?)?,
            )?;
            garble_function(fixture)
        }
        #[cfg(feature = "garbled")]
        Some("garble") => garble_check(evidence::load_fixture(std::path::Path::new(args.get(2).context("fixture directory")?))?),
        #[cfg(feature = "garbled")]
        Some("garble-lab") => {
            let (fixture, _receipt) = evidence::load_lab(
                std::path::Path::new(args.get(2).context("recursion_raw.bin")?),
                &std::fs::read_to_string(args.get(3).context("output_preimage.json")?)?,
            )?;
            garble_check(fixture)
        }
        Some("final-func") => {
            let shared = match args.get(2).map(String::as_str) {
                Some("fixture") => evidence::fixture_shared(),
                Some("lab") => evidence::lab_shared()?,
                _ => evidence::production_shared()?,
            };
            function_report(&evidence::template(&shared))
        }
        Some("check-func") => check_function(evidence::load_fixture(std::path::Path::new(args.get(2).context("fixture directory")?))?, light),
        Some("check-func-lab") => {
            let (fixture, _receipt) = evidence::load_lab(
                std::path::Path::new(args.get(2).context("recursion_raw.bin")?),
                &std::fs::read_to_string(args.get(3).context("output_preimage.json")?)?,
            )?;
            check_function(fixture, light)
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
        _ => bail!("usage: s4 final|final-fixture|final-lab|cairo [--boolean] [--analytic] | check FIXTURE_DIR | check-prod RAW DIGEST_FILE | check-lab RAW PREIMAGE_JSON [--light] | lab-root | final-func [prod|lab|fixture] | check-func FIXTURE_DIR [--light] | check-func-lab RAW PREIMAGE_JSON [--light] | (feature garbled) garble FIXTURE_DIR | garble-lab RAW PREIMAGE_JSON | garble-func FIXTURE_DIR | garble-func-lab RAW PREIMAGE_JSON"),
    }
}

/// Native acceptance, Boolean acceptance and mutation rejection for a proof of the privacy Cairo-verifier circuit.
fn check(fixture: evidence::Fixture, light: bool) -> Result<()> {
    let start = Instant::now();
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
    let mut cases = proof_mutations(&fixture.proof);
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

/// S5: garbles the whole final verifier for the fixture's statement, piece by piece under one delta, and
/// evaluates it with the honest witness and with the witness of a mutated proof.
#[cfg(feature = "garbled")]
fn garble_check(fixture: evidence::Fixture) -> Result<()> {
    use stwo::core::fields::qm31::QM31;
    let start = Instant::now();
    println!("garble: proof under test: {}", fixture.label);
    let valid = evidence::context(&fixture, &fixture.proof);
    anyhow::ensure!(valid.is_circuit_valid(), "the native relation rejected the proof");
    let template = evidence::template(&fixture.shared);
    anyhow::ensure!(valid.circuit() == template.circuit(), "the proof-bearing circuit differs from the template");
    let good = evidence::values(&valid);
    let mut mutated = fixture.proof.clone();
    mutated.trace_at_oods[0] += QM31::from_u32_unchecked(1, 0, 0, 0);
    let bad_context = evidence::context(&fixture, &mutated);
    anyhow::ensure!(bad_context.circuit() == template.circuit(), "the mutation changed the graph");
    anyhow::ensure!(!bad_context.is_circuit_valid(), "the native relation accepted the mutated proof");
    let bad = evidence::values(&bad_context);

    let outputs = evidence::statement_outputs(&fixture.shared, fixture.root, fixture.digest);
    let first = circuits::context::OUTPUT_START;
    let pins: Vec<(usize, [u32; 4])> = (first..first + outputs.len()).zip(outputs).collect();
    let limits = Limits {
        max_vars: 64_000_000, max_constraints: 64_000_000,
        max_permutation: 1 << 22, max_permutation_work: usize::MAX / 4,
    };
    let program = import_finalized(&template, &pins, limits).context("import")?;
    let threads = std::env::var("S5_THREADS").ok().and_then(|t| t.parse().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).min(16));
    println!(
        "garble: program n_vars={} constraints={} input_bits={}, statement words {:08x?}, {threads} threads ({:.1}s)",
        program.n_vars(), program.constraints().len(), program.input_bits(),
        evidence::statement_words(&fixture.shared, fixture.root, fixture.digest), start.elapsed().as_secs_f64()
    );
    // Pieces of 1,000 constraints keep every wire's fan-out (35,001 at most here) inside the engine's
    // 16-bit read counter; 2,000 would not (70,002).
    let out = garble::run(&program, &[&good, &bad], 1000, threads, 117)?;
    println!(
        "garble: {} pieces under one delta, {} ciphertexts ({} bytes at 16 bytes each), {} gates in all, commitment blake3 {}",
        out.pieces, out.ciphertexts, out.ciphertexts * 16, out.gates, hex::encode(out.commitment)
    );
    let (accept, rejecting, label_ok) = out.verdicts[0];
    println!("garble: honest witness: accepted={accept} rejecting_pieces={rejecting} output_label_is_the_accept_label={label_ok}");
    anyhow::ensure!(accept && rejecting == 0 && label_ok, "the garbled circuit did not accept the honest witness");
    let (accept, rejecting, label_ok) = out.verdicts[1];
    println!("garble: mutated proof (trace_at_oods[0]+1): accepted={accept} rejecting_pieces={rejecting} output_label_is_the_reject_label={label_ok}");
    anyhow::ensure!(!accept && rejecting > 0 && label_ok, "the garbled circuit did not reject the mutated proof");
    println!(
        "garble: garbling and both evaluations took {:.1}s on {threads} threads; all checks passed in {:.1}s",
        out.seconds, start.elapsed().as_secs_f64()
    );
    Ok(())
}

/// Six independent changes of a proof, each to a different part of it.
fn proof_mutations(
    p: &circuits_stark_verifier::proof::Proof<stwo::core::fields::qm31::QM31>,
) -> Vec<(&'static str, circuits_stark_verifier::proof::Proof<stwo::core::fields::qm31::QM31>)> {
    let one = stwo::core::fields::qm31::QM31::from_u32_unchecked(1, 0, 0, 0);
    let mut cases = Vec::new();
    let mut m = p.clone(); m.trace_at_oods[0] += one; cases.push(("trace_at_oods[0]+1", m));
    let mut m = p.clone(); m.claimed_sums[0] += one; cases.push(("claimed_sums[0]+1", m));
    let mut m = p.clone(); m.fri.commit.last_layer_coefs[0] += one; cases.push(("fri_last_layer_coef+1", m));
    let mut m = p.clone(); m.oods_pow_nonce += one; cases.push(("oods_pow_nonce+1", m));
    let mut m = p.clone();
    if let Some(x) = m.fri.witness.0.iter_mut().flatten().flatten().next() { *x += one; }
    cases.push(("fri_witness_first+1", m));
    let mut m = p.clone(); m.channel_salt += one; cases.push(("channel_salt+1", m));
    cases
}

const FUNCTION_LIMITS: Limits = Limits {
    max_vars: 64_000_000, max_constraints: 64_000_000,
    max_permutation: 1 << 22, max_permutation_work: usize::MAX / 4,
};
/// Pieces of about a million non-free ANDs (by estimate), at most 20,000 gates.
const PIECE_ANDS: u64 = 1_000_000;
const PIECE_STEPS: usize = 20_000;

fn function_plan(f: &stwo_bitvm3_lowering::Function) -> Result<func::Plan<'_>> {
    let env = |name: &str| std::env::var(name).ok().and_then(|t| t.parse::<u64>().ok());
    let layers = env("S6_LAYERS").map(|x| x as usize).unwrap_or(func::DEFAULT_LAYERS);
    func::Plan::layered(f, env("S6_PIECE_ANDS").unwrap_or(PIECE_ANDS), PIECE_STEPS, layers)
}

/// The gate count of a plan; it does not depend on the input.
fn run_count(plan: &func::Plan, f: &stwo_bitvm3_lowering::Function) -> Result<u64> {
    Ok(func::run_direct(plan, &vec![false; f.input_bits()], None, worker_threads())?.ands)
}

fn worker_threads() -> usize {
    std::env::var("S5_THREADS").ok().and_then(|t| t.parse().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).min(16))
}

/// The statement inputs of the final verifier in function form: the first 32 typed inputs are the 16-bit
/// halves of the eight digest words and then of the eight root words (the order `verify_child` guesses them).
fn statement_input_bits(digest: [u32; 8], root: [u32; 8]) -> Vec<bool> {
    digest.iter().chain(&root).flat_map(|w| (0..32).map(move |i| (w >> i) & 1 != 0)).collect()
}

/// S6: sizes of the final verifier read as a function of its typed inputs.
fn function_report(template: &FinalizedContext<NoValue>) -> Result<()> {
    use stwo_bitvm3_lowering::Kind;
    let start = Instant::now();
    let f = import_function(template, FUNCTION_LIMITS).context("function form")?;
    let count = |kind: Kind| f.inputs().iter().filter(|(_, k)| *k == kind).count();
    println!(
        "func: inputs {} (u16 {}, m31 {}, qm31 {}) = {} input bits; relation form reads {} variables = {} bits",
        f.inputs().len(), count(Kind::U16), count(Kind::M31), count(Kind::Qm31), f.input_bits(), f.n_vars(), f.n_vars() * 128
    );
    anyhow::ensure!(f.inputs().len() as u64 == template.stats().guess as u64, "typed inputs differ from the guess count of upstream");
    anyhow::ensure!(f.inputs()[..32].iter().all(|(_, k)| *k == Kind::U16), "the statement inputs are not 32 16-bit values");
    let plan = function_plan(&f)?;
    let stats = plan.stats();
    println!(
        "func: {} steps in {} pieces over {} depth layers, longest chain of pieces {}, {} carried variables, at most {} alive at once; inputs read {} unread {}",
        f.steps().len(), stats.pieces, stats.layers, stats.depth, stats.carried_variables, stats.max_live, stats.inputs_read, stats.inputs_unread
    );
    println!(
        "func: estimated work {} of which the heaviest chain of pieces {} (parallel speed-up at most {:.1})",
        stats.total_cost, stats.critical_cost, stats.total_cost as f64 / stats.critical_cost.max(1) as f64
    );
    if std::env::var("S6_PLAN_ONLY").is_ok() {
        return Ok(());
    }
    println!("func: non_free_AND={} XOR={} ({:.1}s)", run_count(&plan, &f)?, 0, start.elapsed().as_secs_f64());
    Ok(())
}

/// S6: the function form on a real proof. It must compute upstream's own witness, accept it, and reject
/// changed proofs, changed statements and non-canonical inputs.
fn check_function(fixture: evidence::Fixture, light: bool) -> Result<()> {
    use stwo_bitvm3_lowering::Kind;
    let start = Instant::now();
    println!("func: proof under test: {}", fixture.label);
    let valid = evidence::context(&fixture, &fixture.proof);
    anyhow::ensure!(valid.is_circuit_valid(), "the native relation rejected the proof");
    let template = evidence::template(&fixture.shared);
    anyhow::ensure!(valid.circuit() == template.circuit(), "the proof-bearing circuit differs from the template");
    let f = import_function(&template, FUNCTION_LIMITS).context("function form")?;
    let plan = function_plan(&f)?;
    let threads = worker_threads();
    let good = evidence::values(&valid);
    let honest = f.encode(&good)?;
    let statement = statement_input_bits(fixture.digest, fixture.root);
    anyhow::ensure!(f.inputs()[..32].iter().all(|(_, k)| *k == Kind::U16), "the statement inputs are not 32 16-bit values");
    anyhow::ensure!(honest[..512] == statement[..], "the first 512 input bits are not the statement (digest, root)");
    println!(
        "func: {} input bits = 512 statement bits (digest, root) + {} proof bits; {} pieces on {threads} threads",
        f.input_bits(), f.input_bits() - 512, plan.pieces.len()
    );

    let run = func::run_direct(&plan, &honest, Some(&good), threads)?;
    println!(
        "func: honest input: accepted={} non_free_AND={} computed variables compared with upstream {} mismatches {} ({:.1}s)",
        run.accepted, run.ands, run.compared, run.mismatches, start.elapsed().as_secs_f64()
    );
    anyhow::ensure!(run.accepted && run.mismatches == 0, "the function form disagrees with upstream on the honest proof");

    // `--light` keeps the first of the six proof mutations.
    for (name, bad) in proof_mutations(&fixture.proof).into_iter().take(if light { 1 } else { 6 }) {
        let ctx = evidence::context(&fixture, &bad);
        anyhow::ensure!(ctx.circuit() == template.circuit(), "mutation changed the graph: {name}");
        let native_ok = ctx.is_circuit_valid();
        let values = evidence::values(&ctx);
        let run = func::run_direct(&plan, &f.encode(&values)?, Some(&values), threads)?;
        println!(
            "func: mutation {name}: native_accepts={native_ok} function_accepts={} rejecting_pieces={} mismatches_with_upstream={}",
            run.accepted, run.rejecting_pieces, run.mismatches
        );
        anyhow::ensure!(!native_ok && !run.accepted && run.mismatches == 0, "mutation mishandled: {name}");
    }
    // The statement is input: one changed bit of the digest, or of the root, must be rejected.
    for (name, bit) in [("digest", 0usize), ("root", 256)] {
        let mut input = honest.clone();
        input[bit] = !input[bit];
        let run = func::run_direct(&plan, &input, None, threads)?;
        println!("func: one {name} bit changed in the statement input: function_accepts={}", run.accepted);
        anyhow::ensure!(!run.accepted, "a changed statement was accepted: {name}");
    }
    // A non-canonical field input (a 31-bit limb equal to P) must be rejected at the input boundary.
    let (index, _) = f.inputs().iter().enumerate().find(|(_, (_, k))| *k != Kind::U16).context("no field input")?;
    let mut input = honest.clone();
    for bit in &mut input[f.offset(index)..f.offset(index) + 31] { *bit = true; }
    let run = func::run_direct(&plan, &input, None, threads)?;
    anyhow::ensure!(!run.accepted, "a non-canonical input limb was accepted");
    println!("func: non-canonical input limb rejected; all checks passed in {:.1}s", start.elapsed().as_secs_f64());
    Ok(())
}

/// S6: garbles the final verifier in function form once and evaluates it on the honest proof and on a
/// changed proof. The statement is part of the input, so the garbling does not depend on it.
#[cfg(feature = "garbled")]
fn garble_function(fixture: evidence::Fixture) -> Result<()> {
    let start = Instant::now();
    println!("garble-func: proof under test: {}", fixture.label);
    let valid = evidence::context(&fixture, &fixture.proof);
    anyhow::ensure!(valid.is_circuit_valid(), "the native relation rejected the proof");
    let template = evidence::template(&fixture.shared);
    anyhow::ensure!(valid.circuit() == template.circuit(), "the proof-bearing circuit differs from the template");
    let f = import_function(&template, FUNCTION_LIMITS).context("function form")?;
    let plan = function_plan(&f)?;
    let good = evidence::values(&valid);
    let honest = f.encode(&good)?;
    anyhow::ensure!(honest[..512] == statement_input_bits(fixture.digest, fixture.root)[..], "the first 512 input bits are not the statement");
    let (name, mutated) = proof_mutations(&fixture.proof).swap_remove(0);
    let bad_context = evidence::context(&fixture, &mutated);
    anyhow::ensure!(bad_context.circuit() == template.circuit(), "the mutation changed the graph");
    anyhow::ensure!(!bad_context.is_circuit_valid(), "the native relation accepted the mutated proof");
    let bad = evidence::values(&bad_context);
    let changed = f.encode(&bad)?;
    let threads = worker_threads();
    let stats = plan.stats();
    println!(
        "garble-func: {} input bits (512 statement + {} proof), {} steps in {} pieces over {} depth layers (longest chain {}), {threads} threads ({:.1}s)",
        f.input_bits(), f.input_bits() - 512, f.steps().len(), stats.pieces, stats.layers, stats.depth, start.elapsed().as_secs_f64()
    );
    let out = gfunc::run(&plan, [&honest, &changed], [&good, &bad], threads, 117)?;
    println!(
        "garble-func: {} pieces under one delta, {} ciphertexts ({} bytes at 16 bytes each), {} gates in all, commitment blake3 {}",
        out.pieces, out.ciphertexts, out.ciphertexts * 16, out.gates, hex::encode(out.commitment)
    );
    println!(
        "garble-func: {} labels of wires handed between pieces checked against the garbler; {} handed-on values compared with upstream, {} differ; worst fan-out {}",
        out.handed_on_wires, out.compared, out.mismatches, out.worst_fanout
    );
    anyhow::ensure!(out.mismatches == 0, "garbled evaluation disagrees with upstream on handed-on values");
    let (accept, rejecting, label_ok) = out.verdicts[0];
    println!("garble-func: honest proof: accepted={accept} rejecting_pieces={rejecting} output_label_is_the_accept_label={label_ok}");
    anyhow::ensure!(accept && rejecting == 0 && label_ok, "the garbled function did not accept the honest proof");
    let (accept, rejecting, label_ok) = out.verdicts[1];
    println!("garble-func: mutated proof ({name}): accepted={accept} rejecting_pieces={rejecting} output_label_is_the_reject_label={label_ok}");
    anyhow::ensure!(!accept && rejecting > 0 && label_ok, "the garbled function did not reject the mutated proof");
    println!(
        "garble-func: garbling and both evaluations took {:.1}s on {threads} threads; all checks passed in {:.1}s",
        out.seconds, start.elapsed().as_secs_f64()
    );
    Ok(())
}
