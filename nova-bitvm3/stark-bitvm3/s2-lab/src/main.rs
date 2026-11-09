//! Opt-in S2 laboratory. Generates a tiny upstream example proof once, or checks
//! an existing frozen bundle. This binary is never part of routine component CI.
//! The example uses weak test FRI parameters; it must not authorize funds.
mod direct;
use anyhow::{bail, ensure, Context as _, Result};
use circuits::{
    blake::HashValue,
    context::{Context, FinalizedContext, TraceContext, Var},
    ivalue::{IValue, NoValue},
    ops::Guess,
    simd::Simd,
    wrappers::U32Wrapper,
};
use circuits_stark_verifier::{
    constraint_eval::CircuitEval,
    proof::{empty_proof, Proof, ProofConfig},
    proof_from_stark_proof::{pack_into_qm31s, proof_from_stark_proof},
    statement::Statement,
    verify::verify,
};
use circuits_stark_verifier_examples::{
    simple_air::{self, Eval, SimpleComponent, SimpleRelation, FIB_PREPROCESSED_COLUMNS,
        FIB_SEQUENCE_LENGTH, INTERACTION_POW_BITS, LOG_SIZE_LONG, LOG_SIZE_SHORT},
    simple_statement::{simple_statement_components, SimpleStatement, COMPONENT_LOG_SIZES,
        PREPROCESSED_COLUMN_LOG_SIZES},
};
use indexmap::IndexMap;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::Path, time::Instant};
use stwo::{
    core::{
        air::Component,
        channel::{Blake2sChannel, Channel},
        fields::{m31::M31, qm31::QM31, FieldExpOps},
        fri::{FriConfig, FriParams},
        pcs::{CommitmentSchemeVerifier, PcsConfig},
        proof::ExtendedStarkProof,
        vcs::blake2_hash::Blake2sHash,
        vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher},
        verifier,
    },
};
use stwo_constraint_framework::{preprocessed_columns::PreProcessedColumnId, Relation, TraceLocationAllocator};
use stwo_bitvm3_lowering::{Limits, Program, Value, UPSTREAM};
use stwo_bitvm3_upstream::import_finalized;

const ROOT: [u32; 8] = [1715533920, 602108671, 544739379, 1352385240,
    2796078938, 3611037495, 1627440248, 306213366];
const MAX_BUNDLE: u64 = 8 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    upstream: String,
    proof: ExtendedStarkProof<Blake2sMerkleHasher>,
    claimed_sums: Vec<QM31>,
    interaction_pow_nonce: u64,
    channel_salt: u32,
}
fn config() -> PcsConfig {
    PcsConfig::from_fri_config(FriConfig {
        params: FriParams { log_blowup_factor: 2, fold_step: 1, ..FriParams::test_params() },
        trace_log_size: LOG_SIZE_LONG,
    })
}
fn limits() -> Limits {
    Limits { max_vars: 200_000, max_constraints: 300_000,
        max_permutation: 256, max_permutation_work: 2_000_000 }
}
fn digest(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }
fn json(path: &Path, value: &impl Serialize) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(value)?)?; Ok(())
}

/// The AIR and preprocessing root are upstream's example. Component sizes are
/// fixed constants here, rather than auxiliary guesses. No witness supplies policy.
struct FixedStatement<V: IValue>(SimpleStatement<V>);
impl<V: IValue> Default for FixedStatement<V> {
    fn default() -> Self { Self(SimpleStatement::default()) }
}
impl<V: IValue> Statement<V> for FixedStatement<V> {
    fn claims_to_mix(&self, c: &mut Context<V>) -> Vec<Vec<U32Wrapper<Var>>> { self.0.claims_to_mix(c) }
    fn get_components(&self) -> &IndexMap<&'static str, Box<dyn CircuitEval<V>>> { self.0.get_components() }
    fn pack_component_log_sizes(&self, c: &mut Context<V>) -> Simd {
        let values = pack_into_qm31s(COMPONENT_LOG_SIZES.into_iter()).into_iter()
            .map(|v| c.constant(v)).collect::<Vec<_>>();
        Simd::from_packed(values, COMPONENT_LOG_SIZES.len())
    }
    fn get_preprocessed_column_ids(&self) -> Vec<PreProcessedColumnId> { self.0.get_preprocessed_column_ids() }
    fn get_preprocessed_root(&self, c: &mut Context<V>) -> HashValue<Var> { self.0.get_preprocessed_root(c) }
    fn public_logup_sum(&self, c: &mut Context<V>, e: [Var; 2]) -> Var { self.0.public_logup_sum(c, e) }
}

/// Standalone native Stwo verification. Reconstructs lookup challenges and AIR
/// components from the verifier transcript; none are accepted from the bundle.
fn native(bundle: &Bundle) -> Result<()> {
    ensure!(bundle.upstream == UPSTREAM, "wrong upstream pin");
    ensure!(bundle.channel_salt == 0, "wrong expected salt");
    ensure!(bundle.claimed_sums.len() == 2, "wrong claim shape");
    let cfg = config();
    ensure!(bundle.proof.proof.config == cfg, "proof configuration mismatch");
    ensure!(bundle.proof.proof.commitments.len() == 4, "wrong commitment count");
    ensure!(bundle.proof.proof.commitments[0] == Blake2sHash::from(ROOT), "preprocessed root mismatch");
    let mut channel = Blake2sChannel::default();
    channel.mix_felts(&[QM31::zero()]);
    cfg.fri_params.mix_into(&mut channel);
    let mut pcs = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(cfg);
    pcs.commit(bundle.proof.proof.commitments[0], &PREPROCESSED_COLUMN_LOG_SIZES, &mut channel);
    channel.mix_felts(&[]);
    let trace_sizes = [vec![LOG_SIZE_LONG; FIB_SEQUENCE_LENGTH],
        vec![LOG_SIZE_SHORT; FIB_SEQUENCE_LENGTH]].concat();
    pcs.commit(bundle.proof.proof.commitments[1], &trace_sizes, &mut channel);
    ensure!(channel.verify_pow_nonce(INTERACTION_POW_BITS, bundle.interaction_pow_nonce), "interaction PoW");
    channel.mix_u64(bundle.interaction_pow_nonce);
    let lookup = SimpleRelation::draw(&mut channel);
    // Bind the lookup sums to the intended public Fibonacci outputs, independently
    // of the Boolean/circuit implementation.
    for (index, log_size) in [LOG_SIZE_LONG, LOG_SIZE_SHORT].into_iter().enumerate() {
        let mut expected = QM31::zero();
        for j in 0..(1u32 << log_size) {
            let (mut a, mut b) = (M31::one(), M31::from(j));
            for _ in 2..FIB_SEQUENCE_LENGTH { (a,b) = (b, a*a + b*b + M31::from(j)); }
            let denom: QM31 = lookup.combine(&[a,b]);
            ensure!(!denom.is_zero(), "zero lookup denominator");
            let inv = denom.inverse(); expected += inv + inv + inv;
        }
        ensure!(bundle.claimed_sums[index] == expected, "public lookup sum mismatch");
    }
    channel.mix_felts(&bundle.claimed_sums);
    let interaction_sizes = [vec![LOG_SIZE_LONG; 8], vec![LOG_SIZE_SHORT; 8]].concat();
    pcs.commit(bundle.proof.proof.commitments[2], &interaction_sizes, &mut channel);
    let columns = FIB_PREPROCESSED_COLUMNS.iter()
        .map(|id| PreProcessedColumnId { id: id.to_string() }).collect::<Vec<_>>();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&columns);
    let long = SimpleComponent::new(&mut allocator, Eval { lookup_elements: lookup.clone(),
        preprocessed_column_id: PreProcessedColumnId { id: "row_const_long".into() },
        log_n_instances: LOG_SIZE_LONG }, bundle.claimed_sums[0]);
    let short = SimpleComponent::new(&mut allocator, Eval { lookup_elements: lookup,
        preprocessed_column_id: PreProcessedColumnId { id: "row_const_short".into() },
        log_n_instances: LOG_SIZE_SHORT }, bundle.claimed_sums[1]);
    let components: [&dyn Component; 2] = [&long, &short];
    verifier::verify(&components, &mut channel, &mut pcs, bundle.proof.proof.clone())
        .map_err(|e| anyhow::anyhow!("native STARK verification: {e:?}"))?;
    Ok(())
}
fn context(proof: &Proof<QM31>, cfg: &ProofConfig) -> FinalizedContext<QM31> {
    let mut c = TraceContext::default();
    let vars = proof.guess(&mut c);
    verify(&mut c, &vars, cfg, &FixedStatement::default());
    c.finalize(true)
}
fn values(c: &FinalizedContext<QM31>) -> Vec<Value> {
    c.values().iter().map(|v| v.to_m31_array().map(|x| x.0)).collect()
}
fn native_relation(c: &FinalizedContext<NoValue>, p: &Program, raw: &[Value]) -> bool {
    if raw.iter().flatten().any(|&x| x >= stwo_bitvm3_core::P) { return false; }
    if p.bindings().iter().any(|(&idx, val)| raw[idx] != *val) { return false; }
    let v = raw.iter().map(|x| QM31::from_u32_unchecked(x[0],x[1],x[2],x[3])).collect::<Vec<_>>();
    c.circuit().check(&v).is_ok()
}
fn write_witness(path: &Path, raw: &[Value]) -> Result<String> {
    let bytes = raw.iter().flatten().flat_map(|x| x.to_le_bytes()).collect::<Vec<_>>();
    fs::write(path, &bytes)?; Ok(digest(&bytes))
}
fn generate(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    let start = Instant::now();
    let (_, claimed_sums, cfg, proof, interaction_pow_nonce, channel_salt) = simple_air::create_proof();
    ensure!(cfg == config(), "producer changed the fixed configuration");
    let bundle = Bundle { upstream: UPSTREAM.into(), proof, claimed_sums, interaction_pow_nonce, channel_salt };
    native(&bundle)?;
    let bytes = serde_json::to_vec(&bundle)?;
    ensure!(bytes.len() as u64 <= MAX_BUNDLE, "fixture byte budget");
    fs::write(dir.join("bundle.json"), &bytes)?;
    fs::write(dir.join("bundle.sha256"), format!("{}\n", digest(&bytes)))?;
    json(&dir.join("generation.json"), &serde_json::json!({
        "upstream": UPSTREAM, "bundle_sha256": digest(&bytes), "bundle_bytes": bytes.len(),
        "seconds_including_native_verification": start.elapsed().as_secs_f64(),
        "trace_rows": [32,16], "fri_parameters": cfg.fri_params,
        "fri_security_bits_test_only": cfg.fri_params.security_bits(),
        "native_stark_verified": true, "shinigami_proof": false, "production_security": false
    }))?;
    println!("S2 fixture bytes={} sha256={} generation_seconds={:.3}",bytes.len(),digest(&bytes),start.elapsed().as_secs_f64());
    Ok(())
}
fn check(dir: &Path, expected_sha: &str) -> Result<()> {
    ensure!(fs::metadata(dir.join("bundle.json"))?.len() <= MAX_BUNDLE, "fixture byte budget");
    let bytes = fs::read(dir.join("bundle.json"))?;
    ensure!(digest(&bytes) == expected_sha, "frozen fixture checksum mismatch");
    let bundle: Bundle = serde_json::from_slice(&bytes)?;
    let start = Instant::now(); native(&bundle)?;
    println!("S2 native verifier accepted the frozen authentic proof");
    let cfg = ProofConfig::new(&simple_statement_components::<NoValue>(),
        PREPROCESSED_COLUMN_LOG_SIZES.len(), &config(), INTERACTION_POW_BITS);
    // Build the complete policy graph before extracting any witness from the proof.
    let mut t = Context::<NoValue>::default();
    let proof_vars = empty_proof(&cfg).guess(&mut t);
    let salt_idx = proof_vars.channel_salt.idx;
    verify(&mut t, &proof_vars, &cfg, &FixedStatement::default());
    let template = t.finalize(false);
    let program = import_finalized(&template, &[(salt_idx,[0;4])], limits())?;
    let template_text = format!("{program:?}");
    let template_sha = digest(template_text.as_bytes());
    fs::write(dir.join("template.debug.txt"), &template_text)?;
    println!("S2 fixed template vars={} constraints={} input_bits={} sha256={}",
        program.n_vars(), program.constraints().len(), program.input_bits(), template_sha);
    let proof = proof_from_stark_proof(&bundle.proof, &cfg, bundle.claimed_sums.clone(),
        bundle.interaction_pow_nonce, bundle.channel_salt);
    let valid = context(&proof, &cfg);
    ensure!(valid.circuit() == template.circuit(), "witness-dependent template");
    let good = values(&valid);
    ensure!(native_relation(&template, &program, &good), "native finalized relation rejected authentic proof");
    let (accepted, ands, xors) = direct::run(&program, &good)?;
    ensure!(accepted, "Boolean verifier rejected authentic proof");
    println!("S2 Boolean verifier accepted: AND={ands} XOR={xors}");
    let witness_sha = write_witness(&dir.join("witness.u32le.bin"), &good)?;
    let mut cases = vec![serde_json::json!({"case":"authentic", "accepted":true})];
    // Re-synthesize internal values for each changed proof, using the exact same
    // NoValue template. Thus these cases do more than flip stale internal wires.
    for name in ["trace_oods", "claimed_sum", "fri_witness", "fri_final_coefficient", "trace_auth_path"] {
        let mut bad = proof.clone();
        match name {
            "trace_oods" => bad.trace_at_oods[0] += QM31::one(),
            "claimed_sum" => bad.claimed_sums[0] += QM31::one(),
            "fri_witness" => bad.fri.witness.0.last_mut().unwrap()[0][0] += QM31::one(),
            "fri_final_coefficient" => bad.fri.commit.last_layer_coefs[0] += QM31::one(),
            "trace_auth_path" => bad.eval_domain_auth_paths.data[1][0].0[0] = [0u32;8].into(),
            _ => unreachable!(),
        }
        let c = context(&bad, &cfg);
        ensure!(c.circuit() == template.circuit(), "mutation changed graph: {name}");
        let raw = values(&c);
        let native_ok = native_relation(&template,&program,&raw);
        let (boolean_ok, count, xor_count) = direct::run(&program,&raw)?;
        ensure!(!native_ok && !boolean_ok, "mutation accepted: {name}");
        ensure!((count,xor_count) == (ands,xors), "private values changed topology");
        let sha = write_witness(&dir.join(format!("{name}.u32le.bin")), &raw)?;
        println!("S2 mutation {name}: native=false boolean=false");
        cases.push(serde_json::json!({"case":name,"accepted":false,"native_relation":false,
            "auxiliaries_resynthesized":true,"witness_sha256":sha}));
    }
    let mut alias = good.clone(); alias[0][0] = stwo_bitvm3_core::P;
    ensure!(!direct::run(&program,&alias)?.0, "noncanonical zero alias accepted");
    let mut pins = program.bindings().iter().map(|(&i,&v)|(i,v)).collect::<Vec<_>>();
    pins.iter_mut().find(|(i,_)|*i == salt_idx).unwrap().1 = [1,0,0,0];
    let wrong_policy = Program::new(program.n_vars(), program.constraints().to_vec(), pins, limits())?;
    ensure!(!direct::run(&wrong_policy,&good)?.0, "wrong expected salt accepted");
    cases.push(serde_json::json!({"case":"noncanonical_zero_alias","accepted":false}));
    cases.push(serde_json::json!({"case":"wrong_expected_salt","accepted":false}));
    json(&dir.join("results.json"), &serde_json::json!({
        "stage":"S2 complete small STARK native/Boolean verification",
        "upstream":UPSTREAM,"bundle_sha256":expected_sha,"template_debug_sha256":template_sha,
        "witness_sha256":witness_sha,"variables":program.n_vars(),"constraints":program.constraints().len(),
        "input_bits":program.input_bits(),"and_gates":ands,"xor_gates":xors,"cases":cases,
        "check_seconds":start.elapsed().as_secs_f64(),"trace_rows":[32,16],
        "standalone_native_stark_verified":true,"complete_upstream_circuit_instantiated":true,
        "complete_boolean_relation_verified":true,"full_garbled_run":false,
        "fri_security_bits_test_only":config().fri_params.security_bits(),
        "production_security":false,"shinigami_proof":false,"bitcoin_dispute_tested":false
    }))?;
    println!("S2 complete native/Boolean checks passed in {:.3}s", start.elapsed().as_secs_f64());
    Ok(())
}
fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    match args.as_slice() {
        [_, mode, dir] if mode == "generate" => generate(Path::new(dir)),
        [_, mode, dir, sha] if mode == "check" => check(Path::new(dir),sha),
        _ => bail!("usage: stwo-bitvm3-s2-lab generate DIR | check DIR EXPECTED_SHA256"),
    }.context("bounded S2 experiment")
}
