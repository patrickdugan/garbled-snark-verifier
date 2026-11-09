//! Frozen S2 proof-witness garbling check. Builds the verifier from trusted
//! source/configuration, pins the exact template and both witness byte strings,
//! then checks the existing native/Boolean relation and garbled output labels.
#[path = "../garble.rs"] mod garble;
#[path = "../direct.rs"] mod direct;
use anyhow::{bail, ensure, Result};
use circuits::{blake::HashValue, context::{Context, Var}, ivalue::{IValue, NoValue},
    ops::Guess, simd::Simd, wrappers::U32Wrapper};
use circuits_stark_verifier::{constraint_eval::CircuitEval, proof::{empty_proof, ProofConfig},
    proof_from_stark_proof::pack_into_qm31s, statement::Statement, verify::verify};
use circuits_stark_verifier_examples::{
    simple_air::{INTERACTION_POW_BITS, LOG_SIZE_LONG},
    simple_statement::{simple_statement_components, SimpleStatement, COMPONENT_LOG_SIZES,
        PREPROCESSED_COLUMN_LOG_SIZES},
};
use indexmap::IndexMap;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use stwo::core::{fields::qm31::QM31, fri::{FriConfig, FriParams}, pcs::PcsConfig};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_bitvm3_lowering::{Limits, Value};
use stwo_bitvm3_upstream::import_finalized;

const BUNDLE: &str = "735bf38f3d45a8ef537279d8f4e244b11afee2863ac91ebcab5d079195365210";
const TEMPLATE: &str = "b06319b9e4f7ee9b059e0a5ada2bdad6fc4d16ea938e459dd0cc53a069fd479d";
const GOOD: &str = "73f417a3ccd0d9929ce213f2f719fe7d9733bdc461166adfcb7f8ddcada53881";
const BAD: &str = "ade28229e0e337bb760a3a6d4ceafa340b11fd163c250d13ac884b9eaa83f732";
const ANDS: u64 = 141_577_483;
fn hash(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }
fn read_pinned(path: &Path, expected: &str, max: u64) -> Result<Vec<u8>> {
    ensure!(fs::metadata(path)?.len() <= max, "file budget: {}",path.display());
    let bytes = fs::read(path)?;
    ensure!(hash(&bytes) == expected, "frozen-file digest mismatch: {}",path.display());
    Ok(bytes)
}
fn witness(bytes: &[u8], vars: usize) -> Result<Vec<Value>> {
    ensure!(bytes.len() == vars*16, "witness shape");
    Ok(bytes.chunks_exact(16).map(|q| std::array::from_fn(|i|
        u32::from_le_bytes(q[i*4..i*4+4].try_into().unwrap()))).collect())
}
struct FixedStatement<V: IValue>(SimpleStatement<V>);
impl<V: IValue> Default for FixedStatement<V> {
    fn default() -> Self { Self(SimpleStatement::default()) }
}
impl<V: IValue> Statement<V> for FixedStatement<V> {
    fn claims_to_mix(&self, c: &mut Context<V>) -> Vec<Vec<U32Wrapper<Var>>> { self.0.claims_to_mix(c) }
    fn get_components(&self) -> &IndexMap<&'static str,Box<dyn CircuitEval<V>>> { self.0.get_components() }
    fn pack_component_log_sizes(&self,c: &mut Context<V>) -> Simd {
        let packed = pack_into_qm31s(COMPONENT_LOG_SIZES.into_iter()).into_iter()
            .map(|v|c.constant(v)).collect::<Vec<_>>();
        Simd::from_packed(packed,COMPONENT_LOG_SIZES.len())
    }
    fn get_preprocessed_column_ids(&self) -> Vec<PreProcessedColumnId> { self.0.get_preprocessed_column_ids() }
    fn get_preprocessed_root(&self,c: &mut Context<V>) -> HashValue<Var> { self.0.get_preprocessed_root(c) }
    fn public_logup_sum(&self,c: &mut Context<V>,e: [Var;2]) -> Var { self.0.public_logup_sum(c,e) }
}
fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    let [_,dir] = args.as_slice() else { bail!("usage: s2-garble FROZEN_FIXTURE_DIRECTORY"); };
    let dir = Path::new(dir);
    read_pinned(&dir.join("bundle.json"),BUNDLE,8<<20)?;
    let pcs = PcsConfig::from_fri_config(FriConfig {
        params: FriParams { log_blowup_factor:2, fold_step:1, ..FriParams::test_params() },
        trace_log_size:LOG_SIZE_LONG,
    });
    let cfg = ProofConfig::new(&simple_statement_components::<NoValue>(),
        PREPROCESSED_COLUMN_LOG_SIZES.len(),&pcs,INTERACTION_POW_BITS);
    let mut ctx = Context::<NoValue>::default();
    let p = empty_proof(&cfg).guess(&mut ctx);
    let salt = p.channel_salt.idx;
    verify(&mut ctx,&p,&cfg,&FixedStatement::default());
    let ctx = ctx.finalize(false);
    let program = import_finalized(&ctx,&[(salt,[0;4])],Limits {
        max_vars:200_000,max_constraints:300_000,max_permutation:256,max_permutation_work:2_000_000
    })?;
    ensure!(hash(format!("{program:?}").as_bytes()) == TEMPLATE,"fixed template changed");
    let good = witness(&read_pinned(&dir.join("witness.u32le.bin"),GOOD,4<<20)?,program.n_vars())?;
    let bad = witness(&read_pinned(&dir.join("trace_auth_path.u32le.bin"),BAD,4<<20)?,program.n_vars())?;
    for (raw, expected) in [(&good,true),(&bad,false)] {
        ensure!(raw.iter().flatten().all(|&x|x<stwo_bitvm3_core::P),"canonical encoding");
        let values = raw.iter().map(|x|QM31::from_u32_unchecked(x[0],x[1],x[2],x[3])).collect::<Vec<_>>();
        let native = ctx.circuit().check(&values).is_ok()
            && program.bindings().iter().all(|(&i,v)|raw[i]==*v);
        ensure!(native == expected,"frozen native relation mismatch");
        let boolean = direct::run(&program,raw)?;
        ensure!(boolean.0 == expected && boolean.1 == ANDS,"Boolean relation/count mismatch");
    }
    println!("S2 pinned full verifier and both frozen witnesses rechecked");
    let scratch = dir.join("../s2-ciphertexts.bin");
    let result = garble::run(&program,&good,&bad,ANDS,&scratch);
    // Keep multi-gigabyte ciphertext scratch outside uploaded evidence; remove it
    // even when a checked error is returned. External timeout cleanup is in CI.
    if scratch.exists() { let _ = fs::remove_file(&scratch); }
    let result = result?;
    let evidence = serde_json::json!({"stage":"S2 complete verifier garbled labels",
        "bundle_sha256":BUNDLE,"template_debug_sha256":TEMPLATE,
        "valid_witness_sha256":GOOD,"mutated_witness_sha256":BAD,
        "complete_garbled_relation_verified":true,"garbling":result,
        "fri_security_bits_test_only":16,"production_security":false,
        "shinigami_proof":false,"bitcoin_dispute_tested":false,
        "originating_native_run":42632483370u64});
    fs::write(dir.join("garbling.json"),serde_json::to_vec_pretty(&evidence)?)?;
    println!("S2 full garbled acceptance and rejection passed");
    Ok(())
}
