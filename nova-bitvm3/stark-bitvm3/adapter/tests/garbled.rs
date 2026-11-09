//! Tiny component test only. No SP1/Nova proving, network prover, or Bitcoin
//! transaction construction. Direct label access and fixed seeds are test-only.
use crossbeam::channel;
use garbled_snark_verifier::{
    AesCcrGateHasher, CircuitContext, EvaluatedWire, GarbleMode, GarbledWire, GateHasher, WireId,
    circuit::{CiphertextHandler, CiphertextSource, CircuitBuilder, CircuitInput, CircuitMode,
              EncodeInput, EvaluateMode, ExecuteMode, StreamingResult},
};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use stwo_bitvm3_adapter::Repo;
use stwo_bitvm3_core as s;

const CAP: usize = 1 << 20;
const INPUT_BITS: usize = 64 + 32 + 3 * 256;
const ROOT: &str = "b70f3c3da3dc82663ce0531c981289c34eebaaa8a70723c516d8855941654692";

struct Plain(Vec<bool>);
impl CircuitInput for Plain {
    type WireRepr = Vec<WireId>;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (0..self.0.len()).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<WireId> { w.clone() }
}
impl EncodeInput<ExecuteMode> for Plain {
    fn encode(&self, w: &Self::WireRepr, mode: &mut ExecuteMode) {
        for (id, value) in w.iter().zip(&self.0) { mode.feed_wire(*id, *value); }
    }
}
struct GIn(usize);
impl CircuitInput for GIn {
    type WireRepr = Vec<WireId>;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (0..self.0).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<WireId> { w.clone() }
}
impl<H: GateHasher, T: CiphertextHandler> EncodeInput<GarbleMode<H,T>> for GIn {
    fn encode(&self, w: &Self::WireRepr, mode: &mut GarbleMode<H,T>) {
        for id in w { let label = mode.issue_garbled_wire(); mode.feed_wire(*id,label); }
    }
}
struct EIn { labels: Vec<GarbledWire>, bits: Vec<bool> }
impl CircuitInput for EIn {
    type WireRepr = Vec<WireId>;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (0..self.bits.len()).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<WireId> { w.clone() }
}
impl<H: GateHasher, T: CiphertextSource> EncodeInput<EvaluateMode<H,T>> for EIn {
    fn encode(&self, w: &Self::WireRepr, mode: &mut EvaluateMode<H,T>) {
        for (i,id) in w.iter().enumerate() {
            mode.feed_wire(*id,EvaluatedWire::new_from_garbled(&self.labels[i],self.bits[i]));
        }
    }
}
fn unhex(x:&str)->Vec<u8>{
    (0..x.len()).step_by(2).map(|i|u8::from_str_radix(&x[i..i+2],16).unwrap()).collect()
}
fn build<C: CircuitContext>(c:&mut C,w:&[WireId])->Vec<WireId>{
    assert_eq!(w.len(),INPUT_BITS);
    let mut b=Repo(c);
    let root=s::bytes(&mut b,&unhex(ROOT));
    let siblings=(0..3).map(|i|w[96+256*i..96+256*(i+1)].to_vec()).collect::<Vec<_>>();
    vec![s::merkle_opening(&mut b,&w[..64],&w[64..96],&siblings,&root)]
}
fn good_input()->Vec<bool>{
    let mut data=Vec::new();
    for x in [1u32,25,0] {data.extend(x.to_le_bytes());}
    for h in [
        "a285dca4c8c4d314cb36057790a50b64569b8629cb81dedde23697d6852e7d23",
        "d20fc79d940a0e828112689b035fed645ece483fb50f71184c03dcda9a1bcfb5",
        "8820b311557a838322299ac74929c8dfb0b3c453699a19615a704f5412eac9db",
    ] {data.extend(unhex(h));}
    data.iter().flat_map(|&x|(0..8).map(move |i|(x>>i)&1!=0)).collect()
}
fn check(input:Vec<bool>,expected:bool,case:usize){
    let plain:StreamingResult<ExecuteMode,_,Vec<bool>>=
        CircuitBuilder::streaming_execute(Plain(input.clone()),CAP,|c,w|build(c,&w));
    assert_eq!(plain.output_value,vec![expected]);
    assert!(plain.gate_count.nonfree_gate_count()<100_000);
    let seed=11+case as u64;
    let (tx,rx)=channel::unbounded();
    let g:StreamingResult<GarbleMode<AesCcrGateHasher,_>,_,Vec<GarbledWire>>=
        CircuitBuilder::streaming_garbling(GIn(INPUT_BITS),CAP,seed,tx,|c,w|build(c,&w));
    let ciphertexts=rx.len();
    assert_eq!(ciphertexts as u64,plain.gate_count.nonfree_gate_count());
    let mut rng=ChaChaRng::seed_from_u64(seed);
    let hasher=AesCcrGateHasher::from_rng(&mut rng);
    let evaluated:StreamingResult<EvaluateMode<AesCcrGateHasher,_>,_,Vec<EvaluatedWire>>=
        CircuitBuilder::streaming_evaluation(
            EIn {labels:g.input_wire_values.clone(),bits:input},CAP,
            g.true_wire_constant.select(true).to_u128(),
            g.false_wire_constant.select(false).to_u128(),hasher,rx,|c,w|build(c,&w));
    assert_eq!(evaluated.output_value.len(),1);
    assert!(evaluated.output_value[0].active_label==g.output_value[0].select(expected));
    assert!(evaluated.output_value[0].active_label!=g.output_value[0].select(!expected));
    println!("{{\"case\":{case},\"accepted\":{expected},\"ciphertexts\":{ciphertexts}}}");
}
#[test]
fn authenticating_component_garbles_and_rejects_mutations(){
    let good=good_input();check(good.clone(),true,0);
    for (case,bit) in [0,96,64,67].into_iter().enumerate(){
        let mut bad=good.clone();bad[bit]=!bad[bit];check(bad,false,case+1);
    }
}
