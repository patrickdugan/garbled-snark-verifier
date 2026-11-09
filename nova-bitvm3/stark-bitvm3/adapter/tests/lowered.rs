//! Garbled acceptance of the synthetic all-ten-gate constraint fixture.
//! Fixed seeds and direct label access are local test conventions only.
use crossbeam::channel;
use garbled_snark_verifier::{
    AesCcrGateHasher, CircuitContext, EvaluatedWire, GarbleMode, GarbledWire, GateHasher, WireId,
    circuit::{CiphertextHandler, CiphertextSource, CircuitBuilder, CircuitInput, CircuitMode,
              EncodeInput, EvaluateMode, ExecuteMode, StreamingResult},
};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use stwo_bitvm3_adapter::Repo;
use stwo_bitvm3_lowering::{Value, fixture::all_gate_fixture};
const CAP:usize=1<<20;
struct Plain(Vec<bool>);
impl CircuitInput for Plain {
    type WireRepr=Vec<WireId>;
    fn allocate(&self,mut issue:impl FnMut()->WireId)->Self::WireRepr{(0..self.0.len()).map(|_|issue()).collect()}
    fn collect_wire_ids(w:&Self::WireRepr)->Vec<WireId>{w.clone()}
}
impl EncodeInput<ExecuteMode> for Plain{
    fn encode(&self,w:&Self::WireRepr,mode:&mut ExecuteMode){for(id,value)in w.iter().zip(&self.0){mode.feed_wire(*id,*value);}}
}
struct GIn(usize);
impl CircuitInput for GIn{
    type WireRepr=Vec<WireId>;
    fn allocate(&self,mut issue:impl FnMut()->WireId)->Self::WireRepr{(0..self.0).map(|_|issue()).collect()}
    fn collect_wire_ids(w:&Self::WireRepr)->Vec<WireId>{w.clone()}
}
impl<H:GateHasher,T:CiphertextHandler> EncodeInput<GarbleMode<H,T>> for GIn{
    fn encode(&self,w:&Self::WireRepr,mode:&mut GarbleMode<H,T>){for id in w{let label=mode.issue_garbled_wire();mode.feed_wire(*id,label);}}
}
struct EIn{labels:Vec<GarbledWire>,bits:Vec<bool>}
impl CircuitInput for EIn{
    type WireRepr=Vec<WireId>;
    fn allocate(&self,mut issue:impl FnMut()->WireId)->Self::WireRepr{(0..self.bits.len()).map(|_|issue()).collect()}
    fn collect_wire_ids(w:&Self::WireRepr)->Vec<WireId>{w.clone()}
}
impl<H:GateHasher,T:CiphertextSource> EncodeInput<EvaluateMode<H,T>> for EIn{
    fn encode(&self,w:&Self::WireRepr,mode:&mut EvaluateMode<H,T>){for(i,id)in w.iter().enumerate(){mode.feed_wire(*id,EvaluatedWire::new_from_garbled(&self.labels[i],self.bits[i]));}}
}
fn build<C:CircuitContext>(c:&mut C,w:&[WireId])->Vec<WireId>{
    let (program,_)=all_gate_fixture();vec![program.lower(&mut Repo(c),w).unwrap()]
}
fn input(v:&[Value])->Vec<bool>{v.iter().flatten().flat_map(|&x|(0..32).map(move|i|(x>>i)&1!=0)).collect()}
fn run(v:Vec<Value>,expected:bool,case:usize){
    let bits=input(&v);
    let plain:StreamingResult<ExecuteMode,_,Vec<bool>>=
        CircuitBuilder::streaming_execute(Plain(bits.clone()),CAP,|c,w|build(c,&w));
    assert_eq!(plain.output_value,vec![expected]);
    assert!(plain.gate_count.nonfree_gate_count()<200_000);
    let seed=617+case as u64;let(tx,rx)=channel::unbounded();
    let g:StreamingResult<GarbleMode<AesCcrGateHasher,_>,_,Vec<GarbledWire>>=
        CircuitBuilder::streaming_garbling(GIn(bits.len()),CAP,seed,tx,|c,w|build(c,&w));
    let ciphertexts=rx.len();assert_eq!(ciphertexts as u64,plain.gate_count.nonfree_gate_count());
    let mut rng=ChaChaRng::seed_from_u64(seed);let hasher=AesCcrGateHasher::from_rng(&mut rng);
    let e:StreamingResult<EvaluateMode<AesCcrGateHasher,_>,_,Vec<EvaluatedWire>>=
        CircuitBuilder::streaming_evaluation(EIn{labels:g.input_wire_values.clone(),bits},CAP,
            g.true_wire_constant.select(true).to_u128(),g.false_wire_constant.select(false).to_u128(),hasher,rx,|c,w|build(c,&w));
    assert!(e.output_value[0].active_label==g.output_value[0].select(expected));
    assert!(e.output_value[0].active_label!=g.output_value[0].select(!expected));
    println!("S1 garbling case={case} accepted={expected} ciphertexts={ciphertexts}");
}
#[test]
fn all_gate_lowering_garbles_and_rejects_adversarial_witnesses(){
    let(_,v)=all_gate_fixture();run(v.clone(),true,0);
    let mut bad=v.clone();bad[7][0]^=1;run(bad,false,1);
    let mut bad=v.clone();bad[10][2]=1;run(bad,false,2);
    let mut bad=v.clone();bad[20]=bad[21];run(bad,false,3);
    let mut bad=v.clone();bad[23]=[0;4];run(bad,false,4);
    run(vec![[0;4];v.len()],false,5);
}
