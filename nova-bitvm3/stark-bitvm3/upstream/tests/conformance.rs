use circuits::{circuit as c, context::{FinalizedContext, GuessVar, TraceContext, Var}};
use stwo::core::fields::qm31::QM31;
use stwo_bitvm3_lowering::{Constraint as G, Error, Limits, Value,
    fixture::all_gate_fixture, testing::CompiledCheck};
use stwo_bitvm3_upstream::{import_finalized, import_function};

fn q(v:Value)->QM31{QM31::from_u32_unchecked(v[0],v[1],v[2],v[3])}
fn raw(v:QM31)->Value{v.to_m31_array().map(|x|x.0)}
fn fixture()->FinalizedContext<QM31>{
    let (program,values)=all_gate_fixture();let mut ctx=TraceContext::default();
    for &v in &values[3..]{ctx.new_var(q(v));}
    // Construct the real upstream gate structs; upstream executes the native
    // field and Blake arithmetic, and its finalizer emits domain constraints.
    for gate in program.constraints(){match gate {
        G::Add{a,b,out}=>ctx.circuit.add.push(c::Add{in0:*a,in1:*b,out:*out}),
        G::Sub{a,b,out}=>ctx.circuit.sub.push(c::Sub{in0:*a,in1:*b,out:*out}),
        G::Mul{a,b,out}=>ctx.circuit.mul.push(c::Mul{in0:*a,in1:*b,out:*out}),
        G::PointwiseMul{a,b,out}=>ctx.circuit.pointwise_mul.push(c::PointwiseMul{in0:*a,in1:*b,out:*out}),
        G::Eq{a,b}=>ctx.circuit.eq.push(c::Eq{in0:*a,in1:*b}),
        G::TripleXor{inputs,out}=>ctx.circuit.triple_xor.push(c::TripleXor{input_a:inputs[0],input_b:inputs[1],input_c:inputs[2],out:*out}),
        G::M31ToU32{input,out}=>ctx.circuit.m31_to_u32.push(c::M31ToU32{input:*input,out:*out}),
        G::BlakeG{inputs,outputs}=>ctx.circuit.blake_g_gate.push(c::BlakeGGate{
            input_a:inputs[0],input_b:inputs[1],input_c:inputs[2],input_d:inputs[3],input_f0:inputs[4],input_f1:inputs[5],
            out_a:outputs[0],out_b:outputs[1],out_c:outputs[2],out_d:outputs[3]}),
        G::Permutation{inputs,outputs}=>ctx.circuit.permutation.push(c::Permutation{inputs:inputs.clone(),outputs:outputs.clone()}),
        G::Output{input}=>ctx.circuit.output.push(c::Output{in0:*input}),
    }}
    let m=ctx.new_var(q([37,0,0,0]));
    let u16=ctx.new_var(q([65535,0,0,0]));
    let full=ctx.new_var(q([2,3,5,7]));
    ctx.guessed_vars.as_mut().unwrap().extend([GuessVar::M31(m),GuessVar::U16(u16),GuessVar::QM31(full)]);
    ctx.finalize(false)
}
fn policy()->Vec<(usize,Value)>{vec![(23,[0,0,0,1])]}
fn native_with_policy(ctx:&FinalizedContext<QM31>,values:&[QM31])->bool{
    ctx.circuit().check(values).is_ok()
        && ctx.context.constants().iter().all(|(x,var)|values[var.idx]==*x)
        && policy().iter().all(|(idx,x)|values[*idx]==q(*x))
}
#[test]
fn every_upstream_gate_and_finalized_domain_matches_boolean(){
    let ctx=fixture();ctx.validate_circuit();
    let program=import_finalized(&ctx,&policy(),Limits::default()).unwrap();
    let checker=CompiledCheck::compile(&program,12_000_000);
    let values=ctx.values().clone();let encoded=values.iter().copied().map(raw).collect::<Vec<_>>();
    assert!(native_with_policy(&ctx,&values));assert!(checker.accepts(&encoded));
    let mut cases=0;
    // Every original fixture variable, and each guessed-domain variable. Native
    // values remain canonical so the native reference has a defined input.
    for idx in 0..27 {for limb in 0..4 {
        let mut changed=values.clone();let mut x=raw(changed[idx]);x[limb]=(x[limb]+1)%stwo_bitvm3_core::P;changed[idx]=q(x);
        let expected=native_with_policy(&ctx,&changed);
        assert_eq!(checker.accepts(&changed.iter().copied().map(raw).collect::<Vec<_>>()),expected,"variable {idx}, limb {limb}");
        cases+=1;
    }}
    // Raw field aliases never enter native QM31 arithmetic; the Boolean input
    // boundary must reject them independently.
    for idx in [0,2,3,10,23,24,25,26] {
        let mut changed=encoded.clone();changed[idx][0]=stwo_bitvm3_core::P;
        assert!(!checker.accepts(&changed));
    }
    println!("S1 upstream differential: {cases} canonical mutations; {} variables; {} constraints; {} AND gates",program.n_vars(),program.constraints().len(),checker.ands());
}
#[test]
fn upstream_output_marker_alone_does_not_bind_the_generator(){
    let ctx=fixture();let all_zero=vec![q([0;4]);ctx.values().len()];
    // Actual upstream Circuit::check excludes the public-output contract.
    // The surrounding verifier supplies that contract. Our adapter must too.
    assert!(ctx.circuit().check(&all_zero).is_ok());
    let program=import_finalized(&ctx,&policy(),Limits::default()).unwrap();
    let checker=CompiledCheck::compile(&program,12_000_000);
    assert!(!checker.accepts(&vec![[0;4];program.n_vars()]));
}
#[test]
fn importer_requires_finalization_and_expected_outputs(){
    let ctx=fixture();
    assert_eq!(import_finalized(&ctx,&[],Limits::default()).unwrap_err(),Error::UnboundOutput(23));
    let unfinalized=FinalizedContext{context:TraceContext::default()};
    assert_eq!(import_finalized(&unfinalized,&[],Limits::default()).unwrap_err(),Error::InvalidShape);
    assert!(matches!(import_finalized(&ctx,&[(23,[0;4]),(23,[1,0,0,0])],Limits::default()),Err(Error::ConflictingBinding(23))));
    let _=Var{idx:0}; // Import is intentional: upstream's public index type is used above.
}

/// The fixture with every free variable declared as an upstream guess, so that upstream's own finalizer
/// emits the typing gates the function form reads.
fn guessed_fixture()->FinalizedContext<QM31>{
    let (program,mut values)=all_gate_fixture();let mut ctx=TraceContext::default();
    // The permutation outputs are not guesses. Give them the ascending order the function form computes
    // ([i,i,u] as 124-bit integers), which is one of the permutations the gate allows.
    values[20]=[0,1,0,0];values[21]=[0,1,0,0];values[22]=[0,0,1,0];
    for &v in &values[3..]{ctx.new_var(q(v));}
    for gate in program.constraints(){match gate {
        G::Add{a,b,out}=>ctx.circuit.add.push(c::Add{in0:*a,in1:*b,out:*out}),
        G::Sub{a,b,out}=>ctx.circuit.sub.push(c::Sub{in0:*a,in1:*b,out:*out}),
        G::Mul{a,b,out}=>ctx.circuit.mul.push(c::Mul{in0:*a,in1:*b,out:*out}),
        G::PointwiseMul{a,b,out}=>ctx.circuit.pointwise_mul.push(c::PointwiseMul{in0:*a,in1:*b,out:*out}),
        G::Eq{a,b}=>ctx.circuit.eq.push(c::Eq{in0:*a,in1:*b}),
        G::TripleXor{inputs,out}=>ctx.circuit.triple_xor.push(c::TripleXor{input_a:inputs[0],input_b:inputs[1],input_c:inputs[2],out:*out}),
        G::M31ToU32{input,out}=>ctx.circuit.m31_to_u32.push(c::M31ToU32{input:*input,out:*out}),
        G::BlakeG{inputs,outputs}=>ctx.circuit.blake_g_gate.push(c::BlakeGGate{
            input_a:inputs[0],input_b:inputs[1],input_c:inputs[2],input_d:inputs[3],input_f0:inputs[4],input_f1:inputs[5],
            out_a:outputs[0],out_b:outputs[1],out_c:outputs[2],out_d:outputs[3]}),
        G::Permutation{inputs,outputs}=>ctx.circuit.permutation.push(c::Permutation{inputs:inputs.clone(),outputs:outputs.clone()}),
        G::Output{input}=>ctx.circuit.output.push(c::Output{in0:*input}),
    }}
    let m=ctx.new_var(q([37,0,0,0]));
    let u16=ctx.new_var(q([65535,0,0,0]));
    let full=ctx.new_var(q([2,3,5,7]));
    let guesses=ctx.guessed_vars.as_mut().unwrap();
    guesses.extend([3,4,9,10,11,12,23].map(|idx|GuessVar::QM31(Var{idx})));
    guesses.extend([GuessVar::M31(Var{idx:14}),GuessVar::M31(m),GuessVar::U16(u16),GuessVar::QM31(full)]);
    ctx.finalize(false)
}
fn native_relation(ctx:&FinalizedContext<QM31>,values:&[Value])->bool{
    // Native QM31 arithmetic has no encoding for a noncanonical limb; the Boolean boundary rejects it.
    values.iter().flatten().all(|&x|x<stwo_bitvm3_core::P)
        && {let v:Vec<QM31>=values.iter().copied().map(q).collect();
            ctx.circuit().check(&v).is_ok()&&ctx.context.constants().iter().all(|(x,var)|v[var.idx]==*x)}
}
#[test]
fn function_form_of_an_upstream_finalized_circuit_matches_the_native_checker(){
    use stwo_bitvm3_lowering::{testing::evaluate,Kind};
    let ctx=guessed_fixture();ctx.validate_circuit();
    let f=import_function(&ctx,Limits::default()).unwrap();
    // Upstream's finalizer typed exactly the declared guesses.
    let kinds:Vec<(usize,Kind)>=f.inputs().to_vec();
    let mut expected:Vec<(usize,Kind)>=[3,4,9,10,11,12,23,26].iter().map(|v|(*v,Kind::Qm31)).collect();
    expected.extend([(14,Kind::M31),(24,Kind::M31),(25,Kind::U16)]);expected.sort_by_key(|(v,_)|*v);
    assert_eq!(kinds,expected);
    let values:Vec<Value>=ctx.values().iter().copied().map(raw).collect();
    let honest=f.encode(&values).unwrap();
    let (ok,computed)=evaluate(&f,&honest);
    assert!(ok);assert_eq!(computed,values,"the function must compute upstream's own witness");
    // Every single-bit change of the input: the function's verdict equals upstream's native checker on
    // the assignment the function computed, so both the checks and the computed values are covered.
    let (mut accepted,mut rejected)=(0,0);
    for bit in 0..honest.len() {
        let mut input=honest.clone();input[bit]=!input[bit];
        let (ok,computed)=evaluate(&f,&input);
        assert_eq!(ok,native_relation(&ctx,&computed),"input bit {bit}");
        if ok {accepted+=1} else {rejected+=1}
    }
    assert!(accepted>0&&rejected>0);
    println!("S6 upstream function differential: {} input bits of {} relation bits; {} flips, {rejected} rejected, {accepted} accepted",
        f.input_bits(),f.n_vars()*128,honest.len());
}
#[test]
fn function_importer_refuses_an_unfinalized_or_untyped_circuit(){
    let unfinalized=FinalizedContext{context:TraceContext::default()};
    assert_eq!(import_function(&unfinalized,Limits::default()).unwrap_err(),Error::InvalidShape);
    // The original fixture leaves its free variables undeclared; nothing may be left for a prover to choose.
    assert!(matches!(import_function(&fixture(),Limits::default()),Err(Error::Undetermined(_))));
}
