//! Import the complete finalized upstream gate language at the exact pinned SHA.
//! The caller supplies the trusted verifier template and expected public values.
//! Never construct a template or its output policy from an untrusted proof.
use circuits::{circuit::Circuit, context::FinalizedContext, ivalue::IValue};
use stwo_bitvm3_lowering::{Constraint as G, Error, Limits, Program, Value};

pub fn import_finalized<V: IValue>(context:&FinalizedContext<V>, expected:&[(usize,Value)],
                                    limits:Limits)->Result<Program,Error>{
    if context.context.guessed_vars.is_some(){return Err(Error::InvalidShape);}
    // Deliberately exhaustive. New upstream fields must break compilation rather
    // than silently disappear from the verification relation.
    let Circuit {n_vars,add,sub,mul,pointwise_mul,eq,triple_xor,m31_to_u32,
                 blake_g_gate,permutation,output}=context.circuit();
    let count=add.len().checked_add(sub.len()).and_then(|n|n.checked_add(mul.len()))
        .and_then(|n|n.checked_add(pointwise_mul.len())).and_then(|n|n.checked_add(eq.len()))
        .and_then(|n|n.checked_add(triple_xor.len())).and_then(|n|n.checked_add(m31_to_u32.len()))
        .and_then(|n|n.checked_add(blake_g_gate.len())).and_then(|n|n.checked_add(permutation.len()))
        .and_then(|n|n.checked_add(output.len())).ok_or(Error::Budget)?;
    if count>limits.max_constraints||*n_vars>limits.max_vars{return Err(Error::Budget);}
    for p in permutation {
        if p.inputs.len()>limits.max_permutation||p.outputs.len()>limits.max_permutation {
            return Err(Error::Budget);
        }
    }
    let mut gates=Vec::with_capacity(count);
    gates.extend(add.iter().map(|g|G::Add{a:g.in0,b:g.in1,out:g.out}));
    gates.extend(sub.iter().map(|g|G::Sub{a:g.in0,b:g.in1,out:g.out}));
    gates.extend(mul.iter().map(|g|G::Mul{a:g.in0,b:g.in1,out:g.out}));
    gates.extend(pointwise_mul.iter().map(|g|G::PointwiseMul{a:g.in0,b:g.in1,out:g.out}));
    gates.extend(eq.iter().map(|g|G::Eq{a:g.in0,b:g.in1}));
    gates.extend(triple_xor.iter().map(|g|G::TripleXor{inputs:[g.input_a,g.input_b,g.input_c],out:g.out}));
    gates.extend(m31_to_u32.iter().map(|g|G::M31ToU32{input:g.input,out:g.out}));
    gates.extend(blake_g_gate.iter().map(|g|G::BlakeG{inputs:[g.input_a,g.input_b,g.input_c,g.input_d,g.input_f0,g.input_f1],outputs:[g.out_a,g.out_b,g.out_c,g.out_d]}));
    gates.extend(permutation.iter().map(|g|G::Permutation{inputs:g.inputs.clone(),outputs:g.outputs.clone()}));
    gates.extend(output.iter().map(|g|G::Output{input:g.in0}));
    let mut pins:Vec<_>=context.context.constants().iter()
        .map(|(value,var)|(var.idx,value.to_m31_array().map(|x|x.0))).collect();
    pins.extend_from_slice(expected);
    Program::new(*n_vars,gates,pins,limits)
}
