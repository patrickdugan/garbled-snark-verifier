//! Synthetic all-gate fixture. No STARK proof is generated here.
use crate::{Constraint as G, Limits, Program, Value};
use stwo_bitvm3_core::P;
fn packed(x:u32)->Value{[x&65535,x>>16,0,0]}
fn g(x:[u32;6])->[u32;4]{
    let[mut a,mut b,mut c,mut d,e,f]=x;
    a=a.wrapping_add(b).wrapping_add(e);d=(d^a).rotate_right(16);
    c=c.wrapping_add(d);b=(b^c).rotate_right(12);
    a=a.wrapping_add(b).wrapping_add(f);d=(d^a).rotate_right(8);
    c=c.wrapping_add(d);b=(b^c).rotate_right(7);[a,b,c,d]
}
pub fn all_gate_fixture()->(Program,Vec<Value>){
    let i=[0,1,0,0];let u=[0,0,1,0];let iu=[0,0,0,1];
    let mut v=vec![[0;4],[1,0,0,0],u,i,u,[0,1,1,0],[0,1,P-1,0],iu,[0;4],iu];
    let x=0x12345678u32;let y=0x87654321;let z=0xffff_ffff;
    v.extend([packed(x),packed(y),packed(z),packed(x^y^z),[P-2,0,0,0],packed(P-2)]);
    v.extend(g([x,y,z,1,0,x]).map(packed));
    v.extend([i,u,i,iu]);
    let gates=vec![G::Add{a:3,b:4,out:5},G::Sub{a:3,b:4,out:6},G::Mul{a:3,b:4,out:7},
        G::PointwiseMul{a:3,b:4,out:8},G::Eq{a:7,b:9},
        G::TripleXor{inputs:[10,11,12],out:13},G::M31ToU32{input:14,out:15},
        G::BlakeG{inputs:[10,11,12,1,0,10],outputs:[16,17,18,19]},
        G::Permutation{inputs:vec![3,3,4],outputs:vec![20,21,22]},
        G::Eq{a:7,b:23},G::Output{input:23}];
    (Program::new(v.len(),gates,vec![(23,iu)],Limits::default()).unwrap(),v)
}
