use stwo_bitvm3_lowering::{Constraint as G, Error, Limits, Program, Value, testing::CompiledCheck};
use stwo_bitvm3_core::P;

fn anchors()->Vec<Value>{vec![[0;4],[1,0,0,0],[0,0,1,0]]}
fn program(n:usize,g:Vec<G>,pins:Vec<(usize,Value)>)->Program{Program::new(n,g,pins,Limits::default()).unwrap()}
fn check(p:&Program)->CompiledCheck{CompiledCheck::compile(p,5_000_000)}
fn base(x:u32)->Value{[x,0,0,0]}
fn packed(x:u32)->Value{[x&65535,x>>16,0,0]}
fn add(a:u32,b:u32)->u32{((a as u64+b as u64)%P as u64)as u32}
fn sub(a:u32,b:u32)->u32{((a as u64+P as u64-b as u64)%P as u64)as u32}
fn mul(a:u32,b:u32)->u32{((a as u64*b as u64)%P as u64)as u32}
fn cm(a:[u32;2],b:[u32;2])->[u32;2]{[sub(mul(a[0],b[0]),mul(a[1],b[1])),add(mul(a[0],b[1]),mul(a[1],b[0]))]}
fn qm(a:Value,b:Value)->Value{
    let lo=cm([a[0],a[1]],[b[0],b[1]]);let hi=cm([a[2],a[3]],[b[2],b[3]]);
    let r=cm([2,1],hi);let ab=cm([a[0],a[1]],[b[2],b[3]]);let ba=cm([a[2],a[3]],[b[0],b[1]]);
    [add(lo[0],r[0]),add(lo[1],r[1]),add(ab[0],ba[0]),add(ab[1],ba[1])]
}
fn native_g(x:[u32;6])->[u32;4]{
    let [mut a,mut b,mut c,mut d,e,f]=x;
    a=a.wrapping_add(b).wrapping_add(e);d=(d^a).rotate_right(16);
    c=c.wrapping_add(d);b=(b^c).rotate_right(12);
    a=a.wrapping_add(b).wrapping_add(f);d=(d^a).rotate_right(8);
    c=c.wrapping_add(d);b=(b^c).rotate_right(7);[a,b,c,d]
}
#[test]
fn arithmetic_gate_families(){
    let gates=vec![G::Add{a:3,b:4,out:5},G::Sub{a:3,b:4,out:6},G::Mul{a:3,b:4,out:7},G::PointwiseMul{a:3,b:4,out:8},G::Eq{a:7,b:9}];
    let c=check(&program(10,gates,vec![]));let mut seed=417u64;
    for case in 0..40 {
        let mut random=||{seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;(seed%P as u64)as u32};
        let a=if case==0{[P-1;4]}else{std::array::from_fn(|_|random())};
        let b=if case==0{[0;4]}else{std::array::from_fn(|_|random())};
        let mut v=anchors();v.extend([a,b,std::array::from_fn(|i|add(a[i],b[i])),std::array::from_fn(|i|sub(a[i],b[i])),qm(a,b),std::array::from_fn(|i|mul(a[i],b[i])),qm(a,b)]);
        assert!(c.accepts(&v));
        for idx in 5..10 {let mut bad=v.clone();bad[idx][case%4]=add(bad[idx][case%4],1);assert!(!c.accepts(&bad));}
    }
    println!("S1 arithmetic fixture AND gates: {}",c.ands());
}
#[test]
fn packed_bitwise_gates_and_domains(){
    let words=[0xffff_ffff,0x12345678,0xabcdef01,1,0x88776655,0];
    let out=native_g(words);
    let gates=vec![G::BlakeG{inputs:[3,4,5,6,7,8],outputs:[9,10,11,12]},G::TripleXor{inputs:[3,4,5],out:13},G::M31ToU32{input:14,out:15}];
    let c=check(&program(16,gates,vec![]));
    let mut v=anchors();v.extend(words.map(packed));v.extend(out.map(packed));v.extend([packed(words[0]^words[1]^words[2]),base(P-1),packed(P-1)]);
    assert!(c.accepts(&v));
    for idx in 3..16 {for limb in 0..4 {let mut bad=v.clone();bad[idx][limb]^=1;assert!(!c.accepts(&bad),"variable {idx}, limb {limb}");}}
    // Values above u16 remain canonical M31, so this exercises packed domains.
    for (idx,limb) in [(3,0),(4,1),(8,2),(13,3),(14,1)] {
        let mut bad=v.clone();bad[idx][limb]=65536;assert!(!c.accepts(&bad));
    }
    println!("S1 packed gate fixture AND gates: {}",c.ands());
}
#[test]
fn exact_permutations_preserve_multiplicity(){
    for n in 0..10 {
        let p=program(3+2*n,vec![G::Permutation{inputs:(3..3+n).collect(),outputs:(3+n..3+2*n).collect()}],vec![]);
        let c=check(&p);
        let left=(0..n).map(|i|[(i%3)as u32,(i%2)as u32,0,0]).collect::<Vec<_>>();
        let mut right=left.clone();right.reverse();
        for shift in 0..n.max(1) {
            if n>0 {right.rotate_left(shift%n);}
            let mut v=anchors();v.extend(left.clone());v.extend(right.clone());
            assert!(c.accepts(&v),"n={n}, shift={shift}");
            if n>0 {v[3+n][0]=13;assert!(!c.accepts(&v));}
        }
    }
    let p=program(9,vec![G::Permutation{inputs:vec![3,4,5],outputs:vec![6,7,8]}],vec![]);
    let c=check(&p);let mut v=anchors();v.extend([base(2),base(2),base(3),base(2),base(3),base(3)]);
    assert!(!c.accepts(&v),"same set, different multiplicities");
}
#[test]
fn all_witness_limbs_and_pinned_outputs_reach_acceptance(){
    let p=program(5,vec![G::Eq{a:3,b:4},G::Output{input:4}],vec![(4,[7,8,9,10])]);
    let c=check(&p);let mut v=anchors();v.extend([[7,8,9,10];2]);assert!(c.accepts(&v));
    for idx in 0..v.len(){for limb in 0..4{for value in [P,0x8000_0000,0xffff_ffff] {
        let mut bad=v.clone();bad[idx][limb]=value;assert!(!c.accepts(&bad));
    }}}
    let mut changed=v.clone();changed[3][0]=8;changed[4][0]=8;
    assert!(!c.accepts(&changed),"equal internal values still must match expected public output");
    assert!(!c.accepts(&vec![[0;4];5]),"zeroing the generator cannot collapse constants");
}
#[test]
fn finalized_guess_domains_and_zero_inverse(){
    let m=check(&program(4,vec![G::PointwiseMul{a:3,b:1,out:3}],vec![]));
    let u=check(&program(4,vec![G::M31ToU32{input:3,out:3}],vec![]));
    for (x,m_ok,u_ok) in [(base(65535),true,true),(base(65536),true,false),([3,1,0,0],false,false),([0,0,1,0],false,false)] {
        let mut v=anchors();v.push(x);assert_eq!(m.accepts(&v),m_ok);assert_eq!(u.accepts(&v),u_ok);
    }
    let c=check(&program(5,vec![G::Mul{a:3,b:4,out:1}],vec![]));
    let mut v=anchors();v.extend([base(2),base((P+1)/2)]);assert!(c.accepts(&v));
    v[3]=base(0);v[4]=base(0);assert!(!c.accepts(&v));
}
#[test]
fn malformed_programs_fail_before_lowering(){
    let limits=Limits::default();
    assert_eq!(Program::new(4,vec![G::Output{input:3}],vec![],limits).unwrap_err(),Error::UnboundOutput(3));
    assert!(matches!(Program::new(3,vec![G::Eq{a:0,b:3}],vec![],limits),Err(Error::ReferenceOutOfRange(3))));
    assert!(matches!(Program::new(3,vec![],vec![(2,[0;4])],limits),Err(Error::ConflictingBinding(2))));
    assert!(matches!(Program::new(4,vec![],vec![(3,[P,0,0,0])],limits),Err(Error::NonCanonicalBinding(3))));
    assert!(matches!(Program::new(4,vec![G::Permutation{inputs:vec![3],outputs:vec![]}],vec![],limits),Err(Error::InvalidShape)));
    assert!(matches!(Program::new(3,vec![G::Permutation{inputs:vec![0;65],outputs:vec![0;65]}],vec![],limits),Err(Error::Budget)));
    assert!(matches!(Program::new(usize::MAX,vec![],vec![],limits),Err(Error::Budget)));
    assert!(matches!(Program::new(2,vec![],vec![],limits),Err(Error::InvalidShape)));
}
