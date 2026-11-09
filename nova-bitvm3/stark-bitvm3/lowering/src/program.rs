//! S1: checked Boolean lowering of the pinned upstream circuit gate language.
//!
//! This checks a witness against a TRUSTED, finalized circuit supplied by the
//! caller. It does not construct a STARK verifier or authenticate a circuit
//! chosen by a prover. Pin the circuit and its public bindings outside the
//! witness. All witness limbs are canonical u32 encodings of M31 elements.
use std::collections::{BTreeMap, BTreeSet};
use stwo_bitvm3_core::{self as s, Bits, Gates, Qm, P};

pub const UPSTREAM: &str = "e9a38e12d09979f7a8625e233a80fecac6c38f02";
pub type Value = [u32; 4];

/// All ten gate families in upstream circuits::circuit::Circuit at UPSTREAM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Constraint {
    Add { a: usize, b: usize, out: usize },
    Sub { a: usize, b: usize, out: usize },
    Mul { a: usize, b: usize, out: usize },
    PointwiseMul { a: usize, b: usize, out: usize },
    Eq { a: usize, b: usize },
    TripleXor { inputs: [usize; 3], out: usize },
    M31ToU32 { input: usize, out: usize },
    BlakeG { inputs: [usize; 6], outputs: [usize; 4] },
    Permutation { inputs: Vec<usize>, outputs: Vec<usize> },
    Output { input: usize },
}
impl Constraint {
    fn refs(&self) -> Vec<usize> {
        match self {
            Self::Add { a, b, out } | Self::Sub { a, b, out }
            | Self::Mul { a, b, out } | Self::PointwiseMul { a, b, out } => vec![*a,*b,*out],
            Self::Eq { a, b } => vec![*a,*b],
            Self::TripleXor { inputs, out } => inputs.iter().copied().chain([*out]).collect(),
            Self::M31ToU32 { input, out } => vec![*input,*out],
            Self::BlakeG { inputs, outputs } => inputs.iter().chain(outputs).copied().collect(),
            Self::Permutation { inputs, outputs } => inputs.iter().chain(outputs).copied().collect(),
            Self::Output { input } => vec![*input],
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_vars: usize,
    pub max_constraints: usize,
    pub max_permutation: usize,
    /// Sum of padded sorting-network widths, counted on both sides.
    pub max_permutation_work: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self { max_vars: 4096, max_constraints: 16384, max_permutation: 64,
               max_permutation_work: 16384 }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidShape,
    Budget,
    ReferenceOutOfRange(usize),
    NonCanonicalBinding(usize),
    ConflictingBinding(usize),
    UnboundOutput(usize),
    WitnessLength { expected: usize, actual: usize },
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{self:?}") }
}
impl std::error::Error for Error {}

/// Immutable after validation. Construction is a public policy operation;
/// only `raw` in `lower` is a private witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    n_vars: usize,
    constraints: Vec<Constraint>,
    bindings: BTreeMap<usize, Value>,
}
impl Program {
    pub fn new(n_vars: usize, constraints: Vec<Constraint>, bindings: Vec<(usize, Value)>,
               limits: Limits) -> Result<Self, Error> {
        if n_vars < 3 { return Err(Error::InvalidShape); }
        if n_vars > limits.max_vars || constraints.len() > limits.max_constraints
            || n_vars.checked_mul(128).is_none() { return Err(Error::Budget); }
        // Upstream finalization derives constants from u. Its Output gate does
        // not check a value by itself. Anchor all three base slots explicitly.
        let mut pins = BTreeMap::from([(0,[0,0,0,0]),(1,[1,0,0,0]),(2,[0,0,1,0])]);
        for (idx, value) in bindings {
            if idx >= n_vars { return Err(Error::ReferenceOutOfRange(idx)); }
            if value.iter().any(|&x| x >= P) { return Err(Error::NonCanonicalBinding(idx)); }
            if let Some(old) = pins.insert(idx, value) {
                if old != value { return Err(Error::ConflictingBinding(idx)); }
            }
        }
        let mut permutation_work = 0usize;
        let mut outputs = BTreeSet::new();
        for gate in &constraints {
            // Check widths before allocating references or any Boolean gates.
            if let Constraint::Permutation { inputs, outputs } = gate {
                if inputs.len() != outputs.len() { return Err(Error::InvalidShape); }
                if inputs.len() > limits.max_permutation { return Err(Error::Budget); }
                let width = inputs.len().max(1).checked_next_power_of_two().ok_or(Error::Budget)?;
                let log = width.trailing_zeros() as usize;
                let work = width.checked_mul(log+1).and_then(|x| x.checked_mul(log+1))
                    .and_then(|x| x.checked_mul(2)).ok_or(Error::Budget)?;
                permutation_work = permutation_work.checked_add(work).ok_or(Error::Budget)?;
                if permutation_work > limits.max_permutation_work { return Err(Error::Budget); }
            }
            for idx in gate.refs() {
                if idx >= n_vars { return Err(Error::ReferenceOutOfRange(idx)); }
            }
            if let Constraint::Output { input } = gate { outputs.insert(*input); }
        }
        for idx in outputs {
            if !pins.contains_key(&idx) { return Err(Error::UnboundOutput(idx)); }
        }
        Ok(Self { n_vars, constraints, bindings: pins })
    }
    pub fn n_vars(&self) -> usize { self.n_vars }
    pub fn input_bits(&self) -> usize { self.n_vars * 128 }
    pub fn constraints(&self) -> &[Constraint] { &self.constraints }
    pub fn bindings(&self) -> &BTreeMap<usize, Value> { &self.bindings }

    /// Every canonicality, domain, constant, output and gate check reaches one
    /// acceptance wire. There is no host branch on an input wire's value.
    pub fn lower<B: Gates>(&self, b: &mut B, raw: &[B::W]) -> Result<B::W, Error> {
        if raw.len() != self.input_bits() {
            return Err(Error::WitnessLength { expected: self.input_bits(), actual: raw.len() });
        }
        let mut ok = b.constant(true);
        let mut values = Vec::with_capacity(self.n_vars);
        for chunk in raw.chunks_exact(128) {
            let (value, canonical) = s::decode_qm31(b, chunk);
            ok = b.and(ok, canonical);
            values.push(value);
        }
        for (&idx, value) in &self.bindings {
            let expected: Vec<_> = value.iter().flat_map(|&x| s::constant(b,x as u64,31)).collect();
            let valid = s::equal(b, &values[idx].concat(), &expected);
            ok = b.and(ok, valid);
        }
        for gate in &self.constraints {
            let valid = check(b, gate, &values);
            ok = b.and(ok, valid);
        }
        Ok(ok)
    }
}
fn not<B: Gates>(b: &mut B, x: B::W) -> B::W { let t=b.constant(true); b.xor(x,t) }
fn mux<B: Gates>(b: &mut B, sel: B::W, x: B::W, y: B::W) -> B::W {
    let d=b.xor(x,y); let d=b.and(sel,d); b.xor(x,d)
}
fn zeros<B: Gates>(b: &mut B, bits: impl IntoIterator<Item=B::W>) -> B::W {
    let mut ok=b.constant(true);
    for bit in bits { let z=not(b,bit); ok=b.and(ok,z); }
    ok
}
fn qeq<B: Gates>(b: &mut B, x: &Qm<B::W>, y: &Qm<B::W>) -> B::W { s::equal(b,&x.concat(),&y.concat()) }
fn word<B: Gates>(b: &mut B, q: &Qm<B::W>) -> (Bits<B::W>, B::W) {
    let w=[q[0][..16].to_vec(),q[1][..16].to_vec()].concat();
    let invalid_bits=q[0][16..].iter().chain(&q[1][16..]).chain(&q[2]).chain(&q[3]).copied();
    (w,zeros(b,invalid_bits))
}
fn pack<B: Gates>(b: &mut B, w: &[B::W]) -> Qm<B::W> {
    assert_eq!(w.len(),32);
    let z=b.constant(false);
    let mut lo=w[..16].to_vec(); lo.resize(31,z);
    let mut hi=w[16..].to_vec(); hi.resize(31,z);
    [lo,hi,vec![z;31],vec![z;31]]
}
fn xor<B: Gates>(b: &mut B, a: &[B::W], c: &[B::W]) -> Bits<B::W> {
    a.iter().zip(c).map(|(&x,&y)|b.xor(x,y)).collect()
}
fn add32<B: Gates>(b: &mut B, a: &[B::W], c: &[B::W]) -> Bits<B::W> {
    let mut carry=b.constant(false); let mut out=Vec::with_capacity(32);
    for i in 0..32 {
        let ac=b.xor(a[i],carry); let bc=b.xor(c[i],carry);
        out.push(b.xor(a[i],bc));
        if i != 31 { let t=b.and(ac,bc); carry=b.xor(carry,t); }
    }
    out
}
fn rotr<W: Copy>(w:&[W],n:usize)->Bits<W>{(0..32).map(|i|w[(i+n)%32]).collect()}
fn blake_g<B: Gates>(b:&mut B,w:&[Bits<B::W>;6])->[Bits<B::W>;4]{
    let [mut a,mut c,mut d,mut e]=[w[0].clone(),w[1].clone(),w[2].clone(),w[3].clone()];
    a=add32(b,&a,&c); a=add32(b,&a,&w[4]);
    e=rotr(&xor(b,&e,&a),16); d=add32(b,&d,&e); c=rotr(&xor(b,&c,&d),12);
    a=add32(b,&a,&c); a=add32(b,&a,&w[5]);
    e=rotr(&xor(b,&e,&a),8); d=add32(b,&d,&e); c=rotr(&xor(b,&c,&d),7);
    [a,c,d,e]
}
/// Unsigned comparison, processing little-endian bits. New high unequal bits
/// override the lower comparison. Topology depends only on public widths.
fn less<B: Gates>(b:&mut B,a:&[B::W],c:&[B::W])->B::W{
    let mut lt=b.constant(false);
    for (&x,&y) in a.iter().zip(c) { let diff=b.xor(x,y); lt=mux(b,diff,lt,y); }
    lt
}
fn sorted<B: Gates>(b:&mut B,mut a:Vec<Bits<B::W>>)->Vec<Bits<B::W>>{
    if a.is_empty(){return a;}
    let n=a.len().next_power_of_two();
    // Sentinel is strictly above every canonical QM31 tuple.
    let one=b.constant(true); a.resize(n,vec![one;124]);
    let mut k=2;
    while k<=n {
        let mut j=k/2;
        while j>0 {
            for i in 0..n {
                let other=i^j;
                if other>i {
                    let swap=if i&k==0 {less(b,&a[other],&a[i])} else {less(b,&a[i],&a[other])};
                    let (x,y)=(a[i].clone(),a[other].clone());
                    a[i]=x.iter().zip(&y).map(|(&u,&v)|mux(b,swap,u,v)).collect();
                    a[other]=x.iter().zip(&y).map(|(&u,&v)|mux(b,swap,v,u)).collect();
                }
            }
            j/=2;
        }
        if k==n {break;} k*=2;
    }
    a
}
fn check<B: Gates>(b:&mut B,g:&Constraint,v:&[Qm<B::W>])->B::W{
    match g {
        Constraint::Add {a,b:other,out}=>{let r=s::qm31_add(b,&v[*a],&v[*other]);qeq(b,&r,&v[*out])},
        Constraint::Sub {a,b:other,out}=>{let r=s::qm31_sub(b,&v[*a],&v[*other]);qeq(b,&r,&v[*out])},
        Constraint::Mul {a,b:other,out}=>{let r=s::qm31_mul(b,&v[*a],&v[*other]);qeq(b,&r,&v[*out])},
        Constraint::PointwiseMul {a,b:other,out}=>{
            let r=std::array::from_fn(|i|s::m31_mul(b,&v[*a][i],&v[*other][i]));qeq(b,&r,&v[*out])
        },
        Constraint::Eq {a,b:other}=>qeq(b,&v[*a],&v[*other]),
        Constraint::TripleXor {inputs,out}=>{
            let mut ok=b.constant(true);
            let w:[Bits<B::W>;3]=std::array::from_fn(|i|{let (w,c)=word(b,&v[inputs[i]]);ok=b.and(ok,c);w});
            let r=xor(b,&w[0],&w[1]);let r=xor(b,&r,&w[2]);let r=pack(b,&r);
            let eq=qeq(b,&r,&v[*out]);b.and(ok,eq)
        },
        Constraint::M31ToU32 {input,out}=>{
            let ok=zeros(b,v[*input][1..].iter().flatten().copied());
            let mut w=v[*input][0].clone();w.push(b.constant(false));let r=pack(b,&w);
            let eq=qeq(b,&r,&v[*out]);b.and(ok,eq)
        },
        Constraint::BlakeG {inputs,outputs}=>{
            let mut ok=b.constant(true);
            let w:[Bits<B::W>;6]=std::array::from_fn(|i|{let(w,c)=word(b,&v[inputs[i]]);ok=b.and(ok,c);w});
            let result=blake_g(b,&w);
            for (w,&idx) in result.iter().zip(outputs){let r=pack(b,w);let eq=qeq(b,&r,&v[idx]);ok=b.and(ok,eq);}
            ok
        },
        Constraint::Permutation {inputs,outputs}=>{
            let a=sorted(b,inputs.iter().map(|&i|v[i].concat()).collect());
            let c=sorted(b,outputs.iter().map(|&i|v[i].concat()).collect());
            s::equal(b,&a.concat(),&c.concat())
        },
        // Program::new requires a fixed binding for every Output; lower checked it.
        Constraint::Output {..}=>b.constant(true),
    }
}
