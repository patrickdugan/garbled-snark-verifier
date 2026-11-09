use stwo_bitvm3_core as s;
use s::Gates;

#[derive(Clone, Copy)]
enum Op { Constant(bool), Input(usize), Xor(usize,usize), And(usize,usize) }
struct Circuit { ops: Vec<Op>, inputs: usize }
impl Circuit {
    fn new() -> Self { Self { ops: vec![Op::Constant(false), Op::Constant(true)], inputs:0 } }
    fn input(&mut self, n:usize) -> Vec<usize> {
        (0..n).map(|_| {
            let id=self.ops.len(); self.ops.push(Op::Input(self.inputs)); self.inputs+=1; id
        }).collect()
    }
    fn run(&self, input:&[bool], out:&[usize]) -> Vec<bool> {
        assert_eq!(input.len(),self.inputs);
        let mut v=Vec::with_capacity(self.ops.len());
        for op in &self.ops {
            let value=match *op {
                Op::Constant(x)=>x, Op::Input(i)=>input[i],
                Op::Xor(a,b)=>v[a]^v[b], Op::And(a,b)=>v[a]&v[b]
            };
            v.push(value);
        }
        out.iter().map(|&i|v[i]).collect()
    }
    fn ands(&self) -> usize { self.ops.iter().filter(|o|matches!(o,Op::And(..))).count() }
}
impl Gates for Circuit {
    type W=usize;
    fn constant(&mut self,v:bool)->usize {usize::from(v)}
    fn xor(&mut self,a:usize,b:usize)->usize {
        if a==0{return b} if b==0{return a} if a==b{return 0}
        let id=self.ops.len();self.ops.push(Op::Xor(a,b));id
    }
    fn and(&mut self,a:usize,b:usize)->usize {
        if a==0||b==0{return 0} if a==1{return b} if b==1||a==b{return a}
        let id=self.ops.len();self.ops.push(Op::And(a,b));id
    }
}
fn vectors(kind:&str)->Vec<Vec<&'static str>> {
    include_str!("vectors.txt").lines().filter_map(|l| {
        let row:Vec<_>=l.split_whitespace().collect();
        (row.first()==Some(&kind)).then_some(row)
    }).collect()
}
fn bits(x:u64,n:usize)->Vec<bool>{(0..n).map(|i|(x>>i)&1!=0).collect()}
fn number(x:&[bool])->u64{x.iter().enumerate().fold(0,|v,(i,&b)|v|((b as u64)<<i))}
fn unhex(s:&str)->Vec<u8>{
    if s=="-"{return Vec::new()}
    assert_eq!(s.len()%2,0);
    (0..s.len()).step_by(2).map(|i|u8::from_str_radix(&s[i..i+2],16).unwrap()).collect()
}
fn bytebits(x:&[u8])->Vec<bool>{x.iter().flat_map(|&v|bits(v as u64,8)).collect()}
fn tobytes(x:&[bool])->Vec<u8>{x.chunks_exact(8).map(|v|number(v) as u8).collect()}
fn nums(row:&[&str])->Vec<u64>{row.iter().map(|v|v.parse().unwrap()).collect()}

#[test]
fn m31_boundary_random_and_alias_checks(){
    let mut c=Circuit::new();let w=c.input(62);
    let mut out=s::m31_add(&mut c,&w[..31],&w[31..]);
    out.extend(s::m31_sub(&mut c,&w[..31],&w[31..]));
    out.extend(s::m31_mul(&mut c,&w[..31],&w[31..]));
    for row in vectors("field"){
        let n=nums(&row[1..]);let input=[bits(n[0],31),bits(n[1],31)].concat();
        let got=c.run(&input,&out);
        assert_eq!(got.chunks(31).map(number).collect::<Vec<_>>(),n[2..],"{row:?}");
    }
    println!("m31 add+sub+mul AND gates: {}",c.ands());
    let mut c=Circuit::new();let w=c.input(32);
    let (_,ok)=s::decode_m31(&mut c,&w);let reduced=s::reduce_u32(&mut c,&w);
    for x in [0,1,s::P as u64-1,s::P as u64,s::P as u64+1,0xffff_ffff,0xffff_fffe] {
        assert_eq!(c.run(&bits(x,32),&[ok])[0],x<s::P as u64);
        assert_eq!(number(&c.run(&bits(x,32),&reduced)),x%s::P as u64);
    }
}
#[test]
fn qm31_tower_and_inverse_witness(){
    let mut c=Circuit::new();let w=c.input(248);
    let a=std::array::from_fn(|i|w[31*i..31*(i+1)].to_vec());
    let b=std::array::from_fn(|i|w[124+31*i..124+31*(i+1)].to_vec());
    let out=s::qm31_mul(&mut c,&a,&b).concat();
    for row in vectors("qm"){
        let n=nums(&row[1..]);let input=n[..8].iter().flat_map(|&v|bits(v,31)).collect::<Vec<_>>();
        assert_eq!(c.run(&input,&out).chunks(31).map(number).collect::<Vec<_>>(),n[8..],"{row:?}");
    }
    println!("qm31 multiplication AND gates: {}",c.ands());
    let ok=s::check_qm31_inverse(&mut c,&a,&b);
    for row in vectors("inverse"){
        let n=nums(&row[1..]);let input=n[..8].iter().flat_map(|&v|bits(v,31)).collect::<Vec<_>>();
        assert_eq!(c.run(&input,&[ok])[0],n[8]==1);
        if n[8]==1 {
            let mut bad=input.clone();bad[124]=!bad[124];
            assert!(!c.run(&bad,&[ok])[0]);
        }
    }
}
#[test]
fn blake2s_standard_vectors_and_block_boundaries(){
    for row in vectors("blake"){
        let msg=unhex(row[1]);let mut c=Circuit::new();let w=c.input(msg.len()*8);
        let out=s::blake2s(&mut c,&w);
        assert_eq!(tobytes(&c.run(&bytebits(&msg),&out)),unhex(row[2]),"length {}",msg.len());
        if msg.len()==64 {println!("blake2s 64-byte AND gates: {}",c.ands());assert!(c.ands()<25000);}
    }
}
#[test]
fn channel_matches_upstream_kats_and_draw_schedule(){
    for row in vectors("channel"){
        let msg=unhex(row[1]);let mut c=Circuit::new();let w=c.input(msg.len()*8);
        let mut ch=s::Channel::new(&mut c);ch.mix(&mut c,&w);
        let mut out=ch.digest.clone();out.extend(ch.draw_u32s(&mut c));out.extend(ch.draw_u32s(&mut c));
        out.extend(ch.draw_qm31(&mut c).concat());
        let got=c.run(&bytebits(&msg),&out);
        assert_eq!(tobytes(&got[..256]),unhex(row[2]));
        assert_eq!(tobytes(&got[256..512]),unhex(row[3]));
        assert_eq!(tobytes(&got[512..768]),unhex(row[4]));
        assert_eq!(got[768..].chunks(31).map(number).collect::<Vec<_>>(),nums(&row[5..]));
        // Mixing resets the draw counter; re-mix into a fresh channel is equivalent.
        let fresh=s::Channel::new(&mut c);
        ch.digest=fresh.digest;ch.mix(&mut c,&w);
        let reset=ch.draw_u32s(&mut c);
        assert_eq!(tobytes(&c.run(&bytebits(&msg),&reset)),unhex(row[3]));
    }
}
fn merkle_circuit(root:&[u8])->(Circuit,usize){
    let mut c=Circuit::new();let w=c.input(64+32+3*256);
    let siblings=(0..3).map(|i|w[96+256*i..96+256*(i+1)].to_vec()).collect::<Vec<_>>();
    let root=s::bytes(&mut c,root);
    let ok=s::merkle_opening(&mut c,&w[..64],&w[64..96],&siblings,&root);
    (c,ok)
}
#[test]
fn pinned_merkle_accepts_and_rejects_mutations(){
    let rows=vectors("merkle");let (c,ok)=merkle_circuit(&unhex(rows[0][5]));
    println!("standard lifted Merkle 2-column depth-3 AND gates: {}",c.ands());
    assert!(c.ands()<100000);
    for row in rows{
        let mut input=bytebits(&unhex(row[3]));input.extend(bits(row[2].parse().unwrap(),32));
        for h in row[4].split(','){input.extend(bytebits(&unhex(h)));}
        assert!(c.run(&input,&[ok])[0]);
        // Leaf, each sibling, low index, and a high index bit are all bound.
        for bit in [0,31,64,64+3,64+31,96,96+256,96+512]{
            let mut bad=input.clone();bad[bit]=!bad[bit];assert!(!c.run(&bad,&[ok])[0],"mutation {bit}");
        }
        let mut other_root=unhex(row[5]);other_root[0]^=1;
        let (other,other_ok)=merkle_circuit(&other_root);assert!(!other.run(&input,&[other_ok])[0]);
    }
}
#[test]
fn malformed_leaf_rejected_even_with_matching_hash(){
    // Matching native hash for the noncanonical raw encoding P: the canonical
    // field check must still fail even though the supplied root agrees.
    let mut c=Circuit::new();let w=c.input(32+32+256);
    let ok=s::merkle_opening(&mut c,&w[..32],&w[32..64],&[],&w[64..]);
    let raw=s::P.to_le_bytes();
    let digest=unhex("f5d1a320fdf3c0d1df822e9e7730252047751647702c39e4dfc2bcd7fd69ef1a");
    let input=[bytebits(&raw),bits(0,32),bytebits(&digest)].concat();
    assert!(!c.run(&input,&[ok])[0]);
}
#[test]
fn pow_checks_nonce_and_bit_order(){
    for row in vectors("pow"){
        let mut c=Circuit::new();let w=c.input(64);
        let mut ch=s::Channel::new(&mut c);ch.digest=s::bytes(&mut c,&unhex(row[1]));
        let n=row[3].parse::<u64>().unwrap();
        let ok=ch.check_pow(&mut c,row[2].parse().unwrap(),&w);
        assert!(c.run(&bits(n,64),&[ok])[0]);assert!(!c.run(&bits(n+1,64),&[ok])[0]);
    }
}
#[test]
#[should_panic]
fn unsupported_merkle_depth_is_rejected(){
    let mut c=Circuit::new();let zero=c.constant(false);
    s::merkle_opening(&mut c,&[],&vec![zero;32],&vec![vec![zero;256];31],&vec![zero;256]);
}
