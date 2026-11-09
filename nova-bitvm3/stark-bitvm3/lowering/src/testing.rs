//! Test-only symbolic Boolean DAG. Compiles once and replays multiple witnesses.
//! The recorded gate topology and count are independent of witness values.
use crate::{Program, Value};
use stwo_bitvm3_core::Gates;

#[derive(Clone, Copy)]
enum Op { Constant(bool), Input(usize), Xor(usize,usize), And(usize,usize) }
struct Builder { ops:Vec<Op>, inputs:usize, max_gates:usize }
impl Builder {
    fn push(&mut self,op:Op)->usize{
        assert!(self.ops.len()<self.max_gates,"test Boolean gate budget exceeded");
        let id=self.ops.len();self.ops.push(op);id
    }
    fn inputs(&mut self,n:usize)->Vec<usize>{
        (0..n).map(|_|{let i=self.inputs;self.inputs+=1;self.push(Op::Input(i))}).collect()
    }
}
impl Gates for Builder {
    type W=usize;
    fn constant(&mut self,v:bool)->usize{usize::from(v)}
    fn xor(&mut self,a:usize,b:usize)->usize{
        if a==0{return b;} if b==0{return a;} if a==b{return 0;}
        self.push(Op::Xor(a,b))
    }
    fn and(&mut self,a:usize,b:usize)->usize{
        if a==0||b==0{return 0;} if a==1{return b;} if b==1||a==b{return a;}
        self.push(Op::And(a,b))
    }
}
pub struct CompiledCheck { builder:Builder, out:usize }
impl CompiledCheck {
    pub fn compile(program:&Program,max_gates:usize)->Self{
        let mut b=Builder {ops:vec![Op::Constant(false),Op::Constant(true)],inputs:0,max_gates};
        let w=b.inputs(program.input_bits());
        let out=program.lower(&mut b,&w).expect("validated program and input shape");
        Self {builder:b,out}
    }
    pub fn accepts(&self,values:&[Value])->bool{
        let input:Vec<_>=values.iter().flatten().flat_map(|&x|(0..32).map(move |i|(x>>i)&1!=0)).collect();
        assert_eq!(input.len(),self.builder.inputs);
        let mut v=Vec::<bool>::with_capacity(self.builder.ops.len());
        for op in &self.builder.ops {
            let value=match *op {
                Op::Constant(x)=>x,Op::Input(i)=>input[i],Op::Xor(a,b)=>v[a]^v[b],Op::And(a,b)=>v[a]&v[b]
            };
            v.push(value);
        }
        v[self.out]
    }
    pub fn ands(&self)->usize{self.builder.ops.iter().filter(|x|matches!(x,Op::And(..))).count()}
    pub fn gates(&self)->usize{self.builder.ops.len()}
}
