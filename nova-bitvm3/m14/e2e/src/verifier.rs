//! The final verifier as a circuit, stage by stage, mirroring sp1-hypercube 6.9.0's
//! `ShardVerifier::verify_shard` and the verifiers it calls. The shape (chips, heights, sizes) is
//! taken from the pinned proof and is a circuit constant; every proof value is an input.
use std::collections::BTreeMap;

use garbled_snark_verifier::CircuitContext;
use m12_gates::{self as g, W};
use m14_circuit::{
    ext::{self, Ext},
    field::{self as f, Fe},
    hash::{self, Transcript},
    multilinear as ml, sample, sumcheck,
};
use slop_air::{BaseAir, PairCol, VirtualPairCol};
use slop_algebra::PrimeField32;
use sp1_hypercube::{air::MachineAir, Interaction, PROOF_MAX_NUM_PVS};
use sp1_verifier::compressed::RECURSION_MAX_LOG_ROW_COUNT;

use crate::native::{self, Shard, WrapChip, F};

// ------------------------------------------------------------------ inputs and shape
/// Proof values as input wires, consumed in order.
pub struct Inputs<'a> {
    w: &'a [W],
    at: usize,
}
impl<'a> Inputs<'a> {
    pub fn new(w: &'a [W]) -> Self {
        Inputs { w, at: 0 }
    }
    fn take(&mut self, n: usize) -> &'a [W] {
        let s = &self.w[self.at..self.at + n];
        self.at += n;
        s
    }
    pub fn fe(&mut self) -> Fe {
        Fe::from_wires(self.take(f::BITS))
    }
    pub fn ext(&mut self) -> Ext {
        let w = self.take(4 * f::BITS);
        Ext(std::array::from_fn(|i| Fe::from_wires(&w[i * f::BITS..(i + 1) * f::BITS])))
    }
    pub fn digest(&mut self) -> Vec<W> {
        self.take(256).to_vec()
    }
    pub fn used(&self) -> usize {
        self.at
    }
}

/// Everything fixed by the pinned key and proof shape.
pub struct Shape {
    pub vk_bytes: Vec<u8>,
    pub shape_bytes: Vec<u8>,
    pub num_pv: usize,
    pub chips: Vec<WrapChip>,
    pub degrees: Vec<Vec<u32>>,
    pub max_log_row_count: usize,
    pub niv: usize,
    pub beta_seed_dim: usize,
    pub num_interactions: usize,
}

impl Shape {
    pub fn new(machine: &sp1_hypercube::Machine<F, m13_verify::WrapAir>, vk: &sp1_hypercube::MachineVerifyingKey<native::GC>, reference: &Shard) -> Self {
        let chips: Vec<WrapChip> = native::shard_chips(machine, reference).into_iter().collect();
        let degrees: Vec<Vec<u32>> = native::degrees(reference).into_values().collect();
        let max_arity = chips.iter().flat_map(|c| c.sends().iter().chain(c.receives().iter())).map(|i| i.values.len() + 1).max().unwrap();
        // The recursion record has no public-value interactions (`unwrap_or(1)` in SP1).
        let beta_seed_dim = max_arity.max(1).next_power_of_two().ilog2() as usize;
        let num_interactions = chips.iter().map(|c| c.sends().len() + c.receives().len()).sum::<usize>();
        let niv = num_interactions.next_power_of_two().ilog2() as usize;
        Shape {
            vk_bytes: native::vk_bytes(vk),
            shape_bytes: native::shape_bytes(reference),
            num_pv: native::num_pv(machine),
            chips,
            degrees,
            max_log_row_count: RECURSION_MAX_LOG_ROW_COUNT,
            niv,
            beta_seed_dim,
            num_interactions,
        }
    }
}

fn const_bytes(b: &[u8]) -> Vec<W> {
    b.iter().flat_map(|x| g::const_bits(*x as u128, 8)).collect()
}

fn observe_ext(t: &mut Transcript, x: &Ext) {
    sumcheck::observe_ext(t, x)
}

/// `observe_variable_length_extension_slice`: the length, then the elements.
fn observe_ext_slice_var(t: &mut Transcript, xs: &[Ext]) {
    t.observe_fe(&Fe::constant(xs.len() as u32));
    xs.iter().for_each(|x| observe_ext(t, x));
}

fn sample_ext<C: CircuitContext>(c: &mut C, t: &mut Transcript) -> Ext {
    sumcheck::sample_ext(c, t)
}

// ------------------------------------------------------------------ preamble
pub struct Preamble {
    pub public_values: Vec<Fe>,
    pub main_commitment: Vec<W>,
}

/// `vk.observe_into`, then `verify_shard` up to LogUp-GKR: public values (those past the machine's
/// count are constant zero), the main commitment, the shape.
pub fn preamble<C: CircuitContext>(_c: &mut C, t: &mut Transcript, s: &Shape, inp: &mut Inputs) -> Preamble {
    t.observe_bytes(&const_bytes(&s.vk_bytes));
    let public_values: Vec<Fe> = (0..PROOF_MAX_NUM_PVS).map(|i| if i < s.num_pv { inp.fe() } else { Fe::zero() }).collect();
    public_values.iter().for_each(|x| t.observe_fe(x));
    let main_commitment = inp.digest();
    t.observe_digest(&main_commitment);
    t.observe_bytes(&const_bytes(&s.shape_bytes));
    Preamble { public_values, main_commitment }
}

// ------------------------------------------------------------------ LogUp-GKR
pub struct LogupOut {
    pub ok: W,
    /// `logup_evaluations.point` (derived).
    pub trace_point: Vec<Ext>,
    /// Per chip (shard order): preprocessed and main trace evaluations.
    pub prep: Vec<Option<Vec<Ext>>>,
    pub main: Vec<Vec<Ext>>,
}

fn virtual_col<C: CircuitContext>(c: &mut C, v: &VirtualPairCol<F>, prep: &[Ext], main: &[Ext]) -> Ext {
    let mut r = Ext::constant([v.constant.as_canonical_u32(), 0, 0, 0]);
    for (col, w) in &v.column_weights {
        let x = match col {
            PairCol::Preprocessed(i) => &prep[*i],
            PairCol::Main(i) => &main[*i],
        };
        let t = ext::mul_const(c, x, [w.as_canonical_u32(), 0, 0, 0]);
        r = ext::add(c, &r, &t);
    }
    r
}

/// `Interaction::eval`: (multiplicity, fingerprint).
fn interaction_eval<C: CircuitContext>(c: &mut C, it: &Interaction<F>, prep: &[Ext], main: &[Ext], alpha: &Ext, betas: &[Ext]) -> (Ext, Ext) {
    let m = virtual_col(c, &it.multiplicity, prep, main);
    let b0 = ext::mul_const(c, &betas[0], [it.argument_index() as u32, 0, 0, 0]);
    let mut fp = ext::add(c, alpha, &b0);
    for (k, v) in it.values.iter().enumerate() {
        let e = virtual_col(c, v, prep, main);
        let t = ext::mul(c, &e, &betas[k + 1]);
        fp = ext::add(c, &fp, &t);
    }
    (m, fp)
}

pub fn logup<C: CircuitContext>(c: &mut C, t: &mut Transcript, s: &Shape, inp: &mut Inputs) -> LogupOut {
    let mut oks = Vec::new();
    // proof of work: observe the witness, then GKR_GRINDING_BITS sampled bits must be zero
    let witness = inp.fe();
    t.observe_fe(&witness);
    let wbits = t.sample_bytes(c, 4);
    let low = sample::bits_from_le32(&wbits, sp1_hypercube::GKR_GRINDING_BITS);
    let any = f::or_all(c, &low);
    oks.push(g::not(c, any));

    let alpha = sample_ext(c, t);
    let beta_seed: Vec<Ext> = (0..s.beta_seed_dim).map(|_| sample_ext(c, t)).collect();
    let _pv_challenge = sample_ext(c, t);
    // The recursion record has no public-value constraints: cumulative sum 0.

    let n_out = 1usize << (s.niv + 1);
    let numer: Vec<Ext> = (0..n_out).map(|_| inp.ext()).collect();
    let denom: Vec<Ext> = (0..n_out).map(|_| inp.ext()).collect();
    observe_ext_slice_var(t, &numer);
    observe_ext_slice_var(t, &denom);
    oks.push(ml::all_nonzero(c, &denom));
    let (num_sum, _) = ml::sum_fractions(c, &numer, &denom);
    // sum n/d = 0 with every d nonzero <=> the combined numerator is 0
    oks.push(ext::is_zero(c, &num_sum));

    let first_point: Vec<Ext> = (0..s.niv + 1).map(|_| sample_ext(c, t)).collect();
    let mut numerator_eval = ml::mle_eval(c, &numer, &first_point);
    let mut denominator_eval = ml::mle_eval(c, &denom, &first_point);
    let mut eval_point = first_point;

    for i in 0..s.max_log_row_count - 1 {
        let lambda = sample_ext(c, t);
        let t1 = ext::mul(c, &numerator_eval, &lambda);
        let claim = ext::add(c, &t1, &denominator_eval);
        let nvars = i + s.niv + 1;
        let polys: Vec<Vec<Ext>> = (0..nvars).map(|_| (0..4).map(|_| inp.ext()).collect()).collect();
        let (n0, n1, d0, d1) = (inp.ext(), inp.ext(), inp.ext(), inp.ext());
        let (ok, point, final_eval) = sumcheck::verify(c, t, &claim, &polys);
        oks.push(ok);
        let eq = ml::full_lagrange_eval(c, &point, &eval_point);
        let a = ext::mul(c, &n0, &d1);
        let b = ext::mul(c, &n1, &d0);
        let num_sc = ext::add(c, &a, &b);
        let den_sc = ext::mul(c, &d0, &d1);
        let x = ext::mul(c, &num_sc, &lambda);
        let y = ext::add(c, &x, &den_sc);
        let expected = ext::mul(c, &eq, &y);
        oks.push(ext::eq(c, &final_eval, &expected));
        for v in [&n0, &n1, &d0, &d1] {
            observe_ext(t, v);
        }
        eval_point = point;
        let last = sample_ext(c, t);
        eval_point.push(last.clone());
        let dn = ext::sub(c, &n1, &n0);
        let tn = ext::mul(c, &dn, &last);
        numerator_eval = ext::add(c, &n0, &tn);
        let dd = ext::sub(c, &d1, &d0);
        let td = ext::mul(c, &dd, &last);
        denominator_eval = ext::add(c, &d0, &td);
    }

    let interaction_point = eval_point[..s.niv].to_vec();
    let trace_point = eval_point[s.niv..].to_vec();
    assert_eq!(trace_point.len(), s.max_log_row_count);

    let betas = ml::partial_lagrange(c, &beta_seed);
    let mut point_extended = vec![Ext::zero()];
    point_extended.extend(trace_point.iter().cloned());
    t.observe_fe(&Fe::constant(s.chips.len() as u32));
    let (mut numerators, mut denominators) = (Vec::new(), Vec::new());
    let (mut preps, mut mains) = (Vec::new(), Vec::new());
    for (chip, degree) in s.chips.iter().zip(&s.degrees) {
        let prep: Option<Vec<Ext>> = (chip.preprocessed_width() > 0).then(|| (0..chip.preprocessed_width()).map(|_| inp.ext()).collect());
        if let Some(p) = &prep {
            observe_ext_slice_var(t, p);
        }
        let main: Vec<Ext> = (0..chip.width()).map(|_| inp.ext()).collect();
        observe_ext_slice_var(t, &main);
        let geq = ml::full_geq(c, degree, &point_extended);
        let prep_s: &[Ext] = prep.as_deref().unwrap_or(&[]);
        let zeros_p = vec![Ext::zero(); prep_s.len()];
        let zeros_m = vec![Ext::zero(); main.len()];
        for (it, is_send) in chip.sends().iter().map(|s| (s, true)).chain(chip.receives().iter().map(|r| (r, false))) {
            let (rn, rd) = interaction_eval(c, it, prep_s, &main, &alpha, &betas);
            let (pn, pd) = interaction_eval(c, it, &zeros_p, &zeros_m, &alpha, &betas);
            let pg = ext::mul(c, &pn, &geq);
            let n = ext::sub(c, &rn, &pg);
            let one_minus = ext::sub(c, &Ext::one(), &pd);
            let dg = ext::mul(c, &one_minus, &geq);
            let d = ext::add(c, &rd, &dg);
            numerators.push(if is_send { n } else { ext::neg(c, &n) });
            denominators.push(d);
        }
        preps.push(prep);
        mains.push(main);
    }
    assert_eq!(numerators.len(), s.num_interactions);
    numerators.resize(1 << s.niv, Ext::zero());
    denominators.resize(1 << s.niv, Ext::one());
    let en = ml::mle_eval(c, &numerators, &interaction_point);
    let ed = ml::mle_eval(c, &denominators, &interaction_point);
    oks.push(ext::eq(c, &numerator_eval, &en));
    oks.push(ext::eq(c, &denominator_eval, &ed));

    LogupOut { ok: f::and_all(c, &oks), trace_point, prep: preps, main: mains }
}

/// Map of chip name to index in the shape (tests).
pub fn chip_index(s: &Shape) -> BTreeMap<String, usize> {
    s.chips.iter().enumerate().map(|(i, c)| (c.name().to_string(), i)).collect()
}

pub use hash::DOMAIN_V2;
