//! Complete witnessed affine addition on Pallas and Vesta.
//!
//! Inputs are two points, a claimed sum and a slope. All points are checked
//! on-curve; infinity is (0,0,true). The slope is constrained in-circuit and
//! must be zero on identity/inverse branches. This is a group-law predicate,
//! not an IPA or Nova proof verifier. It uses twelve internal field products.
use super::{
    PastaField, Word, add_mod, and, canonical, double_mod, equal, mux, not, or, select_digit, xor,
};
use crate::{
    CircuitContext, WireId,
    circuit::{FALSE_WIRE, TRUE_WIRE, generate_component_key},
};

/// The verifier chooses the curve; a witness cannot select the field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PastaCurve {
    Pallas,
    Vesta,
}

impl PastaCurve {
    pub fn base_field(self) -> PastaField {
        match self {
            Self::Pallas => PastaField::PallasBase,
            Self::Vesta => PastaField::VestaBase,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AffinePoint {
    pub x: Word,
    pub y: Word,
    pub infinity: WireId,
}

fn all<C: CircuitContext>(c: &mut C, bits: &[WireId]) -> WireId {
    bits.iter().fold(TRUE_WIRE, |acc, bit| and(c, acc, *bit))
}

fn zero<C: CircuitContext>(c: &mut C, a: &Word) -> WireId {
    equal(c, a, &[FALSE_WIRE; 256])
}

// Internal operands must be canonical. The public predicate enforces this
// for external values; modular arithmetic preserves it for intermediates.
fn product<C: CircuitContext>(c: &mut C, f: PastaField, a: &Word, b: &Word) -> Word {
    let tag = [match f {
        PastaField::PallasBase => 0u8,
        PastaField::VestaBase => 1,
    }];
    let key = generate_component_key(
        "nova.pasta.curve.product.v1",
        [("field", tag.as_slice())],
        256,
        512,
    );
    let inputs: Vec<WireId> = a.iter().chain(b).copied().collect();
    let out: Vec<WireId> = c.with_named_child(
        key,
        inputs,
        |ctx, w| {
            let a: Word = w[..256].try_into().expect("fixed arity");
            let b: Word = w[256..].try_into().expect("fixed arity");
            let two = double_mod(ctx, f, &a);
            let three = add_mod(ctx, f, &two, &a);
            let mut acc = select_digit(ctx, b[254], b[255], &a, &two, &three);
            for i in (0..254).step_by(2).rev() {
                acc = double_mod(ctx, f, &acc);
                acc = double_mod(ctx, f, &acc);
                let digit = select_digit(ctx, b[i], b[i + 1], &a, &two, &three);
                acc = add_mod(ctx, f, &acc, &digit);
            }
            acc.to_vec()
        },
        256,
    );
    out.try_into().expect("fixed output arity")
}

fn difference<C: CircuitContext>(c: &mut C, f: PastaField, a: &Word, b: &Word) -> Word {
    let mut borrow = FALSE_WIRE;
    let mut raw = [FALSE_WIRE; 256];
    for i in 0..256 {
        let t = xor(c, a[i], b[i]);
        raw[i] = xor(c, t, borrow);
        let na = not(c, a[i]);
        let nt = not(c, t);
        let u = and(c, na, b[i]);
        let v = and(c, nt, borrow);
        borrow = xor(c, u, v);
    }
    // On underflow the 256-bit sum wraps once: (2^256+a-b)+p = a-b+p.
    let p = f.constant();
    let mut carry = FALSE_WIRE;
    std::array::from_fn(|i| {
        let correction = and(c, borrow, p[i]);
        let t = xor(c, raw[i], correction);
        let result = xor(c, t, carry);
        let u = and(c, raw[i], correction);
        let v = and(c, t, carry);
        carry = xor(c, u, v);
        result
    })
}

fn point_equal<C: CircuitContext>(c: &mut C, p: &AffinePoint, q: &AffinePoint) -> WireId {
    let x = equal(c, &p.x, &q.x);
    let y = equal(c, &p.y, &q.y);
    let flag_diff = xor(c, p.infinity, q.infinity);
    let flag = not(c, flag_diff);
    all(c, &[x, y, flag])
}

fn admit_point<C: CircuitContext>(c: &mut C, f: PastaField, p: &AffinePoint) -> (WireId, Word) {
    let cx = canonical(c, f, &p.x);
    let cy = canonical(c, f, &p.y);
    let x2 = product(c, f, &p.x, &p.x);
    let x3 = product(c, f, &x2, &p.x);
    let y2 = product(c, f, &p.y, &p.y);
    let mut five = [FALSE_WIRE; 256];
    five[0] = TRUE_WIRE;
    five[2] = TRUE_WIRE;
    let rhs = add_mod(c, f, &x3, &five);
    let finite = equal(c, &y2, &rhs);
    let zx = zero(c, &p.x);
    let zy = zero(c, &p.y);
    let infinity = and(c, zx, zy);
    let member = mux(c, p.infinity, finite, infinity);
    (all(c, &[cx, cy, member]), x2)
}

/// Accept exactly when P,Q,R are canonical points, R=P+Q, and the supplied
/// slope is the unique affine slope (or zero for identity/inverse branches).
/// Branches and both curve equations are enforced using Boolean wires.
/// A complete addition check includes canonical membership for all three points.
pub fn check_add<C: CircuitContext>(
    c: &mut C,
    curve: PastaCurve,
    p: &AffinePoint,
    q: &AffinePoint,
    r: &AffinePoint,
    slope: &Word,
) -> WireId {
    let f = curve.base_field();
    let (vp, x2) = admit_point(c, f, p);
    let (vq, _) = admit_point(c, f, q);
    let (vr, _) = admit_point(c, f, r);
    let vs = canonical(c, f, slope);
    let slope_zero = zero(c, slope);
    let same_x = equal(c, &p.x, &q.x);
    let same_y = equal(c, &p.y, &q.y);
    let y_sum = add_mod(c, f, &p.y, &q.y);
    let y_sum_zero = zero(c, &y_sum);
    let inverse = and(c, same_x, y_sum_zero);
    let ordinary = not(c, same_x);
    let y_zero = zero(c, &p.y);
    let y_nonzero = not(c, y_zero);
    let doubling = all(c, &[same_x, same_y, y_nonzero]);
    let regular = or(c, ordinary, doubling);

    let dx = difference(c, f, &q.x, &p.x);
    let dy = difference(c, f, &q.y, &p.y);
    let two_y = double_mod(c, f, &p.y);
    let two_x2 = double_mod(c, f, &x2);
    let three_x2 = add_mod(c, f, &two_x2, &x2);
    let den: Word = std::array::from_fn(|i| mux(c, same_x, dx[i], two_y[i]));
    let num: Word = std::array::from_fn(|i| mux(c, same_x, dy[i], three_x2[i]));
    let den_zero = zero(c, &den);
    let den_nonzero = not(c, den_zero);
    let slope_den = product(c, f, slope, &den);
    let slope_valid = equal(c, &slope_den, &num);

    let slope2 = product(c, f, slope, slope);
    let x_sum = add_mod(c, f, &p.x, &q.x);
    let x_sum_r = add_mod(c, f, &x_sum, &r.x);
    let x_valid = equal(c, &slope2, &x_sum_r);
    let x_delta = difference(c, f, &p.x, &r.x);
    let slope_delta = product(c, f, slope, &x_delta);
    let y_sum_r = add_mod(c, f, &p.y, &r.y);
    let y_valid = equal(c, &slope_delta, &y_sum_r);
    let r_finite = not(c, r.infinity);
    let regular_valid = all(
        c,
        &[
            regular,
            den_nonzero,
            slope_valid,
            x_valid,
            y_valid,
            r_finite,
        ],
    );
    let inverse_valid = all(c, &[inverse, r.infinity, slope_zero]);
    let finite_case = or(c, regular_valid, inverse_valid);
    let eq_pr = point_equal(c, p, r);
    let eq_qr = point_equal(c, q, r);
    let right_identity = and(c, eq_pr, slope_zero);
    let left_identity = and(c, eq_qr, slope_zero);
    let q_case = mux(c, q.infinity, finite_case, right_identity);
    let case = mux(c, p.infinity, q_case, left_identity);
    all(c, &[vp, vq, vr, vs, case])
}
