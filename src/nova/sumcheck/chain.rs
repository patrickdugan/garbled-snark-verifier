//! Multi-round Spartan reduction and the outer-to-inner algebraic transition.
//!
//! The caller owns the shape and must bind the supplied transcript to its
//! verifier key and R1CS instance. Commitment openings and the remaining Nova
//! equations are separate requirements. Intermediate claims are computed wires.
use super::{
    CircuitContext, PastaField, Transcript, WireId, Word, add_mod, and, canonical, difference,
    double_mod, equal, product,
};
use crate::circuit::{FALSE_WIRE, TRUE_WIRE};

/// A computed sumcheck reduction. All acceptance paths must include validity.
#[must_use]
pub struct Reduction {
    value: Word,
    challenges: Vec<Word>,
    valid: WireId,
}

impl Reduction {
    pub fn value(&self) -> &Word {
        &self.value
    }

    pub fn challenges(&self) -> &[Word] {
        &self.challenges
    }

    pub fn validity(&self) -> WireId {
        self.valid
    }

    /// Compare the final claim and carry every earlier admission check.
    pub fn check_final<C: CircuitContext>(&self, c: &mut C, expected: &Word) -> WireId {
        let matches = equal(c, &self.value, expected);
        and(c, self.valid, matches)
    }
}

/// Reduce a nonempty Nova sumcheck using one shared transcript.
///
/// expected_rounds and degree_bound are verifier-owned, as are the lengths
/// of the round vectors. The serialized-proof decoder must enforce these
/// shapes before constructing a circuit. A compressed polynomial of degree d
/// contains d coefficients: a0,a2,...,ad. Degrees 1 through the bound work.
/// Zero-round reductions are intentionally outside this interface.
pub fn reduce<C: CircuitContext>(
    c: &mut C,
    transcript: &mut Transcript,
    initial: &Word,
    rounds: &[Vec<Word>],
    expected_rounds: usize,
    degree_bound: usize,
) -> Reduction {
    assert!(expected_rounds > 0, "sumcheck requires a nonempty shape");
    assert!((2..=3).contains(&degree_bound), "Spartan degree bound");
    assert_eq!(rounds.len(), expected_rounds, "sumcheck round count");
    for coefficients in rounds {
        assert!(
            !coefficients.is_empty() && coefficients.len() <= degree_bound,
            "compressed polynomial degree exceeds verifier shape"
        );
    }

    let field = transcript.scalar_field();
    let mut valid = canonical(c, field, initial);
    let mut value = *initial;
    let mut challenges = Vec::with_capacity(expected_rounds);
    for coefficients in rounds {
        transcript.absorb_scalar_slice(c, b"p", coefficients);
        let challenge = transcript.squeeze(c, b"c");
        valid = and(c, valid, challenge.validity());
        let r = *challenge.bits();
        challenges.push(r);

        let twice_constant = double_mod(c, field, &coefficients[0]);
        let mut linear = difference(c, field, &value, &twice_constant);
        for coefficient in &coefficients[1..] {
            linear = difference(c, field, &linear, coefficient);
        }
        let mut full = Vec::with_capacity(coefficients.len() + 1);
        full.push(coefficients[0]);
        full.push(linear);
        full.extend_from_slice(&coefficients[1..]);
        let mut next = *full.last().expect("nonempty polynomial");
        for coefficient in full[..full.len() - 1].iter().rev() {
            let term = product(c, field, &next, &r);
            next = add_mod(c, field, &term, coefficient);
        }
        value = next;
    }
    Reduction {
        value,
        challenges,
        valid,
    }
}

// The caller supplies internally computed canonical challenge wires.
// eq(tau,r) = product_i (1 - tau_i - r_i + 2*tau_i*r_i).
fn equality_polynomial<C: CircuitContext>(
    c: &mut C,
    field: PastaField,
    tau: &[Word],
    point: &[Word],
) -> Word {
    assert_eq!(tau.len(), point.len());
    let mut one = [FALSE_WIRE; 256];
    one[0] = TRUE_WIRE;
    let mut result = one;
    for (a, b) in tau.iter().zip(point) {
        let ab = product(c, field, a, b);
        let twice_ab = double_mod(c, field, &ab);
        let positive = add_mod(c, field, &one, &twice_ab);
        let sum = add_mod(c, field, a, b);
        let factor = difference(c, field, &positive, &sum);
        result = product(c, field, &result, &factor);
    }
    result
}

/// Checked outer phase and computed inputs for the next inner sumcheck.
/// These values carry no claim about the eventual IPA opening checks.
#[must_use]
pub struct OuterPhase {
    reduction: Reduction,
    mixing: Word,
    inner_claim: Word,
    valid: WireId,
}

impl OuterPhase {
    pub fn challenges(&self) -> &[Word] {
        self.reduction.challenges()
    }

    pub fn inner_claim(&self) -> &Word {
        &self.inner_claim
    }

    pub fn mixing_challenge(&self) -> &Word {
        &self.mixing
    }

    pub fn validity(&self) -> WireId {
        self.valid
    }

    /// Test/export boundary with full accumulated acceptance.
    pub fn check_transition<C: CircuitContext>(
        &self,
        c: &mut C,
        inner_claim: &Word,
        mixing: &Word,
    ) -> WireId {
        let claim_ok = equal(c, &self.inner_claim, inner_claim);
        let mixing_ok = equal(c, &self.mixing, mixing);
        let outputs_ok = and(c, claim_ok, mixing_ok);
        and(c, self.valid, outputs_ok)
    }
}

/// Nova 0.76 outer sumcheck plus its terminal equality and inner transition.
///
/// Derives tau under label "t", reduces the cubic proof from ZERO, checks
/// final = eq(tau,r_x)*(Az*Bz-u*Cz-eval_E), absorbs the four claims under
/// "claims_outer", and derives mixing challenge "r". The resulting inner
/// claim is Az+r*Bz+r^2*Cz. All proof scalars and u are admitted canonically.
///
/// Preconditions: transcript already binds the trusted verifier key and U;
/// u is the SAME wire vector as U.u. The four evaluations must later be
/// linked to the R1CS/IPA equations. This is only the outer algebraic phase.
pub fn outer_phase<C: CircuitContext>(
    c: &mut C,
    transcript: &mut Transcript,
    rounds: &[Vec<Word>],
    expected_rounds: usize,
    u: &Word,
    claims: &[Word; 4],
) -> OuterPhase {
    let field = transcript.scalar_field();
    let mut valid = canonical(c, field, u);
    for value in claims {
        let admitted = canonical(c, field, value);
        valid = and(c, valid, admitted);
    }
    let mut tau = Vec::with_capacity(expected_rounds);
    for _ in 0..expected_rounds {
        let challenge = transcript.squeeze(c, b"t");
        valid = and(c, valid, challenge.validity());
        tau.push(*challenge.bits());
    }
    let reduction = reduce(
        c,
        transcript,
        &[FALSE_WIRE; 256],
        rounds,
        expected_rounds,
        3,
    );
    let eq_tau = equality_polynomial(c, field, &tau, reduction.challenges());
    let ab = product(c, field, &claims[0], &claims[1]);
    let uc = product(c, field, u, &claims[2]);
    let residual = difference(c, field, &ab, &uc);
    let residual = difference(c, field, &residual, &claims[3]);
    let expected = product(c, field, &eq_tau, &residual);
    let terminal_ok = reduction.check_final(c, &expected);
    valid = and(c, valid, terminal_ok);

    transcript.absorb_scalar_slice(c, b"claims_outer", claims);
    let challenge = transcript.squeeze(c, b"r");
    valid = and(c, valid, challenge.validity());
    let mixing = *challenge.bits();
    let rc = product(c, field, &mixing, &claims[2]);
    let b_plus_rc = add_mod(c, field, &claims[1], &rc);
    let mixed = product(c, field, &mixing, &b_plus_rc);
    let inner_claim = add_mod(c, field, &claims[0], &mixed);
    OuterPhase {
        reduction,
        mixing,
        inner_claim,
        valid,
    }
}
