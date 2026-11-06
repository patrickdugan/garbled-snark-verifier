//! Scalar reduction of the W/E opening claims in Nova 0.76 Spartan.
//!
//! Supports unequal polynomial sizes. All challenges and running claims are
//! computed inside the Boolean circuit. The result is a pending opening:
//! its commitment combination and IPA verification are still required.
use super::{
    CircuitContext, PastaField, Transcript, WireId, Word, add_mod, and, canonical, chain,
    difference, double_mod, equal, product, r1cs::AlgebraPhase,
};
use crate::circuit::{FALSE_WIRE, TRUE_WIRE};

/// A point and evaluation from the preceding algebraic phase. Its length is
/// verifier-owned and determines the number of variables of the polynomial.
#[derive(Clone, Copy)]
pub struct EvaluationClaim<'a> {
    pub point: &'a [Word],
    pub value: &'a Word,
}

/// Standard generated Nova batch proof: quadratic compressed polynomials,
/// followed by the W/E evaluations at the appropriate suffixes of the new point.
pub struct BatchProof {
    pub rounds: Vec<Vec<Word>>,
    pub evaluations: [Word; 2],
}

/// The scalar side of one opening, with all preceding acceptance accumulated.
/// The commitment that must eventually be opened is C_W + gamma*C_E, using
/// the original authenticated commitments. This object does not check it.
#[must_use]
pub struct PendingOpening {
    valid: WireId,
    point: Vec<Word>,
    evaluation: Word,
    gamma: Word,
}

impl PendingOpening {
    pub fn validity(&self) -> WireId {
        self.valid
    }

    pub fn point(&self) -> &[Word] {
        &self.point
    }

    pub fn evaluation(&self) -> &Word {
        &self.evaluation
    }

    pub fn commitment_challenge(&self) -> &Word {
        &self.gamma
    }

    /// Test/export boundary. Full acceptance still requires commitment and IPA
    /// checks against these exact computed wires and the trusted verifier key.
    pub fn check_outputs<C: CircuitContext>(
        &self,
        c: &mut C,
        evaluation: &Word,
        gamma: &Word,
    ) -> WireId {
        let evaluation_ok = equal(c, &self.evaluation, evaluation);
        let gamma_ok = equal(c, &self.gamma, gamma);
        let outputs_ok = and(c, evaluation_ok, gamma_ok);
        and(c, self.valid, outputs_ok)
    }
}

fn one() -> Word {
    let mut value = [FALSE_WIRE; 256];
    value[0] = TRUE_WIRE;
    value
}

fn equality<C: CircuitContext>(
    c: &mut C,
    field: PastaField,
    left: &[Word],
    right: &[Word],
) -> Word {
    assert_eq!(left.len(), right.len(), "equality polynomial dimension");
    let mut value = one();
    for (i, (a, b)) in left.iter().zip(right).enumerate() {
        let ab = product(c, field, a, b);
        let twice_ab = double_mod(c, field, &ab);
        let positive = add_mod(c, field, &one(), &twice_ab);
        let sum = add_mod(c, field, a, b);
        let factor = difference(c, field, &positive, &sum);
        value = if i == 0 {
            factor
        } else {
            product(c, field, &value, &factor)
        };
    }
    value
}

/// Primitive for exactly two claims, in witness/error order.
///
/// Caller requirements: the transcript already binds the original instances;
/// claims reuse their exact wires; prior_valid includes every earlier check.
/// Use from_algebra() when continuing the checked R1CS phase. No new point,
/// random challenge or intermediate running claim is accepted as a witness.
/// The proof decoder must enforce the verifier-owned sizes before this call.
pub fn verify_pair<C: CircuitContext>(
    c: &mut C,
    transcript: &mut Transcript,
    claims: [EvaluationClaim<'_>; 2],
    prior_valid: WireId,
    proof: &BatchProof,
) -> PendingOpening {
    let sizes = [claims[0].point.len(), claims[1].point.len()];
    let rounds = sizes[0].max(sizes[1]);
    assert!(rounds > 0, "batch requires at least one variable");
    assert_eq!(proof.rounds.len(), rounds, "batch sumcheck round count");
    assert!(
        proof.rounds.iter().all(|v| v.len() == 2),
        "batch quadratic polynomial shape"
    );

    let field = transcript.scalar_field();
    let mut valid = prior_valid;
    for claim in &claims {
        for value in claim.point.iter().chain(std::iter::once(claim.value)) {
            let admitted = canonical(c, field, value);
            valid = and(c, valid, admitted);
        }
    }
    for value in &proof.evaluations {
        let admitted = canonical(c, field, value);
        valid = and(c, valid, admitted);
    }

    let rho = transcript.squeeze(c, b"r");
    valid = and(c, valid, rho.validity());
    let weights = [one(), *rho.bits()];
    // Before a smaller polynomial starts, its table is replicated along the
    // missing leading variables. This gives 2^(rounds-sizes[i])*claim_i.
    let mut initial = [FALSE_WIRE; 256];
    for i in 0..2 {
        let mut scaled = *claims[i].value;
        for _ in sizes[i]..rounds {
            scaled = double_mod(c, field, &scaled);
        }
        let term = if i == 0 {
            scaled
        } else {
            product(c, field, &weights[i], &scaled)
        };
        initial = add_mod(c, field, &initial, &term);
    }
    let reduction = chain::reduce(c, transcript, &initial, &proof.rounds, rounds, 2);
    let point = reduction.challenges();
    let mut expected = [FALSE_WIRE; 256];
    for i in 0..2 {
        let suffix = &point[rounds - sizes[i]..];
        let eq = equality(c, field, suffix, claims[i].point);
        let evaluated = product(c, field, &eq, &proof.evaluations[i]);
        let term = if i == 0 {
            evaluated
        } else {
            product(c, field, &weights[i], &evaluated)
        };
        expected = add_mod(c, field, &expected, &term);
    }
    let terminal_ok = reduction.check_final(c, &expected);
    valid = and(c, valid, terminal_ok);

    transcript.absorb_scalar_slice(c, b"l", &proof.evaluations);
    let challenge = transcript.squeeze(c, b"c");
    valid = and(c, valid, challenge.validity());
    let gamma = *challenge.bits();
    // The commitment combination zero-pads smaller tables. Its evaluation
    // therefore includes L0(point_prefix), unlike the sumcheck terminal claim.
    let mut joint = [FALSE_WIRE; 256];
    for i in 0..2 {
        let mut scaled = proof.evaluations[i];
        for coordinate in &point[..rounds - sizes[i]] {
            let factor = difference(c, field, &one(), coordinate);
            scaled = product(c, field, &scaled, &factor);
        }
        let term = if i == 0 {
            scaled
        } else {
            product(c, field, &gamma, &scaled)
        };
        joint = add_mod(c, field, &joint, &term);
    }
    PendingOpening {
        valid,
        point: point.to_vec(),
        evaluation: joint,
        gamma,
    }
}

/// Continue the preceding fixed-matrix phase using its exact W/E claim wires.
/// Its failure flag is inseparable from the returned pending opening.
pub fn from_algebra<C: CircuitContext>(
    c: &mut C,
    transcript: &mut Transcript,
    algebra: &AlgebraPhase,
    proof: &BatchProof,
) -> PendingOpening {
    verify_pair(
        c,
        transcript,
        [
            EvaluationClaim {
                point: algebra.witness_point(),
                value: algebra.witness_evaluation(),
            },
            EvaluationClaim {
                point: algebra.error_point(),
                value: algebra.error_evaluation(),
            },
        ],
        algebra.validity(),
        proof,
    )
}
