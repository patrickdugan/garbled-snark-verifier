//! A fixed-degree Spartan sumcheck round with an internally derived challenge.
//! This is a round relation; full Nova verification requires final polynomial
//! evaluation checks, Spartan matrices, commitment openings and more.
use super::{
    CircuitContext, PastaField, WireId, Word, add_mod, and, canonical,
    curve::{difference, product},
    double_mod, equal,
    transcript::Transcript,
};

pub mod chain;
pub mod r1cs;

/// compressed = [a0,a2] (quadratic) or [a0,a2,a3] (cubic).
/// The verifier owns the number of coefficients, domain and challenge schedule.
/// The caller must conjoin this returned gate into final proof acceptance.
pub fn check_round<C: CircuitContext>(
    c: &mut C,
    transcript: &mut Transcript,
    claim: &Word,
    compressed: &[Word],
    expected_next: &Word,
) -> WireId {
    assert!(
        compressed.len() == 2 || compressed.len() == 3,
        "Spartan round must have degree 2 or 3"
    );
    let field: PastaField = transcript.scalar_field();
    let old_ok = canonical(c, field, claim);
    let next_ok = canonical(c, field, expected_next);
    // Matches native UniPoly::to_transcript_bytes, which omits a1.
    transcript.absorb_scalar_slice(c, b"p", compressed);
    let challenge = transcript.squeeze(c, b"c");
    let r = challenge.bits();

    // Since P(0)+P(1)=claim, a1=claim-2*a0-a2-(a3).
    let twice_constant = double_mod(c, field, &compressed[0]);
    let mut linear = difference(c, field, claim, &twice_constant);
    linear = difference(c, field, &linear, &compressed[1]);
    if compressed.len() == 3 {
        linear = difference(c, field, &linear, &compressed[2]);
    }

    let tail = if compressed.len() == 3 {
        let cubic = product(c, field, r, &compressed[2]);
        add_mod(c, field, &compressed[1], &cubic)
    } else {
        compressed[1]
    };
    let quadratic = product(c, field, r, &tail);
    let inner = add_mod(c, field, &linear, &quadratic);
    let higher = product(c, field, r, &inner);
    let next = add_mod(c, field, &compressed[0], &higher);
    let match_next = equal(c, &next, expected_next);
    let inputs_ok = and(c, old_ok, next_ok);
    let transcript_ok = and(c, inputs_ok, challenge.validity());
    and(c, transcript_ok, match_next)
}
