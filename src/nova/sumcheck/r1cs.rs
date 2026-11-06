//! Fixed-matrix outer/inner Spartan algebra over the Pasta scalar fields.
//!
//! This phase binds the inner sumcheck to the R1CS matrices and to the public
//! half of Z = [W, u, X, zero padding]. Commitment openings remain necessary.
use std::collections::BTreeMap;

use super::{
    CircuitContext, PastaField, Transcript, WireId, Word, add_mod, and, canonical, chain,
    difference, product,
};
use crate::circuit::{FALSE_WIRE, TRUE_WIRE};

/// A verifier-owned sparse matrix entry with a canonical little-endian scalar.
#[derive(Clone, Debug)]
pub struct MatrixEntry {
    pub row: usize,
    pub column: usize,
    pub coefficient: [u8; 32],
}

/// Validated, immutable circuit configuration. Never construct this from a
/// proof's claimed verifier key. The caller authenticates the key first.
#[derive(Clone, Debug)]
pub struct R1csShape {
    field: PastaField,
    row_bits: usize,
    witness_bits: usize,
    public_inputs: usize,
    matrices: [Vec<MatrixEntry>; 3],
}

impl R1csShape {
    /// Rows = 2^row_bits, witness slots = 2^witness_bits, columns = 2*witness.
    /// The second column half contains u, then X, then fixed zero padding.
    /// Duplicate entries add together. Empty matrices and zero entries work.
    pub fn new(
        field: PastaField,
        row_bits: usize,
        witness_bits: usize,
        public_inputs: usize,
        matrices: [Vec<MatrixEntry>; 3],
    ) -> Result<Self, &'static str> {
        if row_bits == 0 || row_bits >= usize::BITS as usize {
            return Err("unsupported row dimension");
        }
        if witness_bits == 0 || witness_bits >= usize::BITS as usize - 1 {
            return Err("unsupported witness dimension");
        }
        let rows = 1usize << row_bits;
        let witness = 1usize << witness_bits;
        if public_inputs >= witness {
            return Err("public inputs and u exceed their half of Z");
        }
        let prime: Vec<u8> = field
            .modulus_le()
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        for matrix in &matrices {
            for entry in matrix {
                if entry.row >= rows || entry.column >= 2 * witness {
                    return Err("matrix index exceeds verifier dimensions");
                }
                if entry
                    .coefficient
                    .iter()
                    .rev()
                    .cmp(prime.iter().rev())
                    .is_ge()
                {
                    return Err("matrix coefficient is not canonical");
                }
            }
        }
        Ok(Self {
            field,
            row_bits,
            witness_bits,
            public_inputs,
            matrices,
        })
    }

    fn evaluate<C: CircuitContext>(&self, c: &mut C, rx: &[Word], ry: &[Word]) -> [Word; 3] {
        assert_eq!(rx.len(), self.row_bits);
        assert_eq!(ry.len(), self.witness_bits + 1);
        let mut rows = BTreeMap::new();
        let mut columns = BTreeMap::new();
        let mut cells = BTreeMap::new();
        std::array::from_fn(|index| {
            let mut sum = [FALSE_WIRE; 256];
            for entry in &self.matrices[index] {
                if entry.coefficient == [0u8; 32] {
                    continue;
                }
                let row = *rows
                    .entry(entry.row)
                    .or_insert_with(|| basis(c, self.field, entry.row, rx));
                let column = *columns
                    .entry(entry.column)
                    .or_insert_with(|| basis(c, self.field, entry.column, ry));
                let weight = *cells
                    .entry((entry.row, entry.column))
                    .or_insert_with(|| product(c, self.field, &row, &column));
                let coefficient = constant(&entry.coefficient);
                let term = product(c, self.field, &weight, &coefficient);
                sum = add_mod(c, self.field, &sum, &term);
            }
            sum
        })
    }
}

fn constant(bytes: &[u8; 32]) -> Word {
    std::array::from_fn(|i| {
        if (bytes[i / 8] >> (i % 8)) & 1 == 1 {
            TRUE_WIRE
        } else {
            FALSE_WIRE
        }
    })
}

// Standard multilinear basis, with the first challenge selecting the most
// significant index bit. All point coordinates are internally derived.
fn basis<C: CircuitContext>(c: &mut C, field: PastaField, index: usize, point: &[Word]) -> Word {
    let mut one = [FALSE_WIRE; 256];
    one[0] = TRUE_WIRE;
    let mut result = one;
    for (j, coordinate) in point.iter().enumerate() {
        let factor = if (index >> (point.len() - 1 - j)) & 1 == 1 {
            *coordinate
        } else {
            difference(c, field, &one, coordinate)
        };
        result = if j == 0 {
            factor
        } else {
            product(c, field, &result, &factor)
        };
    }
    result
}

/// Standard generated Nova proof shape: cubic outer and quadratic inner rounds.
/// Serialized lengths must be bounded and verified before circuit construction.
pub struct AlgebraProof {
    pub outer_rounds: Vec<Vec<Word>>,
    pub outer_claims: [Word; 4],
    pub inner_rounds: Vec<Vec<Word>>,
    pub eval_w: Word,
}

/// Computed inputs for batched W/E evaluation openings. Consumers must conjoin
/// validity() with every later acceptance predicate.
#[must_use]
pub struct AlgebraPhase {
    valid: WireId,
    rx: Vec<Word>,
    ry: Vec<Word>,
    eval_w: Word,
    eval_e: Word,
}

impl AlgebraPhase {
    pub fn validity(&self) -> WireId {
        self.valid
    }
    pub fn error_point(&self) -> &[Word] {
        &self.rx
    }
    pub fn witness_point(&self) -> &[Word] {
        &self.ry[1..]
    }
    pub fn witness_evaluation(&self) -> &Word {
        &self.eval_w
    }
    pub fn error_evaluation(&self) -> &Word {
        &self.eval_e
    }
}

/// Execute the outer and inner algebra in one transcript and with shared wires.
///
/// Preconditions: the transcript already binds the trusted verifier-key digest
/// and the exact R1CS instance (including these u and public-input wires).
/// Matrix entries are constants from that same trusted verifier key.
/// This returns an algebraic phase, not an authenticated full-proof verdict.
pub fn verify_algebra<C: CircuitContext>(
    c: &mut C,
    transcript: &mut Transcript,
    shape: &R1csShape,
    u: &Word,
    public_inputs: &[Word],
    proof: &AlgebraProof,
) -> AlgebraPhase {
    assert_eq!(transcript.scalar_field(), shape.field, "R1CS scalar field");
    assert_eq!(
        public_inputs.len(),
        shape.public_inputs,
        "R1CS public arity"
    );
    assert_eq!(
        proof.outer_rounds.len(),
        shape.row_bits,
        "outer round count"
    );
    assert_eq!(
        proof.inner_rounds.len(),
        shape.witness_bits + 1,
        "inner round count"
    );
    assert!(
        proof.outer_rounds.iter().all(|v| v.len() == 3),
        "outer polynomial shape"
    );
    assert!(
        proof.inner_rounds.iter().all(|v| v.len() == 2),
        "inner polynomial shape"
    );
    let field = shape.field;
    let mut valid = canonical(c, field, &proof.eval_w);
    for value in public_inputs {
        let admitted = canonical(c, field, value);
        valid = and(c, valid, admitted);
    }
    let outer = chain::outer_phase(
        c,
        transcript,
        &proof.outer_rounds,
        shape.row_bits,
        u,
        &proof.outer_claims,
    );
    valid = and(c, valid, outer.validity());
    let inner = chain::reduce(
        c,
        transcript,
        outer.inner_claim(),
        &proof.inner_rounds,
        shape.witness_bits + 1,
        2,
    );
    let ry = inner.challenges();
    let evaluations = shape.evaluate(c, outer.challenges(), ry);

    // Sparse public polynomial contains [u,X,0,...,0]. No padding witness.
    let zero_basis = basis(c, field, 0, &ry[1..]);
    let mut public_value = product(c, field, u, &zero_basis);
    for (index, value) in public_inputs.iter().enumerate() {
        let weight = basis(c, field, index + 1, &ry[1..]);
        let term = product(c, field, value, &weight);
        public_value = add_mod(c, field, &public_value, &term);
    }
    // Z(ry) = W(ry_tail) + ry[0]*(public(ry_tail)-W(ry_tail)).
    let delta = difference(c, field, &public_value, &proof.eval_w);
    let public_part = product(c, field, &ry[0], &delta);
    let eval_z = add_mod(c, field, &proof.eval_w, &public_part);

    // The SAME mixing wire from the outer phase weights all three matrices.
    let r = outer.mixing_challenge();
    let rc = product(c, field, r, &evaluations[2]);
    let b_plus_rc = add_mod(c, field, &evaluations[1], &rc);
    let mixed = product(c, field, r, &b_plus_rc);
    let matrix_value = add_mod(c, field, &evaluations[0], &mixed);
    let expected = product(c, field, &matrix_value, &eval_z);
    let terminal = inner.check_final(c, &expected);
    valid = and(c, valid, terminal);
    transcript.absorb_scalar_slice(c, b"w", &[proof.eval_w]);
    AlgebraPhase {
        valid,
        rx: outer.challenges().to_vec(),
        ry: inner.challenges().to_vec(),
        eval_w: proof.eval_w,
        eval_e: proof.outer_claims[3],
    }
}
