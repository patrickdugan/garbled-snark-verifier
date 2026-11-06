//! Boolean Keccak-256 and the non-EVM Nova 0.76.0 transcript byte contract.
//!
//! Bit arrays are little-endian within bytes and lanes. Labels, lengths and
//! the sequence of transcript operations are verifier-owned circuit shape.
//! Full Nova proof parsing and statement binding are outside this component.
use super::{
    CircuitContext, FALSE_WIRE, PastaField, TRUE_WIRE, WireId, Word, and, canonical, equal,
    generate_component_key, mux, not, sub_modulus, xor,
};

const RATE: usize = 1088;
const ROT: [usize; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

fn constants(bytes: &[u8]) -> Vec<WireId> {
    bytes
        .iter()
        .flat_map(|byte| {
            (0..8).map(move |bit| {
                if (byte >> bit) & 1 == 1 {
                    TRUE_WIRE
                } else {
                    FALSE_WIRE
                }
            })
        })
        .collect()
}

fn round_inner<C: CircuitContext>(c: &mut C, a: &[WireId; 1600], rc: u64) -> Vec<WireId> {
    let columns: [WireId; 320] = std::array::from_fn(|i| {
        let x = i / 64;
        let z = i % 64;
        let mut v = a[64 * x + z];
        for y in 1..5 {
            v = xor(c, v, a[64 * (x + 5 * y) + z]);
        }
        v
    });
    let d: [WireId; 320] = std::array::from_fn(|i| {
        let x = i / 64;
        let z = i % 64;
        xor(
            c,
            columns[64 * ((x + 4) % 5) + z],
            columns[64 * ((x + 1) % 5) + (z + 63) % 64],
        )
    });
    let mut b = [FALSE_WIRE; 1600];
    for y in 0..5 {
        for x in 0..5 {
            let lane = x + 5 * y;
            let destination = y + 5 * ((2 * x + 3 * y) % 5);
            for z in 0..64 {
                let source = (z + 64 - ROT[lane]) % 64;
                b[64 * destination + z] = xor(c, a[64 * lane + source], d[64 * x + source]);
            }
        }
    }
    let mut out = [FALSE_WIRE; 1600];
    for y in 0..5 {
        for x in 0..5 {
            for z in 0..64 {
                let next = not(c, b[64 * ((x + 1) % 5 + 5 * y) + z]);
                let product = and(c, next, b[64 * ((x + 2) % 5 + 5 * y) + z]);
                out[64 * (x + 5 * y) + z] = xor(c, b[64 * (x + 5 * y) + z], product);
            }
        }
    }
    for (z, bit) in out[..64].iter_mut().enumerate() {
        if (rc >> z) & 1 == 1 {
            *bit = not(c, *bit);
        }
    }
    out.to_vec()
}

fn permutation<C: CircuitContext>(c: &mut C, mut a: [WireId; 1600]) -> [WireId; 1600] {
    for rc in RC {
        let tag = rc.to_le_bytes();
        let key = generate_component_key(
            "nova.keccak1600.round.v1",
            [("rc", tag.as_slice())],
            1600,
            1600,
        );
        let out: Vec<WireId> = c.with_named_child(
            key,
            a.to_vec(),
            |ctx, wires| {
                let input: [WireId; 1600] = wires.as_slice().try_into().expect("round input arity");
                round_inner(ctx, &input, rc)
            },
            1600,
        );
        a = out.try_into().expect("round output arity");
    }
    a
}

/// Byte-aligned Keccak-256, using legacy 0x01 padding (not SHA3's 0x06).
/// The public input length defines the graph. Every input bit is hashed.
/// A full rate block receives a separate padding block.
pub fn keccak256<C: CircuitContext>(c: &mut C, input: &[WireId]) -> Word {
    assert_eq!(input.len() % 8, 0, "Keccak input must be byte-aligned");
    let mut padded = input.to_vec();
    padded.extend(constants(&[1]));
    let zeros = (RATE - padded.len() % RATE) % RATE;
    padded.resize(padded.len() + zeros, FALSE_WIRE);
    *padded.last_mut().expect("padding byte") = TRUE_WIRE;
    let mut state = [FALSE_WIRE; 1600];
    for block in padded.chunks_exact(RATE) {
        for i in 0..RATE {
            state[i] = xor(c, state[i], block[i]);
        }
        state = permutation(c, state);
    }
    state[..256].try_into().expect("digest width")
}

/// Reduce an arbitrary little-endian 512-bit string modulo a Pasta field.
/// The high 254 bits are below either modulus. Each remaining step shifts
/// in one bit and conditionally subtracts p; 2*r+b < 2*p < 2^256.
/// No quotient or reduction witness is accepted.
pub fn reduce_wide<C: CircuitContext>(c: &mut C, field: PastaField, input: &[WireId; 512]) -> Word {
    let mut remainder = [FALSE_WIRE; 256];
    remainder[..254].copy_from_slice(&input[258..]);
    let tag = [match field {
        PastaField::PallasBase => 0u8,
        PastaField::VestaBase => 1,
    }];
    let key = generate_component_key(
        "nova.pasta.reduce512.step.v1",
        [("field", tag.as_slice())],
        256,
        257,
    );
    for i in (0..258).rev() {
        let mut inputs = remainder.to_vec();
        inputs.push(input[i]);
        let out: Vec<WireId> = c.with_named_child(
            key.clone(),
            inputs,
            |ctx, wires| {
                let shifted: Word =
                    std::array::from_fn(|j| if j == 0 { wires[256] } else { wires[j - 1] });
                let (reduced, borrow) = sub_modulus(ctx, field, &shifted);
                (0..256)
                    .map(|j| mux(ctx, borrow, reduced[j], shifted[j]))
                    .collect()
            },
            256,
        );
        remainder = out.try_into().expect("reduction width");
    }
    remainder
}

fn hash_pair<C: CircuitContext>(c: &mut C, input: &[WireId]) -> [WireId; 512] {
    let mut out = [FALSE_WIRE; 512];
    for suffix in 0..2u8 {
        let mut message = input.to_vec();
        message.extend(constants(&[suffix]));
        let digest = keccak256(c, &message);
        let start = 256 * usize::from(suffix);
        out[start..start + 256].copy_from_slice(&digest);
    }
    out
}

/// Computed challenge and the accumulated admission predicate.
/// Consumers using bits() in algebra MUST conjoin validity() into acceptance.
#[must_use]
pub struct Challenge {
    value: Word,
    valid: WireId,
}
impl Challenge {
    pub fn bits(&self) -> &Word {
        &self.value
    }
    pub fn validity(&self) -> WireId {
        self.valid
    }
    /// Compare a claimed canonical encoding and include every admission check.
    pub fn check<C: CircuitContext>(&self, c: &mut C, claimed: &Word) -> WireId {
        let matches = equal(c, &self.value, claimed);
        and(c, self.valid, matches)
    }
}

/// Nova 0.76 non-EVM transcript. State and counter have no witness setters.
/// For PallasEngine use VestaBase; for VestaEngine use PallasBase.
/// This component implements byte absorption; callers must still enforce
/// structured object encodings, membership and the proof's operation schedule.
pub struct Transcript {
    field: PastaField,
    state: [WireId; 512],
    round: u64,
    pending: Vec<WireId>,
    valid: WireId,
}
impl Transcript {
    pub fn new<C: CircuitContext>(c: &mut C, field: PastaField, label: &[u8]) -> Self {
        let mut initial = constants(b"NoTR");
        initial.extend(constants(label));
        Self {
            field,
            state: hash_pair(c, &initial),
            round: 0,
            pending: Vec::new(),
            valid: TRUE_WIRE,
        }
    }
    /// The verifier-owned scalar field for arithmetic relations.
    pub fn scalar_field(&self) -> PastaField {
        self.field
    }

    /// Low-level encoded bytes. Object-specific admission is the caller's job.
    pub fn absorb_bytes(&mut self, label: &[u8], representation: &[WireId]) {
        assert_eq!(
            representation.len() % 8,
            0,
            "representation must contain bytes"
        );
        self.pending.extend(constants(label));
        self.pending.extend_from_slice(representation);
    }
    pub fn absorb_scalar<C: CircuitContext>(&mut self, c: &mut C, label: &[u8], scalar: &Word) {
        let admitted = canonical(c, self.field, scalar);
        self.valid = and(c, self.valid, admitted);
        self.absorb_bytes(label, scalar);
    }
    /// The transcript's scalar field and the commitment's curve must form
    /// the declared Pasta cycle. This is a verifier-side configuration check.
    fn require_curve(&self, curve: super::curve::PastaCurve) {
        let scalar = match curve {
            super::curve::PastaCurve::Pallas => PastaField::VestaBase,
            super::curve::PastaCurve::Vesta => PastaField::PallasBase,
        };
        assert_eq!(self.field, scalar, "transcript engine/point curve mismatch");
    }

    /// Nova affine-coordinate transcript representation: x||y (64 bytes).
    /// The identity is represented by (0,0), inferred from its coordinates.
    /// The circuit validates canonicality and curve membership before use.
    pub fn absorb_affine_encoded<C: CircuitContext>(
        &mut self,
        c: &mut C,
        label: &[u8],
        curve: super::curve::PastaCurve,
        bytes: &[WireId; 512],
    ) {
        self.require_curve(curve);
        let x: Word = bytes[..256].try_into().expect("affine x");
        let y: Word = bytes[256..].try_into().expect("affine y");
        let x_zero = equal(c, &x, &[FALSE_WIRE; 256]);
        let y_zero = equal(c, &y, &[FALSE_WIRE; 256]);
        let infinity = and(c, x_zero, y_zero);
        let point = super::curve::AffinePoint { x, y, infinity };
        let valid = super::curve::check_member(c, curve, &point);
        self.valid = and(c, self.valid, valid);
        self.absorb_bytes(label, bytes);
    }

    /// Nova Pedersen commitment transcript representation:
    /// canonical x||y||is_infinity (65 bytes). The last byte is exactly
    /// 0x00 or 0x01; nonzero reserved bits reject the entire transcript.
    /// This consumes raw witness bits and preserves their exact byte value.
    pub fn absorb_commitment_encoded<C: CircuitContext>(
        &mut self,
        c: &mut C,
        label: &[u8],
        curve: super::curve::PastaCurve,
        bytes: &[WireId; 520],
    ) {
        self.require_curve(curve);
        let point = super::curve::AffinePoint {
            x: bytes[..256].try_into().expect("commitment x"),
            y: bytes[256..512].try_into().expect("commitment y"),
            infinity: bytes[512],
        };
        let member = super::curve::check_member(c, curve, &point);
        let mut flag_valid = TRUE_WIRE;
        for bit in &bytes[513..520] {
            let is_zero = not(c, *bit);
            flag_valid = and(c, flag_valid, is_zero);
        }
        let valid = and(c, member, flag_valid);
        self.valid = and(c, self.valid, valid);
        self.absorb_bytes(label, bytes);
    }

    /// A slice of scalars is absorbed with one label, as Nova's
    /// TranscriptReprTrait implementation for &[T] does. Every scalar must
    /// be canonical. The caller fixes the slice length in the circuit shape.
    pub fn absorb_scalar_slice<C: CircuitContext>(
        &mut self,
        c: &mut C,
        label: &[u8],
        values: &[Word],
    ) {
        let mut encoded = Vec::with_capacity(values.len() * 256);
        for value in values {
            let valid = canonical(c, self.field, value);
            self.valid = and(c, self.valid, valid);
            encoded.extend_from_slice(value);
        }
        self.absorb_bytes(label, &encoded);
    }

    /// A slice of commitments uses one label and fixed 65-byte records.
    /// The record count is verifier-owned; each flag and point is validated.
    pub fn absorb_commitment_slice<C: CircuitContext>(
        &mut self,
        c: &mut C,
        label: &[u8],
        curve: super::curve::PastaCurve,
        values: &[[WireId; 520]],
    ) {
        self.require_curve(curve);
        let mut raw = Vec::with_capacity(values.len() * 520);
        for value in values {
            let point = super::curve::AffinePoint {
                x: value[..256].try_into().expect("commitment x"),
                y: value[256..512].try_into().expect("commitment y"),
                infinity: value[512],
            };
            let member = super::curve::check_member(c, curve, &point);
            let mut flag_valid = TRUE_WIRE;
            for bit in &value[513..520] {
                let b = not(c, *bit);
                flag_valid = and(c, flag_valid, b);
            }
            let valid = and(c, member, flag_valid);
            self.valid = and(c, self.valid, valid);
            raw.extend_from_slice(value);
        }
        self.absorb_bytes(label, &raw);
    }

    pub fn dom_sep(&mut self, label: &[u8]) {
        self.pending.extend(constants(b"NoDS"));
        self.pending.extend(constants(label));
    }
    fn advance<C: CircuitContext>(&mut self, c: &mut C, label: &[u8]) {
        let next = self
            .round
            .checked_add(1)
            .expect("transcript counter overflow");
        self.pending.extend(constants(b"NoDS"));
        self.pending.extend(constants(&self.round.to_le_bytes()));
        self.pending.extend_from_slice(&self.state);
        self.pending.extend(constants(label));
        self.state = hash_pair(c, &self.pending);
        self.round = next;
        self.pending.clear();
    }
    pub fn squeeze<C: CircuitContext>(&mut self, c: &mut C, label: &[u8]) -> Challenge {
        self.advance(c, label);
        Challenge {
            value: reduce_wide(c, self.field, &self.state),
            valid: self.valid,
        }
    }
    /// Nova's truncated challenge path: 2..=254 low bits, optional leading one.
    pub fn squeeze_bits<C: CircuitContext>(
        &mut self,
        c: &mut C,
        label: &[u8],
        num_bits: usize,
        start_with_one: bool,
    ) -> Challenge {
        assert!((2..=254).contains(&num_bits), "Pasta challenge bit count");
        self.advance(c, label);
        let mut value = [FALSE_WIRE; 256];
        value[..num_bits].copy_from_slice(&self.state[..num_bits]);
        if start_with_one {
            value[num_bits - 1] = TRUE_WIRE;
        }
        Challenge {
            value,
            valid: self.valid,
        }
    }
}
