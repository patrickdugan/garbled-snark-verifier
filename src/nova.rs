//! Boolean Pasta field kernels for a future Nova/Spartan/IPA verifier.
//!
//! These predicates check arithmetic claims. They do not verify Nova proofs.
//! Encodings are 256 little-endian bits and MUST be strictly below the modulus.
use crate::{
    CircuitContext, Gate, WireId,
    circuit::{FALSE_WIRE, TRUE_WIRE, generate_component_key},
};

pub type Word = [WireId; 256];

/// Pallas scalar field = Vesta base field, and conversely.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PastaField {
    PallasBase,
    VestaBase,
}

impl PastaField {
    pub fn modulus_le(self) -> [u64; 4] {
        match self {
            Self::PallasBase => [
                0x992d30ed00000001,
                0x224698fc094cf91b,
                0,
                0x4000000000000000,
            ],
            Self::VestaBase => [
                0x8c46eb2100000001,
                0x224698fc0994a8dd,
                0,
                0x4000000000000000,
            ],
        }
    }
    fn constant(self) -> Word {
        let p = self.modulus_le();
        std::array::from_fn(|i| {
            if (p[i / 64] >> (i % 64)) & 1 == 1 {
                TRUE_WIRE
            } else {
                FALSE_WIRE
            }
        })
    }
}
fn xor<C: CircuitContext>(c: &mut C, a: WireId, b: WireId) -> WireId {
    let w = c.issue_wire();
    c.add_gate(Gate::xor(a, b, w));
    w
}
fn and<C: CircuitContext>(c: &mut C, a: WireId, b: WireId) -> WireId {
    let w = c.issue_wire();
    c.add_gate(Gate::and(a, b, w));
    w
}
fn or<C: CircuitContext>(c: &mut C, a: WireId, b: WireId) -> WireId {
    let w = c.issue_wire();
    c.add_gate(Gate::or(a, b, w));
    w
}
fn not<C: CircuitContext>(c: &mut C, a: WireId) -> WireId {
    xor(c, a, TRUE_WIRE)
}
fn mux<C: CircuitContext>(c: &mut C, select_b: WireId, a: WireId, b: WireId) -> WireId {
    let d = xor(c, a, b);
    let t = and(c, select_b, d);
    xor(c, a, t)
}
/// Subtract the selected field modulus. The modulus is a compile-time constant,
/// so each borrow step uses one non-free gate instead of a generic full subtractor.
fn sub_modulus<C: CircuitContext>(c: &mut C, field: PastaField, x: &Word) -> (Word, WireId) {
    let p = field.modulus_le();
    let mut borrow = FALSE_WIRE;
    let mut out = [FALSE_WIRE; 256];
    for i in 0..256 {
        let pbit = (p[i / 64] >> (i % 64)) & 1 == 1;
        let diff = xor(c, x[i], borrow);
        out[i] = if pbit { not(c, diff) } else { diff };
        let nx = not(c, x[i]);
        borrow = if pbit {
            or(c, nx, borrow)
        } else {
            and(c, nx, borrow)
        };
    }
    (out, borrow)
}
fn add_inner<C: CircuitContext>(c: &mut C, field: PastaField, a: &Word, b: &Word) -> Word {
    let mut carry = FALSE_WIRE;
    let mut sum = [FALSE_WIRE; 256];
    for i in 0..256 {
        let t = xor(c, a[i], b[i]);
        sum[i] = xor(c, t, carry);
        let u = and(c, a[i], b[i]);
        let v = and(c, t, carry);
        carry = xor(c, u, v);
    }
    // For admitted a,b < p, a+b < 2p < 2^256; one subtraction suffices.
    let (reduced, borrow) = sub_modulus(c, field, &sum);
    std::array::from_fn(|i| mux(c, borrow, reduced[i], sum[i]))
}
/// Internal arithmetic on admitted canonical operands. Callers enforce admission.
/// A cached child keeps repeated additions out of the root metadata graph.
fn add_mod<C: CircuitContext>(c: &mut C, field: PastaField, a: &Word, b: &Word) -> Word {
    let tag = [match field {
        PastaField::PallasBase => 0u8,
        PastaField::VestaBase => 1,
    }];
    let key = generate_component_key("nova.pasta.add.v1", [("field", tag.as_slice())], 256, 512);
    let inputs: Vec<WireId> = a.iter().chain(b).copied().collect();
    let out: Vec<WireId> = c.with_named_child(
        key,
        inputs,
        |ctx, wires| {
            let a: Word = wires[..256].try_into().expect("fixed input arity");
            let b: Word = wires[256..].try_into().expect("fixed input arity");
            add_inner(ctx, field, &a, &b).to_vec()
        },
        256,
    );
    out.try_into().expect("fixed output arity")
}
fn equal<C: CircuitContext>(c: &mut C, a: &Word, b: &Word) -> WireId {
    let mut ok = TRUE_WIRE;
    for i in 0..256 {
        let d = xor(c, a[i], b[i]);
        let same = not(c, d);
        ok = and(c, ok, same);
    }
    ok
}
pub fn canonical<C: CircuitContext>(c: &mut C, field: PastaField, x: &Word) -> WireId {
    sub_modulus(c, field, x).1
}
fn admitted<C: CircuitContext>(
    c: &mut C,
    field: PastaField,
    a: &Word,
    b: &Word,
    z: &Word,
) -> WireId {
    let x = canonical(c, field, a);
    let y = canonical(c, field, b);
    let z = canonical(c, field, z);
    let xy = and(c, x, y);
    and(c, xy, z)
}
/// True iff a,b,z have canonical encodings and z = a+b mod p.
pub fn check_add<C: CircuitContext>(
    c: &mut C,
    field: PastaField,
    a: &Word,
    b: &Word,
    z: &Word,
) -> WireId {
    let valid = admitted(c, field, a, b, z);
    let sum = add_mod(c, field, a, b);
    let eq = equal(c, &sum, z);
    and(c, valid, eq)
}
/// Modular doubling of a canonical operand, specialized to a fixed modulus.
/// For 0 <= a < p < 2^255, 2*a fits in 256 bits and needs at most one
/// conditional subtraction. Child caching bounds circuit metadata growth.
fn double_mod<C: CircuitContext>(c: &mut C, field: PastaField, a: &Word) -> Word {
    let tag = [match field {
        PastaField::PallasBase => 0u8,
        PastaField::VestaBase => 1,
    }];
    let key = generate_component_key(
        "nova.pasta.double.v1",
        [("field", tag.as_slice())],
        256,
        256,
    );
    let out: Vec<WireId> = c.with_named_child(
        key,
        a.to_vec(),
        |ctx, wires| {
            let x: Word = wires.as_slice().try_into().expect("fixed input arity");
            let shifted: Word = std::array::from_fn(|i| if i == 0 { FALSE_WIRE } else { x[i - 1] });
            let (reduced, borrow) = sub_modulus(ctx, field, &shifted);
            (0..256)
                .map(|i| mux(ctx, borrow, reduced[i], shifted[i]))
                .collect()
        },
        256,
    );
    out.try_into().expect("fixed output arity")
}

/// Fixed topology 2-bit digit selection: 00=0, 01=a, 10=2a, 11=3a.
fn select_digit<C: CircuitContext>(
    c: &mut C,
    bit0: WireId,
    bit1: WireId,
    a: &Word,
    two: &Word,
    three: &Word,
) -> Word {
    let key = generate_component_key(
        "nova.pasta.radix4.select.v1",
        [] as [(&str, &[u8]); 0],
        256,
        770,
    );
    let inputs: Vec<WireId> = a
        .iter()
        .chain(two)
        .chain(three)
        .copied()
        .chain([bit0, bit1])
        .collect();
    let out: Vec<WireId> = c.with_named_child(
        key,
        inputs,
        |ctx, wires| {
            (0..256)
                .map(|i| {
                    let low = and(ctx, wires[768], wires[i]);
                    let high = mux(ctx, wires[768], wires[256 + i], wires[512 + i]);
                    mux(ctx, wires[769], low, high)
                })
                .collect()
        },
        256,
    );
    out.try_into().expect("fixed output arity")
}

/// True iff canonical a,b,z satisfy z = a*b mod p.
///
/// Radix-4 Horner: precompute {0,a,2a,3a}, then process two multiplier bits
/// per round. The top two bits of a canonical Pasta value are zero, so
/// digits cover bits 0..253. Every digit and round has identical topology.
pub fn check_mul<C: CircuitContext>(
    c: &mut C,
    field: PastaField,
    a: &Word,
    b: &Word,
    z: &Word,
) -> WireId {
    let valid = admitted(c, field, a, b, z);
    let two = double_mod(c, field, a);
    let three = add_mod(c, field, &two, a);
    let mut acc = select_digit(c, b[252], b[253], a, &two, &three);
    for i in (0..252).step_by(2).rev() {
        acc = double_mod(c, field, &acc);
        acc = double_mod(c, field, &acc);
        let digit = select_digit(c, b[i], b[i + 1], a, &two, &three);
        acc = add_mod(c, field, &acc, &digit);
    }
    let eq = equal(c, &acc, z);
    and(c, valid, eq)
}
