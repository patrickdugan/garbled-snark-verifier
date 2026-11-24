//! The statement predicate alone (`full::statement`): the pinned equalities and the public-values
//! digest. These tests never build the full verifier.
use std::borrow::{Borrow, BorrowMut};

use garbled_snark_verifier::{
    circuit::{CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, ExecuteMode, StreamingResult},
    WireId,
};
use m13_verify::FinalStatement;
use m14_circuit::field::{Fe, P};
use m14_e2e::{full, native};
use slop_algebra::{AbstractField, PrimeField32};
use slop_symmetric::CryptographicHasher;
use sp1_primitives::SP1Field;
use sp1_recursion_executor::RecursionPublicValues;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../m13/fixtures/");

fn statement_file(name: &str) -> FinalStatement {
    serde_json::from_slice(&std::fs::read(format!("{FIXTURES}{name}")).unwrap()).unwrap()
}

struct Plain(Vec<bool>);
impl CircuitInput for Plain {
    type WireRepr = Vec<WireId>;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (0..self.0.len()).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<WireId> {
        w.clone()
    }
}
impl EncodeInput<ExecuteMode> for Plain {
    fn encode(&self, w: &Self::WireRepr, mode: &mut ExecuteMode) {
        for (id, value) in w.iter().zip(&self.0) {
            mode.feed_wire(*id, *value);
        }
    }
}

fn run_statement(values: &[u32], expect: &FinalStatement) -> bool {
    let bits = values.iter().flat_map(|value| (0..31).map(move |bit| (value >> bit) & 1 != 0)).collect();
    let r: StreamingResult<ExecuteMode, _, Vec<bool>> = CircuitBuilder::streaming_execute(Plain(bits), 1 << 22, |c, w| {
        let pv = w.chunks_exact(31).map(Fe::from_wires).collect::<Vec<_>>();
        vec![full::statement(c, &pv, expect)]
    });
    // 50 equalities with pinned constants (30 gates each) and their conjunction, then the
    // public-values digest. The count is the same for every statement and every input.
    assert_eq!(
        r.gate_count.nonfree_gate_count(),
        50 * 30 + 49 + full::ROOT_DIGEST_GATES,
        "statement predicate gate count"
    );
    r.output_value[0]
}

/// SP1's root digest of the statement fields and nonce in `values`, written to the digest slots.
fn set_root_digest(values: &mut [u32]) {
    let felts: Vec<SP1Field> = values.iter().map(|&v| SP1Field::from_canonical_u32(v)).collect();
    let digest = m13_verify::root_public_values_digest(felts.as_slice().borrow());
    let pv: &mut RecursionPublicValues<u32> = values.borrow_mut();
    pv.digest = digest.map(|x| x.as_canonical_u32());
}

fn hex_bytes(h: &str) -> Vec<u8> {
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn hex_limbs(h: &str) -> Vec<u32> {
    hex_bytes(h).chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect()
}

fn public_values(expect: &FinalStatement) -> Vec<u32> {
    let mut values = vec![0; std::mem::size_of::<RecursionPublicValues<u8>>()];
    let pv: &mut RecursionPublicValues<u32> = values.as_mut_slice().borrow_mut();
    pv.exit_code = 0;
    pv.is_complete = 1;
    pv.sp1_vk_digest.copy_from_slice(&hex_limbs(&expect.program_vk_digest));
    pv.vk_root.copy_from_slice(&hex_limbs(&expect.recursion_vk_root));
    for (dst, src) in pv.committed_value_digest.iter_mut().flatten().zip(hex_bytes(&expect.committed_values_sha256)) {
        *dst = src as u32;
    }
    pv.proof_nonce = [7, P - 1, 0, 1 << 30];
    set_root_digest(&mut values);
    values
}

/// The public values of a committed wrap proof, as the circuit reads them.
fn proof_public_values(path: &str) -> Vec<u32> {
    native::load(path).proof.public_values[..std::mem::size_of::<RecursionPublicValues<u8>>()]
        .iter()
        .map(|x| x.as_canonical_u32())
        .collect()
}

#[test]
fn every_statement_field_the_digest_and_the_nonce_are_bound() {
    let expect = statement_file("c4-statement.json");
    let values = public_values(&expect);
    assert!(run_statement(&values, &expect));

    let mut indices = (0..values.len() as u32).collect::<Vec<_>>();
    let o: &mut RecursionPublicValues<u32> = indices.as_mut_slice().borrow_mut();
    let mut checked = vec![o.exit_code, o.is_complete];
    checked.extend(o.sp1_vk_digest);
    checked.extend(o.vk_root);
    checked.extend(o.committed_value_digest.iter().flatten().copied());
    checked.extend(o.digest);
    checked.extend(o.proof_nonce);
    assert_eq!(checked.len(), 62);
    for index in checked {
        let mut altered = values.clone();
        altered[index as usize] = (altered[index as usize] + 1) % P;
        assert!(!run_statement(&altered, &expect), "public value {index} escaped the statement checks");
    }
}

#[test]
fn real_proofs_satisfy_the_statement_and_replaced_fields_do_not() {
    let c4 = proof_public_values(native::FIXTURE_V2);
    let a = proof_public_values(&format!("{FIXTURES}a-wrap-blake3-v2.bin"));
    let m16 = proof_public_values(&format!("{FIXTURES}m16-wrap-blake3-v2.bin"));
    let (e_c4, e_a, e_m16) = (statement_file("c4-statement.json"), statement_file("a-statement.json"), statement_file("m16-statement.json"));
    assert!(run_statement(&c4, &e_c4), "c4");
    assert!(run_statement(&a, &e_a), "guest A");
    assert!(run_statement(&m16, &e_m16), "M16");
    assert!(!run_statement(&c4, &e_m16));

    // What a prover who edits the public values before proving the wrap would present: the control
    // guest's proof (its digest, its nonce) showing the M16 guest's key and committed statement.
    // Every pinned equality holds; the digest does not.
    let mut forged = c4.clone();
    {
        let from: &RecursionPublicValues<u32> = m16.as_slice().borrow();
        let (key, committed) = (from.sp1_vk_digest, from.committed_value_digest);
        let pv: &mut RecursionPublicValues<u32> = forged.as_mut_slice().borrow_mut();
        pv.sp1_vk_digest = key;
        pv.committed_value_digest = committed;
    }
    assert!(!run_statement(&forged, &e_m16), "replaced statement fields accepted");
    // With the digest recomputed over the replaced fields the predicate holds: the digest is
    // the only thing in the way, and the wrap AIR is what fixes its value.
    set_root_digest(&mut forged);
    assert!(run_statement(&forged, &e_m16));
}

#[test]
fn the_poseidon2_gadget_equals_sp1s_hasher() {
    use rand::{Rng, SeedableRng};
    let hasher = sp1_primitives::poseidon2_hasher();
    let mut rng = rand_chacha::ChaChaRng::seed_from_u64(1453);
    for n in [1usize, 8, 9, 53, 53, 53] {
        let xs: Vec<u32> = (0..n).map(|_| rng.gen_range(0..P)).collect();
        let felts: Vec<SP1Field> = xs.iter().map(|&x| SP1Field::from_canonical_u32(x)).collect();
        let want: [SP1Field; 8] = hasher.hash_slice(&felts);
        let bits = xs.iter().flat_map(|x| (0..31).map(move |bit| (x >> bit) & 1 != 0)).collect();
        let r: StreamingResult<ExecuteMode, _, Vec<bool>> = CircuitBuilder::streaming_execute(Plain(bits), 1 << 22, |c, w| {
            let input = w.chunks_exact(31).map(Fe::from_wires).collect::<Vec<_>>();
            m14_circuit::poseidon2::hash(c, &input).iter().flat_map(|e| e.0.clone()).collect()
        });
        let got: Vec<u32> = r.output_value.chunks(31).map(|b| b.iter().enumerate().map(|(i, &v)| (v as u32) << i).sum()).collect();
        assert_eq!(got, want.map(|x| x.as_canonical_u32()).to_vec(), "{n} inputs");
    }
}
