//! Function form against relation form on the all-gate fixture: the same circuit read as a computation
//! must compute the witness the relation accepts, and must reject exactly when the relation rejects the
//! assignment it computed.
use stwo_bitvm3_core::P;
use stwo_bitvm3_lowering::{
    fixture::function_fixture,
    testing::{evaluate, CompiledCheck},
    Constraint as G, Error, Function, Kind, Limits, Program, Value,
};

fn function() -> (Function, Vec<Value>) {
    let (n, gates, constants, values) = function_fixture();
    (Function::new(n, gates, constants, Limits::default()).unwrap(), values)
}
/// The relation over the same gates (markers included), without the `Output` gate, whose pin belongs to a
/// statement and not to the circuit.
fn relation() -> CompiledCheck {
    let (n, gates, constants, _) = function_fixture();
    let gates = gates.into_iter().filter(|g| !matches!(g, G::Output { .. })).collect();
    CompiledCheck::compile(&Program::new(n, gates, constants, Limits::default()).unwrap(), 12_000_000)
}

#[test]
fn inputs_are_the_typed_guesses_and_nothing_else() {
    let (f, _) = function();
    let kinds: Vec<(usize, Kind)> = f.inputs().to_vec();
    let mut expected: Vec<(usize, Kind)> = [3, 4, 9, 10, 11, 12, 23].iter().map(|v| (*v, Kind::Qm31)).collect();
    expected.push((14, Kind::M31));
    expected.push((24, Kind::U16));
    expected.sort_by_key(|(var, _)| *var);
    assert_eq!(kinds, expected);
    assert_eq!(f.input_bits(), 7 * 124 + 31 + 16);
    assert_eq!(f.outputs(), &[23]);
    // 11 original gates minus the Output gate, plus the one gate that uses the 16-bit guess.
    assert_eq!(f.steps().len(), 11);
    assert!(f.steps().iter().all(|s| !matches!(s.gate, G::Output { .. })));
    println!("S6 function fixture: {} of {} variables are inputs, {} input bits against {} in relation form",
        f.inputs().len(), f.n_vars(), f.input_bits(), f.n_vars() * 128);
}

#[test]
fn computes_the_witness_the_relation_accepts() {
    let (f, values) = function();
    let (ok, computed) = evaluate(&f, &f.encode(&values).unwrap());
    assert!(ok);
    assert_eq!(computed, values);
    assert!(relation().accepts(&computed));
}

#[test]
fn verdict_equals_the_relation_on_the_computed_assignment_for_every_input_bit_flip() {
    let (f, values) = function();
    let relation = relation();
    let honest = f.encode(&values).unwrap();
    let (mut accepted, mut rejected) = (0, 0);
    for bit in 0..honest.len() {
        let mut input = honest.clone();
        input[bit] = !input[bit];
        let (ok, computed) = evaluate(&f, &input);
        assert_eq!(ok, relation.accepts(&computed), "input bit {bit}");
        if ok { accepted += 1 } else { rejected += 1 }
    }
    // Both verdicts must occur, or the comparison proves nothing: variable 4 only feeds unchecked
    // outputs when its change keeps the multiset and product checks intact, and most flips break a check.
    assert!(rejected > 0);
    println!("S6 function fixture: {} single-bit input flips, {rejected} rejected, {accepted} accepted, all equal to the relation", honest.len());
}

#[test]
fn noncanonical_input_limbs_are_rejected() {
    let (f, values) = function();
    let honest = f.encode(&values).unwrap();
    for (i, (_, kind)) in f.inputs().iter().enumerate() {
        let limbs = match kind { Kind::U16 => 0, Kind::M31 => 1, Kind::Qm31 => 4 };
        for limb in 0..limbs {
            let mut input = honest.clone();
            let start = f.offset(i) + 31 * limb;
            for bit in &mut input[start..start + 31] { *bit = true; } // the limb is P
            assert!(!evaluate(&f, &input).0, "input {i} limb {limb} = P accepted");
        }
    }
    assert_eq!(P, 0x7fff_ffff);
}

#[test]
fn gate_order_does_not_matter() {
    let (n, mut gates, constants, values) = function_fixture();
    let reference = Function::new(n, gates.clone(), constants.clone(), Limits::default()).unwrap();
    gates.reverse();
    let reversed = Function::new(n, gates, constants, Limits::default()).unwrap();
    assert_eq!(reversed.inputs(), reference.inputs());
    let input = reference.encode(&values).unwrap();
    assert_eq!(evaluate(&reversed, &input), evaluate(&reference, &input));
}

#[test]
fn free_or_doubly_typed_variables_are_refused() {
    let (n, gates, constants, _) = function_fixture();
    // Without its marker, variable 9 is neither constant, guessed nor computed.
    let untyped: Vec<G> = gates.iter().filter(|g| !matches!(g, G::Add { a: 9, b: 0, out: 9 })).cloned().collect();
    assert_eq!(Function::new(n, untyped, constants.clone(), Limits::default()).unwrap_err(), Error::Undetermined(9));
    let mut twice = gates.clone();
    twice.push(G::PointwiseMul { a: 9, b: 1, out: 9 });
    assert_eq!(Function::new(n, twice, constants.clone(), Limits::default()).unwrap_err(), Error::InvalidShape);
    // A gate that could only define a variable from itself leaves it undetermined.
    let mut cyclic = gates;
    cyclic.push(G::Add { a: 26, b: 3, out: 26 });
    assert_eq!(Function::new(n + 1, cyclic, constants, Limits::default()).unwrap_err(), Error::Undetermined(26));
}

#[test]
fn permutation_outputs_are_computed_in_ascending_order_or_checked_when_given() {
    let anchors = vec![(0, [0; 4]), (1, [1, 0, 0, 0]), (2, [0, 0, 1, 0])];
    // Three guessed inputs permuted into three outputs nobody else defines: the outputs are computed.
    let mut gates: Vec<G> = (3..6).map(|v| G::Add { a: v, b: 0, out: v }).collect();
    gates.push(G::Permutation { inputs: vec![3, 4, 5], outputs: vec![6, 7, 8] });
    let f = Function::new(9, gates.clone(), anchors.clone(), Limits::default()).unwrap();
    assert_eq!(f.inputs().len(), 3);
    let values = |a: Value, b: Value, c: Value| {
        let mut v = vec![[0; 4], [1, 0, 0, 0], [0, 0, 1, 0], a, b, c];
        v.extend([[0; 4]; 3]);
        v
    };
    // value + key * u with distinct keys, as the Stwo verifier builds them; order by key.
    let (x, y, z) = ([7, 0, 3, 0], [9, 0, 1, 0], [5, 0, 2, 0]);
    let (ok, computed) = evaluate(&f, &f.encode(&values(x, y, z)).unwrap());
    assert!(ok);
    assert_eq!(&computed[6..9], &[y, z, x]);
    // The fourth limb outranks the third, the first breaks ties last.
    let (ok, computed) = evaluate(&f, &f.encode(&values([1, 0, 0, 1], [P - 1, 0, 5, 0], [0, 0, 5, 0])).unwrap());
    assert!(ok);
    assert_eq!(&computed[6..9], &[[0, 0, 5, 0], [P - 1, 0, 5, 0], [1, 0, 0, 1]]);

    // The same gate with guessed outputs is a multiset check: any order passes, a changed element fails.
    gates.extend((6..9).map(|v| G::Add { a: v, b: 0, out: v }));
    let f = Function::new(9, gates.clone(), anchors.clone(), Limits::default()).unwrap();
    assert_eq!(f.inputs().len(), 6);
    let mut v = values(x, y, z);
    v[6] = z; v[7] = x; v[8] = y;
    assert!(evaluate(&f, &f.encode(&v).unwrap()).0);
    v[8] = x;
    assert!(!evaluate(&f, &f.encode(&v).unwrap()).0);

    // Outputs that are partly given and partly free have no meaning here.
    let mut mixed: Vec<G> = (3..7).map(|v| G::Add { a: v, b: 0, out: v }).collect();
    mixed.push(G::Permutation { inputs: vec![3, 4, 5], outputs: vec![6, 7, 8] });
    assert_eq!(Function::new(9, mixed, anchors, Limits::default()).unwrap_err(), Error::InvalidShape);
}
