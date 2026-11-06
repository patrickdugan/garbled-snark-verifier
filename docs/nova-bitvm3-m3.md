# M3: complete Pasta addition and Nova transcript byte contract

This increment targets the Pallas/Vesta -> Nova 0.76.0 -> Spartan/IPA path.
It changes only the user's fork. Existing header provers, checkpoints and fold
width k remain unchanged. No Bitcoin transactions are created.

## Complete point-addition predicate

`src/nova/curve.rs` checks the relation R=P+Q with one additional canonical
field element, the affine slope. A point consists of 256 little-endian x bits,
256 little-endian y bits, and one infinity flag. Infinity is exactly (0,0,true).
The verifier selects Pallas or Vesta; witness bits cannot choose the modulus.
Each finite point satisfies y^2=x^3+5. All three points receive canonical
encoding and membership checks. Both Pasta groups have cofactor one.

The circuit includes every branch for every input. Identity cases require
R to equal the other point and slope=0. Finite inverse pairs require R to be
infinity and slope=0. Ordinary addition constrains

    (x_Q-x_P)*slope = y_Q-y_P

Doubling constrains

    (2*y_P)*slope = 3*x_P^2

The active denominator must be nonzero. Both regular cases require finite R and

    slope^2 = x_P+x_Q+x_R
    slope*(x_P-x_R) = y_P+y_R

Membership and canonical admission make the branch tests well-defined.
A nonzero denominator fixes the unique slope; the two coordinate equations
then fix R. The zero-y doubling case enters inverse cancellation. Thus every
accepted assignment gives the complete group law, assuming the field kernels
compute their documented operations. This is an informal correctness argument.

Twelve internal field multiplications share field-tagged component templates.
The helper reproduces the tested M2 radix-4 computation and retains bit 254.
The only extra witness is the slope. Its equation is checked by the circuit.
An eventual IPA compiler must bind every intermediate point to one shared wire
representation and include all group checks in its final verdict.

## Evidence and independent checks

The dependency-free Python relation check exercised 547,778 exhaustive cases
over five small prime fields locally, including all candidate sums and slopes.
Additional full-width edge cases ran on both Pasta fields. Python establishes
the relation logic; it does not execute the Rust Boolean graph.

Rust integration tests use halo2curves =0.9.0 as an independent group oracle.
They cover identity, doubling, inverse cancellation, ordinary addition and
negative scalar multiples on both curves. Invalid on-curve results, changed
slopes, each noncanonical coordinate/slope port, noncanonical infinity and
finite (0,0) are rejected. File-backed AES garbling tests evaluate the same
fixed graph on all branches and compare output labels and ciphertext digests.
The deterministic seeds and reuse of test input-label pairs are confined to
conformance tests and provide no malicious-protocol security guarantee.

CI compiles the curve/transcript executables before recording their run metrics.
The timed invocation still includes Cargo startup/checks. Its RSS is not an
OS-enforced memory ceiling. Ciphertext files use a 64 KiB writing buffer and
upstream's 4 MiB reader. Their size excludes input labels and all protocol or
Bitcoin overhead. Gate counts and Rust outcomes must be taken from a completed
successful workflow, not inferred from the Python result.

## Exact transcript contract, host-side conformance

`nova-bitvm3/tests/transcript.rs` independently assembles the default non-EVM
transcript bytes, then compares challenges against nova-snark =0.76.0 for both
engines. This is a native byte-contract test. Keccak is not yet in the Boolean
verifier. CI retains the installed crate's keccak.rs alongside its lockfile.

    pair(M) = Keccak256(M || 0x00) || Keccak256(M || 0x01)
    state_0 = pair("NoTR" || protocol_label)
    pending = concat(absorb_label || object_repr, ...)
    dom_sep(label): append "NoDS" || label to pending
    state_next = pair(pending || "NoDS" || u64le(round) || state || squeeze_label)
    challenge = integer_le(state_next) mod scalar_modulus

After each squeeze, increment the round, retain the raw 64-byte state and clear
pending. The two curve engines reduce to different scalar moduli. Scalar
representations are canonical 32-byte little-endian. Tests compare repeated
squeezes, domain separation and ordered scalar absorption; mutation cases cover
labels and order. This does not yet establish all structured proof-object
encodings, Poseidon consistency checks, or a complete Nova transcript trace.

## Reproduce

    python3 nova-bitvm3/curve_reference.py
    cargo test --release --manifest-path nova-bitvm3/Cargo.toml --features native-reference,curve-reference --test curves --test transcript -- --nocapture --test-threads=1

## Remaining integration

The next compiler work is fixed-shape parsing of actual compressed proofs,
Boolean Keccak and challenge reduction, complete structured-object encodings,
Nova's Poseidon consistency checks, Spartan sumcheck and both IPA/MSM paths.
Keep verifier-key identity, step count, initial state and expected final state
bound to verifier-owned expectations. The curve predicate alone authorizes no
Bitcoin spend. BitVM3 setup, input consistency and the transaction graph still
require their own implementation and adversarial tests.
