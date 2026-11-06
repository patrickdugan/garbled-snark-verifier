# Nova BitVM3 M2: radix-4 multiplication and fixed-prime reduction

This increment is committed to the user's fork. Its goal is to cut the Boolean
cost of Pasta field multiplication while keeping canonical admission strict.

## Construction

Both Pasta moduli have the form p = 2^254 + c and are below 2^255. For canonical
a and b, the two most significant bits of b are zero. Write b in 127 radix-4
digits d_i, each taken from two adjacent bits of the 254-bit multiplier.

Precompute A_0=0, A_1=a, A_2=2a mod p and A_3=3a mod p. Start with
x=A_{d_126}; for descending digits set x=(4x + A_{d_i}) mod p. Every step
performs two fixed-modulus doublings, a Boolean 2-bit digit selection, then a
modular addition. The first digit is selected directly. Since each intermediate
is canonical and p < 2^255, doubling fits within 256 bits and requires at
most one subtraction of p. An addition of two canonical residues also requires
at most one subtraction.

For subtraction of the fixed modulus, the borrow recurrence at bit i is:
- p_i=0: borrow' = (!x_i) AND borrow
- p_i=1: borrow' = (!x_i) OR borrow

The computed difference is x_i XOR p_i XOR borrow, and a mux selects the
reduced result if no borrow occurred. This uses one non-free borrow gate per
bit for the modulus comparison, rather than generic variable subtraction.
The circuit's branching and gate layout are witness-independent.

The external verifier checks a,b,z against the canonical modulus before
accepting the multiplication claim. Internal arithmetic presumes canonical
values; malformed inputs are rejected by the final conjunction.

## Tests

- Python reference: exhaustive correctness and wrong-output rejection for
  small fields with even and odd word widths; randomized 256-bit operands
  over both Pasta moduli, plus noncanonical operands.
- Rust: original BigUint comparisons, high radix-4 digit cases,
  additional seeded random vectors, and Execute/Garble/Evaluate label checks
  on true, false and noncanonical claims.
- CI: dedicated workflow on main changes, with gate counts, ciphertext
  bytes, native Nova proof round-trip, time/RSS log and version evidence.

Baseline M1 measured 719,875 non-free gates and 11,518,000 emitted ciphertext
bytes for one multiplication predicate, and 3,075 non-free gates for addition.
The M2 gate counts must come from a successful Rust CI run; estimates are
not treated as measurements. Check that run before declaring improvement.

## Scope and safety

These arithmetic kernels do not parse Nova transcripts, perform Spartan
sumcheck, verify IPA commitments, or authenticate a Bitcoin transaction.
The existing header prover and fold width k are unchanged. The test garbler
buffers ciphertexts in a Vec; its live-wire reservation is not a hard RSS cap.
Build and run memory measurements include compilation. Reference RNG seeds
are deterministic for conformance and are unsuitable for production garbling.

Next: optimized Pallas/Vesta group operations, full Fiat-Shamir transcript
reproduction, Spartan verification, IPA openings, and BitVM3 label/transaction
binding. Preserve a transparent proving and compression path.
