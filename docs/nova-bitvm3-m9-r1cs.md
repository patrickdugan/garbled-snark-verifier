# M9: fixed-matrix inner R1CS algebra

`src/nova/sumcheck/r1cs.rs` connects the outer phase to the inner sumcheck in
one transcript. Every intermediate claim and challenge is a computed wire.
The verifier supplies immutable sparse A/B/C matrices with canonical constants.
Matrix dimensions, public arity and every entry index are validated before
constructing gates. Coefficients and indices have no proof-witness ports.

For row challenges rx and column challenges ry, the circuit evaluates each
matrix's multilinear extension using MSB-first index weights. It caches only
occupied row/column/cell weights, without allocating the full dense matrix.
Duplicate sparse entries add together. Empty matrices and zero entries work.

The public half of the assignment has the exact shape [u,X,0,...,0]. Its
multilinear evaluation is computed from the same u/public wires supplied to
the phase. No padding witnesses exist. The witness half contributes eval_W:

  eval_Z = (1-ry[0])*eval_W + ry[0]*public_eval(ry[1..])

The final inner sumcheck claim is required to equal

  (A(rx,ry) + r*B(rx,ry) + r^2*C(rx,ry)) * eval_Z.

Here r is the mixing wire produced by the outer phase. The phase then absorbs
[eval_W] once under label `w`, preserving Nova 0.76.0's continuation schedule.
All canonicality checks and both terminal equations enter `validity()`.
The returned W/E points and evaluations are ready for the next batched-opening
stage. Consumers must include validity in eventual proof acceptance.

## Tests and evidence

The native fixtures use Nova 0.76.0's actual cubic and quadratic sumcheck
provers and verifiers on small sparse matrices. Both Pasta fields are covered.
Negative matrix coefficients, u and public inputs are nontrivial. An independent
integer-model check before coding covered 80 cases and 720 algebra assertions.
This model check did not execute Boolean gates or transcript hashing.

Adversarial fixtures include a complete native sumcheck pair with nonzero public
padding and another with swapped assignment halves. Each retains internally
consistent transcript claims; the Boolean inner terminal equation must reject.
Other tests change trusted matrix constants, use noncanonical late coefficients,
or alter eval_W and recompute the following transcript challenge.
The disk-backed graph is tested against honest and nonzero-padding assignments.

CI builds before timing and exports installed Nova source, gate/ciphertext counts
and /usr/bin/time resource records. Report measured results only after success.
Reproducible labels are confined to tests. The allocation reserve is not a
hard RAM limit. The test writes one graph to disk and replays it; production
label delivery, cut-and-choose and crash recovery remain separate work.

## Boundaries

This is an R1CS algebraic phase, not a complete compressed Nova verifier.
The caller must first bind the trusted verifier-key identity and the exact
instance U to the transcript, reusing the same u and X wires. Authentication
of W/E evaluations still requires batching and IPA openings. Nova's Poseidon
and step/state consistency checks, bounded proof decoding, and the BitVM3
transaction graph remain pending. The API supports the standard generated
cubic/quadratic polynomial shapes and nonzero round counts.

This milestone launches no user-machine or header-chain proving job.
The targeted test command (from the repository root) is:

```sh
cargo +1.90.0 test --release --locked --manifest-path nova-bitvm3/Cargo.toml --features native-reference,curve-reference --test spartan_r1cs -- --nocapture --test-threads=1
```
