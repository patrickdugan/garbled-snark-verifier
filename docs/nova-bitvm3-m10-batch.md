# M10: witness/error batch evaluation reduction

The new `sumcheck::batch` module continues the checked R1CS scalar algebra.
`from_algebra` takes an `AlgebraPhase`, uses its exact witness/error points and
evaluations, and carries its validity wire into the result. The same mutable
transcript continues from the previous `w` absorption. No challenge or running
claim enters as an independent witness.

## Unequal-size equations

Let k_i be the variable count of claim i, n=max(k_0,k_1), and e_i=P_i(x_i).
W is always first and E second. Squeeze rho with label `r`; the weights are
1 and rho. The quadratic batch sumcheck starts from

  initial = 2^(n-k_0)*e_0 + rho*2^(n-k_1)*e_1.

Each round absorbs its compressed coefficients under `p` and squeezes `c`.
Its terminal value must equal

  sum_i rho^i * l_i * eq(x_i, r[n-k_i..]).

The l_i values are then absorbed together under one `l` label. Squeezing `c`
produces gamma, the commitment mixing challenge. The pending evaluation is

  joint = sum_i gamma^i * l_i * product_j<n-k_i (1-r[j]).

The first power-of-two factor accounts for replicated tables during sumcheck.
The final product accounts for zero-padded tables in the combined commitment.
Both equations are required when W and E have different lengths.

## Scope of the result

`PendingOpening` contains a computed point, evaluation, gamma and accumulated
validity. It specifies the opening still to be checked against C_W+gamma*C_E.
This milestone does not compute that curve combination or verify its IPA.
Original commitment membership and transcript instance binding remain caller
requirements from earlier stages. A valid PendingOpening is not a complete
Spartan or compressed Nova verification result.

`verify_pair` exposes the scalar primitive for two claims. Its caller supplies
the preceding validity wire and verifier-owned lengths. Use `from_algebra`
for the actual M9 continuation so claim wires cannot be substituted at that
boundary. External serialized lengths still need bounded parsing.

## Tests

The standalone test uses Nova 0.76.0's public `prove_batch_eval` and
`verify_batch` functions, plus independent multilinear evaluation of a
zero-padded combined table. Nova's top-level `PolyEvalInstance` fields are
private, so this fixture does not call `batch_eval_verify` directly. CI retains
the installed source containing that function for an exact schedule review.

Cases include equal sizes, unequal sizes in both directions and one constant
polynomial. Zero tapes with noncanonical scalar aliases have their entire
raw-byte transcript recomputed; their field algebra still holds, and admission
must reject them. Changed terminal values are supplied with matching new gamma
and output claims. Omitting the final zero-padding factor must also reject.

The integration test generates outer, inner and batch proofs natively, then
runs the connected M9/M10 Boolean graph. A nonzero-padding assignment has
internally consistent proofs at every stage and must still fail through the
inherited M9 validity. Disk-backed tests replay genuine garbled batch graphs
on valid and adversarial assignments and compare ciphertext digests.

## Resource evidence and execution

The GitHub workflow separates compilation from timed test execution, fixes
build/Rayon concurrency at two and runs tests serially. The ciphertext sink
uses a 64-KiB writer buffer; allocator reservations do not enforce an OS RAM
cap. Final measured gates and RSS belong to the successful CI artifact.
The component counts exclude cut-and-choose and Bitcoin transaction overhead.

Run explicitly after the user's local proving pause ends:

```sh
cargo +1.90.0 test --release --manifest-path nova-bitvm3/Cargo.toml --features native-reference,curve-reference --test spartan_batch --test spartan_batch_integration -- --nocapture --test-threads=1
```

The existing local runner's named suites are unchanged. No user-machine job
is launched by this change. The transparent Nova/Spartan/IPA path, Bitcoin
header checkpoints and fold width k remain unchanged.
