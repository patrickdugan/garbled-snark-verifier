# M10 verified results: W/E batch evaluation reduction

Recorded November 6, 2026. Executable revision under test:
`f648d39f7ce15903c9a659eb4d8c9e8770f8e015` on the user's fork's main branch.
The follow-up only joins one import line to satisfy rustfmt and records this
report. Algebra, fixtures and circuit topology are unchanged.

## Provenance

- [Successful dedicated batch workflow 42233571761](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42233571761)
- Job `127945301772`: every step successful.
- [Artifact 13510098739](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42233571761/artifacts/13510098739)
- Downloaded ZIP SHA-256, independently matched to GitHub metadata:
  `6ac5b422fa35fb7d26a351b8d9a037b6fb3596f873afa433990694a74677bfa9`.
- Cargo.lock SHA-256:
  `281568467dfed5cdaa44c7392a2a2a22e140b2ed5045a449bec5a925e47a7279`.

The downloaded artifact includes the installed Nova 0.76.0 source used by
these tests. Its `batch_eval_verify` and `batch_diff_size` equations and
transcript labels were checked after download. The native comparison calls
public `SumcheckProof::prove_batch_eval` and `verify_batch`. A separate
multilinear evaluator checks the resulting zero-padded combined table;
this fixture does not directly invoke the top-level `batch_eval_verify`
whose `PolyEvalInstance` fields are private.

| Installed source | SHA-256 |
| --- | --- |
| spartan/mod.rs | becff8c058ec8a722b35d7014cd85bb7ad53fb5f4aa1a70b974d4d7caf5cc8d9 |
| spartan/sumcheck.rs | 9aa4778690d9ed3464a5b1c1406f924761ae9571aef0986ca4396946ffc021a5 |
| spartan/snark.rs | c67d985f77e50b15a0bf4675d92b6766a0b2d2a3a3f018e15bbeac85cc14b69f |

## Connected stage

`src/nova/sumcheck/batch.rs` reduces the witness and error evaluation claims
to one pending opening. `from_algebra` reuses the exact M9 W/E points and
scalar claim wires and carries forward M9 validity. The existing mutable
transcript supplies both batching challenges; intermediate claims are
computed wires. Proof inputs are quadratic compressed coefficients and two
terminal polynomial evaluations.

For sizes k_W and k_E, with n=max(k_W,k_E), the sumcheck starts from

  2^(n-k_W)*eval_W + rho*2^(n-k_E)*eval_E.

Its terminal equation checks the supplied evaluations against equality
polynomials on the correct suffixes of the computed point. After absorbing
both terminal evaluations with one `l` label, the circuit squeezes gamma
under `c`. The pending evaluation includes the missing-prefix Lagrange
factors, product(1-r_j), required by zero-padding the smaller table.

The result contains a point, evaluation, gamma and accumulated validity.
The curve commitment that must eventually be checked is C_W+gamma*C_E.
This stage does not compute that point or verify its IPA opening.

## Passed tests

The dedicated workflow passed **23 Rust tests**: six new batch tests,
two new connected R1CS-to-batch tests, and fifteen existing algebra
regressions (six chain, six R1CS, three single-round sumcheck).

New cases include:

- Eight size pairs on each Pasta field: equal lengths, unequal lengths in
  both directions, and one constant polynomial.
- Forged terminal evaluations accompanied by freshly recomputed transcript
  challenges and joint output values. The terminal equation rejects them.
- Noncanonical points/claims/coefficients on zero-polynomial tapes whose
  reduced field algebra still holds and whose raw-byte hashes match.
  Rejection therefore exercises canonical admission.
- Missing zero-padding factors, prior failure propagation, malformed
  verifier-owned round shapes, and changed exported output scalars.
- Honest connected fixtures using native outer, inner and batch provers.
  A nonzero-padding assignment still generates internally consistent native
  proofs, but the integrated circuit retains the earlier M9 rejection.
- Two disk-backed garbled graphs, each replayed for a valid assignment,
  forged terminal evaluation, omitted padding, and noncanonical zero tape.
  Every expected output label and full-stream ciphertext digest matched.

Constructor-panic text for invalid shape tests is expected and is caught;
those tests finish successfully. This API requires at least one variable in
one of the two polynomials and standard quadratic generated round shapes.
Both-zero-variable batching is outside this interface.

## Measured batch graphs

| Graph | Non-free gates | Emitted ciphertext bytes |
| --- | ---: | ---: |
| PallasEngine scalar / VestaBase, W has 1 variable and E has 2 | 6,580,767 | 105,292,272 |
| VestaEngine scalar / PallasBase, W has 2 variables and E has 1 | 6,580,767 | 105,292,272 |

These are complete fixture graphs, including prefix absorption, output
comparisons and a following transcript challenge. They exclude original
commitment combination, IPA verification, input-label delivery, output
commitments, cut-and-choose replication and Bitcoin transaction data.

| Prebuilt test command | Wall time | Maximum RSS | Swaps |
| --- | ---: | ---: | ---: |
| Six batch tests, including garbling/replays | 31.25 s | 53,328 KiB = 52.078125 MiB | 0 |
| Two connected R1CS-to-batch tests | 17.09 s | 54,052 KiB = 52.78515625 MiB | 0 |

Compilation ran in the preceding separate step. Cargo's cached preparations
took 0.10 and 0.09 seconds; the binaries reported 31.14 and 16.98 seconds.
The integration tests use plaintext Boolean execution; streamed garbling is
measured in the standalone batch tests. These are component-suite runtimes,
not per-proof timings. No OS-enforced RAM limit exists in this harness.
Large real shapes still need their own measurements.

An independent Python integer model in the assistant's sandbox passed 180
cases and 920 identities over both Pasta primes, including 140 unequal-size
padding mutations. Another 198 checks covered gamma and point coordinates
at 0, 1 and p-1. Those checks exclude transcript hashing and garbled execution
and are separate from GitHub CI. Integer-model source SHA-256:
`eae80fbdec38fefc07874417199f6652bacd0aadf0ae172ac5f0824de70abd15`.

## Remaining work and other checks

The next cryptographic component is the checked curve combination
C_W+gamma*C_E and its IPA verification against the authenticated generators.
The original commitment wires and verifier-key identity must remain bound to
the same statement. Complete compressed Nova acceptance also needs the
remaining Poseidon/state checks and bounded proof decoding. BitVM3 input
authentication and Bitcoin spending paths remain additional protocol work.

The inherited Code Checks run 42233571720 passed spelling, reported one
rustfmt import-layout difference and failed its unused-dependency job.
The follow-up applies that exact layout correction. Dedicated M10 success
is independent of the inherited SP1 and repository-wide workflows.

No user-machine proving job was launched. Header checkpoints, fold width k
and the transparent Pallas/Vesta + Spartan/IPA configuration are unchanged.
Usage and scope are in [the M10 design note](../nova-bitvm3-m10-batch.md).
