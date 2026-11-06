# M7/M8 verified results: multi-round reduction and outer Spartan algebra

Recorded November 6, 2026. Executable source under test:
`c066800ed1f7701cb8f24f3b22254c5b43d6e37d` on the user's fork's main branch.
This evidence-only commit changes no executable code.

## Provenance

- [Successful dedicated workflow 42195312359](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42195312359)
- Conformance job: `127816996942`, all steps successful.
- [Artifact 13491828023](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42195312359/artifacts/13491828023)
- Downloaded ZIP SHA-256, independently matched to GitHub's digest:
  `69be96840d66fb51997f3524a17c7e18e2d0dd7cde3ae6fc69c75b1e4c240e60`.
- Cargo.lock SHA-256:
  `281568467dfed5cdaa44c7392a2a2a22e140b2ed5045a449bec5a925e47a7279`.

The artifact retains the exact installed Nova 0.76.0 source used for the
native comparison. Its `spartan/snark.rs` outer equation and transcript
schedule were inspected after download.

| Source retained in artifact | SHA-256 |
| --- | --- |
| spartan/snark.rs | c67d985f77e50b15a0bf4675d92b6766a0b2d2a3a3f018e15bbeac85cc14b69f |
| spartan/sumcheck.rs | 9aa4778690d9ed3464a5b1c1406f924761ae9571aef0986ca4396946ffc021a5 |
| spartan/polys/univariate.rs | 2eea91c18e295b7454eb8ff5141c98a8d35ea8b5f0b3235fcb611aaa522db992 |

## Implemented

`src/nova/sumcheck/chain.rs` computes every running claim inside the circuit,
using a single persistent transcript. Proof inputs contain the compressed
polynomial coefficients. Challenge and intermediate-claim witnesses are absent.
Canonical admission failures are carried through final acceptance.

The outer algebraic phase starts with the zero claim, derives tau internally,
checks `final = eq(tau,r_x)*(Az*Bz-u*Cz-eval_E)`, absorbs the four evaluations
under `claims_outer`, and derives mixing challenge `r`. It computes the inner
phase starting claim `Az+r*Bz+r^2*Cz` without an independent witness for r.

The caller still owns verifier-key and R1CS-instance binding before this phase,
and must reuse the same wires for U.u. Remaining R1CS matrix and IPA checks
must authenticate these claimed evaluations before full-proof acceptance.

## Passed tests

All **31 distinct Rust tests** in the dedicated workflow passed: six field
kernel tests, four curve tests, three host-transcript tests, five Boolean
transcript tests, four structured-encoding tests, three single-round sumcheck
tests and six new chain/outer-phase tests. Earlier Python references and
local-wrapper tests also passed.

New coverage includes:

- Native Nova comparison for 1, 2, 3 and 4 rounds across both Pasta fields,
  checking the final claim and the following transcript challenge.
- Reordered rounds, reset transcripts, changed context and altered proof words.
- Noncanonical early and late coefficients accompanied by recomputed raw-byte
  transcript outputs. Those assignments still reject through admission.
- Honest outer fixtures constructed from multilinear tables with E=A*B-u*C
  at each Boolean point. A separate test prover interpolates cubic round
  polynomials, then checks them with native SumcheckProof::verify.
- Altered outer evaluations accompanied by recomputed mixing/inner outputs.
  Rejection therefore requires the terminal polynomial equation too.
- Disk-backed garbling and replay of both the chain and outer phase, checking
  expected output labels and the full ciphertext digest.

The deliberately mismatched shape test catches an expected constructor panic.
Its panic text appears in the log, followed by a successful test result.
Zero-round reductions are intentionally outside the new API. Verifier-owned
shape lengths must also be enforced by the eventual serialized-proof decoder.

An additional independent integer-model check ran in the assistant's sandbox:
64 honest cases over both Pasta fields, with 160 round-identity checks. This
was an algebra check without transcript hashing and is separate from CI.

## Measured garbled test graphs

| Graph | Non-free gates | Emitted ciphertext bytes |
| --- | ---: | ---: |
| Three-round cubic chain, VestaBase / PallasEngine scalar | 4,407,824 | 70,525,184 |
| Two-round outer phase and inner transition, PallasBase / VestaEngine scalar | 7,069,211 | 113,107,376 |

These are complete test graphs. They include fixture-context absorption and a
following-challenge comparison, plus checks of the claimed outputs. The outer
graph also binds its fixture u before entering the phase. Ciphertext bytes
exclude input-label delivery, output commitments, cut-and-choose replication
and Bitcoin transaction overhead.

The command running all six prebuilt M7/M8 tests took **26.21 seconds** and
peaked at **53,604 KiB RSS = 52.34765625 MiB**, with zero swaps. The executable
reported 26.14 seconds, while Cargo's cached preparation took 0.06 seconds.
Compilation was performed in the preceding stage. These are component-suite
measurements, not full-verifier or header-prover resource requirements.
There is no OS-enforced process-memory limit in this test harness.

## Native reference and repository checks

The unchanged native toy proof of 2 -> 9 -> 86 under x -> x^2+5 passed again,
including changed-state/step rejection and serialized round-trip verification.
It remains a 10,592-byte Spartan/IPA compressed proof. Runtime was 5.60451872
seconds including setup and multiple verification calls, excluding compilation.
Proof SHA-256: `346234171df69ba1812f033d6674c2bc2940cfc83957329ee146888a4731ada4`.

Formatting and spelling passed in inherited Code Checks run 42195312154.
Its unused-dependency job failed. Inherited CI run 42195312386 passed rustfmt
and failed during SP1 asset building; its later clippy and build/test steps
were skipped. Dedicated Nova success is distinct from repository-wide CI.

The local runner's existing named suites are unchanged in this milestone;
the new target is selected directly with the command in
[the M7/M8 design note](../nova-bitvm3-m78-chain.md). No proving job was
launched on the user's machine. Existing header checkpoints and k are unchanged.

## Remaining integration work

The next step is the inner R1CS check, including fixed matrix evaluations at
(r_x,r_y), public-input evaluation and eval_Z binding. Batched evaluation and
both IPA paths follow. Complete Nova acceptance also requires Poseidon and
step/state consistency, bounded version-pinned proof decoding and a trusted
verifier-key identity. BitVM3 authenticated inputs and its Bitcoin transaction
graph remain separate protocol work. No complete compressed Nova proof has
yet been verified by the garbled circuit.
