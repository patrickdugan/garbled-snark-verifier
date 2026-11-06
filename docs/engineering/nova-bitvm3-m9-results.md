# M9 verified results: fixed-matrix inner R1CS algebra

Recorded November 6, 2026. Executable code under test:
`a7f202539b08dff2f6041aa8790d99c343d23798` on the user's fork's main.
The follow-up commit applies only rustfmt whitespace to the new Rust module
and adds this evidence record. Its algebra and test inputs are unchanged.

## Provenance

- [Successful M9 workflow 42201028209](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42201028209)
- Job `127836067456`: every step succeeded.
- [Artifact 13493564111](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42201028209/artifacts/13493564111)
- Downloaded ZIP SHA-256, independently matched against GitHub metadata:
  `2e6826f2d3f22445eac28f6e40ca95d73815831de0a474d90c65a5297d0791a6`.
- Resolved Cargo.lock SHA-256:
  `281568467dfed5cdaa44c7392a2a2a22e140b2ed5045a449bec5a925e47a7279`.

The original dedicated Nova workflow 42201027975 also passed all stages on
this code revision, including earlier components and the native toy compressed
proof reference. M9 ran on GitHub's hosted runner. No user-machine proving or
Bitcoin header-chain proving was launched.

## What is connected

`src/nova/sumcheck/r1cs.rs` executes the existing outer phase, carries its
computed claim into the inner sumcheck, and checks the final inner claim against
fixed A/B/C matrix evaluations and the prescribed assignment layout. The same
transcript and mixing-challenge wires are used throughout.

The verifier owns sparse matrix indices and coefficients. Constructor checks
reject invalid dimensions, indices outside the declared matrix, oversized public
input arity and noncanonical coefficients. Entries become circuit constants.
The matrix evaluator uses MSB-first index weights and caches occupied rows,
columns and cells, avoiding a full dense matrix allocation.

The second half of Z is [u,X,0,...,0]. Its multilinear value is computed from
those exact input wires, with zero padding supplied by circuit constants.

  eval_Z = (1-ry[0])*eval_W + ry[0]*public_eval(ry[1..])
  final_inner = (A(rx,ry)+r*B(rx,ry)+r^2*C(rx,ry))*eval_Z

The phase then absorbs [eval_W] under label `w`. Returned W/E evaluation points
and scalar claims are inputs to the upcoming batched-opening stage.

## Passed tests

All six new R1CS Rust tests passed. The M9 workflow also reran all nine existing
single-round and chain/outer-phase regression tests successfully.

Fixtures use Nova 0.76.0's native cubic and quadratic sumcheck provers, followed
by its native verifier. Both Pasta fields are covered. Tests include negative
matrix coefficients and nontrivial u/public-input values.

The important adversarial fixtures each contain an internally consistent pair
of native sumcheck proofs. One uses nonzero public padding; another swaps the
witness and public halves. Their matching transcript outputs are insufficient
for acceptance: the fixed-layout terminal equation rejects both.

Other cases alter verifier matrix constants or eval_W, use noncanonical public
inputs or late inner coefficients, and recompute the following transcript
challenge where applicable. A malformed verifier configuration is rejected
before constructing gates. Honest and nonzero-padding assignments were also
replayed through one disk-backed garbled graph, with correct output labels and
matching full-stream ciphertext digests.

Before coding, an independent integer model checked 80 honest cases over both
Pasta primes and 720 algebra assertions, including sparse/dense matrix parity
and assignment-half/padding mutations. That check excluded transcript hashing
and Boolean execution and is separate from the CI evidence.

## Measured graph and resources

The measured graph uses a small fixture: four constraint rows, four witness
slots, one public input, eight assignment columns and fifteen sparse entries
across the three matrices. It includes two cubic outer rounds and three
quadratic inner rounds, fixture-context absorption and a following-challenge
comparison. It is not a full Nova proof verifier.

| Metric | Result |
| --- | ---: |
| Non-free gates | 31,024,935 |
| Free XOR gates | 58,343,632 |
| Total gates | 89,368,567 |
| Streamed ciphertext bytes | 496,398,960 |
| Six-test command wall clock | 39.93 seconds |
| Peak RSS | 53,412 KiB = 52.16015625 MiB |
| Swaps | 0 |

Compilation was a preceding separate step. The timed log reports Cargo's
cached preparation in 0.09 seconds, with 39.83 seconds inside the test binary.
The timing includes the entire suite and repeated graph evaluations. The
ciphertext bytes cover one graph and exclude input labels, output commitments,
cut-and-choose replication and Bitcoin transaction overhead. A 64 KiB writer
buffer and the existing FileSource keep the ciphertext stream on disk. There
is no OS-enforced process-memory cap. Large real circuit matrices still require
separate cost and resource measurements; do not extrapolate the fixture's RSS.

## Reference-source check

The downloaded artifact contains the exact installed Nova sources. The inner
assignment equation, matrix weighting and `w` absorption schedule were checked
against that installed source after the successful run.

| Installed source | SHA-256 |
| --- | --- |
| spartan/snark.rs | c67d985f77e50b15a0bf4675d92b6766a0b2d2a3a3f018e15bbeac85cc14b69f |
| spartan/sumcheck.rs | 9aa4778690d9ed3464a5b1c1406f924761ae9571aef0986ca4396946ffc021a5 |
| spartan/polys/multilinear.rs | 1c7cce19577e241493cb769d2e613b84e8a0908b5eec5b00a3fdc28b88a03a61 |

## Remaining boundary and other CI

The caller must authenticate the verifier-key identity and bind the actual
instance U to the transcript before this phase, reusing the same u and X wires.
The test prefix intentionally isolates the algebra and is not the full U
serialization. W/E claims still need batched evaluation and IPA opening checks.
Nova's Poseidon/step/state checks, bounded proof decoding, authenticated BitVM3
inputs and the Bitcoin transaction graph remain additional requirements.
The API admits standard generated cubic/quadratic shapes and nonzero rounds.

The initial inherited rustfmt job reported layout-only differences in the new
module. The follow-up applies its exact formatting changes. The dedicated M9
and earlier Nova conformance runs succeeded independently of that style job.
Repository-wide SP1 and dependency workflows have their own status; these
results establish no repository-wide green CI claim.
