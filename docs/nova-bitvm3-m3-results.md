# M3 verified evidence: Pasta addition and transcript conformance

Recorded November 6, 2026. The source under test is
`2baa614053b00931f07d4423baa3e01c175e6151` on the user's fork's main branch.
This evidence-only commit changes no executable code.

## Reproduction and provenance

- [Successful dedicated workflow 42162594627](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42162594627)
- Conformance job: `127711532345`; every step completed successfully.
- [Artifact 13477408082](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42162594627/artifacts/13477408082)
- Downloaded ZIP SHA-256, checked against GitHub's artifact digest:
  `21540da844891722384c70e4bb36ec86e85b78bccd9d09ca6122853df83d55dc`.
- Resolved `Cargo.lock` SHA-256:
  `1bf607f0994d6f602ece034440a15fdfcd368a1f9633a5c8f6fe57dadba73ba6`.
- The actual installed Nova 0.76.0 `src/provider/keccak.rs` is retained in the
  artifact. Its SHA-256 is
  `9a63349a255e0bdf24117f07ec50aeafb592995eb5520186c8ffcfd89b4bb6b9`.

The artifact was downloaded and its result files inspected after the successful
job. Rust execution was on GitHub's hosted runner. The independent Python
curve-relation check also ran locally. The lockfile is retained in this artifact;
release builds still need a reviewed committed lockfile.

## Passed checks

| Suite | Result |
| --- | --- |
| Existing Python field-kernel mirror | 11 test groups passed |
| Independent integer curve relation | 547,778 exhaustive cases over five small fields passed, plus full-width Pasta checks |
| Existing Rust field/garbling tests | 6 test groups passed |
| New independent curve and streamed-garbling tests | 4 test groups passed |
| Native exact-transcript conformance | 3 test groups passed |
| Native recursive/compressed Nova example | Passed, including expected output, wrong-state/step rejection and serialization round trip |

Curve tests compare with halo2curves =0.9.0 on Pallas and Vesta. They exercise
14 native input-point pairs per curve, then test valid results, changed slopes
and substituted on-curve outputs. Separate malformed-input cases cover each
coordinate/slope port, malformed infinity and finite (0,0). A fixture audit
checks identity flags and native membership independently of the Boolean graph.

The streamed tests garble one graph for each curve and evaluate 12 assignments
per graph, covering all addition branches and incorrect slopes. Output labels
and ciphertext digests must match. Reusing both label choices in this test is
conformance plumbing, not a production garbled-circuit input protocol.

The transcript mirror matched 16 successive 32-byte challenges for each engine,
32 challenge comparisons in total. Additional tests mutate the protocol label,
absorption order, squeeze label and counter state. The test log's phrase
"16 challenge bytes matched" refers to sixteen complete challenge encodings.
These tests cover scalar absorption and domain/squeeze behavior. Structured
proof-object encodings and Boolean Keccak remain separate work.

## Measured complete point-addition predicate

| Curve | Non-free gates | Free XOR gates | Total gates | Ciphertext bytes |
| --- | ---: | ---: | ---: | ---: |
| Pallas | 4,340,269 | 7,714,045 | 12,054,314 | 69,444,304 |
| Vesta | 4,340,269 | 7,700,206 | 12,040,475 | 69,444,304 |

Each predicate includes canonical membership checks for P, Q and claimed R,
as well as the constrained affine slope and every exceptional branch.
It contains twelve computed field products. Bytes count 16-byte ciphertext
records, excluding input labels, commitments, cut-and-choose replication and
Bitcoin transactions. The graph is written to disk and replayed through the
upstream FileSource, with a 64 KiB writer buffer and 4 MiB reader buffer.

The prebuilt M3 curve and transcript test command took **44.29 seconds** and
peaked at **53,384 KiB RSS (52.13 MiB)**, with zero swaps. This command includes
all independent comparisons and repeated streamed evaluations, plus Cargo's
startup/checking overhead. Compilation ran in an earlier untimed step. This
is neither a per-addition latency measurement nor a full verifier memory result.
No OS-enforced memory ceiling is claimed.

## Native reference

The unchanged native example proves 2 -> 9 -> 86 under x -> x^2+5, using
Nova 0.76.0, Pallas/Vesta and Spartan/IPA. It serialized to **10,592 bytes**.
The example's 9.305264083-second runtime includes setup, proving, compression
and several native verification calls, excluding compilation.

- Proof SHA-256:
  `9e2c5c0df94a6bce61ecfd507d0bf82a400007e0c074ff877b77556686ff246a`.
- Verifier-key SHA-256:
  `1fbcf1bb4982f9d95ed588871300160d6e826319218da030101ac9badbfacfc0`.

The new proof path retains transparent parameter generation and IPA compression.
The repository's existing Groth16 modules remain present as upstream code.

## Corrections and CI scope

The earlier M3 runs are preserved as failed evidence in
[nova-bitvm3-m3-diagnostics.md](nova-bitvm3-m3-diagnostics.md). A missing Rust
coordinate type annotation and a native-oracle infinity-encoding mistake were
fixed before this successful run. The curve predicate rejected finite (0,0)
as required; the fixture adapter now checks is_identity explicitly.

The dedicated Nova workflow is green. Inherited Code Checks run 42162594541
passed formatting and spelling and failed its cargo-udeps step. The broader
SP1-related CI was still building at the last inspection. These M3 results
do not assert a repository-wide green status.

## Integration boundary and next work

M3 supplies a complete group-law relation and host-side transcript conformance.
A full compressed Nova proof has not been verified inside a garbled circuit.
The remaining verifier work includes Boolean Keccak and challenge reduction,
structured proof decoding/absorption, Poseidon consistency checks, Spartan
sumcheck and both IPA/MSM paths. BitVM3's authenticated input setup and Bitcoin
transaction graph remain separate acceptance gates.

The measured membership-heavy point predicate is a baseline. Before scaling
MSMs, measure reuse of already-validated points and fixed-generator arithmetic
while preserving shared-wire binding and all exceptional cases. The full
verifier's gate and assertion costs require their own benchmarks. Existing
Bitcoin-header checkpoints and fold width k were left unchanged.
