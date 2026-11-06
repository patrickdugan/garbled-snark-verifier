# M6: verified Spartan sumcheck round evidence

Evidence recorded 2026-11-06 for executable revision
`334637afc1809fe0b1b19a6ebf6dc061ff2db19b` on
`patrickdugan/garbled-snark-verifier` main.

- [Dedicated successful workflow](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42171772571)
- Conformance job: `127741017961`
- [Evidence artifact](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42171772571/artifacts/13481637776)
- Artifact ZIP SHA-256: `2822ea55e216b36879221f70f95fd6cd692aaf9625ace45f98101af48c5f0227`
- ZIP digest was independently verified against GitHub metadata.

## Verified cases

The dedicated workflow passed all stages, including the pinned Nova 0.76.0
native reference proof. The new M6 test binary passed 3 Rust groups:

- Quadratic and cubic sumcheck rounds checked against
  `SumcheckProof::verify` on PallasEngine and VestaEngine.
- Noncanonical inputs and changed running claims or polynomial coefficients
  rejected under both scalar moduli.
- Disk-backed garbling and evaluation of one cubic round passed for a valid
  claim, a corrupted coefficient, and a corrupted output claim, with consistent
  ciphertext digest and expected garbled output labels.

All earlier field, Pasta curve, Keccak and structured-object transcript
conformance stages also passed. The Python field and curve mirrors passed;
the independent integer curve relation test covers 547,778 exhaustive cases.

## Measured M6 single-round circuit

| Metric | Result |
|---|---:|
| Non-free gates | 1,451,270 |
| Emitted ciphertext bytes | 23,220,320 |
| M6 test command wall clock | 5.08 seconds |
| Prebuilt executable peak RSS | 53,768 KiB (52.51 MiB) |
| Reported swaps | 0 |

Timing measures the three M6 component tests together, including replay
of valid and invalid assignments and Cargo startup, with compilation in an
earlier separate stage. RAM measures the prebuilt component test executable.
The ciphertext count is one cubic round, without input labels, output
commitments, cut-and-choose replication or transaction data. There is no
OS-enforced process-memory budget in this harness.

The unchanged native transparent Nova reference generated and checked a
10,592-byte Spartan/IPA compressed proof for two applications of
x -> x^2+5, starting at 2 and ending at 86. The reference program elapsed
9.31667023 seconds, including parameter generation and multiple verification
calls but excluding compilation. This is not a Bitcoin header prover benchmark.

## Development boundaries

The standalone round reconstructs the missing linear coefficient
`a1 = claim - 2*a0 - a2 - a3 (mod p)`, absorbs compressed coefficients with
a single `p` label and derives challenge `c` from the in-circuit Boolean
Keccak transcript. Degree and transcript schedule are fixed by the verifier.
Validating a complete Spartan proof additionally requires its initial claim,
the R1CS matrix/evaluation equations and final IPA commitments/openings.
Nova's Poseidon consistency, step/public-state binding and Bitcoin settlement
logic are also pending. No proving run was launched on the user's machine.

The inherited repository-wide workflow failed separately: SP1's `succinct`
toolchain reports an unsupported `remap-path-scope` option, while
`cargo-udeps` reports unused dependencies. A `codespell` false-positive
on the Nova `E::TE` associated type was corrected by a narrow dictionary
entry in this documentation follow-up. These are distinct from the green
dedicated M6 conformance run.
