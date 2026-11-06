# M4 final runtime and local-runner evidence

Recorded November 6, 2026. Executable source under test:
`29af77e3df75aabd88f19aa7b9ca99b90ffa6294` on the user's fork's main branch.
This evidence-only commit changes no executable code.

[Dedicated workflow 42166596231](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42166596231)
passed every step. The conformance job is `127724396784`.
[Artifact 13479231406](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42166596231/artifacts/13479231406)
was downloaded and its logs/receipts inspected. The ZIP SHA-256 matches GitHub:
`459f34a11bbdefac5dbeca11f9a365783d47f622c20a62d91e6ab747270316bc`.

## Boolean transcript

The circuit computes legacy Keccak-256 and 512-bit little-endian reduction
inside the Boolean graph. It maintains Nova's prior hash state across squeezes,
handles full and truncated challenges, and carries canonical scalar admission
into acceptance. Labels and the absorption/squeeze schedule belong to the
verifier-owned graph. See [M4 design](nova-bitvm3-m4-transcript.md).

The 5 M4 Rust groups passed again. Test coverage includes 96 complete challenge
encodings matched to Nova 0.76.0 across both engines, Keccak padding boundaries,
wide-reduction aliases and malformed absorbed scalars. Streamed garbling tested
7 assignments per field, including changed earlier inputs and wrong claims.

| Four-challenge graph | Non-free gates | Total gates | Ciphertext bytes |
| --- | ---: | ---: | ---: |
| Pallas base / VestaEngine scalar | 858,891 | 3,548,858 | 13,742,256 |
| Vesta base / PallasEngine scalar | 858,891 | 3,546,527 | 13,742,256 |

The bytes count emitted ciphertext records for one graph. Input labels,
cut-and-choose replication and Bitcoin transaction overhead are excluded.

The prebuilt M4 test command took **6.32 seconds** and peaked at
**53,588 KiB RSS = 52.33203125 MiB**, with zero swaps. The test executable
reported 6.23 seconds for its five groups. Build and run use identical feature
sets; the log shows Cargo finishing its cached preparation in 0.08 seconds
and contains no compilation. This measures all M4 component tests, including
repeated evaluations, rather than one proof or the full Nova verifier.

## Local runner

All 5 Python wrapper tests passed. CI also executed:

```sh
python3 nova-bitvm3/local_run.py --suite transcript --jobs 2 --threads 2 --output nova-bitvm3/results/local-ci
```

The receipt reported passed, with a clean tracked worktree and the correct
source commit. The cached build phase took 0.1141 seconds; the transcript run
phase took 6.3277 seconds. Logs and dependency lockfile hashes are retained in
`results/local-ci/`. Hardware fields describe the GitHub runner, not the user's
upgraded laptop. Linux was exercised; native Windows Rust compilation remains
untested here.

The wrapper records RAM and free disk snapshots, bounded build/Rayon concurrency,
a dependency lockfile and separate build/run phases. It preserves failed-run
receipts and logs, refuses conflicting lockfiles, and supports preparation via
--build-only or --plan. It does not enforce a hard process-memory limit or
measure peak RSS itself; the 52.33 MiB figure above comes from /usr/bin/time.

[Local run instructions](nova-bitvm3-local-run.md) provide commands for the
post-upgrade component suite and the separate native toy proof baseline.

## Other checks and proof baseline

The existing 6 Rust field groups, 4 curve groups and 3 host-transcript groups
passed alongside the 5 M4 groups, for **18 Rust groups** in the dedicated run.
The Python field reference and exhaustive independent curve relation also passed.
The local wrapper's actual invocation reran the transcript tests successfully.

The native transparent Nova reference again produced a **10,592-byte** proof
for 2 -> 9 -> 86 with Spartan/IPA compression. Its receipt checks the expected
final state, rejects changed initial state/step count and verifies a serialized
round trip. Native runtime was 7.9506 seconds excluding compilation.

- Proof SHA-256: `9107796039460f841f504ab98e80305defe696e3d20b90bbb51fb37122be6d7d`.
- Verifier-key SHA-256: `1fbcf1bb4982f9d95ed588871300160d6e826319218da030101ac9badbfacfc0`.
- Cargo.lock SHA-256: `1bf607f0994d6f602ece034440a15fdfcd368a1f9633a5c8f6fe57dadba73ba6`.

Inherited Code Checks run 42166596128 passed formatting and spelling and failed
its unused-dependency job. A green dedicated Nova run does not imply all
inherited SP1/repository workflows passed.

## Next integration boundary

Full compressed Nova verification in a garbled circuit still needs structured
proof decoding/absorption, Poseidon consistency checks, Spartan sumcheck and
both IPA verification paths. BitVM3's authenticated input setup and transaction
binding remain separate work. The Bitcoin header prover, existing checkpoints
and fold width k are unchanged. No user-machine proving run was launched.
