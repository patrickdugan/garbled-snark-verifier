# M4 verified Boolean transcript evidence

Source tested: `74118d40b4aa13e23bedcfbc4773a2f8450413d2`.
[Dedicated workflow 42165716972](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42165716972)
completed successfully, including the native compressed proof reference.
[Artifact 13479230325](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42165716972/artifacts/13479230325)
was downloaded and inspected. ZIP SHA-256 matches GitHub's digest:
`1055e6fd41421f229c1b00aeaf4253c7ec1d8469fb650bf1da263a152e3cc3d9`.

## Boolean and garbled result

All five new Rust test groups passed. The sequence test derived four successive
challenges, one of them using squeeze_bits, entirely through Boolean gates.
It matched pinned Nova 0.76.0 over both scalar fields, including high-bit
canonical operands and six truncation/leading-bit configurations: 96 complete
challenge-encoding comparisons. Disk garbling evaluated seven assignments for
each field, with expected output labels and ciphertext digests checked.

The negative tests reject altered challenge bits, altered earlier inputs,
protocol-label and absorption-order changes, changed squeeze labels, and
noncanonical scalar encodings even when their raw-byte challenge values match.
Keccak tests cover 14 lengths including 135/136/137 and 271/272/273 bytes,
comparing against sha3 =0.10.9 Keccak256 and rejecting Sha3_256 outputs.
Wide-reduction tests check 32 inputs per field, each with a correct result,
a wrong result and a noncanonical alias.

| Four-challenge graph | Non-free gates | XOR gates | Total gates | Ciphertext bytes |
| --- | ---: | ---: | ---: | ---: |
| Pallas base field (VestaEngine scalar) | 858,891 | 2,689,967 | 3,548,858 | 13,742,256 |
| Vesta base field (PallasEngine scalar) | 858,891 | 2,687,636 | 3,546,527 | 13,742,256 |

This includes initialization, all hashes, three full 512-to-field reductions,
one truncated challenge, canonical scalar checks and comparison with four
claimed values. It is one component graph, not the full proof verifier.
Ciphertext bytes exclude input labels and BitVM3 protocol replication.

The M4 test executable reported **6.20 seconds** across all five groups.
The surrounding /usr/bin/time command reported **27.91 seconds** and
**609,376 KiB maximum RSS**, including a 21.69-second recompilation due to a
feature-set mismatch between build and run. That RSS is not runtime-only.
The following workflow edit uses the same features for build and run to remove
this confound; a later successful artifact is required for runtime-only memory.

Existing six Rust field groups, four curve groups and three host-transcript
groups also passed, making 18 Rust groups in total. The Python field mirror and
independent curve relation continued to pass. The native proof remained 10,592
bytes, with expected final output 86 and wrong-state/step rejection.

## Scope

The non-EVM Keccak transcript and its field reduction now run in the garbled
circuit. Structured proof decoding/absorption, Poseidon consistency, Spartan
sumcheck and both IPA verification paths are still needed for full compressed
Nova verification. The Bitcoin header prover and its k are unchanged.

Inherited CI failed rustfmt on four formatting hunks in the new module. The
following patch applies that formatting without changing the circuit. Broader
SP1/dependency checks are separate from the successful dedicated Nova workflow.

## Local preparation

See [local runner instructions](nova-bitvm3-local-run.md). The wrapper has five
Python test groups covering command planning, build/run separation, failed
build stopping, real subprocess failure/timeout logs and lockfile conflicts.
Those wrapper tests passed locally on Linux before submission. The updated CI
also runs the wrapper against actual transcript tests. No local proving job
was launched on the user's machine.
