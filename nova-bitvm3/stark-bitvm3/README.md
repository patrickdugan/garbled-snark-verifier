# Direct Stwo-to-Boolean prototype

## S4: Shinigami receipts accepted by the Boolean relation of the Stwo final verifier

The unmodified 169,856-word Shinigami executable is proved as a task of upstream's privacy bootloader (laboratory profile L21), recursed into a 1-to-1 circuit proof, and accepted by the Boolean lowering of the final verifier: 4,783,261,848 non-free ANDs, gate for gate the production verifier of `starkware-libs/proving` at `e9a38e12`. Four receipts are committed (CSV and SHA256 hashlock, accepted and rejected); proof mutations, statement mutations and a non-canonical alias are rejected. The statement (circuit root, output digest, program hash, receipt) is derived by the checker, never read from the witness. Proving takes about 40 s and 15.4 GB on a laptop; the checker needs 1.6 GB. Nothing is garbled at this size yet and no Bitcoin script exists. See [S4.md](S4.md), [S4_RESULTS.json](S4_RESULTS.json) and [NEXT.md](NEXT.md).

## S3q: native Shinigami proof

The lookup residual of S3f to S3o was an input mismatch (the public segment context). With that one field corrected, the unmodified pinned prover and verifier accept a proof of the standalone Shinigami trace. See [S3Q.md](S3Q.md) and [S3P.md](S3P.md).

## S3n producer attribution: 4,096 XOR8 zero inputs from bitwise_builtin

The bounded native [S3n diagnostic](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42772759725) attributed every zero-input request for XOR8 tag 112558620 to `bitwise_builtin`, accounting for its local `−4096` table multiplicity. Source-pinned AIR declares one positive XOR8 lookup per 4,096-row builtin instance. The original global Cairo LogUp assertion still rejects the Shinigami proof. All four CI jobs passed, with 1.61 GB peak RSS and 19.227 seconds of native diagnostic execution. See [S3N.md](S3N.md) and [S3N_RESULTS.json](S3N_RESULTS.json).

## Latest S3m checkpoint: XOR8 component agreement

The source-captured `verify_bitwise_xor_8` native diagnostic matched its claimed QM31 LogUp value across **131,072 source-row relation entries**, with 1.60 GB peak RSS and 19.015 seconds of native runtime. The local M31 relation cleanup leaves a single zero-input tuple of multiplicity −4096 at tag `112558620`. The original global LogUp assertion still rejects the Shinigami proof. All four jobs passed in [run 42769770190](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42769770190). See [S3M.md](S3M.md) and [S3M_RESULTS.json](S3M_RESULTS.json).

## Latest relation-audit result: S3j

[Run 42753720798](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42753720798) tested a source-pinned diagnostic that skipped reconstructing the unused interaction tree. It still exceeded **4 GiB sampled RSS** before reporting unmatched tuples. The native proof and lookup assertion remained incomplete; all three routine CI jobs passed. See [S3J.md](S3J.md) and [S3J_RESULTS.json](S3J_RESULTS.json). Further experiments target component-local trace reconstruction.

## S3L local LogUp consistency checkpoint

A native 2,048-row `range_check_11` audit recomputed the exact QM31 LogUp sum from upstream relation tuples and matched the native interaction claim in all four field limbs. One bounded native trial ran in 21.427 seconds at 1.60 GB peak RSS; the global Cairo proof assertion still failed as expected. All four CI jobs passed. See [S3L.md](S3L.md) and [S3L_RESULTS.json](S3L_RESULTS.json).

## S3h tracker row-domain and memory diagnostics

The upstream relation tracker initially panicked after reconstructing constant columns at a reduced polynomial domain. An ephemeral source-pinned row-domain correction passed lightweight checks. The follow-up full audit exceeded the 4 GiB sampled RSS limit before outputting tuples; the watchdog stopped the trial. The pinned native lookup residual remains under investigation. See [S3H.md](S3H.md) and [S3H_RESULTS.json](S3H_RESULTS.json).

## S3f/S3g lookup and preprocessing experiments

[Run 42744991308](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42744991308) measured the nonzero lookup-sum failure under `canonical_small`: 37 present interaction components reproduced the exact native residual, and the original assertion rejected the proof. The source-pinned profile consumed 1.23 GiB sampled RSS at failure. [S3F.md](S3F.md) and [S3F_RESULTS.json](S3F_RESULTS.json) preserve the diagnostic evidence.

The alternative `canonical_without_pedersen` with the full sequence-table range compiled, then crossed its 4 GiB RSS limit in Merkle preprocessing before lookup verification. [Run 42745990977](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42745990977), [S3G.md](S3G.md), and [S3G_RESULTS.json](S3G_RESULTS.json) record that bounded negative result. Cairo proof generation, program binding and any Ark/UTXORef settlement authority remain outstanding.

The S2 checkpoint checks an authentic small Stwo STARK through a fixed complete verifier in native, Boolean and garbled execution. It uses a squared-Fibonacci AIR with 32/16-row traces and deliberately weak test parameters.

S3a adds a pinned Shinigami execution adapter and explicit transaction receipts. Its Cairo tests and standalone execution pass. The first native Cairo proving attempt stopped on an allocation failure under the fixed 6 GiB address-space cap. Cairo proof verification and its connection to the garbled verifier remain open.

## Latest application checkpoint: S3a

Execution code `6618c3ac44f3081bf450f9fb7ba249137cf7cb33` passed all enabled jobs in [run 42641621378](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42641621378). The real Shinigami engine, with a documented pure-Cairo SHA compatibility patch, passed **21 Cairo tests** covering CSV/hashlock scripts, independent hash vectors and profile rejection.

The standalone CSV execution used **157,303 Cairo steps**, produced an exact **21-word receipt**, and reported zero executed syscalls. A local receipt audit checks the echoed transaction and independent transaction-hash calculation and rejects 25 output mutations. This audit concerns captured execution data; it does not verify a STARK.

The optional native probe at `c8894f4` ran the bootloader successfully, producing 121,452,932 bytes of prover input. Proving then aborted on a 469,762,048-byte allocation under the 6 GiB address-space cap. No proof was produced. That failed run and its saved trace are recorded in [S3.md](S3.md) and [S3_RESULTS.json](S3_RESULTS.json). Default CI does not launch or retry the probe.

## Complete-verifier checkpoint: S2 passed

Tested code: `f90a7095f0cb4541b3eae73877e278cd70f79f2b`. All four jobs passed in [workflow run 42633574320](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42633574320).

The complete fixed verification relation has **141,577,483 non-free gates**. It accepted the authentic example proof in native, Boolean and garbled execution. Seven negative cases failed native/Boolean checks; the full garbled test also rejected an altered authentication path with newly synthesized internal values.

Garbling took **24.7 seconds**, followed by **19.3 seconds per evaluation**. The off-chain ciphertext file was **2.11 GiB**, and peak RSS for the full command was **3.33 GiB**. These hosted-CPU measurements exclude compilation and apply to the test-only example. Its FRI parameters account for **16 security bits**, so production verification needs a separately reviewed profile and measurements.

See [S2.md](S2.md) and [S2_RESULTS.json](S2_RESULTS.json). The S2/S3 Actions artifacts have finite retention; keep independent copies of their byte-exact evidence archives.

## Earlier checkpoints

S1 at `315837b4` imports all ten native gate families, including exact permutations, packed-word hash gates and finalized witness-domain constraints. Its compact all-gate fixture garbled to 43,055 ciphertexts and rejected five adversarial witnesses. An actual upstream-finalized synthetic circuit matched the native checker across 108 canonical mutations. Details remain in [S1.md](S1.md) and [S1_RESULTS.json](S1_RESULTS.json).

S0 at `41a4b008` supplies field/hash/transcript primitives. Its two-column, depth-three Merkle opening uses 57,929 ciphertexts. Historical evidence remains in [RESULTS.json](RESULTS.json).

## Upstream and interfaces

The Stwo verifier pin is `starkware-libs/proving` at `e9a38e12d09979f7a8625e233a80fecac6c38f02`, using standard Blake2s with M31 and the CM31/QM31 tower. Other hash profiles require independent compatibility evidence. Scarb 2.18 declares a different Stwo-Cairo producer revision, so its proof bytes cannot be assumed compatible with S2.

`core/` and `lowering/` have no third-party runtime dependencies. `adapter/` uses the repository garbler with parent default features disabled. `upstream/` imports finalized native constraints and binds constants and expected outputs. `s2-lab/` checks a frozen complete example proof through disk-backed garbling. `s3-shinigami/` executes its restricted script profiles and exposes a separately opted-in native proof probe.

The graph and expected statement are trusted configuration. Acceptance combines canonical encodings, all imported constraints and every expected binding. Internal verifier values are supplied as witnesses and checked, contributing to the 12,206,976-bit S2 input layout.

## Routine tests

```sh
python3 nova-bitvm3/stark-bitvm3/reference_vectors.py
cargo +1.90.0 test --locked --manifest-path nova-bitvm3/stark-bitvm3/core/Cargo.toml -- --nocapture --test-threads=2
cargo +1.90.0 test --locked --manifest-path nova-bitvm3/stark-bitvm3/lowering/Cargo.toml --features test-utils -- --nocapture --test-threads=2
cargo +1.90.0 test --manifest-path nova-bitvm3/stark-bitvm3/adapter/Cargo.toml --tests -- --nocapture --test-threads=1
cargo +1.94.0 test --manifest-path nova-bitvm3/stark-bitvm3/upstream/Cargo.toml --test conformance -- --nocapture --test-threads=1
```

Generate Python vectors before compiling core tests. Routine CI keeps bounded CPU jobs. Shinigami execution and native proving use separate explicit workflow inputs/commit markers. Nova, SP1 and CUDA proving remain outside this workstream.

## Required before application use

A successful Cairo proof must be matched to its exact producer, program identity, hash profile and expected public output. The current S3 profiles test CSV and SHA256 components; they do not implement an Ark exit or a UTXORef state machine. Those applications need ownership/authorization, transaction-state relations, chain policy and replay controls. Production-security parameters and Bitcoin dispute transactions remain separate acceptance requirements.

Fixed seeds, direct label access and weak test proofs are laboratory conventions. [NEXT.md](NEXT.md) specifies the saved-input memory investigation and remaining verifier/application work.
