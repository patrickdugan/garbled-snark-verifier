# Direct Stwo-to-Boolean prototype

A pinned upstream Stwo verifier can now check an authentic small STARK through the repository's Boolean and garbled engines. The S2 checkpoint uses a fixed squared-Fibonacci AIR with 32/16-row traces and deliberately weak test parameters. Shinigami/Cairo execution proofs and Ark/UTXORef application statements remain the next integration targets.

## Current checkpoint: S2 passed

Tested code: `f90a7095f0cb4541b3eae73877e278cd70f79f2b`. All four jobs passed in [workflow run 42633574320](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42633574320).

The complete fixed verification relation has **141,577,483 non-free gates**. It accepted the authentic proof in native, Boolean and garbled execution. Seven negative cases failed the native/Boolean checks; the full garbled test also rejected a changed authentication path with newly synthesized internal values.

Garbling took **24.7 seconds**, followed by **19.3 seconds per evaluation**. The ciphertext file was **2.11 GiB**, and peak RSS for the full garble/evaluate command was **3.33 GiB**. These hosted-CPU measurements exclude compilation and cover this test-only example. The FRI parameters account for **16 security bits**, so production verification needs its own profile and measurements.

See [S2.md](S2.md) for reproduction and boundaries, and [S2_RESULTS.json](S2_RESULTS.json) for exact evidence. The frozen artifact has finite retention; keep an independent copy of its evidence ZIP.

## Earlier checkpoints retained

S1 at `315837b4e32bead8e012f53e0b4a73ebdc0fd195` imports all ten native gate families, including exact permutations, packed-word hash gates and finalized witness-domain constraints. A compact all-gate fixture garbled to 43,055 ciphertexts and rejected five adversarial witnesses. An actual upstream-finalized synthetic circuit matched the native checker across 108 canonical mutations. Details remain in [S1.md](S1.md) and [S1_RESULTS.json](S1_RESULTS.json).

S0 at `41a4b00820211823058f7f2a77f57cef3105985e` provides field, hash and transcript primitives. Its two-column, depth-three Merkle opening uses 57,929 ciphertexts. Historical measurements remain in [RESULTS.json](RESULTS.json).

The S2 run retains all 19 Rust regression tests from S0/S1 and adds one backend-topology unit test. The full-proof checks are executable assertions recorded separately from those test counts.

## Upstream and interfaces

Upstream is pinned to `starkware-libs/proving` commit `e9a38e12d09979f7a8625e233a80fecac6c38f02`. Its selected profile uses standard Blake2s with M31 and the CM31/QM31 extension tower. Blake2s-M31 and Poseidon profiles require independent end-to-end compatibility evidence.

`core/` and `lowering/` have no third-party runtime dependencies. `adapter/` uses the existing garbler with parent default features disabled. `upstream/` imports actual finalized native constraints and binds constants and expected outputs. `s2-lab/` instantiates the full verifier for a fixed example, produces an authentic fixture through an explicit generator, and tests saved proof witnesses through disk-backed garbling.

The graph and expected statement are trusted configuration. Acceptance conjoins canonical input encodings, all imported constraints and every expected binding. Internal verifier values are supplied as witnesses and checked, which contributes to the 12,206,976-bit input layout in the S2 example.

## Run routine tests

```sh
python3 nova-bitvm3/stark-bitvm3/reference_vectors.py
cargo +1.90.0 test --locked --manifest-path nova-bitvm3/stark-bitvm3/core/Cargo.toml -- --nocapture --test-threads=2
cargo +1.90.0 test --locked --manifest-path nova-bitvm3/stark-bitvm3/lowering/Cargo.toml --features test-utils -- --nocapture --test-threads=2
cargo +1.90.0 test --manifest-path nova-bitvm3/stark-bitvm3/adapter/Cargo.toml --tests -- --nocapture --test-threads=1
cargo +1.94.0 test --manifest-path nova-bitvm3/stark-bitvm3/upstream/Cargo.toml --test conformance -- --nocapture --test-threads=1
```

Generate the Python vectors before compiling core tests. Routine CI excludes prover features and keeps fixed CPU job caps. The opt-in S2 job checks a frozen authentic fixture, with explicit memory and time limits. Nova and SP1 proving remain outside this workstream.

## Required before application use

Match an authentic Shinigami proof to its producer commit, hash profile, Cairo program and public outputs. Bind the application statement to the expected Bitcoin transaction context and policy. Ark exit/forfeit conditions and UTXORef authorization/state transitions need their own checks. Production proof parameters and Bitcoin dispute transactions must be validated before routing funds through this path.

Fixed seeds, direct label access and test-security proofs are laboratory conventions. The next work is specified in [NEXT.md](NEXT.md).
