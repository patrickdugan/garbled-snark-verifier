# Direct Stwo-to-Boolean prototype

Experimental components and a finalized-circuit importer for eventual Shinigami, Ark and UTXORef verification in the repository's garbled-circuit engine. S0 covers field/hash/channel primitives and Merkle openings. S1 lowers the complete gate language of a pinned upstream arithmetic circuit. Complete STARK verification remains a later milestone.

## Current checkpoint: S1 passed

Tested code: `315837b4e32bead8e012f53e0b4a73ebdc0fd195`. All jobs passed in [workflow run 42627178138](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42627178138).

| Test group | Passed |
| --- | ---: |
| S0 components, with 204 independent vectors | 8 |
| S1 lowering and adversarial input checks | 6 |
| Compiled upstream conformance | 3 |
| Garbling, covering 11 cases across S0 and S1 | 2 |

S1 imports all ten native gate families, including exact permutations, packed-word hash gates and finalized witness-domain constraints. It binds constants and every public output. A compact all-gate fixture garbled to **43,055 ciphertexts**, accepted its valid witness and rejected five adversarial witnesses. A larger fixture built by upstream's actual finalizer matched the native checker across **108 canonical mutations**. See [S1.md](S1.md) and [S1_RESULTS.json](S1_RESULTS.json) for the precise fixture boundaries and measurements.

## S0 measurements retained

The original S0 code was tested at `41a4b00820211823058f7f2a77f57cef3105985e`. Its pinned-root opening emitted 57,929 ciphertexts, accepted a valid opening and rejected four mutations. These checks continue to pass in the S1 workflow.

| S0 component | Measured AND-class gates |
| --- | ---: |
| M31 addition, subtraction and multiplication combined | 2,362 |
| QM31 multiplication | 22,859 |
| Standard Blake2s hash of 64 variable bytes | 15,221 |
| Two-column, depth-three uniform Merkle opening | 57,929 |

Historical S0 timings and artifact hashes remain in [RESULTS.json](RESULTS.json). Component gate counts provide no complete-verifier size estimate.

## Upstream and interfaces

Upstream source is pinned to `starkware-libs/proving` commit `e9a38e12d09979f7a8625e233a80fecac6c38f02`. S0 primitive source hashes are listed in [upstream.json](upstream.json). Its hash profile uses standard Blake2s with M31 and the CM31/QM31 tower. Blake2s-M31 and Poseidon profiles require separate end-to-end compatibility evidence.

`core/` and `lowering/` require no third-party runtime dependencies. `adapter/` lowers the Boolean operations into the existing repository garbler with parent default features disabled, including SP1 soldering. `upstream/` compiles actual native gate and field code, imports finalized circuit constraints, and pins caller-supplied expected outputs. The caller must select a trusted circuit and statement independently of the proof witness.

The complete upstream STARK verification function has not yet been instantiated through the importer. S1's compiled native tests use synthetic circuits with upstream finalization. Authentic Shinigami proofs must be matched to their exact producer version, proof profile and public-output contract.

## Run the tests

From the repository root:

```sh
python3 nova-bitvm3/stark-bitvm3/reference_vectors.py
cargo +1.90.0 test --locked --manifest-path nova-bitvm3/stark-bitvm3/core/Cargo.toml -- --nocapture --test-threads=2
cargo +1.90.0 test --locked --manifest-path nova-bitvm3/stark-bitvm3/lowering/Cargo.toml --features test-utils -- --nocapture --test-threads=2
cargo +1.90.0 test --manifest-path nova-bitvm3/stark-bitvm3/adapter/Cargo.toml --tests -- --nocapture --test-threads=1
cargo +1.94.0 test --manifest-path nova-bitvm3/stark-bitvm3/upstream/Cargo.toml --test conformance -- --nocapture --test-threads=1
```

Generate the Python vectors before compiling the core integration tests. The generated vectors are SHA-256-pinned and checked against three literal upstream known-answer tests. CI retains resolved adapter/upstream lockfiles with the logs. Test-only fixed seeds and direct access to garbled labels are unsuitable for deployment.

All default jobs are bounded CPU tests. Prover features are checked in the dependency graph, and no Nova or Stwo proof generation runs. Only the focused workflow ran on the tested branch push.

## Required before application use

An authentic proof must pass the complete pinned STARK relation, including transcript scheduling, AIR/composition evaluation, OODS, FRI and all PCS openings. Cairo program and public outputs must bind the application statement. Ark exit/forfeit rules and UTXORef authorization/state transitions need independent application checks. Bitcoin dispute transactions and setup assumptions require their own adversarial tests.

Do not route deposits, exits or production proof receipts through this prototype. The continuation is specified in [NEXT.md](NEXT.md).
