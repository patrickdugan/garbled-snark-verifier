# S0: direct Stwo-to-Boolean prototype

Experimental components for eventual Shinigami, Ark and UTXORef verification in the repository's garbled-circuit engine. The initial acceptance bit authenticates a single Merkle opening under a pinned root. Complete STARK verification remains a later milestone.

## Verified result

Both jobs passed on code commit `41a4b00820211823058f7f2a77f57cef3105985e` in [workflow run 42621218798](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42621218798).

The dependency-free core passed 8 tests over 204 independently generated component vectors, with literal upstream hash/channel known-answer tests. The repository adapter also passed its garbled test: one valid opening reached the accept label; four mutations reached the reject label. Each case emitted 57,929 ciphertexts, matching the Boolean non-free gate count.

| Component | Measured AND-class gates |
| --- | ---: |
| M31 addition, subtraction and multiplication, combined | 2,362 |
| QM31 multiplication | 22,859 |
| Standard Blake2s hash of 64 variable bytes | 15,221 |
| Two-column, depth-three uniform Merkle opening | 57,929 |

Core tests took 0.06 seconds after compilation. The garbling test took 0.20 seconds across all five cases, including plain execution and garble/evaluate checks. These are hosted-runner test timings. They do not measure a complete STARK verifier. Exact job IDs, artifact hashes and scope flags are recorded in [RESULTS.json](RESULTS.json).

## Upstream profile

Upstream: `starkware-libs/proving` at `e9a38e12d09979f7a8625e233a80fecac6c38f02`. Exact source blobs are in [upstream.json](upstream.json). This targets standard Blake2s, with M31 and the CM31/QM31 extension tower. The channel sampling schedule follows that commit, including the draw/mix domain-separation byte and four coefficients computed as adjacent reduced words `a + 2*b`.

The separate Blake2s-M31 and Poseidon profiles require their own compatibility work. An actual Shinigami proof must be matched to its producer version and verifier profile before integration.

## Run bounded component tests

From the repository root:

```sh
python3 nova-bitvm3/stark-bitvm3/reference_vectors.py
cargo +1.90.0 test --locked --manifest-path nova-bitvm3/stark-bitvm3/core/Cargo.toml -- --nocapture --test-threads=2
cargo +1.90.0 test --manifest-path nova-bitvm3/stark-bitvm3/adapter/Cargo.toml --test garbled -- --nocapture --test-threads=1
```

The Python step must run before compiling the core tests because those tests include the generated vectors. The core crate has no third-party dependencies. Its SHA-256-pinned vectors come from `hashlib.blake2s` and integer arithmetic, with three literal upstream known-answer vectors anchoring the hash/channel conventions. These are synthetic component data. Upstream Stwo itself was not compiled in this milestone.

The adapter calls the existing repository circuit builder in execute, garble and evaluate modes. It disables parent default features, including SP1 soldering. Its test uses fixed seeds and direct input-label access solely for local correctness checks. CI retains the resolved adapter lockfile as an artifact.

CI limits the component job to five minutes and the adapter job to ten, with shorter command timeouts. Only the focused workflow ran on the tested branch push. No Nova or full STARK proof was generated.

## Implemented

Canonical M31 decoding and reduction, base-field arithmetic, QM31 multiplication and checked inverse witnesses, standard Blake2s-256, channel mixing and sampling, PoW nonce checking, and a uniform-height lifted-Merkle opening checker with all index bits constrained. The public circuit shape never depends on private witness values.

The tests check field aliases, zero inverse witnesses, hash block boundaries, transcript draw/reset order, mutation of the leaf and each sibling, root mismatch, and out-of-range query indices. The pinned-root garbling test checks the active output label against both possible labels.

## Remaining acceptance requirements

FRI, OODS, AIR constraints, complete transcript scheduling, mixed-height PCS opening checks and Cairo program/public-output binding still need integration. A root supplied freely by the prover does not authenticate the application statement: callers must derive or pin it through the complete verifier relation. Every external field validity bit and inverse-witness check must reach acceptance.

Ark exit/forfeit rules and UTXORef authorization/state transitions are separate application relations. Bitcoin dispute transactions and security review remain separate requirements. See [NEXT.md](NEXT.md) for the bounded continuation plan.

Do not route deposits, exits, or production proof receipts through S0.
