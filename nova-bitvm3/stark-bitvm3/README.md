# S0: direct Stwo-to-Boolean prototype

Experimental components for eventual Shinigami, Ark and UTXORef verification in the repository's garbled-circuit engine. This folder exposes no complete STARK verification API. The initial acceptance bit authenticates a single Merkle opening under a pinned root.

Upstream: `starkware-libs/proving` at `e9a38e12d09979f7a8625e233a80fecac6c38f02`. Exact source blobs are in `upstream.json`. This targets standard Blake2s, with M31 and the CM31/QM31 extension tower. The channel sampling schedule follows that commit, including the draw/mix domain-separation byte and four coefficients computed as adjacent reduced words `a + 2*b`.

## Run bounded component tests

```sh
python3 nova-bitvm3/stark-bitvm3/reference_vectors.py
cargo +1.90.0 test --locked --manifest-path nova-bitvm3/stark-bitvm3/core/Cargo.toml -- --nocapture --test-threads=2
```

The core crate has no third-party dependencies. Python generates 204 deterministic component vectors from `hashlib.blake2s` and integer arithmetic; their SHA-256 is committed. Three literal upstream known-answer vectors anchor the hash/channel conventions. These fixtures are synthetic component data, not full Stwo proofs.

Implemented: canonical M31 decoding and reduction, base-field arithmetic, QM31 multiplication and checked inverse witnesses, standard Blake2s-256, channel mixing and sampling, PoW nonce checking, and a uniform-height lifted-Merkle opening checker with all index bits constrained. The public circuit shape never depends on private witness values.

## Boundaries

FRI, OODS, AIR constraints, complete transcript scheduling, mixed-height PCS opening checks and Cairo program/public-output binding still need integration. A root supplied freely by the prover authenticates nothing useful: callers must derive or pin it through the complete verifier relation. Every external field validity bit and inverse-witness check must reach acceptance. Ark exit/forfeit rules and UTXORef authorization/state transitions are separate application relations. Bitcoin dispute transactions and security review remain separate requirements.

Do not route deposits, exits, or production proof receipts through S0.
