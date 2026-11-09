# S2 bounded full-verifier laboratory

This opt-in executable uses the authentic squared-Fibonacci example in the pinned upstream prover. It generates traces of 32 and 16 rows, writes a frozen proof bundle, checks that bundle with the standalone native Stwo verifier, instantiates the complete upstream arithmetic-circuit verifier independently of the proof, and lowers that relation through S1.

The statement fixes the component sizes, preprocessing root and empty public claim. The native verifier reconstructs its lookup challenges and checks the expected public sums. Boolean acceptance includes all imported constraints and canonical witness encodings. The generator's source revision is pinned to `e9a38e12d09979f7a8625e233a80fecac6c38f02`.

The FRI configuration intentionally uses upstream test settings: 3 queries, blowup factor 4 and 10 FRI PoW bits. Upstream's FRI accounting gives 16 bits for this test configuration. It has no production-security claim. This is an upstream example AIR, not a Shinigami/Cairo execution proof or a Bitcoin settlement implementation.

## Explicit commands

```sh
cargo +nightly-2026-03-06 build --manifest-path nova-bitvm3/stark-bitvm3/s2-lab/Cargo.toml
BIN=nova-bitvm3/stark-bitvm3/s2-lab/target/debug/stwo-bitvm3-s2-lab
OUT=nova-bitvm3/stark-bitvm3/s2-lab/out
timeout --kill-after=5s 60s "$BIN" generate "$OUT"
timeout --kill-after=5s 180s "$BIN" check "$OUT" "$(cat "$OUT/bundle.sha256")"
```

The expected digest is an external fixture-policy input. A digest supplied alongside an adversarial proof is not an authentication mechanism.

Generation is outside routine component CI. The extra laboratory job runs only for an explicit `[s2-fixture]` commit marker or a manual dispatch with `s2_fixture=true`. It has a ten-minute job cap, two CPU workers and a 6 GiB virtual-memory cap during execution. Compilation and runtime have separate deadlines. No SP1, Nova or CUDA prover is invoked.

Results are written only after the corresponding assertions pass. Mutated converted proof fields get newly synthesized internal values; every resulting graph must equal the independent template. Artifacts include the actual proof bundle, exact template digest, witness files and dependency lockfile. Complete garbled execution is a subsequent check and is recorded separately.
