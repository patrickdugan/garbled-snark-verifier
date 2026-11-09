# S2 bounded full-verifier laboratory

The authentic pinned upstream squared-Fibonacci proof has passed native, complete Boolean and full garbled checks. Read [../S2.md](../S2.md) and [../S2_RESULTS.json](../S2_RESULTS.json) for exact evidence and reproduction commands.

`src/main.rs` offers explicit `generate DIR` and `check DIR EXPECTED_SHA256` commands. Generation uses 32/16-row traces with upstream's weak test FRI parameters. The check builds its full NoValue template independently of the proof and re-synthesizes auxiliary witnesses for five changed-proof cases. Canonicality and expected-policy mismatches are tested separately.

`src/bin/s2-garble.rs` reconstructs the fixed template from trusted source, compares its hash with the successful native/Boolean run, validates exact frozen witness hashes and runs the full relation through the repository garbler. Enable it with `--features garbled`. Ciphertexts stream to a bounded temporary file outside the uploaded evidence directory. Both active-label correctness and ciphertext-stream hashes are checked.

This example has 16 bits under upstream's FRI security accounting and is unsuitable for production. It is an example AIR rather than a Cairo/Shinigami execution statement. Bitcoin disputes and Ark/UTXORef application semantics remain separate requirements.

Routine CI skips this laboratory. An explicit `[s2-fixture]` marker or manual `s2_fixture=true` enables a ten-minute CPU job with fixed command deadlines and a 6 GiB runtime memory cap. The final workflow downloads the saved proof instead of regenerating it. No Nova, SP1 or CUDA proof is generated.

The source artifact has finite retention. Archive the evidence ZIP, including Cargo.lock, before its February 7, 2027 expiry. Copy the saved lockfile into this crate and build with `--locked` for reproduction. Seeds and direct label selection in the garbling test are test-only conventions.
