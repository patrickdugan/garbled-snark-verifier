# S3g: no-Pedersen preprocessing experiment (source pinned)

The preceding [S3f diagnostic](S3F.md) captured the complete nonzero lookup sum for a small Shinigami transaction execution, with 37 present interaction components. The cause remains unidentified. This stage tests a single precise alternative hypothesis: the 20-log sequence-table ceiling in `canonical_small` is insufficient for the saved Cairo execution, whereas the upstream `canonical_without_pedersen` variant retains sequence tables through log 25. The saved input's Pedersen builtin is absent. A successful native proof must still pass the unchanged upstream verifier.

## Profile and guards

`s3-shinigami/params/canonical-no-pedersen-96.json` pins source revision `467d5c6d4d6d526c1db8ff69c14f2de6d57f4d73`, BLAKE2s, zero salt, `canonical_without_pedersen`, lifting log 26, and the same FRI parameters (pow 26, 70 queries, blowup log 1, fold 1). The upstream nominal FRI accounting is 96 bits. Full Cairo and application soundness are separate audits.

The full preprocessed profile contains 73,338,480 M31 field cells, whose raw 4-byte values account for roughly 279.76 MiB before interpolation, commitments or scratch. The saved standalone input has 9,624,654 bytes and SHA-256 `c3c3622b6c10fe54f2efbb9f48d4cbcedb96143b904aa29eaa8fb07e8b65eb55`. The compiled executable's original JSON SHA-256 remains `a9bdc409d2f7ee443ac62cabdc8df27fb44c85a435ca9350788bee890f61bef3`.

The executable only runs under an explicit `[s3-no-pedersen]` commit marker or `workflow_dispatch` input `s3_no_pedersen_profile=true`. The native binary uses the upstream `--verify` flag. A one-shot 120-second runtime is guarded by a sampled 4 GiB RSS limit; the Rust build has 600 seconds within a 15-minute job deadline. Routine CI remains proof-free. Proof outputs retain a 128 MiB file ceiling, and the frozen input is removed after use.

The Python preflight rejects any Pedersen builtin usage or unpinned profile parameters. Tests prevent accepting changed FRI security, bool-as-integer aliases, shifted lifting size or missing builtin metadata.

## Acceptance and scope

A successful one-shot native run would establish that the source-matched Rust verifier accepted one STARK proof for the restricted standalone Shinigami CSV execution. It would not authenticate Ark state, UTXORef state transitions, proof-bound Shinigami executable identity, Bitcoin chain state or BitVM3 dispute execution. Compatibility with S2's separately pinned Stwo verifier needs an explicit translation of proof and public outputs.

If the global lookup sum remains nonzero, the failed result should be retained and the next diagnostic should inspect relation-specific multiplicities rather than disabling the source assertion.

## Measured one-shot outcome

The run [42745990977](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42745990977) built the source-matched native prover successfully. Its explicit **one** proof attempt was terminated by the 4 GiB sampled RSS watchdog while generating the preprocessed Merkle commitment. The proof process ran for **19.315 seconds**, reported **4,295,876,608 bytes peak RSS** (limit **4,294,967,296**) and **7,535,628,288 bytes peak virtual size**, and exited on SIGTERM (`-15`). The global lookup check was **never reached**. Native proof generation and verification remain incomplete. All three regular CI jobs passed independently.

The [failure artifact](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42745990977/artifacts/13731358056) contains the exact preflight, resource report, build and proof logs (ZIP SHA-256 `b99042e4aab5c748059dbfba19e96e11c048f5c2c4830cb5c8ddd805f96bf086`). [S3G_RESULTS.json](S3G_RESULTS.json) records the machine-readable negative result. This run cannot determine whether full-length sequence preprocessing fixes the earlier `canonical_small` lookup-sum mismatch.

The next proposed investigation is an **opt-in, memory-budgeted relation-level balance audit** of the original 1.2 GiB `canonical_small` trace. The pinned upstream `stwo-cairo-prover` has a `relation-tracker` feature that summarizes nonzero multiplicities per relation and tuple. It interpolates trace polynomials and can be memory-intensive, so its cost and output should be capped separately before execution. The native lookup assertion must remain enabled for acceptance. A matched producer/verifier proof will be required after any repair.
