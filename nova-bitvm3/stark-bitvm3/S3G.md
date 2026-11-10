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
