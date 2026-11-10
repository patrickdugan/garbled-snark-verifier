# S3n: source attribution of the XOR8 zero-input lookup

## Frozen evidence and question

S3m checked a source-captured `verify_bitwise_xor_8` table using the original preprocessing and base rows, obtaining 131,072 signed relation entries. Its sum matched the native QM31 interaction claim exactly, and its local multiplicity ledger reduced to a single zero-input tuple:

\[
  \mathrm{CommonLookupElements}[112558620,0,0,0] = -4096
  \pmod{2^{31}-1}.
\]

The original global Cairo lookup check still fails with the pinned nonzero QM31 residue. Cross-component relation cancellation remains unverified. [S3M_RESULTS.json](S3M_RESULTS.json) records the S3m values and producer versions.

## New source-pinned experiment

Count each native call to `verify_bitwise_xor_8::ClaimGenerator::add_packed_inputs` where its packed input unpacks to `[0,0,0]`. Separate relation index 0 (tag 112558620) from relation index 1 (tag 521092554). Attribute direct callers using Rust's `#[track_caller]` on that **same** method. The pinned source exposes four known source components: `triple_xor_32`, `blake_g`, `blake_compress_opcode`, and `bitwise_builtin`. All other callers are counted in an explicit `other` bucket.

`tools/instrument_xor8_counterparties.py` applies four temporary patches to a clean checkout of Stwo-Cairo revision `467d5c6d4d6d526c1db8ff69c14f2de6d57f4d73`. It composes the previously verified source-captured XOR8 local audit and a diagnostic counter in the original table generator. Every source counter uses an atomic increment alongside an existing native atomic multiplicity increment, which is kept byte-for-byte unchanged. The counter never influences trace values or the Fiat-Shamir transcript. Its records are emitted from the table's `write_trace` after the source components have populated the table and before its original commitment.

`tools/summarize_xor8_counterparties.py` requires the same failed native global lookup assertion, the exact original XOR8 QM31 claimed sum, an untruncated one-tuple table residual and a complete 5×2 source-counter inventory. It calculates the total supplied positive zero-input requests for the target relation. The predeclared hypothesis is **4,096 requests**, which would account for the table's `-4096` supply. An alternative observed count is retained as a failed or incomplete cancellation hypothesis, with the native proof status remaining false.

The caller count alone is *input-routing evidence*. Even a +4096 count cannot certify that the parent AIR components emitted the matching positive relation entries, or that all other Cairo relations balance. The native proof and application acceptance gates therefore remain closed.

## CI and safety envelope

The first code commit runs only bounded Python source-shape, mutation and parser tests, alongside existing circuit and garbling unit tests. Only a separate explicit `[s3-counterparties]` commit or workflow input `s3_xor8_counterparties=true` launches the native diagnostic. The frozen standalone CSV prover input is hash-pinned. The native execution remains limited to 4 GiB sampled process-tree RSS, 120 seconds, and a 15-minute job cap with 600 seconds for compilation. It must reach the original global zero-sum assertion and **reject** the native proof.

This experiment does not produce a full Shinigami STARK, nor any authenticated Ark/UTXORef transaction or Bitcoin-enforceable BitVM3 dispute protocol. The immediate follow-up after source attribution is to verify the caller-side **AIR relation** for the largest observed source bucket, and compare its tuple multiplicities against the table's local residual.
