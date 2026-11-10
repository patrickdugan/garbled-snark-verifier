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

## Single native diagnostic activation

The source-counter code at [commit 1e6a695b](https://github.com/patrickdugan/garbled-snark-verifier/commit/1e6a695b7e78df6e0fdb9266266be4b1bd9a14c8) passed all three focused routine jobs in [run 42772601202](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42772601202), including fail-closed source and evidence tests. This separate `[s3-counterparties]` marker authorizes **one** native source-auditing diagnostic against the already-frozen Shinigami CSV fixture, under the original 4 GiB sampled RSS, 120-second runtime and 15-minute CI limits. The result will disclose all five callsite groups for each XOR8 relation and record whether the tag-112558620 input-routing tally matches the prior table supply of −4096. The original native global lookup zero-sum assertion must still reject the proof.

## S3n measured result: producer calls fully attributed

The one-shot trial [42772759725](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42772759725) passed all four jobs. Every one of the 4,096 positive requests for the all-zero tuple under relation index 0 (tag 112558620) came from **`bitwise_builtin`**. The other observed source groups `triple_xor_32`, `blake_g`, `blake_compress_opcode` and `other` each supplied zero requests. Every source supplied zero all-zero requests for relation index 1 (tag 521092554). The source request total +4,096 exactly accounts for the XOR8 table's independently recorded `[112558620] -> -4096` local row multiplicity.

The frozen standalone Cairo input reports the bitwise-builtin memory segment as addresses **357,832 through 378,312**, totaling 20,480 memory cells. The pinned Stwo-Cairo builtin format uses **five** cells per instance, and `CairoClaimGenerator` derives its log-size from this length. The source therefore has **4,096 bitwise-builtin instances**, log-size 12. The pinned `bitwise_builtin` AIR declares one positive `VerifyBitwiseXor_8` use per row. Its `BitwiseXorNumBits8::evaluate` subroutine adds a positive `CommonLookupElements` entry with tag 112558620. The native producer counter reports all 4,096 supplied tuples were `[0,0,0]`. This source crosswalk supplies a concrete explanation for the table's zero tuple, although the AIR of the caller itself was not executed by this diagnostic.

Native runtime was **19.227 seconds**, with **1,606,266,880 bytes peak sampled RSS** under the unchanged 4 GiB guard. The original native Cairo zero-sum assertion rejected with exit code 101, reproducing the same QM31 global residual `(1866027004 + 1908263159i) + (1713629672 + 1017174456i)u`. It generated no complete Cairo STARK proof and made no Bitcoin authorization.

The exact source patch, bounded-run logs and structured caller tally are in [Actions artifact 13742429158](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42772759725/artifacts/13742429158), ZIP SHA-256 `9130abaa246ecc9b52564fb11d8384b284a74c9d3b05539d55d373e38a785163`; [S3N_RESULTS.json](S3N_RESULTS.json) contains the machine-readable result.

## Next: audit the caller AIR

The next suitable bounded experiment uses source-pinned bitwise-builtin base columns to confirm that the positive `BitwiseXorNumBits8` AIR entries for the same 4,096 rows really are `[112558620,0,0,0]`. These source rows should be captured at the original `bitwise_builtin::ClaimGenerator::write_trace` boundary, where `ComponentTrace::to_evals` has canonical bit-reversed row ordering. The audit must retain native field signs and call the unmodified upstream relation evaluator. This would directly test caller-side cancellation within the same relation tuple, then redirect the global LogUp investigation to other component or public-memory contributions.
