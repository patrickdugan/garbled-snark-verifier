# S3m: source-pinned XOR8 LogUp claim comparison

## Existing evidence

S3f recorded a nonzero global QM31 LogUp residual from the standalone Shinigami regtest CSV execution. It captured 37 present interaction component sums. S3L reconstructed 2,048 range_check_11 rows and verified the component's signed LogUp sum against its native interaction claim, limb for limb. The global LogUp assertion continued to reject the proof. All four S3L jobs passed in [run 42760962243](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42760962243).

The next selected component is **verify_bitwise_xor_8**, which has a **nonzero** claimed sum in the same frozen S3f trace:

\[
(2105135349+1091656546i)+(1373784603+2082926218i)u.
\]

The source-pinned Cairo AIR at 467d5c6d4d6d526c1db8ff69c14f2de6d57f4d73 defines verify_bitwise_xor_8 with three preprocessed columns, two base columns and a canonical 2^16-row domain. It emits two common-lookup relations per row, for **131,072** signed relation entries. This tests the component-local reconstruction on a larger, multi-column AIR within the same memory budget.

## Diagnostic implementation

The instrument_xor8_relations.py script specializes the S3L component-local collector, maintaining source-checking and temporary patch discipline. It selects precisely five source trace columns from the pinned FrameworkComponent and evaluates them on the canonical 65,536-row circle domain, including degree-reduced constants. The upstream add_to_relation_entries evaluator computes the signed field tuples.

To bound runtime, QM31::batch_inverse computes inverse denominators using Stwo's exact field arithmetic. The code checks each denominator for zero, sums signed multiplicity divided by challenge.combine(tuple), and compares the reconstructed result against the native verify_bitwise_xor_8 claimed sum. Every source shape is checked, including all three preprocessed columns, the two base columns, 65,536 rows and 131,072 relation entries.

The summarize_xor8_relations.py parser accepts only the pinned global residual, the original native assertion failure, and the XOR8 claim recorded by S3f. A matching component sum is reported as local consistency evidence. A mismatch records its exact four QM31 limbs for investigation. The relation text has a strict 64 KiB cap and may be labeled truncated. All output remains a partial inventory of relation tuples.

Native Cairo proving, compatible garbled verification, Ark/UTXORef application validation and Bitcoin dispute settlement remain outstanding.

## Resource and acceptance bounds

The first push runs proof-free Python and Rust checks, including shape drift and malformed evidence. One explicitly marked [s3-xor8] commit or s3_xor8_relation_audit=true workflow dispatch permits a single native diagnostic using the immutable saved Shinigami CSV input. The run keeps 4 GiB sampled RSS, 120 seconds runtime, a 600-second source-matched compile limit and a 15-minute overall job cap. Nova, SP1, CUDA, and full STARK-to-BitVM3 garbling remain outside this experiment.

A successful diagnostic requires a source-pinned component comparison and the original global lookup assertion's rejection of the native proof. If XOR8's source sum matches, the remaining work is identifying the discrepancy in other component claims or cross-component/public-memory cancellation while preserving the original proof relation.

## Native one-shot activation

The proof-free source/parser tests, upstream conformance and tiny garbling tests passed at [run 42764695755](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42764695755) for commit `4cd07d3d`. One explicit commit marker now activates the bounded XOR8 native diagnostic on the same frozen Shinigami input. The tested patch imports exact upstream component metadata and reuses its relation evaluator; the original failed global LogUp assertion is the required final condition. The native run will record the component's four QM31 sum limbs, their equality with the S3f pinned claimed value, memory and timing, even when a component mismatch is observed. No Nova or Bitcoin proving is involved.

## First bounded native result and source-domain repair

The one-shot run [42764839454](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42764839454) compiled successfully and entered the XOR8 tracker. It hit the diagnostic shape assertion **source polynomial exceeds selected component trace degree** before emitting tuple values. The native process exited 101 after **21.142 seconds** with **1,601,064,960 bytes peak RSS**, under the fixed 4 GiB guard. It never reached the global lookup zero-sum assertion and produced no Cairo proof. The three routine CI jobs passed.

Source inspection confirmed that upstream BitwiseXor preprocessing creates canonical 16-log source evaluations through BitwiseXor::gen_column_simd. The commitment scheme may lift those source polynomials to a larger domain. Reducing their committed degree and requiring it to fit exactly 16-log was an overly restrictive diagnostic reconstruction assumption. The source-pinned correction reads the **three original preprocessing columns** directly from the exact PreProcessedTrace object already held by the native prover, checks their stable IDs, log sizes and 65,536-row lengths, and retains reconstructed committed-polynomial checks for the two base-trace columns. The complete proof relation and global native assertion remain unchanged. The parser requires an explicit original-table source marker.

The negative result is preserved in [S3M_FIRST_FAILURE.json](S3M_FIRST_FAILURE.json) and [artifact 13739153977](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42764839454/artifacts/13739153977) (ZIP SHA-256 1186f62b9e7f1fac9790cc0db97c5d25abd91fbec46975a6a733c4d07001e4c1). This test isolated a mismatch in the diagnostic's assumptions about source and lifted commitment domains, leaving the XOR8 claimed-sum comparison open.

## Source-table retry

The source-reconstruction repair in commit `dcfa35c6` passed all three routine jobs in [run 42766297752](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42766297752). A second and separate opt-in `[s3-xor8]` trial applies only the pinned diagnostic source changes and retains the same frozen input, 4 GiB sampled RSS limit and 120-second native execution cap. The native global LogUp assertion must remain the final failed-proof gate; any source-mapping failure is recorded as diagnostic failure.

## Second native trial: base source-domain mismatch

The corrected preprocessing source in [run 42766465895](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42766465895) reached the XOR8 tracker and emitted `S3_LOCAL_PREPROCESS_SOURCE canonical_pinned_original`. Its next assertion rejected the **base** committed-polynomial reconstruction: `base source polynomial exceeds selected component degree` at the diagnostic source line. Native runtime was **20.218 seconds** with **1,582,567,424 bytes sampled peak RSS**. The original global lookup equality was not reached; the source-matched native proof remains unverified. All three routine jobs passed. The failure is saved in [artifact 13739769029](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42766465895/artifacts/13739769029), ZIP SHA-256 `0f4c3597018e62cd383735f195c6825516d63d0cc7c0ffcb0ed0c1aaed8a98cb`.

The S3m follow-up captures the original two 65,536-row `verify_bitwise_xor_8` base columns **at the producer’s `CairoClaimGenerator::write_trace` call**, before `tree_builder.extend_evals`. The upstream Stwo `ComponentTrace::to_evals` creates the canonical `CanonicCoset::new(16).circle_domain()`. In the ephemeral relation-tracker build, a source-pinned `OnceLock` stores those two vectors for the local audit. The exact same vectors are passed onward to the unmodified commitment builder. Compilation without the `relation-tracker` feature uses the same converter and commitment data flow. The audit rejects unexpected source-column domain or row count and requires a recorded `S3_LOCAL_BASE_SOURCE captured_native_write_trace` marker.

A third ephemeral file patch is now required under the source pin: `crates/prover/src/witness/cairo_claim_generator.rs` alongside the existing prover and tracker changes. The source-identity check validates all three files before changing any. Routine CI tests the source-anchored capture and the parser before another explicitly marked trial. The global native lookup equality remains the proof-acceptance gate.
