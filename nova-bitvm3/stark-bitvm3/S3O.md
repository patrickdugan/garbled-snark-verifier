# S3o: caller-AIR cancellation of the XOR8 zero tuple

## Frozen evidence and question

S3m reconstructed the 65,536-row `verify_bitwise_xor_8` table from source and matched its QM31 interaction claim. Its local ledger reduced to one tuple, `CommonLookupElements[112558620,0,0,0] = -4096` (mod 2^31-1). S3n counted the producer calls and attributed all 4,096 zero-input requests for relation tag 112558620 to `bitwise_builtin`. Both are routing or table-side evidence. Neither executed the caller's AIR, so neither showed that the positive entries the proof system itself derives from the caller are `[112558620,0,0,0]` and add up to +4,096.

The native global lookup assertion still fails with the pinned residual `(1866027004 + 1908263159i) + (1713629672 + 1017174456i)u`.

Question for S3o: do the positive XOR8 entries produced by the pinned `bitwise_builtin` AIR cancel the table's -4,096 exactly?

## What the pinned AIR does

`bitwise_builtin` at Stwo-Cairo `467d5c6d` has 89 base columns and one preprocessed column (`Seq`). Its `RELATION_USES_PER_ROW` are `MemoryAddressToId` x5, `MemoryIdToBig` x5, `VerifyBitwiseXor_9` x27 and `VerifyBitwiseXor_8` x1: 38 relation entries per row. The single XOR8 use is `BitwiseXorNumBits8::evaluate([op0_limb_27, op1_limb_27], xor_col85)`, which adds `+1 * CommonLookupElements[112558620, op0_limb_27, op1_limb_27, xor_col85]`. Limbs 0 to 26 are 9 bits wide (the XOR9 uses) and limb 27 is the remaining top limb (bits 243 and up), so any operand below 2^243 gives `[112558620,0,0,0]`; the Shinigami hashing inputs are 32-bit words. The frozen run has 3,085 real bitwise-builtin instances (the VM reports `bitwise_builtin: 3,085`) padded to 4,096 segment instances, so 4,096 rows is the expected row count.

## Experiment

`tools/instrument_xor8_caller_air.py` composes onto the S3m patch (same three upstream files, same revision pin, same fail-closed shape checks) and adds three diagnostic-only changes, all behind the `relation-tracker` feature:

1. **Capture.** At `CairoClaimGenerator::write_trace`, the 89 evaluations that `bitwise_builtin` hands to `tree_builder.extend_evals` are bound to a local and copied into a write-once static before being passed on unchanged. They are the native `ComponentTrace::to_evals()` values on `CanonicCoset::new(12)`, bit-reversed, so canonical ordering is preserved. Only this component's 89 columns (4,096 rows each, about 1.5 MB) are kept. No preprocessing, base or interaction tree is reconstructed or interpolated.
2. **Evaluation.** The one preprocessed column comes from the same `PreProcessedTrace` object the native commitment used (`seq_12`, id and log size asserted). Upstream's unmodified `stwo_constraint_framework::relation_tracker::add_to_relation_entries` then evaluates the pinned `bitwise_builtin::Eval` on every row. The 4,096 x 38 = 155,648 entries are grouped by relation tag; every row must carry exactly one XOR8 entry.
3. **Ledger.** The S3m table audit keeps its 131,072 signed table entries in the same process. The caller's XOR8 entries and the table's entries are grouped by exact `(tuple, multiplicity)` and printed. The parser recomputes the signed multiplicity ledger modulo M31 per tuple from those groups, and the same two sides are summed as QM31 under the native interaction challenge.

The component's complete LogUp sum (all four relation families) is compared with its native `bitwise_builtin` interaction claim, and each family's QM31 contribution is printed, so XOR8 is never compared as a partial sum against a full claim.

### Negative controls

Six deterministic mutations are applied to the real rows in the native run and, independently, to the printed groups by the parser: a caller entry missing, duplicated, with an altered tuple, with an altered multiplicity, and a table entry missing or duplicated. Each must leave a nonzero tuple in the ledger (expected counts 1, 1, 2, 1, 1, 1). The parser rejects the log if the native count differs from its own recomputation.

## CI and safety envelope

Routine CI runs only the Python source-shape, parser and mutation tests (`test_xor8_caller_air.py`) with the existing S3 suite, plus the existing circuit and garbling jobs. Only a separate `[s3-caller]` commit marker, or workflow input `s3_xor8_caller_air=true`, runs the native diagnostic against the frozen standalone CSV input, hash-pinned as before. It is limited to 4 GiB sampled process-tree RSS, 120 seconds and the existing 15-minute job cap. It must reach the original global lookup assertion and reject the native proof (exit 101). No Nova, SP1 or CUDA work runs, and Cairo proof verification stays false.

The result is published as run annotations as well as an artifact, so it can be read without downloading the artifact.

## Local reproduction note

Regenerating the standalone prover input locally (Scarb 2.18.0, the pinned program, executable SHA-256 `a9bdc409...bef3`) gives the same 9,624,654 bytes but not the frozen SHA-256: three executions produced two different hashes, and the canonical (key-sorted) JSON hashes differ as well, so the execution output is not serialized deterministically. The Fiat-Shamir transcript, and therefore the numeric challenge-dependent values (the residual and the XOR8 claim), depend on that content. Challenge-dependent numbers are therefore taken only from the CI run on the frozen artifact. A local run is useful for shape and structure only.
