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

Routine CI runs only the Python source-shape, parser and mutation tests (`test_xor8_caller_air.py`) with the existing S3 suite, plus the existing circuit and garbling jobs. Only a separate commit marker (`s3-caller` in square brackets), or workflow input `s3_xor8_caller_air=true`, runs the native diagnostic against the frozen standalone CSV input, hash-pinned as before. It is limited to 4 GiB sampled process-tree RSS, 120 seconds and the existing 15-minute job cap. It must reach the original global lookup assertion and reject the native proof (exit 101). No Nova, SP1 or CUDA work runs, and Cairo proof verification stays false.

The result is published as run annotations as well as an artifact, so it can be read without downloading the artifact.

## Measured result: the XOR8 zero tuple cancels exactly

The native diagnostic ran once in CI on the frozen standalone input: [run 42834108025](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42834108025), job `s3-small-profile` (129891592008), code commit [ffe0596](https://github.com/patrickdugan/garbled-snark-verifier/commit/ffe059656e781328d55ac8232a581fd0bdd855bb). The three routine jobs in the same run passed. The `[s3-caller]` marker was in that commit's message, so the diagnostic started on the first push. That is the one CI native run of this stage.

| Quantity | Value |
|---|---|
| Source rows captured | 4,096 (log size 12), 89 base columns plus the `seq_12` column, digest `6ea9ccb9974ec6bdaf50e14cdc7f9d826117d848f058a3d219682660fdf72f83` (Blake2s) |
| Entries from the pinned AIR | 155,648 = 4,096 x 38; every row has exactly one XOR8 entry |
| Caller XOR8 entries | 4,096, every one `[112558620,0,0,0]` with multiplicity +1; signed total **+4,096** |
| Table XOR8 entries | 131,072, of which one is nonzero: `[112558620,0,0,0]` with multiplicity -4,096 (2147479551 mod M31); signed total **-4,096** |
| Signed ledger (mod M31) | caller + table = 0 for every tuple; **0 nonzero tuples** |
| QM31 ledger under the native challenge | caller `(42348298, 1055827101, 773699044, 64557429)` + table `(2105135349, 1091656546, 1373784603, 2082926218)` = `(0, 0, 0, 0)` |
| Negative controls (nonzero tuples left) | missing caller entry 1, duplicated caller entry 1, altered caller tuple 2, altered caller multiplicity 1, missing table entry 1, duplicated table entry 1; the parser recomputed every count from the printed groups |
| Component LogUp vs native claim | recomputed = claimed = `(1876312143, 249812616, 1375950257, 238553224)`; the four relation families add up to it exactly |
| Native run | 17.903 s, peak sampled RSS 1,639,202,816 bytes (1.64 GB) under the 4,294,967,296-byte cap, peak VMS 1,829,367,808 bytes, exit code 101 |
| Native global assertion | still fails with `(1866027004 + 1908263159i) + (1713629672 + 1017174456i)u`; no Cairo proof produced or verified |

The XOR8 table claim of S3m, `(2105135349, 1091656546, 1373784603, 2082926218)`, is the table half of the QM31 ledger, so the cancellation uses the same frozen transcript as S3m and S3n.

### What bitwise_builtin contributes to the other families

The same evaluation accounts for the rest of the component's claim. These families are **not** balanced by anything in this experiment; they are the supply side's to cancel.

| Relation tag | Name | Entries (+1 each) | Distinct tuples |
|---|---|---|---|
| 1444891767 | `MemoryAddressToId` | 20,480 | 20,480 (one per builtin-segment cell, 357,832 to 378,311) |
| 1662111297 | `MemoryIdToBig` | 20,480 | 9,431 |
| 95781001 | `VerifyBitwiseXor_9` | 110,592 (27 per row) | 8,481 |
| 112558620 | `VerifyBitwiseXor_8` | 4,096 | 1 |

### Interpretation

The positive XOR8 entries that the pinned AIR derives from the 4,096 original `bitwise_builtin` rows are exactly 4,096 copies of `[112558620,0,0,0]`, and they cancel the table's -4,096 both as an M31 multiplicity ledger and as a QM31 sum. Together with S3n (no other producer calls the table with a zero input, and relation index 1 is unused), the XOR8 relation family is balanced, so it contributes nothing to the global residual. The caller component's own LogUp sum equals its native interaction claim, so its AIR evaluation under the native challenge is consistent with the claim the prover committed to. Three components now agree locally with their native claims: `range_check_11` (S3l), `verify_bitwise_xor_8` (S3m) and `bitwise_builtin` (S3o).

The global lookup assertion still fails and no proof exists. The remaining residual lies in other relation families, in the 34 other present components, or in public memory.

## Next: where the residual can still hide

The remaining unbalanced terms, ranked by what S3o measured:

1. **The memory relations (`MemoryAddressToId`, `MemoryIdToBig`) with public memory.** Every builtin and opcode component adds uses of these two tags, and `bitwise_builtin` alone adds 40,960 of them. Public memory (with the initial and final `Opcodes` state) is the only part of the global sum that no component's AIR produces, so a mismatch in how the adapter emitted it, or in how the producer counted its uses in the memory tables' multiplicities, would not show up in any per-component check. The next experiment is a per-tuple ledger for these two tags across **all** active components plus the public-memory entries, against the memory tables' yields.
2. **`VerifyBitwiseXor_9`.** It is the largest family of this component (110,592 entries) and has its own table, with a 2^18-row preprocessed trace. It reuses the S3m/S3o technique unchanged but is the larger of the two table audits.

The enabling change is the capture boundary S3o just validated. S3h and S3j crossed 4 GiB because they interpolated and re-evaluated whole trees. Capturing every component's base evaluations where they enter `TreeBuilder::extend_evals` (one place, instead of one patch per component) and evaluating each component on its own, with its preprocessed columns generated on demand, keeps only the tuples of the two memory tags in a streaming ledger. That is a design to measure, not a result: its memory use is unmeasured.

## Local reproduction note

The standalone prover input regenerated locally (Scarb 2.18.0, the pinned program, executable SHA-256 `a9bdc409...bef3`) is the same size, 9,624,654 bytes, but not byte-identical to the frozen file. Three executions gave two different SHA-256 values, and the key-sorted canonical JSON hashes also differ, so the execution output is not serialized in a stable order. Despite that, a local run of the same patch (WSL, same pins, 23.4 s, 1.64 GB RSS) printed the same source digest, the same component claim, the same XOR8 claim and the same global residual as the CI run, so the prover's trace does not depend on that ordering. The CI run on the frozen artifact is the recorded evidence; the local run is a cross-check only, and the log block it printed is kept as the fixture `tools/fixtures/s3o-caller-block.txt`.

## Scope

This does not produce a Cairo STARK proof, a Shinigami execution receipt that anything verifies, a BitVM3 dispute, or any Ark or UTXORef state. It shows one relation family of one component pair balanced. Full proof verification stays false until the original native verifier accepts a complete proof.
