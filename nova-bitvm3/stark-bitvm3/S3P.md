# S3p: the whole lookup residual lives in two memory relations

## Frozen evidence and question

S3o showed that the XOR8 family balances exactly and that three of the 37 present components reproduce their native claims from source rows. The native global lookup assertion still fails with `(1866027004 + 1908263159i) + (1713629672 + 1017174456i)u`. Question for S3p: which relation tags carry that residual, and which public-memory entries or component rows are responsible?

## Experiment

`tools/instrument_memory_ledger.py` patches an ephemeral Stwo-Cairo `467d5c6d` checkout in two files (the prover and the relation-tracker module), behind the `relation-tracker` feature:

1. **One capture point.** `write_trace` takes `&mut impl TreeBuilder`; the prover now passes a thin wrapper that copies every `extend_evals` column (bit-reversed, canonical domain) and forwards the original vector unchanged. The wrapper checks that each column span equals the tree builder's own allocation. This replaces the one-patch-per-component capture of S3o: 717 base columns and 23,690,176 cells in total (about 95 MB of M31).
2. **Component-by-component evaluation.** For each of the 37 present components (the list is generated from the pinned `CairoComponents` struct, 66 fields, and fails closed if it changes), upstream's unmodified `add_to_relation_entries` evaluates the pinned AIR on that component's captured rows. Preprocessed columns are generated on demand from the same `PreProcessedTrace` the commitment used and dropped afterwards. Nothing is interpolated.
3. **Public data.** The terms of `PublicData::logup_sum` are rebuilt entry by entry (program, safe call, segment ranges and output for `MemoryAddressToId` and `MemoryIdToBig`, plus the initial and final `Opcodes` state) and their sum is asserted equal to the native function.
4. **Balance.** Every entry is attributed to its relation tag. Per tag the run prints the entry count, the signed multiplicity total modulo M31 and the QM31 sum under the native challenge, per component and in total. A per-tuple signed ledger is kept for the two memory tags and the opcode tag.
5. **Classification.** Tuples of the address relation with a nonzero net are mapped back to the public-memory section that produced them (program, safe call, segment ranges, output) and compressed into address runs.

The parser recomputes every sum from the lines below it (tag sums into component sums, component and public parts into family totals, families into the lookup total), and a sweep test deletes or duplicates each line of a log block. A component that misses its own claim, or a family with a nonzero total, is reported as a result and not rejected.

The original global assertion is unchanged and rejects the proof. The native run is capped at 4 GiB sampled RSS and 120 seconds, with a 90 second budget inside the diagnostic after which remaining components are recorded as skipped.

## Measured result

CI run [42846262735](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42846262735), code commit `0c6e1eb`, frozen standalone input, 34.0 s, 3,027,251,200 bytes peak sampled RSS, exit 101. A local WSL run of the same patch printed identical values (46.8 s, 3.03 GB).

| Quantity | Value |
|---|---|
| Components evaluated | 37 of 37, none skipped |
| Components whose evaluated LogUp sum equals their native claim | **37 of 37** |
| Public-data decomposition vs native `logup_sum` | equal, `(559615079, 1208624373, 2076115172, 2076164551)` |
| Sum of all family totals | `(1866027004, 1908263159, 1713629672, 1017174456)`, **equal to the native residual** |
| Relation families observed | 37 |
| Families whose QM31 total is zero | 35, including `OPCODES`, both XOR8 relations, `VERIFY_BITWISE_XOR_9`, all range checks |
| Families with a nonzero total | **2: `MEMORY_ADDRESS_TO_ID` (tag 1444891767) and `MEMORY_ID_TO_BIG` (tag 1662111297)** |
| Net multiplicity of each | +86,383 (more uses than yields) |
| Address tuples with a nonzero net | 86,383 of 524,288, every one net +1 |
| Id-to-big tuples with a nonzero net | 24,405 of 81,920 (values repeat, so nets are larger) |

So the residual is exactly the two memory families, and all other arithmetic in the proof system balances.

### Where the unmatched uses come from

All 86,383 unmatched address uses are public-memory entries; none are component rows.

| Public section | Entries in the claim | Unmatched |
|---|---|---|
| program | 169,856 | 0 |
| safe call | 2 | 0 |
| segment ranges | 22 | 16 |
| output | 86,388 | 86,367 |

The unmatched addresses form three runs: 169,862 (length 8), 292,264 (length 8) and 292,296 (length 86,367). The output builtin of this program has 21 cells; the claim lists 86,388 output entries, 86,367 of which are the cells of the range-check and bitwise builtin segments (292,296 onward).

### Why

The frozen prover input carries `public_segment_context.present = [true] x 11`, the bootloader default that declares all eleven builtin segments public. The Shinigami standalone executable has three: output, range_check and bitwise. Stwo-Cairo's `extract_public_segments` therefore reads eleven start pointers from `initial_ap` and eleven stop pointers ending at `final_ap`, which for a three-builtin layout includes eight unrelated cells at each end (the two runs of length 8). It also takes its `output` range from the first pair, so the output stop pointer is a wrong cell and the output section swallows the next builtin segments. The claim's `public_data` and `logup_sum` then count those 86,383 extra public-memory uses.

The producer yields public memory from a different list, the VM's `public_memory_addresses` in the same input, and that list already matches the true layout: 169,885 addresses, exactly the program (169,856), the safe call (2), three start and three stop pointers (6) and the 21 output cells. The memory tables' multiplicities cover that list and not the 86,383 extra entries, so each extra entry leaves one use without a yield in both memory relations.

[S3Q.md](S3Q.md) tests this explanation directly.

## Scope

This is a diagnosis of a failed proof. It does not accept a proof by itself, does not change the prover, and the original assertion stays in place.
