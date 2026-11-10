# S3h: bounded Cairo relation-multiplicity audit

The pinned Stwo-Cairo revision `467d5c6d4d6d526c1db8ff69c14f2de6d57f4d73` has a native `relation-tracker` feature. Its diagnostic reconstructs original trace evaluations from committed polynomial evaluations and summarizes unmatched per-relation tuples with multiplicities. The upstream call appears **after** the debug assertion for the global LogUp sum. Consequently the S3f `canonical_small` failed proof cannot reach the tracker without a diagnostic-only hook.

## Controlled hypothesis

S3f measured a nonzero QM31 residual with 37 present interaction components under the smaller preprocessed trace. The original assertion failed with native exit code 101, around 1.23 GiB sampled RSS. S3g's full-sequence no-Pedersen profile crossed the 4 GiB memory guard while committing its preprocessed trace, before the LogUp check. Neither run produced a native Cairo proof.

S3h instruments `crates/prover/src/prover.rs` in a clean, ephemeral copy of the exact pinned upstream revision. With the `stwo-cairo-prover/relation-tracker` feature enabled, the existing debug assertion is **postponed until immediately after** committing the interaction trace and auditing the unmatched relation tuples. Uninstrumented builds retain the original assertion location. Both paths perform the original native nonzero-sum assertion. The feature is only built when `[s3-relations]` or the explicit `s3_relation_audit=true` workflow input is provided.

The trace tracker can interpolate, allocate and examine large numbers of rows. The full diagnostic stays within **4 GiB sampled process-tree RSS**, **120 seconds** of execution, and the existing **15-minute CI job budget**, with at most two Cargo build workers and a 600-second cold-build cap. Its Rust output is capped at 65,536 UTF-8 bytes. A truncated summary is labeled as such and does not claim complete relation coverage.

`tools/summarize_relations.py` requires the native prover to fail with code 101 and exactly the S3f baseline residual, and it validates strict diagnostic delimiters and tuple shapes. Its JSON reports up to four unmatched tuple examples per relation and explicitly leaves proof, application, garbled and settlement status false. Any missing diagnostic, changed source shape, memory-budget exit or unexpected prover acceptance fails this experiment's parser.

Routine CI runs only fast unit tests of the patch generator and log parser. No routine proof generation or full garbling occurs.

## Evidence and follow-up

A successful S3h **diagnostic job** means that the native assertion rejected the same witness and the relation tracker produced parseable evidence under budget. It does not establish proof soundness. The next source-side fix must explain and remove the unmatched relation multiplicity, preserve every original AIR/LogUp obligation, and pass a source-matched native prover **and** verifier check. Only then can the correct Cairo verifier be lowered to Boolean gates and evaluated through the BitVM3 garbler.

The recorded relation audit is scoped to the saved Shinigami regtest CSV fixture. Ark exit semantics, UTXORef authorization and actual Bitcoin dispute settlement remain future, independently tested application relations.

## Single source-pinned diagnostic activation

The first code-only pass at `f43adcb4d5817ecf1fb343700f588609d3095365` passed all three routine CI jobs in [run 42750869821](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42750869821), including the instrumentation/parser unit tests. The following separate, marker-triggered commit is the only authorized S3h relation-tracker trial. It will reproduce the baseline failed native lookup assertion, print a capped relation anomaly summary, and retain process-tree RSS and elapsed-time evidence. A failed resource guard is an inconclusive diagnostic that must remain visible as a failed job.

## First attempt: upstream tracker row-domain panic

[Run 42751015710](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42751015710) compiled the exact upstream relation tracker and reached the interaction commitment, but the tracker panicked in `crates/constraint-framework/src/prover/relation_tracker.rs:95`: `index out of bounds: the len is 2 but the index is 2`. The failed one-shot diagnostic ran **25.981 seconds** with **2,070,794,240 bytes sampled peak RSS**, under the original 4 GiB guard. No relation summary, native STARK proof, or verifier acceptance resulted. The prior native lookup assertion was not reached because the tracker panicked first. The routine component, garbling and conformance jobs succeeded.

Source inspection identifies a separate defect in the tracker reconstruction at `stwo_cairo_prover/crates/prover/src/debug_tools/relation_tracker.rs`. It calls `reduce_degree(poly.evals.clone().interpolate())` and then re-evaluates on a domain selected from **the reduced polynomial degree**. Constant columns may therefore have two values even though the relation evaluator iterates the original component's much larger row count. The next diagnostic patch preserves `poly.evals.domain` before degree reduction and uses that original domain during reconstruction, with the original LogUp assertion intact and no changes to proof or AIR arithmetic. Both transient upstream-file edits are source-pinned and SHA-256 logged.

The [failed-run artifact](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42751015710/artifacts/13734345821) preserves the original exception and resource report, ZIP SHA-256 `b6ec404a41aa84bbeebcb1b62be79fe63d05d3511b24cbe0588ffe2773258bbb`. The measured failure is a **diagnostic tooling bug**; it says nothing new about the validity of the Shinigami execution or the native lookup residual.
