# S3j: skip unused interaction-tree reconstruction in the relation audit

The S3h domain-corrected tracker run [42752306358](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42752306358) crossed the **4 GiB sampled RSS** cap during relation-tracker reconstruction, after the `S3_RELATIONS_BEGIN` marker and before any summary was printed. It ended at **4,301,787,136 bytes sampled peak RSS** after 45.65 seconds, without a proof or native acceptance. The frozen input and original source-pinned LogUp assertion remain unchanged. The failure artifact is [13733469602](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42752306358/artifacts/13733469602), SHA-256 `9245f6e70da568df1688c80d6fe889d115a9bbb305024ac8c497e68366b40aa1`.

The upstream relation evaluator `stwo-constraint-framework` at Stwo revision `aeceb74c` explicitly prohibits reading `INTERACTION_TRACE_IDX=2`. It calculates relation entries from the public preprocessing columns and base traces. Yet `stwo-cairo-prover::debug_tools::relation_tracker::track_cairo_relations` reconstructed **all three** commitment trees into CPU evaluations before beginning per-component iteration.

For this diagnostic-only experiment, `tools/instrument_relations.py` adds a source-pinned patch to the ephemerally checked-out Cairo tracker that clears the unused interaction tree from its **reconstruction copy**. The interaction commitment is still created and included in the prover before this diagnostic. The native LogUp assertion remains mandatory, and the original trace-domain preservation from S3h remains in force. Normal proving builds receive neither patch.

A single opt-in `[s3-relations]` run, after fast static checks, retains the frozen `canonical_small` trace, **4 GiB RSS / 120-second** native guard and the **15-minute** job cap. The parser accepts diagnostic completion only when the source-pinned native lookup assertion fails with the pinned residual and the relation summary is well formed; output truncation is disclosed. The experiment cannot establish a Shinigami proof or Bitcoin settlement.

If reconstruction still exceeds budget, the next step is component-local reconstruction and incremental aggregation of relation multiplicities. That would require separate source-level verification against upstream's unmodified relation evaluator.

## One-shot activation

Routine components, upstream conformance and small garbling all passed at [42753560632](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42753560632) after the diagnostic reconstruction patch. The next marker-triggered commit initiates exactly one `canonical_small` relation audit using the same immutable trace and unchanged resource ceilings. Its result will be documented in a separate run record.

## Measured opt-in outcome

The single S3j trial ran as [GitHub Actions 42753720798](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42753720798) at `0c6be6327efd5477b36f12b8c7b1133fe2c68313`. **All three routine jobs passed.** The native tracker-only job compiled and ran, emitted `S3_RELATIONS_BEGIN`, then exceeded its 4 GiB sampled RSS budget after **39.048 seconds**. Its peak RSS was **4,299,522,048 bytes**, with **5,312,008,192 bytes peak virtual size**. It emitted **zero relation tuple summaries** and never reached the original lookup-sum assertion. No native proof was produced. The watchdog terminated the process group with exit code `-15`.

The upstream prover reported trace cell counts of `[10,161,776, 23,690,176, 31,786,752]` for preprocessing, base and interaction trees. The diagnostic already omitted reconstructing the interaction tree and nevertheless crossed the same budget. The remaining cost therefore lies in the reconstructed preprocessing/base traces and the retained prover state. The exact contribution of each allocation has not been measured.

The [run artifact](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42753720798/artifacts/13734469104) has ZIP SHA-256 `727889b8824db1a64edc588299a7ec91d2486275b1c9ec2a441755774841b2c7`. [S3J_RESULTS.json](S3J_RESULTS.json) records the negative result, exact commit/source pins, run limits and evidence pointer.

## Next engineering gate

Avoid another full-tree diagnostic on the default hosted runner. Extract **component-local** original trace evaluations into a bounded cache, preferably using already-stored trace evaluations where compatible with the correct domain. Stwo's `Poly::evals` are committed evaluation-domain data; copying them directly requires verifying the circle-domain and blowup mapping against the canonical source trace. Preserve per-component masks and use the pinned native evaluator to test equivalence on small fixtures before applying it to Shinigami.

An alternative is to instrument the individual Cairo LogUp interaction generators with per-relation counters before the commitment stage, capped to selected relation names. Either route must preserve the native relation identity and make the original zero-sum assertion pass before any proof is accepted.
