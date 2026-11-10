# S3j: skip unused interaction-tree reconstruction in the relation audit

The S3h domain-corrected tracker run [42752306358](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42752306358) crossed the **4 GiB sampled RSS** cap during relation-tracker reconstruction, after the `S3_RELATIONS_BEGIN` marker and before any summary was printed. It ended at **4,301,787,136 bytes sampled peak RSS** after 45.65 seconds, without a proof or native acceptance. The frozen input and original source-pinned LogUp assertion remain unchanged. The failure artifact is [13733469602](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42752306358/artifacts/13733469602), SHA-256 `9245f6e70da568df1688c80d6fe889d115a9bbb305024ac8c497e68366b40aa1`.

The upstream relation evaluator `stwo-constraint-framework` at Stwo revision `aeceb74c` explicitly prohibits reading `INTERACTION_TRACE_IDX=2`. It calculates relation entries from the public preprocessing columns and base traces. Yet `stwo-cairo-prover::debug_tools::relation_tracker::track_cairo_relations` reconstructed **all three** commitment trees into CPU evaluations before beginning per-component iteration.

For this diagnostic-only experiment, `tools/instrument_relations.py` adds a source-pinned patch to the ephemerally checked-out Cairo tracker that clears the unused interaction tree from its **reconstruction copy**. The interaction commitment is still created and included in the prover before this diagnostic. The native LogUp assertion remains mandatory, and the original trace-domain preservation from S3h remains in force. Normal proving builds receive neither patch.

A single opt-in `[s3-relations]` run, after fast static checks, retains the frozen `canonical_small` trace, **4 GiB RSS / 120-second** native guard and the **15-minute** job cap. The parser accepts diagnostic completion only when the source-pinned native lookup assertion fails with the pinned residual and the relation summary is well formed; output truncation is disclosed. The experiment cannot establish a Shinigami proof or Bitcoin settlement.

If reconstruction still exceeds budget, the next step is component-local reconstruction and incremental aggregation of relation multiplicities. That would require separate source-level verification against upstream's unmodified relation evaluator.

## One-shot activation

Routine components, upstream conformance and small garbling all passed at [42753560632](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42753560632) after the diagnostic reconstruction patch. The next marker-triggered commit initiates exactly one `canonical_small` relation audit using the same immutable trace and unchanged resource ceilings. Its result will be documented in a separate run record.
