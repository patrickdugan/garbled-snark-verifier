# Continuation after S2 and S3a

## S3L result: local LogUp claim agrees

The source-pinned `range_check_11` local trace audit [passed](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42760962243): the exact signed QM31 sum of its reconstructed row relations **matched** the native `range_check_11` interaction claim. Its 2,048 rows yielded 959 nonzero distinct tuples. This local equality narrows the global mismatch without clearing it. The native Cairo global lookup assertion still failed, with 1.60 GB peak RSS. [S3L.md](S3L.md) and [S3L_RESULTS.json](S3L_RESULTS.json) record all measurements.

Next use the same bounded technique for another active component, ideally `range_check_12` or a small opcode relation, and compare its reconstructed LogUp sum with the corresponding native claim. Accumulate cross-component tuples only after each local sum agrees; preserve signed multiplicities, source revisions, and unmodified native proof acceptance.

## Updated S3j outcome (November 10, 2026)

The reconstruction-pruned relation tracker ([S3J.md](S3J.md)) still crossed **4 GiB RSS** after 39.048 seconds, before producing any tuple summary. The process was stopped by its existing budget; no native proof was generated or verified. Record: [S3J_RESULTS.json](S3J_RESULTS.json). Three routine CI jobs passed, and the S2 test-only proof path remains unchanged.

The next task is source-equivalent, **component-local reconstruction** of only the preprocessed/base columns referenced by the active relation, or a targeted LogUp generator audit. Test trace-domain, bit-reversed ordering and blowup alignment against the pinned native implementation. Keep the original lookup assertion, signed multiplicities, native verification, and receipt binding as acceptance conditions. Hold full-trace reconstruction and higher-memory cloud proving pending a measured design.

## Updated S3h blocker: tracker memory

The [S3h relation audit](S3H.md) exposed an upstream diagnostic-only row-domain indexing bug, then crossed the 4 GiB RSS guard when that bug was corrected. Its last run reached `S3_RELATIONS_BEGIN` but emitted no relation tuples before the watchdog stopped it at 4.30 GB RSS. The source-pinned initial lookup residual remains unchanged, and native Cairo proof generation has not completed.

The next proof-free engineering target is a **streaming relation-balance collector**: limit one component/relation family at a time, avoid retaining the entire reconstructed trace and vector of all `RelationTrackerEntry` values, and account for duplicates and multiplicities exactly modulo M31. Compare the streamed totals with the 37-component native QM31 residual, then rerun only one resource-capped diagnostic after local unit tests. Preserve unmodified native prover and verifier checks as the final acceptance gate. Do not raise the GitHub runner RSS cap or start a full proof while this evidence is incomplete.

## Updated blocker: S3f/S3g (November 10, 2026)

The native lookup failure under `canonical_small` is now localized to a nonzero sum of 37 present component contributions plus public memory; the exact QM31 residual and source patch are recorded in [S3F_RESULTS.json](S3F_RESULTS.json). The native assertion remains the acceptance gate. Repeating the experiment with `canonical_without_pedersen` consumed the 4 GiB RSS budget **during preprocessing**, before the lookup check (see [S3G_RESULTS.json](S3G_RESULTS.json)). This larger variant cannot be evaluated within the current cap.

The next controlled task is a bounded relation-level multiplicity audit on the low-memory `canonical_small` trace, using the pinned upstream `relation-tracker` only in an opt-in diagnostic. Record unmatched relation name and tuple values, identify the producer/trace-layout cause, patch its source, and require the original native prover and verifier to accept the same pinned transaction before attempting the S2 Boolean/garbled bridge. Avoid retrying the larger preprocessing job or raising runner memory limits without a changed and measured hypothesis.

S2 at `f90a7095` passed an authentic small Stwo proof through one fixed complete verifier in native, Boolean and garbled execution. Its 16-bit FRI test profile remains unsuitable for production. S3a at `6618c3ac` executes a pinned Shinigami adapter with explicit receipts; the native proof probe at `c8894f4` stopped at an allocation failure under the 6 GiB address-space limit. Preserve these distinct evidence boundaries.

## Resume from the saved Shinigami execution

The source artifact from run 42642735526 contains `prover_input.json.gz`, the compiled executable, source patch, receipt audit and native failure report. Its uncompressed prover input hashes to `02c8508f635c7934b1a3ac13eedf5545ea4681f1a72edc51685c7b0fd5ccc031`. Work from that trace instead of repeating execution or proving without a changed hypothesis.

First isolate the memory cost: distinguish fixed preprocessing from trace allocation and virtual-memory reservations. The failed allocation requested 469,762,048 bytes with a 6 GiB address-space cap; exact peak physical RAM was not measured. Keep the present CI cap. The compiled program has 169,856 words, while bootloader execution expanded the measured workload from 157,303 to 2,769,899 steps. Investigate a standalone fixed-program route and compile-time specialization of the two explicitly allowed script profiles. Any change to Shinigami semantics or its hash backend requires new differential tests and a new program pin.

Scarb 2.18 declares producer revision `467d5c6d`; S2 pins proving revision `e9a38e12`. Choose a matched producer/verifier pair before importing proof bytes. Define the public-memory contract explicitly: current standalone output has 21 receipt cells, bootloader output has 24, and the selected Cairo circuit expects a two-cell output digest. Bind the exact expected program and receipt in the verifier. A log check, an observed program hash or a successful generic native proof check alone does not discharge that obligation.

Obtain and freeze a native-verifiable Cairo proof under a deliberate budget. Then build its proof-independent complete verifier template, audit its graph and public bindings, and measure its Boolean gate/input count before starting garbling. Default CI must remain proof-free; `[s3-prove]` is an explicit opt-in and the saved failed attempt must remain recorded.

## Full applications and production profile

S3a admits only a fixed CSV locking script and a SHA256 hashlock, with push-only ScriptSig and no witness inputs. It does not support signature verification or establish an Ark exit/forfeit path. Ark adds ownership, transaction-graph and timeout rules. UTXORef requires an explicit authorization/state-transition relation and consumer replay state. Chain anchoring, reorg policy and current spendability need independent checks. The request echo does not supply those semantics.

Replace S2's weak FRI profile with a security-reviewed production configuration. Build and measure that complete graph; do not scale the S2 gate count into a production estimate. Audit denominator nonzero obligations, transcript binding, proof shape and finalized witness domains. Compiler correctness remains tested differentially and formally unproved.

## Fixtures, input cost and Bitcoin settlement

S2/S3 evidence archives currently depend on finite Actions retention ending February 7, 2027; preserve byte-exact durable copies. Regenerated JSON may change order and hashes. The supplied ChatGPT evidence ZIPs provide independent copies, and the optional S2 workflow fails closed when its pinned source artifact expires.

Investigate constant elimination and reducing internal witness inputs while preserving the accepted relation. S2 exposes 12,206,976 input bits, so authenticated-input costs need measurement. Specialize only on trusted public template structure.

A Bitcoin-enforceable integration still needs authenticated garbled inputs, setup assumptions, transaction/challenge construction and adversarial dispute execution. The fixed-seed/direct-label laboratory exercises correctness only. Off-chain ciphertext bytes do not measure on-chain transaction bytes.

Keep Nova, SP1 and CUDA proving outside this workstream. Narrow broad pull-request CI paths before opening a PR while retaining coverage of the sources those workflows exercise.
