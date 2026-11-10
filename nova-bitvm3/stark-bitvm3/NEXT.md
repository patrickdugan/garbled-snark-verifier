# Continuation after S2 and S3a

## S3q: the native Shinigami proof blocker is cleared (laboratory profile)

The global lookup residual of S3f to S3o was an **input mismatch**, not a prover or AIR defect. S3p ([S3P.md](S3P.md), [run 42847980948](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42847980948)) evaluated all 37 active components, each of which reproduces its native claim, and balanced every relation family: 35 are exactly zero and the two memory relations carry the whole residual, +86,383 uses each. All 86,383 unmatched address uses are public-memory entries. The frozen prover input declares all eleven builtin segments public (the bootloader default) although the standalone Shinigami executable has three (output, range_check, bitwise), so the claim lists 86,367 builtin cells as program output and eight garbage pointer cells at each end, none of which the memory tables yielded; the VM's own `public_memory_addresses` already matches the real layout.

S3q ([S3Q.md](S3Q.md), [run 42849912173](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42849912173)) changes only `public_segment_context.present` to `[true,false,true,false,true,false,false,false,false,false,false]` and runs the unmodified pinned prover with its built-in verification: **the native verifier accepts a complete proof** of the frozen standalone CSV execution, 47,197,275 bytes (SHA-256 `ab65f837…fabb2`, identical locally and in CI), 32.1 s, 2.66 GB peak RSS, under the 120 s and 4 GiB caps. The profile is the laboratory `canonical_small` (96-bit nominal FRI); the proof binds no program identity, receipt or application statement.

The flags `native_proof_verified` can now be true for this profile; every application and Bitcoin flag stays false. Default CI stays proof-free; `[s3-context]` is the explicit opt-in.

### Next: the verifier side

1. **Matched pair.** The proof format is Stwo-Cairo `467d5c6d` (Scarb 2.18's producer). The Boolean verifier of S2 is pinned to Stwo `e9a38e12`. Decide between porting that verifier to this format (`CairoProofForRustVerifier`) and re-proving with a prover at the S2 revision with the same context correction; measure both.
2. **Public-memory contract.** The verifier must pin the expected program (the 169,856-word executable hash), the 21 output words, the initial and final state, and the `present` vector of the public segment layout: a prover that chose another vector would produce a different claim. Bind all of it, not only a generic acceptance.
3. **Input size.** The 47 MB JSON is not the wire format. Measure the binary proof (`CairoProofForRustVerifier`), the number of authenticated input bits and the Boolean gate count of the proof-independent verifier template for this revision before any garbling.
4. **Profile.** Replace the 96-bit laboratory profile by a reviewed production configuration and rebuild the template for it; do not scale the S2 gate count.
5. Keep Nova, SP1 and CUDA proving outside this workstream.

The producer default is worth reporting upstream: at `467d5c6d` the adapter (`stwo_cairo_prover/crates/adapter/src/adapter.rs`, line 45) calls `PublicSegmentContext::bootloader_context()` unconditionally, and the prover input Scarb 2.18 wrote for this standalone executable carries that all-present context, so an executable with fewer than eleven builtins gets an unbalanced claim.

## S3o: XOR8 zero tuple cancels at the caller AIR

[Run 42834108025](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42834108025) evaluated the pinned `bitwise_builtin` AIR, through upstream's unmodified relation evaluator, on its 4,096 original base rows. All 4,096 positive XOR8 entries are `[112558620,0,0,0]` (+4,096); the table side is `-4096`. The signed M31 ledger and the QM31 sum under the native challenge are both zero, six negative controls (missing, duplicated or altered entries) are all detected, and the component's full LogUp sum equals its native claim. Native run: 17.903 s, 1.64 GB peak RSS, exit 101. The global lookup assertion still fails with the same residual and no proof exists. See [S3O.md](S3O.md) and [S3O_RESULTS.json](S3O_RESULTS.json).

The XOR8 family is balanced and out of the residual. Next, extend the same source-capture technique to a per-tuple ledger for the **`MemoryAddressToId` and `MemoryIdToBig` relations across all active components plus public memory**, against the memory tables' yields. Capture every component's base evaluations once, where they enter `TreeBuilder::extend_evals`, evaluate components one at a time, and keep only the tuples of those two tags. `VerifyBitwiseXor_9` (110,592 entries from this component, a 2^18-row table) is the second target. Keep the original lookup assertion, signed multiplicities and the native verifier as acceptance conditions.

## S3n: XOR8 zero-tuple routing accounted for

The [bounded native source audit](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42772759725) reports that **all 4,096** zero-input calls for XOR8 relation tag 112558620 originate from the `bitwise_builtin` producer, with zero contributions from the other four source groups. The table's single residual tuple is `−4096` and is thus reconciled at the input-routing level. The frozen bitwise-builtin segment contains exactly 4,096 instances and its pinned AIR declares one positive XOR8 relation per row. The global Cairo LogUp assertion remains nonzero and rejects the native proof. See [S3N.md](S3N.md) and [S3N_RESULTS.json](S3N_RESULTS.json).

Next test the **positive caller AIR tuples** directly through a bounded native `bitwise_builtin` source-row audit. Once confirmed, the XOR8 zero tuple can be excluded from likely global mismatches; investigate other nonzero relation tuples and the public-memory terms with source-matched per-component accounting. Keep the full Shinigami/Cairo proof and BitVM3 settlement flags false until original native prover/verifier acceptance succeeds.

## S3m completed: XOR8 source rows agree with native claim

[Run 42769770190](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42769770190) successfully compared `verify_bitwise_xor_8` source rows with its pinned native interaction claim. Recomputed QM31 LogUp matched all four limbs from **131,072** relation entries. The local signed multiplicity ledger leaves one tuple `[112558620] -> -4096` (mod M31). This is a component-local result; the global lookup assertion still fails. Peak sampled RSS **1.60 GB**, native runtime **19.015 seconds**. All four CI jobs passed; [S3M.md](S3M.md) and [S3M_RESULTS.json](S3M_RESULTS.json) preserve the evidence.

Next source-track positive uses of the XOR8 tag `112558620` through `triple_xor_32`, `bitwise_builtin`, `blake_g`, and `blake_compress_opcode`. Determine whether their zero-input padded-row multiplicities cancel −4096. Use the source-pinned original Cairo row values and a targeted M31 ledger before attempting broader global cancellation. Keep source-match checks, native claimed-sum verification, and original global zero-sum assertion. The exact Shinigami native proof and BitVM3 application/settlement layer remain unverified.

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
