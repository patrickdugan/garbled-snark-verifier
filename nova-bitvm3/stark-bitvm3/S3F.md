# S3f: isolate a nonzero Cairo lookup residual

The source-pinned Stwo-Cairo prover at `467d5c6d4d6d526c1db8ff69c14f2de6d57f4d73` failed the original global lookup-sum assertion during its first native proof attempt with the reduced preprocessing profile. [Run 42724836768](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42724836768) completed a cold build and reached the proof computation, then returned code 101 after approximately 18.7 seconds. Peak sampled RSS was 1,316,683,776 bytes and virtual size 1,500,905,472 bytes, well below the 4 GiB guard. The reported nonzero QM31 sum was `(1866027004 + 1908263159i) + (1713629672 + 1017174456i)u`. No proof was produced.

The next experiment identifies the **contributors** without changing the verification relation or suppressing the existing assertion. Run `[s3-lookup]` on an isolated branch commit, or use `workflow_dispatch` with `s3_lookup_diag=true`. That job applies an ephemeral instrumentation patch only after verifying the exact upstream Git revision and a pristine copy of `crates/cairo-air/src/claims.rs`. The patch adds printing of the public-memory lookup sum, every present interaction-claim sum, and the total when the total is nonzero. It leaves the arithmetic and native equality assertion intact. It records the patch digest in the archived evidence.

`tools/summarize_lookup.py` accepts a diagnostic **only** if the native assertion fails, the one-shot proof report records a failed proof, and all reported QM31 limbs recombine to the total modulo `2^31-1`. The outcome always carries `native_proof_verified=false`, with application and settlement authorizations false. The full source-level inventory is 66 interaction components. This is a reproducible localization tool, not proof verification or a replacement for a native assertion.

Routine CI runs static Python checks of the instrumentation and its parser. The optional diagnostic retains the source-pinned `canonical_small` profile, 120-second prover deadline, 4 GiB sampled RSS guard and two build workers. Its 600-second compile budget and 15-minute job limit are unchanged. No Nova, SP1, CUDA or S2 full garbling runs are triggered.

The logical next step is to compare the reported contributions with a source-pinned interaction relation audit, isolate the unmatched component or public-memory term, then make a **separate** producer-side fix with native verification as its acceptance gate. A mismatch between the Scarb 2.18 execution input and this Stwo-Cairo producer is another hypothesis to test; the present logs do not determine the cause.

The S2 verifier remains a separate, valid test-only example. Shinigami proof support still needs successful native Cairo proving, program/public-output binding, a matching Boolean verifier revision, and adversarial settlement tests.

## Measured diagnostic result

The [bounded run 42744991308](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42744991308) completed every CI job. The diagnostic job itself passed because it correctly observed the **original failed assertion**, reconstructed the native total from the component sums and kept the proof-status flags false. It did not produce or verify a Cairo proof.

The pinned source inventory has 66 interaction components; 37 were present in this execution. The native total was `(1866027004 + 1908263159i) + (1713629672 + 1017174456i)u`, including the public-memory contribution `(559615079 + 1208624373i) + (2076115172 + 2076164551i)u`. The QM31 diagnostic reconciled modulo M31. The original assertion exited with code 101 after **17.713 seconds**, at **1,232,371,712 bytes peak RSS** and **1,316,700,160 bytes peak virtual size**.

This component-level sum inventory is necessary evidence but does not identify a unique faulty relation. Each claim may contribute to multiple relations. Upstream instrumentation was applied ephemerally, with source and patch SHA-256 stored in the [Actions artifact](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42744991308/artifacts/13730548693). The ZIP has SHA-256 `7d5b83602054c0ff9009044dc10298a40e1ef3fcf1dc029e9df93d1ddbdeb18a`.

The next controlled hypothesis is `canonical_without_pedersen` with a 25-log sequence range and 26-log lifting. The saved execution does not use the Pedersen builtin. The pinned upstream source explicitly supports that preprocessing variant; it uses 73,338,480 cells versus 10,161,776 in `canonical_small`. A separate 4 GiB RSS-limited run will determine whether shortening the sequence table caused this residual.
