# S3L: source-matched LogUp sum check for the local range-check component

## S3k result

The source-pinned S3k native diagnostic in [Actions 42759229663](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42759229663) completed successfully as a **failed-proof diagnostic**. It reconstructed one preprocessed and one base trace column for the 2,048-row `range_check_11` component using upstream's component evaluator, emitting 2,048 raw relation entries, which aggregated into 959 nonzero signed tuples in `CommonLookupElements`. The summary was untruncated. Its original native LogUp assertion returned code 101, peak sampled RSS was **1,583,017,984 bytes**, and native execution took **18.72 seconds**. All three regular CI jobs passed. [S3K_RESULTS.json](S3K_RESULTS.json) records the evidence. The local tuples alone do not demonstrate a globally unbalanced relation.

## New S3L hypothesis

The relation tracker collects field tuples and multiplicities, while the native Cairo prover records an independent claimed LogUp sum for that component. We can compare both values using the **exact Fiat-Shamir `CommonLookupElements` drawn by the native prover**. For the 2,048 source-evaluated rows of `range_check_11`, calculate:

\[
S_{11} = \sum_{(m,v)\in E_{11}} m\,\mathrm{combine}_{\chi}(v)^{-1}\in\mathrm{QM31}
\]

Here \(E_{11}\) is the upstream `add_to_relation_entries` output, \(m\) is the signed M31 multiplicity, and \(\chi\) is the pinned native challenge. Compare \(S_{11}\) against `interaction_claim.range_check_11.claimed_sum`. The code rejects zero denominators, retains every encoded tuple, and records both sums as full QM31 components. It always preserves the original global LogUp assertion as the proof acceptance boundary.

This tests whether the native `range_check_11` interaction generator agrees with the same component's source-level row relation. A mismatch can localize the producer bug to that component or its trace layout. If they agree, other components or the public-memory relation need investigation, with the same bounded method.

## Tests and resource ceiling

The script still requires a clean source checkout of Stwo-Cairo revision `467d5c6d4d6d526c1db8ff69c14f2de6d57f4d73`, paired with Stwo revision `aeceb74c`. Routine tests exercise the patch generator and parser with matching, mismatching and malformed comparison logs, without building a proof. The diagnostic remains opt-in using the `[s3-local]` marker, reusing the 4 GiB sampled RSS limit, 120-second native runtime limit, 600-second compiler limit and 15-minute total job cap.

No result is accepted as proof verification. The new parser requires that the **native global assertion rejects** the saved Shinigami execution, and every result explicitly marks garbled Cairo proof, Bitcoin settlement and Ark/UTXORef authorization false.

## Next gate

A component-claim mismatch should be reproduced with a minimal native fixture before changing generator code. Matching component sums lead to inspecting another small component with an active interaction claim, followed by cross-component cancellation of the `CommonLookupElements` relation. Every repair must eventually pass unmodified native proving and native verification for the exact Shinigami program and public statement. The S2 garbler remains a separate, older Stwo protocol path until source compatibility is established.

## One native diagnostic activation

Routine CI passed for the code in [commit 8e178cb9](https://github.com/patrickdugan/garbled-snark-verifier/commit/8e178cb9044de1403f54fb680bba8ef84ffb525b), including its fast parser/source-shape checks, original S0/S1 circuits and the existing garbling integration. The following separate marker-triggered commit makes **one** opt-in `[s3-local]` run against the immutable saved Shinigami CSV execution, using the existing 4 GiB sampled RSS watchdog, 120-second proof deadline and 15-minute total CI job. A diagnostic is successful only if the source-matched component comparison is recorded, the native global lookup assertion rejects the proof, and the report remains explicitly unauthenticated. This trigger does not start Nova/SP1 or full STARK-to-BitVM3 garbling.

## Measured source-pinned comparison

[Run 42760962243](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42760962243) passed all four jobs on trigger commit `b67a9fba`. The opt-in native diagnostic recovered **2,048 raw source rows and 959 distinct nonzero signed tuples** (including a zero-value tuple), with total negative multiplicity 51,200 in M31 representatives. From the native Fiat-Shamir challenge, their exact QM31 sum was:

`(1940708650 + 312008446i) + (1727873078 + 211651567i)u`.

This **equaled** `interaction_claim.range_check_11.claimed_sum` limb for limb. The native global lookup assertion still rejected the full Shinigami execution with code 101 and the same pinned QM31 global residual. Peak sampled RSS was **1,602,859,008 bytes** and the native diagnostic ran for **21.427 seconds**, below both the 4 GiB and 120-second bounds.

The result rules out a mismatch between reconstructed source relations and the native claimed LogUp sum **for this selected component and source profile**. It leaves the 36 other active interaction claims, public-memory contribution, full relation cancellation, and the separate producer/verifier compatibility question open.

Evidence: [Actions artifact 13738271051](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42760962243/artifacts/13738271051), ZIP SHA-256 `28730264fb7b4352e1ab5b48271f65270df4ffcaac3f956f79255277184795d2`; machine-readable [S3L_RESULTS.json](S3L_RESULTS.json). No native Cairo proof or Bitcoin authorization was produced.
