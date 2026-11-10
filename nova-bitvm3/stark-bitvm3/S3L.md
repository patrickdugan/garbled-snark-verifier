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
