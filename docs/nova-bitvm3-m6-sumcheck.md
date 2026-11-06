# Nova BitVM3 M6: Spartan sumcheck round

Nova 0.76 uses a compressed univariate polynomial that omits its linear
coefficient. A quadratic round transmits [a0,a2], while a cubic round
transmits [a0,a2,a3]. The verifier reconstructs
a1=claim-2*a0-a2-a3 (a3=0 in degree 2) to enforce P(0)+P(1)=claim.

The verifier absorbs the compressed coefficients under a single "p" label,
then derives challenge "c" from the Boolean Keccak transcript. It evaluates
P(c) with Horner's method and compares against the claimed next value.
Scalar admission checks cover every supplied field word; degree and
transcript scheduling are verifier-owned.

CI compares this graph against a genuine native SumcheckProof::verify round
for both Pasta scalar fields, both degrees and near-modulus coefficients.
Incorrect claims, coefficients and noncanonical field aliases must reject.
This runs on GitHub and leaves local header proving untouched.

This is a per-round check. Its initial claim and final evaluation must still
be bound to the Spartan R1CS statement and IPA openings before it can accept
an entire Nova proof. The final Bitcoin transaction setup is separate.

## Disk-backed M6 conformance extension

The cubic round now has an additional streamed garbling/evaluation test. It
writes ciphertexts with a fixed 64-KiB writer buffer, reopens the generated
stream through FileSource, verifies its digest, and checks the result label
for one valid and two mutated input assignments. The CI run supplies measured
non-free gate count and streamed ciphertext bytes. These are per-round costs
and exclude cut-and-choose and full proof inputs.
