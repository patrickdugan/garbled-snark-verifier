# S3q: a native-verified proof of the Shinigami standalone trace

## Hypothesis from S3p

S3p localized the whole global lookup residual to 86,383 extra public-memory entries. They arise because the frozen prover input declares all eleven builtin segments public (`public_segment_context.present = [true] x 11`, the bootloader default), while the standalone Shinigami executable has three (output, range_check, bitwise). The VM's own `public_memory_addresses` already matches the three-builtin layout. If that explanation is complete, changing only the context should make the lookup argument balance and let the original native prover and verifier accept the proof.

## Experiment

`tools/prove_corrected_context.py` takes the frozen standalone input (same SHA-256 and byte pins as S3d, restored from the gzip, with the Pedersen and Poseidon builtin checks), changes exactly one field, and runs the **unmodified** pinned prover binary with its built-in verification under the S3d profile (`canonical_small`, nominal 96-bit FRI):

- `public_segment_context.present` is derived from `builtin_segments` in the canonical order (output, pedersen, range_check_128, ecdsa, bitwise, ec_op, keccak, poseidon, range_check_96, add_mod, mul_mod). For this program that is `[true, false, true, false, true, false, false, false, false, false, false]`.
- The correction is applied only when the current context is exactly the all-present default, and only when the derived context differs. Any other value, an unknown builtin segment, a missing output segment or a malformed context shape is refused.
- Nothing else in the input changes (a test compares every other key). The binary is built with the default feature set (no diagnostic patch), the profile is the pinned `canonical-small-96.json`, and verification is the prover's own `--verify`, which runs the Rust verifier of the same Stwo-Cairo revision.

The run is limited to 4 GiB sampled RSS and 120 seconds, and it records the proof size and SHA-256. It never marks program identity, the receipt or any application statement as bound.

## Local result (WSL, regenerated standalone input)

| Prover build | Result | Time | Peak RSS |
|---|---|---|---|
| Unmodified Stwo-Cairo `467d5c6d` (clean tree, no `S3_` strings in the binary) | `Proved successfully`, native verifier accepted | 63.8 s | 2,652,856,320 bytes |
| Diagnostic build of S3p (feature enabled, lookup sum zero so the audit block is skipped) | same | 43.5 s | 2,757,668,864 bytes |

The proof is 47,197,275 bytes of JSON with SHA-256 `ab65f8373baf77f96e2f18e40a93f8897cfa67ff39eccb30dbedcb44f00fabb2`, **identical** from both builds, so the prover is deterministic and the diagnostic patch does not touch it. The same input with the default context fails the native assertion with the S3f residual, as before.

## CI result on the frozen artifact

[Run 42849912173](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42849912173), job `s3-small-profile`, commit `ff9d526`, frozen standalone input (SHA-256 `c3c3622b6c10fe54f2efbb9f48d4cbcedb96143b904aa29eaa8fb07e8b65eb55`, restored and re-hashed by the tool):

| Quantity | Value |
|---|---|
| Context correction | `[true x 11]` to `[true, false, true, false, true, false, false, false, false, false, false]` (output, range_check, bitwise) |
| Corrected input | 9,624,662 bytes, SHA-256 `d9e259e05bfb7c85079cdb43c9dbe2a8d18aa75f86a7ba601886035d2fe22e3c` |
| Native prover and verifier | unmodified Stwo-Cairo `467d5c6d`, `canonical_small` profile, `--verify`, **accepted** |
| Proof | 47,197,275 bytes, SHA-256 `ab65f8373baf77f96e2f18e40a93f8897cfa67ff39eccb30dbedcb44f00fabb2`, **identical to the local proof** |
| Runtime and memory | 32.122 s, peak sampled RSS 2,656,403,456 bytes (limits: 120 s, 4,294,967,296 bytes) |
| Report status | `native_small_profile_verified_application_binding_outstanding`; `application_statement_authenticated` and `program_identity_bound` are false |

The routine jobs of the same run passed. The artifact `shinigami-s3-small-ff9d526da9562f102964a9ec672096aaef5bcb88` (zip digest `sha256:cd9ada22fb7c418ba06f5c282f5076ffe652dab343967c150f66ffbd99420458`) holds the proof and the run report.

## What this establishes, and what it does not

Established: for the frozen Shinigami standalone CSV execution, the pinned Stwo-Cairo prover produces a proof that the pinned Stwo-Cairo verifier accepts, within the 4 GiB and 120 second limits of this workstream. The blocker recorded in S3f to S3o, a nonzero global lookup residual, was an input mismatch in the public segment context and not a prover or AIR defect.

Not established:

- The profile is the laboratory `canonical_small` with 96-bit nominal FRI security. It is not a production security profile.
- This is an execution proof. The program identity (the compiled executable hash), the public output and the receipt are not bound to anything a BitVM3 verifier checks. A verifier must also pin the public segment layout, since a prover that chose a different `present` vector would produce a different claim.
- The proof format is Stwo-Cairo `467d5c6d` (Scarb 2.18's producer). The Boolean verifier of S2 is pinned to a different Stwo revision (`e9a38e12`), so importing this proof needs a matched producer and verifier pair.
- No garbling, no Bitcoin script and no dispute protocol was involved.

## Next

The blocker named at the start of S3 is cleared at the laboratory profile, so the work moves to the verifier side: choose the verifier revision that matches this proof format, define the public-memory contract (program hash, output words, segment layout), build the proof-independent verifier template for that revision and measure its Boolean gate and input counts. The 47 MB JSON proof is not the input size: the wire format and the number of authenticated input bits must be measured. See [NEXT.md](NEXT.md).
