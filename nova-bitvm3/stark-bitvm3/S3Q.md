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

CI result: see the section below once the run is archived.

## What this establishes, and what it does not

Established: for the frozen Shinigami standalone CSV execution, the pinned Stwo-Cairo prover produces a proof that the pinned Stwo-Cairo verifier accepts, within the 4 GiB and 120 second limits of this workstream. The blocker recorded in S3f to S3o, a nonzero global lookup residual, was an input mismatch in the public segment context and not a prover or AIR defect.

Not established:

- The profile is the laboratory `canonical_small` with 96-bit nominal FRI security. It is not a production security profile.
- This is an execution proof. The program identity (the compiled executable hash), the public output and the receipt are not bound to anything a BitVM3 verifier checks. A verifier must also pin the public segment layout, since a prover that chose a different `present` vector would produce a different claim.
- The proof format is Stwo-Cairo `467d5c6d` (Scarb 2.18's producer). The Boolean verifier of S2 is pinned to a different Stwo revision (`e9a38e12`), so importing this proof needs a matched producer and verifier pair.
- No garbling, no Bitcoin script and no dispute protocol was involved.

## Next

The blocker named at the start of S3 is cleared at the laboratory profile, so the work moves to the verifier side: choose the verifier revision that matches this proof format, define the public-memory contract (program hash, output words, segment layout), build the proof-independent verifier template for that revision and measure its Boolean gate and input counts. The 47 MB JSON proof is not the input size: the wire format and the number of authenticated input bits must be measured. See [NEXT.md](NEXT.md).
