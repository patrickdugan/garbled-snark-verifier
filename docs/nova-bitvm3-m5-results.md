# M5 structured transcript result

[GitHub Actions run 42169378919](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42169378919)
passed on commit `8fd0e3c3672d2178432f007fe8ed50de24a809c8`.
Artifact 13480477547 has ZIP SHA-256:
`28422b69dd0b87a6ebb558cebccab523f758cfa9d2e333aa1587db4c54fb8c36`.

The four new Rust tests passed, covering affine (64-byte) and commitment
(65-byte) representations against pinned Nova 0.76, identity flags and
membership checks, malformed points, canonical scalars and slices.
The Pallas commitment stream measured **1,444,879 non-free gates** and
**23,118,064 ciphertext bytes**. The structured suite ran in 5.03 seconds,
peaked at **53,704 KiB RSS** with zero swaps, excluding compilation.
The original native toy Nova reference still produced 10,592 proof bytes.

The dedicated job passed field, curve, transcript, local runner and native
proof tests. This does not establish a full Spartan/IPA proof verifier.
