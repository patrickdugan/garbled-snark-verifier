# Nova for BitVM3 M5: structured point/commitment absorption

This milestone adds strict native Nova transcript entry points for inputs that
will eventually come from a serialized Spartan/IPA proof. Nova 0.76.0 uses
different representations for affine points and Pedersen commitments. The
verifier must carry those distinctions into the Boolean garbled circuit.

## Wire formats

- Affine point: 32 little-endian x bytes and 32 little-endian y bytes.
  The unique identity encoding is all-zero coordinates. The membership
  predicate derives identity from both coordinates, validates both fields
  and checks y²=x³+5 for finite points.
- Pedersen commitment: 32-byte x, 32-byte y and one byte is_infinity.
  Only 0x00 and 0x01 are admitted. An identity must have (0,0,0x01);
  finite (0,0,0x00) and nonzero coordinates with flag 0x01 are rejected.
- Scalar slice: each member is 32 bytes in the engine's scalar field.
  One label precedes the complete concatenation. Every scalar is checked
  for canonical encoding.
- Commitment slice: N adjacent 65-byte encodings, one leading label, and
  membership checks for every element. N is fixed by circuit construction.

All formats in this milestone are Nova *transcript representations*. The
internal bincode serialization of a compressed proof has a different layout
and requires a version-pinned, length-bounded parser.

The verifier owns the field and curve pair. PallasEngine's scalar field is
VestaBase, while VestaEngine's scalar field is PallasBase. A caller cannot
select the curve using an input witness. Boolean transcript admission carries
into Challenge::check, and the raw low-level absorb_bytes API remains
available only for call sites that enforce their own structural checks.

## Conformance

- Native affine transcript absorption for Pallas and Vesta, including
  identity and nontrivial multiples of the generator
- Native default Pedersen commitment (identity), including its final 0x01
- Canonical point membership checks and malformed x, off-curve y, swapped
  identity flag and reserved flag bits
- Native scalar slice absorption and malformed member rejection
- Two-commitment vector with one label and per-member flag checks
- Disk-streamed real garbling and evaluation of valid and forged commitment
  inputs with ciphertext digest parity

The digest of malformed raw bytes is deliberately computed independently.
Passing that digest as the claimed challenge must still fail because the
membership or encoding admission predicate is false.

## Limits and next gate

This verifies the byte contract and membership of transcript objects; it does
not parse complete bincode proofs or implement Spartan sumcheck, Poseidon,
IPA openings, proof key verification, and BitVM3 transaction integration.
The native toy proof runner remains independent of this test.

The disk-streaming component tests report gate counts and memory evidence.
Their allocator reservation is not a hard RSS cap, and proof generation on
the user's upgraded device is a later action.

Next: inspect a complete pinned CompressedSNARK proof's internal transcript
schedule; implement the structured proof parser and checked sumcheck claims.
Keep the established transparent Pallas/Vesta + Spartan/IPA setup.
