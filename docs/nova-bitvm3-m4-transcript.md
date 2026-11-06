# M4: Boolean Nova transcript

The target is the non-EVM transcript in nova-snark =0.76.0. The actual pinned
source from M3 has SHA-256
`9a63349a255e0bdf24117f07ec50aeafb592995eb5520186c8ffcfd89b4bb6b9`.
The new module is `src/nova/transcript.rs`.

## Computation

The circuit computes all 24 Keccak-f[1600] rounds with 1088-bit rate and
512-bit capacity. It uses byte-aligned legacy Keccak padding: delimited
suffix 0x01 and the final rate bit set. Rotation and lane indexing follow
https://keccak.team/keccak_specs_summary.html. The output is 256 bits.
Cached round keys include the round constant.

For pending absorbed bytes B, previous 64-byte state S, host counter n and
squeeze label L, construct M = B || NoDS || LE64(n) || S || L. Compute
S' = Keccak256(M || 0x00) || Keccak256(M || 0x01). Full challenges are
LE512(S') modulo the engine's scalar field. The initial state uses
M = NoTR || protocol_label. Every squeeze stores S' and clears B.

Reduction accepts arbitrary 512-bit input. Its high 254 bits are below both
Pasta primes and initialize the remainder; 258 fixed-topology bit steps
then compute 2*r+b and conditionally subtract p. This establishes a canonical
result without a supplied quotient witness. PallasEngine uses VestaBase for
challenge reduction, and VestaEngine uses PallasBase.

The truncated `squeeze_bits` path copies the requested 2..=254 low bits and
optionally sets the highest requested bit. It advances the same transcript
state and counter as a full squeeze.

## Admission and integration contract

`absorb_scalar` accumulates canonical encoding predicates.
`Challenge::check` compares the derived value and conjoins accumulated admission.
Algebraic callers consuming `Challenge::bits` must conjoin `validity` in the
final acceptance predicate. `absorb_bytes` is low level: its caller must validate
the representation, curve membership and proof-object encoding as appropriate.

Labels, lengths, operation order and field choice are verifier-owned graph
parameters. The API supplies no setter for prior state or counter. This code
has no EVM serialization mode. A complete Nova verifier still needs its exact
structured proof schedule, Poseidon consistency checks, Spartan sumcheck and
both IPA paths, followed by BitVM3's authenticated input/transaction binding.

## Tests and evidence

`nova-bitvm3/tests/boolean_transcript.rs` compares hashes with sha3 =0.10.9,
including lengths around 135/136 bytes and multiple rate blocks; it explicitly
rejects SHA3-256 digests. Wide reductions are compared with BigUint over both
fields, with wrong outputs and noncanonical aliases rejected. Four consecutive
challenges, including a truncated squeeze, are compared with pinned Nova for
both engines. Tests vary truncation widths and high canonical scalar bits.

Adversarial checks mutate claims, protocol labels, absorb order and squeeze
labels. A raw-byte oracle supplies matching challenges for a noncanonical
scalar and verifies that admission still rejects it. Disk tests garble one
graph per field and evaluate seven assignments with output-label and ciphertext
digest checks. Reusing input label choices is test-only conformance plumbing.

The independent local Python bit mirror matched empty/abc Keccak vectors,
two test challenges from pinned Nova and 90 wide-reduction vectors. Its optional
PyCryptodome comparison was skipped because that dependency was unavailable;
the Rust sha3 comparison is required in CI. Rust outcomes and measured gate
counts must be taken from the dedicated workflow, not this design note.

The test sink uses a 64 KiB writer buffer and the upstream file reader.
Neither this setting nor the wire reservation is an enforced process RAM cap.
No Bitcoin transaction is authorized by these component checks.
