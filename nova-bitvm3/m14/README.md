# M14: the M13 final verifier as a fixed garbled circuit

M13 left a native verifier of the SP1 wrap layer under BLAKE3 ([`../m13/verify`](../m13/verify)) and a
garbled price derived from operation counts of one verification. M14 builds that verifier as a
Boolean circuit with a fixed shape, keeping every check `verify_final` makes (wrap key pin, STARK,
exit code 0, completeness, guest key, recursion key root, committed statement digest).

Order of work:
1. field arithmetic (KoalaBear, its degree-4 extension, challenge sampling);
2. hashing (BLAKE3 of fixed-length inputs, the Fiat-Shamir transcript, Merkle paths);
3. SP1's verifier logic for the wrap shape (jagged PCS, BaseFold, zerocheck and LogUp-GKR
   sumchecks), the statement and pin checks;
4. the whole circuit run on the committed proof and on mutated proofs, against `m13-verify`.

Steps 1 and 2 are in [`circuit/`](circuit). Steps 3 and 4 are not built yet.

## What is built

[`circuit/src`](circuit/src):
- `field.rs`: canonical-input check, add, sub, neg, double, halve, multiply (M12's Karatsuba
  product and Barrett reduction), constant multiply, inverse (SP1's addition chain), powers,
  equality, select, wide reduction, and constant-base powers by an index given as bits.
- `ext.rs`: SP1's `BinomialExtensionField<KoalaBear, 4>` (X^4 = 3). Multiplication reduces lazily:
  the 16 integer products are summed per coefficient (wrapped terms times 3) and reduced once.
  Also square (10 products), Frobenius maps, and inverse as in p3's `frobenius_inv`.
- `sample.rs`: fixed-cost challenge sampling (see below).
- `hash.rs`: BLAKE3 of any fixed length (chunks, flags, counters, parent tree), M13's byte
  transcript, Merkle leaf and node hashing, path roots and digest equality.

A multiplication whose operand is a compile-time constant takes the constant path automatically,
so the circuit's gate count reflects which operands are actually constant.

## Checks

[`circuit/tests/gadgets.rs`](circuit/tests/gadgets.rs), 11 tests:
- **Against SP1's own types** (`p3-koala-bear 0.4.3-succinct`, `BinomialExtensionField<KoalaBear, 4>`):
  - every base and extension gadget on edge values (0, 1, p - 1, (p ± 1)/2, 2^24, 2^30, the
    extension's d-th root) and random inputs;
  - inverse of 0 returns 0, where the native inverse returns `None`; callers that must reject 0
    test `is_zero`.
- **Against the `blake3` crate:** BLAKE3 of 0 to 5,000 bytes (1 to 5 chunks).
- **Against M13's transcript:** a native copy of `Blake3Transcript` runs an 11-step
  observe/sample script, including a 1,100-byte absorb and a 33-byte squeeze across a re-hash.
- **Against real verifications:** `m13-verify` with `M13_TRANSCRIPT_TRACE` records every byte
  its transcript observes and samples while verifying the c4 final proof. The recordings are in
  [`circuit/fixtures/c4-v1-transcript.bin`](circuit/fixtures) and `c4-v2-transcript.bin`:
  - v1: 39,568 bytes observed, 8,836 sampled;
  - v2: 39,568 bytes observed, 17,124 sampled.

  Given the observed bytes, the circuit transcript produces every sampled byte of both. This
  exact transcript of the final verifier costs 11,198,078 gates under v2 (10,916,094 under v1).
- **Merkle paths:**
  - roots match a native BLAKE3 tree;
  - a flipped sibling bit or a wrong root is rejected.
- **Barrett domain:**
  - M12's reduction circuit keeps 31 bits of the quotient, so it is exact for x < p·2^31;
  - the native model is swept on 16.8 M values below p²;
  - the circuit is checked at the p² and 2^61 boundaries and fails at 2^62 - 1;
  - every caller passes less than p², which is why wide values split at bit 61.
- **Garbled evaluation:** each case below is garbled, then evaluated with the input labels of real
  values, and every output label must be the garbler's label for the native result bit:
  - extension multiplication;
  - base inverse;
  - the sampler;
  - the canonical check on a non-canonical input;
  - the full transcript script.
- **Gate counts:** taken in ExecuteMode and as GarbleMode ciphertexts (the two must agree), and
  required to equal [`circuit/RESULTS.json`](circuit/RESULTS.json).

## Measured gate counts

Non-free (AND-class) gates; XOR and NOT are free.

| Gadget | Gates | M13 price assumption |
| --- | ---: | ---: |
| base multiply / square | 2,068 | 2,068 |
| base add / sub / neg | 94 / 91 / 90 | 94 |
| base constant multiply: ×3, ×11, ×2^24, ×d-th root, ×two-adic generator (2^24) | 159, 328, 365, 611, 1,057 | 159 / 328 / 2,068 |
| base inverse (36 multiplications) | 74,448 | counted as multiplications |
| canonical-input check | 30 | not priced |
| extension multiply (lazy reduction) | 30,115 | 34,693 (16 reduced products) |
| extension square | 19,524 | — |
| extension × base | 8,272 | — |
| extension Frobenius | 1,402 | — |
| extension inverse | 154,736 | — |
| index power g^idx, 24-bit index | 21,891 | — |
| challenge, base field (8 bytes mod p) | 464 | — |
| challenge, extension | 1,856 | — |
| BLAKE3, one 64-byte block (Merkle node, 16-element leaf) | 10,281 | 10,410 |
| BLAKE3, 1,025 bytes (18 compressions) | 183,385 | 187,380 |
| **Transcript of the c4 final verification, v2** (1,177 compressions) | **11,198,078** | 12,252,570 (1,177 × 10,410) |
| Transcript of the c4 final verification, v1 (1,144 compressions) | 10,916,094 | 11,909,040 |

## Decisions

**Circuit input encoding.** SP1's KoalaBear deserializer does not range-check in release builds:
`from_canonical_u32` only debug-asserts, then reduces mod p. The native verifier therefore accepts
any 32-bit word and uses its residue.

The circuit takes each field element of the proof as 31 bits and rejects values ≥ p
(`is_canonical`, 30 gates). For every proof the native verifier accepts, the canonical encoding of
its field values is accepted by the circuit, and the reverse also holds. The circuit accepts
exactly the same field values, with one encoding each.

**Fixed-cost challenge sampling (transcript v2).** SP1's `SerializingChallenger32` samples by
rejection: it takes 4 bytes, keeps 31 bits, and retries while the value is ≥ p (about 1 in 128).
Each rejection shifts the byte position of every later challenge. A circuit would need a
variable-offset selector for every later sample. M13's price instead covered this with observed
runs plus a margin.

v2 takes 8 bytes per base-field challenge and reduces the little-endian u64 mod p (464 gates).
- Every challenge consumes a fixed number of bytes, so the transcript's shape is fixed.
- No residue has probability above (1 + p/2^64)/p. Any event over the challenges therefore has
  at most (1 + 2^-33) times its uniform probability, so each Fiat-Shamir soundness term grows by
  that factor.
- Query indices (`sample_bits`) stay as they are: 4 bytes masked to the low bits, which is uniform.
- v2 uses its own transcript domain (`hash::DOMAIN_V2`).

**The prover side of v2 is in M13's code.**
- `ctx::Blake3ChallengerV2` and `Blake3KoalaBearV2` are SP1 `IopCtx` types.
- SP1's CPU prover proved the c4 shrink proof's wrap layer under them (`m13 wrap-only-v2`).
  The output is [`../m13/fixtures/c4-wrap-blake3-v2.bin`](../m13/fixtures/c4-wrap-blake3-v2.bin):
  same key, statement and size as v1, proved in 55 s.
- `m13-verify verify-v2` accepts it.
- Flipped bytes and altered public values are refused, and v1 and v2 proofs are each refused by
  the other verifier. These checks are in `m13/verify/tests/final_verifier.rs`.
- One v2 verification spends 1,177 transcript compressions in 537 squeezes
  ([`../m13/results/verify-counts-c4-v2.json`](../m13/results/verify-counts-c4-v2.json)), against
  1,144 in 504 for v1.

Two checks tie the circuit to v2:
- the circuit's sampler is checked against v2's native formula (`ctx::sample_base_v2`);
- the circuit transcript reproduces the recorded v2 verification byte for byte (above).

Which sampled bytes become which field challenge is fixed by the verifier logic (step 3).

**Constant multiplications.** M13's operation counter classified a multiplication as
"small-constant" from its runtime operand values. In the circuit, only compile-time constants are
cheap. Until step 3 shows which operands are constants, the reference price is M13's upper tier
(1.97 × 10^9 gates), plus the items M13 left unpriced.

## Reproduce

Windows (MSVC):

```powershell
$env:RUSTUP_TOOLCHAIN='1.90.0-x86_64-pc-windows-msvc'
cargo test --release --locked --manifest-path nova-bitvm3/m14/circuit/Cargo.toml -- --test-threads=2 --nocapture
```

Linux: the same `cargo +1.90.0 test ...` command; CI runs it in [`nova-m14.yml`](../../.github/workflows/nova-m14.yml).
`M14_WRITE_RESULTS=1` rewrites `RESULTS.json`.
