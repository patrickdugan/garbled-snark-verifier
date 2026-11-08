# M16: mainnet chain state and an SPV payment in one SP1 guest

The [`sp1/program`](sp1/program) guest verifies a Nova proof of the Bitcoin mainnet header chain,
anchored at genesis. It then proves that a transaction output is in a block with n confirmations
under the proven tip.

Private inputs:
1. the k = 1 verifier key, raw-encoded ([M15](../m15));
2. the chain segments: `u32 m | m × (u32 len | NHC1 bundle)`. Segment i + 1 must start at segment
   i's end state (`z0 == zn`, canonical bytes);
3. the payment: `u32 n | headers B..T | u32 vout | u32 len | tx (no witness) | u32 depth |
   siblings | u32 index`.

The guest refuses unless every one of these holds:
- the key matches the pin for (network, k);
- Nova accepts every segment;
- the segments chain;
- header T hashes to the tip in zn;
- B..T link by previous-block hash;
- the transaction is not 64 bytes, parses completely with at least one input, and has output
  `vout`;
- its txid folds up the Merkle branch to header B's root.

The checks that don't need the tip run first, so a bad payment is refused in under a second.

Statement: guest A's 1,164-byte layout (magic | k | steps | z0 | zn | sha256(compressed vk) |
proofs digest), followed by a 128-byte payment record:

```
"PAY1" | segments | height_B | hash_B | confirmations | txid | vout | value | script length | sha256(script)
```

The genesis anchor is z0 in the statement, the same as in guest A.

Tools:
- [`sp1/script`](sp1/script) (`m16-nova-spv-script`): `elf`, `segments`, `execute`, `mutations`
  and `decode`.
- [`fetch_mainnet.py`](fetch_mainnet.py): reads every header from a Bitcoin Core node (pruned is
  fine) and builds the payment input.
- [`scripts`](scripts): the WSL build and the two-shard mainnet fold.

## Test chain: block 170, two segments

Inputs:
- headers 0–800, folded as two segments (0–400 and 400–800);
- the payment is block 170's second transaction (`f4184fc5…`, 10 BTC, output 0, Merkle depth 1),
  with headers 170–800, so 631 confirmations.

With the raw-key guest (ELF `bb7d51b0…`):

| Run | Result |
| --- | --- |
| execute | 34,064,279,163 instructions, 873 s, 9.1 GB peak RSS; statement `67a9deb9…`, the same as the compressed-key build |
| compressed key in place of the raw key | refused |
| 13 mutations | all refused (3,569 s in total) |

The 13 mutations:
- tip nonce, payment block's Merkle root, transaction byte, vout out of range, index, trailing
  byte, Merkle sibling;
- tip header dropped, middle link broken;
- first segment's start height, first segment's proof byte;
- second segment's z0;
- segments swapped.

## Mainnet

Inputs:
- Bitcoin Core 31.1, a pruned node (`prune=550`, `listen=0`), synced headers to tip 975,072
  (`…6ff792`) in about 15 minutes.
- `fetch_mainnet.py` read the 975,073 headers back with 975,077 RPC calls in 5,322 s.
- `nova-chain native-check` agreed with Core on hash, chainwork, bits, time and median time at
  every height (535 s).

Payment:
- block 975,067 (`…55fe22`, 6,153 transactions), 6 confirmations;
- transaction `a652ab0c…0045`, output 0, 940,000 sats to P2WPKH, Merkle depth 13.
- The node, being pruned, refused `getblockfrompeer` for the block. The raw block came from
  mempool.space. That source needs no trust: its header matches the dumped header at that height,
  and the guest checks the Merkle branch against it.

| File | SHA-256 |
| --- | --- |
| headers.bin | `bc9d6ecb…21de` |
| block.bin | `41600bb8…aae8` |
| payment.bin | `6a50449f…d2a9` |

Fold:
- two shards (0–487,536 and 487,536–975,072), 10 threads each, on a 20-thread laptop CPU;
- 413.1 s per 2,000 headers per shard, so about 9.7 headers/s combined;
- earlier benchmarks: 5.2 headers/s with one process, 10.4 with 2 × 10, 14.4 with 4 × 5, 16.3 with
  6 × 3.

Two shards trade CPU time against guest cost:
- each extra segment adds a Nova verification to the guest. With raw keys that is about
  13 × 10^9 instructions: 21.2 × 10^9 for one segment against 34.1 × 10^9 for two.
- the expected mainnet guest is about 34 × 10^9 instructions. Guest A's GPU rate was about
  6.6 × 10^9 per hour.
