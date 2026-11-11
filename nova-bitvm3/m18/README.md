# M18: a windowed UTXO map folded in Nova, and balance proofs against it

M16 proves that a payment exists: an output was created in a block with k confirmations on the
proven mainnet chain. It cannot prove that the output is still unspent, because Bitcoin headers
commit to each block's transactions, not to the UTXO set. A balance (the sum of a script's
unspent outputs) needs both.

M18 folds, in Nova, an assume-valid pass over the blocks of a window H..T:
- re-hash every transaction (no witness) and rebuild each block's Merkle root;
- check that root against the block's header, and link the headers H..T;
- keep a map of every output created in the window, marking an output spent when a later input
  spends it.

It does not check scripts, signatures, amounts or any other consensus rule ("assume-valid"): the
headers are proven-work headers, and validity is inherited from the chain's acceptance, as in
Core's assumevalid. A balance proof is a set of map entries, created in H..T and unspent at T,
checked against the folded map's root. T is tied to the NHC1 header-chain proof by its hash.

## Why a window, and the cost

Re-hashing the block bodies with SHA-256 is the dominant cost and cannot be avoided: it is what
binds the transactions to the proven headers.
- The NHC1 header fold (`btc-header-fold`, the circuit behind the mainnet chain proof) measured
  82,809 R1CS constraints per header: three SHA-256 compressions plus checks. One compression
  alone measures 25,840 constraints (Nova 0.76 frontend gadget, constant IV).
- Mainnet blocks 975,067..975,072 carry 810,812 bytes of non-witness transaction data on average
  (1.56 MB raw), 15,357 compressions for the transaction bodies, so 3.97 × 10^8 constraints of
  SHA-256 per block before the txid finish, the Merkle merges, parsing and map updates.

A fold from genesis would take years, so the map covers a window, and a balance covers outputs
created inside it. The per-step and per-block figures are in Status.

## The map

An indexed Merkle tree (a sorted linked list in a fixed-depth Merkle tree, as used for nullifier
sets), depth D, over the scalar field of Pallas, hashed with Poseidon:
- key `k` = the low 248 bits of `Poseidon(txid_lo, txid_hi, vout)` (txid in internal byte order as
  two 128-bit limbs). Keys are below 2^248, so an order comparison is a 249-bit decomposition;
- leaf `(k, next_k, next_index, value, script_hash, spent)`, hashed as a 6-input Poseidon, with
  `script_hash = Poseidon(script bytes packed 31 per element, length)`. Leaf 0 is a sentinel with
  key 0; `next_k = 0` marks the last leaf; an empty slot is the leaf hash 0.

Operations, one per event:
- **create** (an output): a non-membership proof for k (the low leaf has `key < k < next_key`),
  then the low leaf is updated and the new leaf appended;
- **spend, in window** (an input whose outpoint is in the map): a membership proof, then
  `spent = 1`; a leaf already spent cannot be spent again;
- **spend, before window** (an input spending an output created before H): a non-membership proof
  for k. Nothing changes.

A Utreexo forest supports add and delete but not proofs of absence. Absence is what makes the
window sound: a prover who called an in-window spend "before window" would keep a spent output in
the map, and the non-membership proof refuses that.

The coinbase input (the null outpoint, first transaction of a block) produces no event. All
outputs are created, OP_RETURN included; an unspendable output never counts toward a balance
except as its own value, which is zero for every OP_RETURN in practice. A duplicate txid (the two
BIP30 pairs before height 91,880) fails non-membership, so a window cannot cover those blocks.

## The step circuit

One uniform Nova step, so the existing verifiers (M12's guest A, the M14 BitVM3 circuit,
TradeLayer's type-36 verifier) apply with a new key and no new code. A step:
1. absorbs c SHA-256 blocks of one transaction's padded non-witness serialization (a step never
   spans two transactions) and runs the byte parser over them. The parser is a state machine over
   version, input count, outpoints, scriptSig lengths and bytes, sequences, output count, values,
   script lengths and bytes, and lock time. It appends each completed input and output, as an
   event, to a producer hash chain;
2. pops one event from a consumer hash chain and applies one map operation. At the window's end
   the producer and consumer chains and counts must be equal, so every event is applied once, in
   order;
3. on a transaction's last block, finishes SHA-256d into the txid and pushes it onto a Merkle
   builder (a stack of up to 15 digests in the state). One SHA-256d merge of two digests runs
   per step;
4. on a block's last step, finishes the Merkle root (with Bitcoin's odd-node duplication), hashes
   the 80-byte header, and checks the root and the link to the previous header hash.

The fold's public output is: H, T, the hash of header H − 1, the hash of header T, the map root,
the number of created and spent outputs, and the event chain heads.

## Status

Native reference and cost model (2026-11-11). The first window is mainnet 975,067..975,072, the
six blocks under M16's payment (txid `a652ab0c…0045`, output 0, 940,000 sats). The step circuit
is not built yet.

Reproduce: `scripts/cargo.sh test --release` (13 tests), then `m18 run`, `m18 cost`, `m18 fold`
and `scripts/cost_model.py`. Raw blocks come from mempool.space into a data directory (not
committed) and are pinned by `fixtures/blocks.json` (heights, hashes, sizes, SHA-256). All six
headers match the six headers inside the M16 payment input.

Built:
- `src/native.rs`: block parsing (segwit stripped to the non-witness serialization), txid, Merkle
  root with odd-node duplication, header links, the depth-32 indexed Merkle tree over Poseidon
  (M17's sponge), create / spend-in-window / spend-before-window with proof generation and
  checking, double spends and false "before window" claims refused, balance queries.
- `src/cost.rs`: the map operations as Nova gadgets (create, spend in window, non-membership),
  checked satisfiable and root-equal to the native map, a forged claim unsatisfiable, and the
  SHA-256 absorption gadget checked against `sha2`.

Window 975,067..975,072 (`results/native-975067-975072.json`): every header links and every
Merkle root matches. 32,693 transactions, 4,864,871 non-witness bytes, 92,141 padded SHA-256
blocks for the bodies, 47,238 inputs (6 coinbase), 74,592 outputs. Events: 74,592 creates, 26,447
in-window spends, 20,785 before-window spends. 32,729 Merkle merges. Final map: 74,593 leaves,
root `9d4dbc82…d220` (little-endian hex in the results file). The native run with every proof
checked took 1,563 s.

Balance at 975,072. Output `a652ab0c…0045:0` (940,000 sats) is in the map at leaf 8 and unspent;
its membership proof verifies against the final root and its value equals the PAY1 value. It is
the only window output paying its script (`00148e04…ea96`, SHA-256 matches PAY1), so the balance
of that script at 975,072 is 940,000 sats, with a verified balance proof.

Constraints (`results/constraints.json`, Nova 0.76 TestConstraintSystem):

| unit | constraints |
|---|---|
| SHA-256 compression | 25,840 |
| Poseidon sponge, 2 / 3 / 6 inputs | 313 / 313 / 625 |
| map create, D = 32 | 43,316 |
| map spend in window | 21,995 |
| map spend before window (non-membership) | 11,822 |

Create is 128 two-input hashes along four paths, three leaf hashes, the key hash with its
canonical 255-bit decomposition, and two 249-bit comparisons. The byte parser is not built; no
figure below includes it.

Fold timing (`results/fold-timing-run1.json`, `results/fold-timing.json`; Nova 0.76, Pallas and
Vesta, 4 threads, laptop shared with another running job, 20 steps each; a step is c compressions
plus one create, with the SHA-256 state and the map root carried in the Nova state):

| c | constraints per step | seconds per step, run 1 / run 2 | seconds per million constraints |
|---|---|---|---|
| 1 | 70,280 | 1.04 / 1.31 | 14.8 / 18.6 |
| 4 | 150,392 | 0.98 / 2.17 | 6.5 / 14.4 |
| 8 | 257,208 | 4.03 / 2.08 | 15.6 / 8.1 |

Step times move with the other job's load (the steps of one run range from 0.9 to 3.5 s), so the
model uses the pooled rate over both runs: 12.14 s per million constraints.

Cost model (`scripts/cost_model.py`, `results/cost-model.json`). A step is c absorb compressions
and one create (measured above) plus the units the design puts in every step: one Merkle merge
(3 compressions), the txid finish (1) and the header hash (3), each at 25,840. The step count of a
block is its event count, 20,304 on average: every event takes one step, and the absorb stream
(15,357 steps at c = 1) and the merge stream (5,455) fit inside it. The step count is the same for
c = 1, 4, 8, so the smallest step, c = 1, is the cheapest:

| c | constraints per step | steps per block | constraints per block | minutes per block | window of six |
|---|---|---|---|---|---|
| 1 | 251,160 | 20,304 | 5.10 × 10^9 | 1,032 | 103 h |
| 4 | 331,272 | 20,304 | 6.73 × 10^9 | 1,361 | 136 h |
| 8 | 438,088 | 20,304 | 8.89 × 10^9 | 1,800 | 180 h |

Where the constraints go per block at c = 1: the typed map operations alone are 6.8 × 10^8 (12,432
creates, 4,408 in-window spends, 3,464 before-window spends at their measured costs) and the body
compressions 4.0 × 10^8. The rest is the per-step merge, txid finish and header units, which a
uniform step pays on every step although a block needs 5,455 merges, 5,449 txid finishes and one
header hash. They are the largest line, so the next design step is to run them at their true rate
(conditional on the step's phase), not to widen c.
