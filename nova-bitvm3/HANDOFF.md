# Integrating nova-bitvm3 into other projects

What another project can consume from this directory, and one brief per target project. Each
brief is meant to start its own session; the session reads this file first.

## What exists

| Piece | Where | State (2026-11-11) |
| --- | --- | --- |
| Nova header chain (NHC1 mainnet, NHT4 testnet4), genesis-anchored, k = 1 | `zk-rusto-no-bitcoino` (`nova-chain`) | testnet4 to 158,970 proven; mainnet 0–975,072 proven in two shards |
| Guest A: Nova verify inside SP1 | [`m12`](m12), raw keys in [`m15`](m15) | 21.2 × 10^9 instructions with raw keys, statement unchanged |
| M16 guest: chain + SPV payment | [`m16`](m16) | mainnet tip 975,072 with a payment at 975,067 executed: 34.1 × 10^9 instructions, statement `cae6068f…c869`, 13/13 mutations refused; proved on the GPU, wrapped, and accepted by the M14 circuit plain and garbled (final proof `m13/fixtures/m16-wrap-blake3-v2.bin`) |
| GPU prover | [`prover-gpu`](prover-gpu) | guest A (03c56e6) and the M16 mainnet guest proved on the laptop GPU |
| SP1 wrap verifier, native, BLAKE3 transcript v2 | [`m13/verify`](m13/verify) | pins in [`m13/pins.json`](m13/pins.json) |
| Final verifier as a garbled circuit | [`m14`](m14) | 785,442,492 non-free gates, garbled and evaluated on real proofs |
| Bitcoin Script (legacy, P2SH, witness v0) as a Nova step, from Shinigami's engine | [`m17`](m17) | 6,808 constraints per step; native engine agrees with Core on all 2,756 non-Taproot vectors; signature, hash and locktime checks deferred to a native claim checker |

## The interface other projects use

A consumer never touches Nova. It receives an SP1 wrap proof and checks it with `m13-verify`
(or, in a BitVM3 setting, the M14 circuit). The statement it accepts is the guest's committed
public values:

```
guest A (1,164 bytes): magic "NHC1"|"NHT4" | u32 k | u32 steps | z0 (17 × 32) | zn (17 × 32)
                       | sha256(compressed vk) | proofs digest
M16 adds 128 bytes:    "PAY1" | u32 segments | u32 height_B | hash_B | u32 confirmations
                       | txid | u32 vout | u64 value | u32 script length | sha256(script)
```

Integers are little-endian; txid and hash_B are in Bitcoin's internal byte order (reversed from
how explorers show them). The mainnet bytes are
[`m13/fixtures/m16-public.bin`](m13/fixtures/README.md): k = 1, steps 975,072, then PAY1 with 2
segments, height 975,067, 6 confirmations, vout 0, 940,000 sats, a 22-byte script.

z0 is the genesis state, so a consumer pins it; zn carries the tip height, tip hash and
chainwork. A consumer must check: the program vk digest it trusts, magic and k, z0 equal to the
genesis state for its network, `confirmations` ≥ its own threshold, and the payment fields it
expected (txid or script hash, value, vout). It must not trust a statement whose tip chainwork
it has not compared against what it knows of the chain: the proof shows a valid
proof-of-work chain from genesis, not that it is the heaviest one.

Pins:
- mainnet k = 1 key: compressed `6aa50d09…da1d`, raw `4e815db8…7615`;
- testnet4 k = 1 key: compressed `6894f490…c12a`, raw `63f91f1e…d20e`;
- M16 ELF `bb7d51b0…` (rebuild with [`m16/scripts/build.sh`](m16/scripts/build.sh));
- M16 program key `dfc68a5d…cb60` (in [`m13/pins.json`](m13/pins.json));
- M16 mainnet statement (tip 975,072, payment at 975,067) `cae6068f…c869`, proved: final proof
  and statement in [`m13/fixtures`](m13/fixtures/README.md) (`m16-*`).

Costs to budget: about 5 GPU hours per mainnet M16 proof (two segments) on the laptop; extending
an existing chain proof is `nova-chain resume` at about 5 headers/s per process plus one GPU run;
the garbled verifier is 12.6 GB of ciphertext per instance.

## Briefs

Each is independent. None needs another's result. Until the mainnet proof lands, integrate
against the mainnet statement above (its inputs are listed in `m16/README.md`), the block-170
test inputs and the testnet4 pins; swap in the proof when it is published here.

### 1. zk-rusto-no-bitcoino: mirror and pin
Repo `patrickdugan/zk-rusto-no-bitcoino`, path `integrations/bitvm3-nova`. Mirror `m15` and `m16`
(sources, READMEs, scripts; no build output), add the mainnet k = 1 pin to `nova-header-chain`'s
pin table next to NHT4, and add a CI job that builds the M16 ELF and checks its hash. Done when
the mirror builds in CI and the pin test passes.

Status: pin and CI job done; the ELF hash check fails and needs a decision.
- Mainnet (NHC1) k = 1 pinned in `m12/native/src/pins.rs` (`M12_PINNED_KEYS`; the upstream table at
  de607d3 held only mainnet k = 10 and testnet4 k = 5, 10). New `m12/native/tests/pins.rs`: accepted for
  mainnet k = 1, refused for testnet4 and for k = 2, 5, 10, 20, and other keys refused for mainnet k = 1.
  Run in WSL: 3 passed; `k1_key_rebuilds_to_its_pin` still passes. zk-rusto 99b23f7, this repo b72508f.
- CI job `.github/workflows/bitvm3-nova-m16-elf.yml` (SP1 v6.9.0 via sp1up, protoc, `m16-nova-spv-script elf`):
  zk-rusto runs 42956307446, 42957698722, 42959382930, 42961666740 (c204d4a through 3a371d7). The build
  succeeds; the runner's ELF is 1,239,848 bytes with SHA-256 `789aa6c9569e195ff51694faaf94bbf7313cc757ee737132a615dffcbe8d4240`,
  identical on every run, against the pinned `bb7d51b0...`. Same cargo-prove (b8387fa) and rustc 1.96.0-dev as the
  WSL build. The pin is unchanged.
- Cause: the guest build is not byte-stable. Two builds in WSL from the same clean checkout at same-length
  paths gave 1,239,848 bytes (`ae19737f...`) and 1,240,008 bytes (`066bd5e2...`); neither equals `bb7d51b0...`.
  The differences are code bytes only (the non-path string sets match). The README's ELF hash needs a
  reproducible build (single codegen unit or a fixed build container) before CI can pin it.


### 2. UTXO-Ref / KeyAgentNet: payment-gated release
Repo `patrickdugan/UTXO-Ref` (branch `research/keyagentnet-distributed-v01`). The distributed
signer releases a signature only on a valid M16 statement whose payment pays a script the
coordinator registered, with at least n confirmations. Add a statement parser and policy check
in Rust, verified with `m13-verify` as a library, and regtest scenarios: accepted payment, wrong
script, too few confirmations, wrong genesis, tampered proof. Done when the new scenarios run in
the existing regtest harness alongside the 12 current ones.

### 3. TradeLayer-Rust: deposit proofs
TradeLayer-Rust's deposit path. Use the PAY1 record as an attestation that a deposit output
exists with a given script hash and value, consumed by the listener, so a light client can
credit a deposit without a full node. Design note first (where the statement enters consensus,
replay protection by txid:vout), then the parser, then tests. Bitcoin first; keep the Litecoin
path separate.

### 4. blossom-storage-bonds: bond settlement on a proven payment
Repo `patrickdugan/blossom-storage-bonds` (public). Phase 6 used risc0-to-bitvm2's header
chain. Add a variant that uses the M16 statement for
"client paid the provider on chain" and the Nova chain for the epoch seeds' block hashes, with
both pins checked. Done when `full-stack.ts` can run with the M16 verifier in place of the
risc0 term guest on regtest-shaped fixtures.

### 5. vtxo-exit-proof: confirmed exit
Repo `patrickdugan/vtxo-exit-proof` (public, with CI). Prove that an Ark VTXO's exit transaction
confirmed: the M16 record's txid equals the last exit-chain transaction, with n confirmations.
Compose by checking both statements in one verifier (or by recursion in SP1 if cheaper; measure
both). Done when the composed check is tested against a regtest exit.

### 6. Litecoin analogue
The Nova step circuit hashes SHA-256d; Litecoin's proof of work is Scrypt, which is far too
large per Nova step. Write the design note only: an SP1-proved Scrypt check per header batched
under the Nova chain of SHA-256d links, its cost from the measured single-header Scrypt proof,
and whether that is cheaper than a per-header SP1 path. No implementation until the numbers favour it.

### 7. rust-bitcoin zk-client: light client on the Nova statement
Fork `patrickdugan/rust-bitcoin`, branch `zk-client`. Add a sync mode that accepts the guest A
statement (verified by `m13-verify`) as the starting checkpoint instead of re-verifying headers,
then follows headers from zn's tip natively. Done when the client syncs testnet4 from the NHT4
statement and agrees with Core on the tip.

## Links

- This directory: https://github.com/patrickdugan/garbled-snark-verifier/tree/main/nova-bitvm3
- M15 + M16 commit: https://github.com/patrickdugan/garbled-snark-verifier/commit/d4aefcd
