# S3d: native Cairo STARK with reduced preprocessed trace and FFT size

## Source-level memory diagnosis

Both saved-input experiments used Scarb 2.18.0's native Stwo-Cairo producer
at declared revision `467d5c6d4d6d526c1db8ff69c14f2de6d57f4d73`.
The bootloader input had **121,452,932 bytes** and 2,769,899 Cairo steps.
Its standalone equivalent had **9,624,654 bytes** and 157,303 Cairo
steps. Each proof attempt crossed a 4 GiB sampled RSS budget before
completing; virtual memory peaked at 14,147,178,496 bytes in both.

Inspection of this exact producer reveals two input-independent allocation
drivers:

1. `crates/common/src/preprocessed_columns/preprocessed_trace.rs` defines
   `CANONICAL_SIZE = 543100528` M31 field cells, including large Pedersen
   and sequence tables. It also defines `CANONICAL_SMALL = 10161776` cells.
   Counting just one 4-byte M31 value per cell gives **2.02 GiB** vs
   **38.76 MiB** as a *raw-value reference* (about 53.45x fewer cells).
   Polynomial interpolation, commitments, padding and scratch allocations
   add substantially to either number.
2. `crates/prover/src/prover.rs` defaults to
   `preprocessed_trace = Canonical` and `lifting_log_size = None`.
   Its default twiddle domain size is
   `LOG_MAX_ROWS + max(cairo_air_bound, log_blowup) = 27 + 1 = 28`.
   A selected lifting log of 22 reduces the number of twiddle-domain
   points by **64x**. That does not imply a 64x reduction in total RAM.

The recorded standalone trace's Pedersen and Poseidon builtin segments
are both absent. It has 378,673 address-to-id entries and 7,670 counted
program counter entries. The small preprocessed profile retains a
different, narrow-window Pedersen table, and therefore does not assume
that a missing Pedersen builtin licenses removing every Pedersen
constraint from the AIR.

## Exact pinned proposal

The file `s3-shinigami/params/canonical-small-96.json` follows
`ProverParameters` at upstream revision `467d5c6d` and selects:

- `preprocessed_trace = canonical_small`
- `lifting_log_size = 22`
- `store_polynomials_coefficients = false`
- `channel_hash = blake2s`
- `pow_bits = 26`, `n_queries = 70`, `log_blowup_factor = 1`
  (96 bits under upstream's **nominal FRI** accounting).

The selected lifting size is an experiment, with extra headroom above
`SMALL_MAX_SEQUENCE_LOG_SIZE = 20` and the trace observed in S3c.
The native prover must accept the profile and its own matched verifier
must accept the proof before the result counts. This profile has *not*
been security reviewed for Ark, UTXORef or Bitcoin settlement.

The upstream CLI `crates/dev_utils/src/bin/prove.rs` accepts explicit
`--prover_input_path`, `--params_json`, `--proof_path` and `--verify`.
The wrapper's `scarb prove` command has its own default parameters;
S3d builds the **matching source-pinned native binary** and passes this
configuration directly. Upstream pins its Rust toolchain to
`nightly-2025-06-23`.

The trial is explicitly opt-in through `s3_small_profile=true` or a
`[s3-small-profile]` commit marker. GitHub Actions downloads the
immutable [S3c standalone artifact](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42721464987/artifacts/13721151251)
containing its byte-exact input. Source and compressed inputs are checked
before execution. There is **one** native proof attempt, at **4 GiB
sampled RSS** and a **120-second runtime deadline**. Cold compilation
has its own cap, with at most two workers, and the entire job is capped
at ten minutes.

## Security and future compatibility

The modified Shinigami wrapper has unused signature-syscall branches,
with `allow-syscalls=true`. Recorded CSV execution used zero syscalls.
Independent analysis of the Cairo producer's syscall handling and a
proof-bound executable identity are still required.

A successful direct native STARK proof could establish its pinned Cairo
execution relation under the selected profile. The Boolean/garbled S2
verifier uses a **different upstream Stwo revision** and a tiny example
AIR. It cannot accept this Cairo proof without a separate matched
producer/verifier translation. Public output binding, authenticated
garbled labels and Bitcoin dispute transactions are subsequent gates.
No Nova, SP1 or CUDA proving is invoked by S3d.

The memory watchdog uses sampled process-group resident sets; abrupt
host OOM can occur between samples. Default CI runs only static Python
profile tests and earlier Rust checks.

## Reproduction

With the named pinned input artifact expanded in `s3-shinigami/out/frozen`
and an exact checkout of `starkware-libs/stwo-cairo` revision
`467d5c6d4d6d526c1db8ff69c14f2de6d57f4d73` under
`s3-shinigami/vendor/stwo-cairo`:

```sh
cd nova-bitvm3/stark-bitvm3/s3-shinigami
python3 tools/check_low_memory_profile.py --upstream vendor/stwo-cairo
cargo +nightly-2025-06-23 build --locked --profile witness-opt-1 \
  --manifest-path vendor/stwo-cairo/stwo_cairo_prover/Cargo.toml \
  -p stwo-cairo-dev-utils --bin prove
python3 tools/prove_low_memory.py --prove-small-once \
  --rss-mib 4096 --timeout-seconds 120
```
