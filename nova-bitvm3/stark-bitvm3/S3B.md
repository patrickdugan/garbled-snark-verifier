# S3b: saved-trace native proving under observed RSS

## Scope and hypothesis

The first explicit S3a `scarb prove` attempt stopped at an allocation of
469,762,048 bytes under a 6 GiB **virtual address space** limit (`RLIMIT_AS`).
Its measured peak resident memory was unavailable. The native prover may reserve
substantial virtual address space without actually committing that much RAM.

S3b changes just that hypothesis: remove `RLIMIT_AS` from the proof process,
sample the sum of RSS for all ordinary children in the prover's Linux process
group every 100 ms, and terminate the group if it exceeds **4 GiB RSS** or
**120 seconds**. The experiment uses the exact saved `prover_input.json.gz`
from [S3a run 42642735526](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42642735526).
There is **one** opt-in proof attempt per invocation, and verification begins
only after an actual native proof file exists.

The watchdog also reports peak virtual bytes, elapsed time, process count and
return code, including failures. It is a best-effort userspace safety guard,
not a kernel-enforced cgroup. Shared pages can be counted in multiple
processes; a sudden allocation can still trigger host OOM between samples.
The GitHub job retains headroom for the runner and has a ten-minute deadline.

## Reproducibility and script behavior

The input stream is decompressed under a 121,452,932-byte ceiling, and must
match SHA-256 `02c8508f635c7934b1a3ac13eedf5545ea4681f1a72edc51685c7b0fd5ccc031`.
Both the source executable and the locally rebuilt executable must match
`a9bdc409d2f7ee443ac62cabdc8df27fb44c85a435ca9350788bee890f61bef3`.
The Shinigami, RIPEMD160 and SHA1 revisions and local SHA patch digests must
also match S3a. The restored input is placed in the old `execution2` folder.
The native verification step uses Scarb 2.18.0's matching producer/verifier.

`tools/prove_saved.py --prove-saved` is an explicit one-shot command.
The `tools/guarded_process.py` helper uses `/proc` and POSIX process groups.
It applies a 128 MiB maximum file size and disables core dumps; the
proof-stage virtual-memory limit is intentionally absent. It writes
`out/rss-proof-report.json`, `out/rss-proving.txt`, and, if reached,
`out/rss-verification.txt` and `out/native-proof.json`.

Routine CI runs only fast Python guard and restore tests alongside existing
bounded CPU component jobs. The single proof probe is opt-in via
`workflow_dispatch: s3_rss_probe=true` or the `[s3-rss-probe]` commit marker;
its source artifact is downloaded from an immutable Actions run.

## Security and remaining blockers

This is a test-only wrapper which was compiled with `allow-syscalls=true`
because the imported engine retains signature syscall branches. The tested
CSV path executed no syscalls. The Cairo proof stack documents limitations
around proving syscall-enabled executables; syscall availability and proof
soundness require a separate audit. Signature transactions remain unsupported.

Any successful native proof establishes, at most, that Scarb's pinned native
verifier accepted a saved Shinigami execution. It does not establish a
Bitcoin-enforceable Ark exit, UTXORef state transition, or proof-bound program
identity. The S2 complete Boolean STARK verifier pins a different producer
revision, uses weak 16-bit FRI test parameters, and has a different
public-output contract. Those mismatches must be resolved before using its
garbler for a Shinigami proof. Bitcoin dispute transactions and authenticated
input labels remain separate research tasks.

S3a hashes and the failed proof attempt remain untouched in `S3_RESULTS.json`.

## Single bounded trial activation

The input-restoration path matched the saved archive's 121,452,932 bytes,
executable hash and SHA patch in an independent local extraction. Eight
Python watchdog and restore tests passed on the repository runner in
[run 42720468137](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42720468137).
The next explicit marker invokes the one-shot RSS experiment using the
same immutable source artifact; its result is to be recorded separately.
