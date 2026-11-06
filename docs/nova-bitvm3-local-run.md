# Local Nova component run after the RAM upgrade

Run from the repository root with Python 3.10+ and rustup. The wrapper invokes
Rust 1.90.0, leaves default SP1 features disabled, and builds each selected
configuration before timing its run. It never launches the Bitcoin header prover.

## First run

```sh
git pull --ff-only origin main
rustup toolchain install 1.90.0 --profile minimal
python nova-bitvm3/local_run.py --suite all --jobs 4 --threads 4
```

On Windows, `py -3` may be used in place of `python`. WSL uses the same command.
The Python wrapper includes Windows memory discovery and process-tree cleanup;
CI exercises Linux. Native Windows Rust compilation has not been tested here.
The jobs/threads values are concurrency settings, not RAM ceilings. Begin with
2 for either setting when other jobs need the machine. Tests run serially.

`all` covers the field kernels, complete point-addition relations, host transcript
reference, and Boolean/garbled transcript checks. Each run gets a fresh directory
under `nova-bitvm3/results/local-<UTC timestamp>/`. It contains receipt.json,
command logs, resolved Cargo.lock and SHA-256 identities for retained artifacts.
The receipt records total/available RAM where supported, CPU count, free disk,
commit, tracked worktree changes, command status and separate build/run times.
It does not measure peak process RAM or enforce an OS memory limit.

For only the new work:

```sh
python nova-bitvm3/local_run.py --suite transcript --jobs 4 --threads 4
```

## Per-round Spartan conformance

The added `sumcheck` suite checks one degree-2 or degree-3 Spartan round
against Nova 0.76, including a streamed cubic-round garbling benchmark.
It remains a component test:

```sh
python nova-bitvm3/local_run.py --suite sumcheck --jobs 2 --threads 2
```

## Native transparent proof baseline

```sh
python nova-bitvm3/local_run.py --suite native --jobs 4 --threads 4
```

This runs the existing two-step x -> x^2+5 Nova reference (2 -> 9 -> 86), with
Spartan/IPA compression, and saves proof.bin, vk.bin and the native receipt.
It is a native toy proof, not a mainnet/header proof or a full garbled verifier.
Use the separate header-prover repository for the later chain-proving job;
this change does not modify its circuit width k or existing checkpoints.

## Preparation and reproducibility

`--build-only` compiles the selected suite and skips execution. `--plan` prints
commands without invoking Cargo or writing files. The per-command timeout is
30 minutes; `--timeout-minutes N` changes it. Failure or timeout returns a
nonzero exit code and retains the logs and failure receipt.

The first run resolves dependencies when Cargo.lock is absent. All subsequent
commands use --locked. For byte-identical dependency selection, extract Cargo.lock
from the CI evidence ZIP and pass `--lockfile /path/to/Cargo.lock`; the wrapper
refuses to overwrite a different existing lockfile. M3 and the initial M4 run
used lock SHA-256 `1bf607f0994d6f602ece034440a15fdfcd368a1f9633a5c8f6fe57dadba73ba6`.

```sh
python nova-bitvm3/local_run.py --suite all --build-only --jobs 2
python nova-bitvm3/local_run.py --suite transcript --plan
```

The useful comparison is the run-phase log and elapsed time against the same
commit and lockfile. Hardware discovery is a snapshot, and installed RAM alone
does not establish a proving-memory budget. Preserve headroom for the OS and
other work before choosing a larger header batch.
