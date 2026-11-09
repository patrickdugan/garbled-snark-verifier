# S3c: one bounded standalone Shinigami proof experiment

The S3b bootloader trace used **2,769,899** Cairo steps and crossed **4 GiB
resident memory** after 10.116 seconds, reaching **13.18 GiB virtual
address space**. S3b stopped safely; no native proof was produced. See
[S3B_RESULTS.json](S3B_RESULTS.json) and
[run 42720650399](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42720650399).

The original **standalone** execution used only **157,303** Cairo steps,
a reduction in the executed workload by a factor of about **17.6**.
Scarb documents that standalone executions can be given directly to
`scarb prove`. S3c tests this separate, smaller trace using the same
pinned executable, fixed CSV request and local SHA-256 compatibility patch.

The executable SHA-256 must be
`a9bdc409d2f7ee443ac62cabdc8df27fb44c85a435ca9350788bee890f61bef3`.
Before proving, a new execution must pass the independent 21-word receipt
audit with zero reported syscalls. Its prover-input bytes and hash are
recorded and a deterministic gzip copy is saved for future comparisons.

Proving is explicitly opt-in via `s3_standalone_probe=true` or
`[s3-standalone-probe]`. The one-shot Scarb prover gets a **4 GiB sampled
RSS** ceiling and **120-second** deadline; the whole job has a ten-minute
hard cap. Default CI adds only small, proof-free Python tests. A proof file
is checked by Scarb's native verifier if the prover succeeds.

The active program includes Starknet signature-syscall branches even
though this CSV profile executes zero syscalls. Scarb cautions that syscall-
enabled programs have proof limitations. A successful native proof requires
a separate soundness and program-identity audit. Standalone verification
cannot by itself bind a bootloader program hash. S2 pins a different Stwo
producer and an unrelated test AIR. Ark and UTXORef validity, authenticated
garbled inputs and Bitcoin dispute settlement remain separate work.

No Nova, SP1 or CUDA proof runs in this experiment.
