# S3 Shinigami receipt laboratory

This package calls the real Shinigami engine at commit 7e8c05d60b4bd7ae91ddc18a42e8e13090286f0c. It restricts execution to one noncoinbase legacy-script input, with explicit prevout data and fixed CSV/CLTV/minimal-push/push-only flags. The serialized output includes the complete request and the engine's verdict. It does not validate chain inclusion, spendability, consensus activation, an Ark transaction graph, or a UTXORef state machine. Application tags are domain separators only.

Scarb 2.18.0 matches the toolchain version recorded by the pinned proving monorepo. The two external Cairo dependencies are pinned to the revisions in Shinigami's own lockfile and connected by local manifest paths. No Shinigami engine source is patched.

The initial fixtures exercise a CSV delay and a SHA256 preimage lock. Valid cases and boundary mutations execute the imported Cairo engine. Compilation and execution evidence must be inspected before treating this checkpoint as passed. A proof consumer must cryptographically authenticate the exact compiled program and expected serialized output. A matching receipt digest or an echoed application tag alone is insufficient.

The optional CI job has a ten-minute cap, a 6 GiB execution address-space limit and bounded build/test commands. Full Nova proving remains excluded. Cairo proof generation and complete Boolean/garbled verification are separate opt-in milestones.
