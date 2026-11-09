# Continuation after S2

S2 at `f90a7095` checked an authentic upstream example STARK against one fixed complete verifier in native, Boolean and garbled execution. Preserve the source pin, fixture hashes, explicit public bindings and bounded execution policy described in S2.md.

## Shinigami and production-profile work

Locate a small authentic Shinigami proof with its exact producer version and Cairo program identity. Determine the complete proof/hash/channel profile before choosing an adapter. The currently tested profile is standard Blake2s at proving commit `e9a38e12`; proof bytes from a different profile must fail closed. Begin with standalone native verification and a frozen fixture, then construct the corresponding proof-independent verifier template.

Bind the authenticated public output to the intended application statement. It should identify the Bitcoin network and transaction/input and all required prevout data, with the applicable script semantics and verifier policy. Ark adds transaction-graph and timeout requirements. UTXORef adds authorization, state-transition and replay-prevention checks. Chain anchoring, reorg policy and current spendability need their appropriate independent checks.

Replace the 16-bit test FRI profile with a security-reviewed production configuration. Record its complete graph and input-commitment costs before starting a large garbled run. The S2 ciphertext count cannot be scaled into a production estimate without building that profile. Keep GPU/Nova proving outside this experiment.

Audit the actual complete relation for denominator nonzero obligations, transcript binding, proof-shape policy and finalized witness domains. The S1 gate tests and S2 mutations provide differential evidence; formal compiler correctness and a cryptographic security review remain outstanding.

## Budget, fixtures and settlement

The current frozen evidence lives in a hash-pinned Actions artifact, also supplied as a ZIP in the ChatGPT result. Preserve a durable in-repository copy before the source artifact's February 7, 2027 expiry. The existing optional workflow fails closed when that source artifact is unavailable. Preserve byte-exact bundle/witness hashes, since a regenerated proof's JSON map ordering can differ.

Investigate constant elimination and reducing internal witness inputs while preserving the same accepted relation. S2 exposes 12,206,976 input bits for its small example, so authenticated-input overhead deserves a separate benchmark. Use trusted template structure for specialization and keep all private values out of graph construction decisions.

A Bitcoin-enforceable deployment also needs authenticated garbled inputs, setup assumptions, the transaction/challenge graph and adversarial dispute execution. The current fixed-seed, direct-label laboratory does not implement that protocol. Off-chain ciphertext bytes are distinct from on-chain transaction bytes.

Default CI remains on small components. Run full-verifier work only by explicit opt-in, with fixed wall-time and memory caps. Preserve coverage of unrelated workflows when narrowing their paths for a future PR; broad nova-bitvm3 pull-request globs still need review before opening one.
