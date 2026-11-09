# Continuation after S1

## Completed checkpoints

S0 implements bounded Boolean Stwo primitives and a garbled pinned-root opening. S1 imports every gate family of the pinned upstream finalized circuit and checks raw witnesses with explicit constants/public outputs. The importer compiles against actual upstream code and passes native differential tests. Synthetic all-gate witnesses also pass through the repository garbler. Evidence lives in RESULTS.json and S1_RESULTS.json.

## S2: one authentic proof through a fixed full verifier

Select a small immutable Stwo proof and independently verify it with the exact native verifier profile. Prefer a recorded fixture. If one must be generated, use a separate opt-in command with wall-time and memory caps; keep proof generation out of default CI. Nova guest A proving is outside this workstream.

The pinned upstream `crates/stark_verifier_examples/src/verify_test.rs` demonstrates construction of a no-value verifier circuit and a traced witness from a small proof. Its `simple_air.rs` is a candidate reference application. Those sources were inspected; S1 did not invoke that example or build its prover. Record the actual hash profile instead of assuming that the S0 standard-Blake2s profile is selected by the example.

Build the trusted verifier template from the selected application, proof parameters and fixed public policy, independently of witness bytes. Use the complete `crates/stark_verifier/src/verify.rs` relation and actual finalization. Import it with the S1 adapter. Pin the template identity and all public outputs. A traced context can supply witness values, but its graph and constants must agree with the independently built template before reuse.

Require the immutable valid proof to pass native verification and the entire Boolean relation. Mutate proof data, query indices, commitments and public claims while retaining the same template and policy. Every input-canonicality check must reach acceptance. Confirm equivalent accept/reject labels in garbled evaluation under an explicit resource budget.

The S1 default shape limits intentionally admit small fixtures only. Count the full template and estimate its Boolean work before increasing them. Record input bits, constants, constraints per family, largest permutation, total non-free gates and peak memory. Internal variable witnesses increase the authenticated input layout; include their cost.

Completion evidence for S2 must distinguish a complete small STARK proof from the current synthetic gate fixtures. Passing S2 for a simple AIR does not establish Cairo/Shinigami compatibility.

## Shinigami, Ark and UTXORef

Pin the Shinigami/Cairo producer and its program identity. Require exact proof-format, channel, hash and public-output agreement with the chosen verifier. Then authenticate one small Script execution result and mutation cases.

The application statement must bind the Bitcoin network, transaction/input, required prevout amounts and scripts, Script version/flags, and the selected program/verifier policy. The chain anchor and reorg/freshness policy remain separately checked. Ark adds its transaction-graph and timeout conditions. UTXORef adds authorization, state-transition and replay-prevention rules.

A digest supplied as an unverified label establishes none of these checks. The authenticated program output must bind the intended data, and the consumer must compare it with an independently selected expected statement. Current spendability and broader Bitcoin transaction validity need their corresponding checks beyond Script execution.

## Bitcoin enforcement and resource comparison

Validate authenticated garbled inputs, setup assumptions and adversarial Bitcoin challenge transactions as a separate stage. The tests' seeded randomness and direct label access serve local correctness checks only.

Keep default CI on bounded verification fixtures. Compare complete verifier gates, input commitments, garbling bytes, peak memory and dispute costs with the existing SP1 route only after the full relation passes. Neither S0's 57,929-gate opening nor S1's 43,055-gate compact fixture estimates a complete STARK verifier.

Before opening or merging a PR, narrow existing broad `nova-bitvm3/**` PR filters for this isolated workstream while preserving tests for their actual dependencies. The current feature-branch push uses only the dedicated component workflow.
