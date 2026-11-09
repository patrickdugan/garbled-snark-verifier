# Continuation after S0

## S1: pin one real proof and its complete verification relation

Obtain a small authentic proof produced by the selected Shinigami/Cairo toolchain. Record producer commit, program identity, public output encoding, proof parameters and all hash/channel choices. Verify it with the independently pinned native verifier first. Keep that proof and its expected statement immutable and checksum-bound. A mismatch with S0's standard Blake2s profile is an explicit compatibility task.

Use an existing small fixture wherever possible. A new fixture-generation command must have explicit wall-time and memory limits and run outside normal CI. Nova guest A proving is outside this workstream.

## S2: choose and test the complete lowering boundary

The pinned upstream provides `crates/stark_verifier/src/verify.rs`, which builds an arithmetic-circuit verifier through `crates/circuits`. Investigate lowering that representation to this repository's Boolean engine. Importing it has not been implemented by S0.

Inventory every gate type and every constraint in the finalized upstream circuit before accepting a proof. This includes guessed-variable domains, constants, range checks and permutation/multiset semantics. Unsupported gates must fail closed. The prover must never supply an arbitrary circuit or replace the pinned statement. Auxiliary inverse witnesses must be checked, with zero denominators rejected.

An alternative is a direct port of the native verification stages. Either approach must cover the full transcript, proof-of-work checks, OODS, AIR/composition evaluation, complete FRI, query derivation and PCS decommitments. Compare native and Boolean intermediate values on the same immutable proof and mutate each major input class.

Completion evidence: a real proof passes the pinned native verifier and Boolean verifier; mutated proof or statement values fail; corresponding garbled execution reaches the expected labels. Record the total gate count and peak memory only after complete acceptance is wired.

## Application binding for Ark and UTXORef

Define the application statement before exposing a receipt. It must bind the intended Bitcoin network, transaction and input, all required prevout values/scripts, script version and flags, and the exact program/verifier policy. The selected chain anchor and freshness/reorg policy are separately checked. Ark adds its transaction-graph and timeout rules. UTXORef adds its authorization and state-transition relation, including replay prevention.

A digest field alone does not prove these checks ran: the authenticated Cairo output must bind the data, and the consumer must compare it with the expected application statement. Full Bitcoin transaction validity and current spendability require their corresponding checks beyond script execution.

## Settlement and budget gate

Treat Bitcoin challenge transactions, authenticated garbled inputs, setup assumptions, and adversarial dispute execution as a separate acceptance stage. S0's test-only label access and seeded randomness are unsuitable for deployment.

Keep default CI on recorded small fixtures with fixed resource caps. Measure complete verifier gates, garbling bytes, peak RSS and dispute costs before comparing a direct Stwo route with the existing SP1 wrapper. The 57,929-gate component result supplies no full-verifier size estimate.

## Before opening or merging a pull request

The experimental branch push triggers only the dedicated component workflow. Some existing repository pull-request workflows match `nova-bitvm3/**`; narrow their paths for this isolated pilot before opening a PR if preserving the lightweight CI envelope is required. Preserve coverage for changes to the sources those workflows actually exercise.
