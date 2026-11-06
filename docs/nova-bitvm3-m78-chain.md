# M7/M8: computed sumcheck chains and outer-phase algebra

The new `nova::sumcheck::chain` module retains a shared Boolean transcript
across every round. Each claim is computed from the previous round and its
hash-derived challenge. The witness contains compressed coefficients only;
there are no intermediate-claim or challenge inputs to replace.

## M7 reduction

`reduce` accepts verifier-owned expected round count and degree bound.
It supports nonempty proofs with degree bounds 2 or 3 and per-round degrees
1 through that bound. The circuit constructor rejects mismatched shapes.
Zero-round handling is intentionally outside this API. Every external scalar
is checked for canonical representation. The result's acceptance bit retains
all prior admission failures, including failures in earlier transcript input.

The initial claim must be bound by the caller to the Spartan statement.
A standalone reduction is not a complete satisfiability or commitment proof.
The serialized decoder must enforce the same public shape before allocating.

## M8 outer phase and transition

`outer_phase` follows Nova 0.76's non-EVM transcript schedule:

1. Squeeze the verifier-owned number of tau challenges under label `t`.
2. Reduce the cubic outer proof from the constant zero claim.
3. Check `final = eq(tau,r_x) * (Az*Bz - u*Cz - eval_E)`.
4. Absorb `[Az,Bz,Cz,eval_E]` under `claims_outer`.
5. Squeeze mixing challenge `r` and compute `Az+r*Bz+r^2*Cz` for the inner phase.

All equality-polynomial products and field operations run in Boolean gates.
The caller supplies a transcript already bound to the trusted verifier key
and relaxed R1CS instance U. The u argument must share its wires with U.u.
Final R1CS matrix/evaluation equations and IPA openings are still required.
The returned validity wire must be conjoined with subsequent acceptance.

## Tests and evidence

The new integration test checks native Nova reductions on both Pasta fields
for one through four rounds. It checks the next transcript challenge too.
Counterexamples include resets, reordered rounds, modified proof words and
noncanonical scalars accompanied by recomputed raw-byte hash outputs.

Outer-phase fixtures use actual multilinear tables. The error table satisfies
E=A*B-u*C at each Boolean point. An independent test prover sums over remaining
Boolean assignments, interpolates each cubic polynomial, and then checks the
proof with Nova 0.76's native SumcheckProof::verify. The Boolean graph checks
its final equality and transition. Tampered evaluation claims are also tested
with recomputed mixing and inner outputs, so rejection must include the
terminal algebraic relation.

Disk-backed garbling/evaluation covers a three-round cubic chain and a
two-round outer phase. Counts are printed by successful CI; none are inferred
here. Source files from the actual pinned Nova package are retained in its
artifact. Peak RSS is measured after compilation by /usr/bin/time. Buffer
reservations remain separate from any OS memory ceiling.

Run the new test directly when local runs resume:

```sh
cargo +1.90.0 test --release --locked --manifest-path nova-bitvm3/Cargo.toml \
  --features native-reference,curve-reference --test spartan_chain \
  -- --nocapture --test-threads=1
```

No header proving or user-device workload is launched by this development.
This milestone does not implement bincode decoding, inner R1CS matrix checks,
batched polynomial evaluation, IPA verification, Nova Poseidon consistency,
or the authenticated BitVM3 transaction graph.
