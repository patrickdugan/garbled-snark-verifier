# M3 conformance failures and corrections

The initial run 42161557288 on ff798d8 passed the existing field tests and the
547,778-case Python curve-relation check. Rust compilation of the independent
curve oracle required an explicit Coordinates<A> type. The source formatting
check also requested expansion of one array. Commit d20de4d fixes both.

Run 42161814109 on d20de4d compiled all new tests, then rejected the intended
identity case. The halo2curves fixture adapter had inferred infinity from the
absence of coordinates. halo2curves' CurveAffine::coordinates calls
Coordinates::from_xy, and its curve membership admits the (0,0) identity.
Consequently the adapter received coordinates for infinity and encoded it as
finite (0,0). The Boolean predicate correctly rejects finite (0,0).

The adapter now determines infinity using is_identity(), and demands coordinates
only for finite points. A separate fixture test checks the identity, inverse
cancellation and every native fixture's canonical coordinates and curve equation.
The curve arithmetic predicate itself is unchanged. The unused Group import
was removed. CI uses --no-fail-fast across curve and transcript test binaries,
so a failure in one still leaves diagnostic results for the other.

Both runs above are failed evidence. Their emitted gate counts are preliminary
until the corrected independent and garbled conformance tests pass.
