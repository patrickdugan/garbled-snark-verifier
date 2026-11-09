# Shinigami receipt laboratory

This package executes the pinned Shinigami engine for two explicitly bounded legacy-script profiles. It produces a receipt containing the complete transaction request, fixed semantics and the execution verdict. See [S3.md](../S3.md) and [S3_RESULTS.json](../S3_RESULTS.json) for measurements and exact evidence.

**Execution checkpoint passed:** 21 Cairo tests, a standalone CSV execution with 157,303 steps, and a 21-word receipt checked against independent transaction bytes and transaction-hash calculation. The local receipt audit rejects 25 output mutations. An additional bootloader execution completed and its compressed prover input is saved.

**Native proving remains blocked:** the one opt-in proof attempt aborted on an allocation failure under the 6 GiB address-space cap. No Cairo proof was generated or verified. S2's full Boolean/garbled proof result remains a separate small example.

## Sources and compatibility

Shinigami is pinned to `7e8c05d60b4bd7ae91ddc18a42e8e13090286f0c`. RIPEMD160 and SHA1 dependencies use the exact revisions in its lockfile. Scarb is 2.18.0. `tools/prepare.py` localizes those dependencies and replaces three SHA-256 imports with `compat/sha256.cairo`, recording the exact patch and hashes. The engine's Bitcoin opcode and transaction logic remain unchanged.

The pure Cairo SHA implementation is tested against twelve independent SHA-256 and double-SHA-256 vectors. The compiler admits upstream's unused signature syscall branches through `allow-syscalls=true`; supported locking scripts and push-only ScriptSig checks keep those paths outside this pilot. Both measured CSV executions reported zero syscalls.

## Scope

Only regtest-tagged, single-input, noncoinbase legacy transactions are accepted by the wrapper. Supported locking scripts are a fixed ten-unit CSV script and a SHA256 hashlock. Application IDs label intended consumers. Ark ownership/exit graphs, UTXORef state transitions, signatures, chain anchoring and replay prevention remain separate requirements.

The complete request is public in the receipt, including ScriptSig. The log auditor does not authenticate a STARK, and the native proof probe never emits a production acceptance token. A future verifier must bind the expected compiled program and public output to the application's own statement. Scarb's bundled producer differs from the S2 verifier pin; the public-output format also needs an explicit adapter.

## Run

With pinned checkouts under `vendor/`, use:

```sh
python3 tools/prepare.py
python3 tools/cases.py out
scarb build
scarb test
scarb execute --no-build --arguments-file out/csv_valid.args.json --print-program-output --print-resource-usage > out/execution.txt
python3 tools/audit_execution.py out/execution.txt
```

`tools/prove_once.py --prove` is a separate, explicitly opted-in experiment. It enforces its memory/file limits and command deadlines, writes each stage's return code and preserves failure evidence. The known allocation failure is recorded in S3_RESULTS.json; default CI does not retry it. No Nova proving is part of this package.

## Independent receipt equality policy (S3e-preflight)

The proof-free Python `tools/receipt_policy.py` encodes the exact Shinigami Cairo public-output words for the scoped Ark CSV and UTXORef hashlock requests, including full transaction bytes, prevout script/amount/height, request ID, verdict and double-SHA-256 transaction hash. `tools/test_receipt_policy.py` checks both accepted fixture formats against their input serializers, including the previously captured 21-word CSV receipt; it rejects every individual public-output word mutation, context substitutions and noncanonical Cairo values. The function's result always marks STARK proof, program identity, chain spendability and application-state verification as **false**. These checks are a consumer-side equality contract and must never be used as a settlement authorization. The producer-version mismatch with S2 remains open.
