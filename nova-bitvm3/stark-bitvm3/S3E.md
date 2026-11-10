# S3e: Exact public memory pins for Shinigami STARK candidates

## Source evidence

The byte-exact S3c standalone trace contains 169,856 public program words. Their canonical 32-byte little-endian Cairo serialization hashes to `ef98c72eff798d04a235c395be190c38b536a584a9dd5f66692e2174ac5b8b7f`, matching the compiled Shinigami executable bytecode hash recorded in S3a. The output has 21 words matching the independently serialized CSV request and execution result.

The S3a bootloader trace contains 3,182 public program words with digest `81761bcc7b4d619eca468e933248097b304135b29d855be1ccfba02363c2966e`. Its output has 24 words. The initial three words are observed bootloader metadata and are pinned separately; their interpretation as a cryptographically authenticated executable identity remains an open requirement.

## New implementation

`s3-shinigami/tools/claim_binding.py` checks a future Cairo STARK proof JSON against repository-owned policies. It compares the complete `claim.public_data.public_memory.program`, canonical field limbs, exact output words, public output segment addresses, preprocessed trace choice, channel salt and nominal PCS/FRI parameters. The standalone policy directly pins executable bytecode. The bootloader policy covers the bootloader's own public program.

A structurally matching JSON claim remains unauthenticated until its exact bytes pass the **matching native Stwo-Cairo verifier**. All reports explicitly return false for native-proof verification, authenticated executable identity, application state and Bitcoin settlement. Source producer compatibility with S2 and BitVM3 challenge transactions remain separate milestones.

`tools/rederive_source_pin.py` recomputes these hashes and receipts from the frozen 121,452,932-byte bootloader input or the 9,624,654-byte standalone input. The code uses source file sizes, SHA-256 and exact memory addresses. This was checked independently against both archived S3a/S3c inputs, without prover execution. Routine CI only runs small synthetic mutation cases; archived traces stay out of CI.

## New native-prover finding

The reduced-memory trial in [run 42724836768](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42724836768) successfully compiled the pinned Stwo-Cairo prover. Proving reached the interaction trace, then stopped at the `lookup_sum` assertion in `crates/prover/src/prover.rs:185`. The measured peak RSS was **1,316,683,776 bytes**, with 18.719 seconds of proof-process runtime.

The saved standalone witness is incompatible with that trial's `canonical_small` preprocessed relation. Repeating the same input/profile pair will repeat the failure. No STARK proof was produced. A new proving attempt requires a changed, justified preprocessing relation, source pin and independently verified native result.

## Audit commands

From `nova-bitvm3/stark-bitvm3/s3-shinigami`:

```sh
python3 tools/rederive_source_pin.py /path/to/shinigami-s3-standalone-evidence.zip --profile standalone
python3 tools/rederive_source_pin.py /path/to/shinigami-s3-native-probe.zip --profile bootloader
python3 -m unittest discover -s tools -p 'test_*.py' -v
python3 tools/claim_binding.py /path/to/proof.json --profile standalone
```

The last command only checks the public fields. An authentic native proof and matched verifier remain necessary for an authenticated acceptance result. Ark exit/forfeit logic, UTXORef state authorization, spendability and Bitcoin dispute settlement are outside this checkpoint.
