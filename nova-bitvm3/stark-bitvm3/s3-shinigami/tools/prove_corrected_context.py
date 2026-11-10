#!/usr/bin/env python3
"""One opt-in native proof of the frozen Shinigami CSV trace with its public segment
context corrected to the builtins the program actually has.

S3p localized the whole global lookup residual to two memory relations. The cause is
an input mismatch, not a prover constraint: the frozen prover input declares all eleven
builtin segments public (the bootloader default), but the standalone executable has
three (output, range_check, bitwise). The claim's public-memory extraction then reads
eleven start and stop pointers, mistakes 86,367 builtin cells for program output, and
adds public-memory uses that the memory tables never yielded. The VM's own
`public_memory_addresses` already matches the three-builtin layout.

This tool changes exactly that one field, only from the all-present default, and runs
the unmodified pinned prover with its built-in verification. It is not a Shinigami
application receipt: program identity and the receipt binding stay outstanding.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

from check_low_memory_profile import check_profile, verify_upstream_checkout
from guarded_process import guarded_run, write_report, MAX_FILE_BYTES
from prove_low_memory import (
    PROFILE_PATH, SOURCE_INPUT_BYTES, SOURCE_INPUT_SHA256, check_frozen_input, validate_frozen_source,
)
from prove_saved import digest, restore_input

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "out"
# Canonical builtin order of PublicSegmentContext / PublicSegmentRanges in Stwo-Cairo.
BUILTIN_ORDER = (
    "output", "pedersen_builtin", "range_check_builtin", "ecdsa_builtin", "bitwise_builtin",
    "ec_op_builtin", "keccak_builtin", "poseidon_builtin", "range_check96_builtin",
    "add_mod_builtin", "mul_mod_builtin",
)
ALL_PRESENT = [True] * len(BUILTIN_ORDER)


def derive_present(builtin_segments: dict) -> list[bool]:
    """Which of the eleven canonical builtin segments the execution actually has."""
    unknown = sorted(k for k, v in builtin_segments.items() if v is not None and k not in BUILTIN_ORDER)
    if unknown:
        raise ValueError(f"unknown builtin segment in the prover input: {unknown}")
    if builtin_segments.get("output") is None:
        raise ValueError("the prover input has no output segment")
    return [builtin_segments.get(name) is not None for name in BUILTIN_ORDER]


def correct_context(data: dict) -> dict:
    """Replace the all-present default context by the derived one; touch nothing else."""
    context = data.get("public_segment_context")
    if not isinstance(context, dict) or set(context) != {"present"}:
        raise ValueError("unexpected public segment context shape")
    before = list(context["present"])
    if before != ALL_PRESENT:
        raise ValueError("refusing to change a public segment context that is not the all-present default")
    after = derive_present(data["builtin_segments"])
    if after == before:
        raise ValueError("the derived context equals the default; nothing to correct")
    context["present"] = after
    return {
        "field": "public_segment_context.present",
        "builtin_order": list(BUILTIN_ORDER),
        "before": before,
        "after": after,
        "present_builtins": [n for n, p in zip(BUILTIN_ORDER, after) if p],
        "public_memory_addresses_in_input": len(data["public_memory_addresses"]),
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--prove-corrected-once", action="store_true", required=True)
    p.add_argument("--source", type=Path, default=OUT / "frozen")
    p.add_argument("--upstream", type=Path, default=ROOT / "vendor/stwo-cairo")
    p.add_argument("--rss-mib", type=int, default=4096)
    p.add_argument("--timeout-seconds", type=int, default=120)
    a = p.parse_args()
    if not (1024 <= a.rss_mib <= 5120 and 1 <= a.timeout_seconds <= 120):
        p.error("RSS budget 1024..5120 MiB and deadline 1..120 seconds required")
    OUT.mkdir(parents=True, exist_ok=True)
    report_path = OUT / "small-profile-context-report.json"
    report = dict(
        schema=1, stage="S3q: native proof with the public segment context corrected",
        status="started", native_proof_verified=False, application_statement_authenticated=False,
        program_identity_bound=False, bitcoin_consensus_and_dispute_verified=False,
        s2_boolean_garbled_verification=False,
        scope="one pinned standalone CSV trace; laboratory only; unmodified pinned prover and verifier",
        recorded_security="96-bit upstream nominal FRI PoW+queries",
        stages=[], rss_budget_mib=a.rss_mib, deadline_seconds=a.timeout_seconds)
    frozen = OUT / "small-profile-prover-input.json"
    corrected = OUT / "small-profile-corrected-input.json"
    proof = OUT / "small-profile-native-proof.json"
    try:
        report["config"] = check_profile(json.loads(PROFILE_PATH.read_text()))
        report["upstream_sha"] = verify_upstream_checkout(a.upstream)
        report["source"] = validate_frozen_source(a.source)
        report["input"] = restore_input(a.source / "standalone-prover-input.json.gz", frozen,
                                        expected_bytes=SOURCE_INPUT_BYTES, expected_sha256=SOURCE_INPUT_SHA256)
        report["trace"] = check_frozen_input(frozen)
        data = json.loads(frozen.read_text())
        report["context_correction"] = correct_context(data)
        corrected.write_text(json.dumps(data, separators=(",", ":")))
        report["corrected_input"] = dict(bytes=corrected.stat().st_size, sha256=digest(corrected))
        if proof.exists():
            raise ValueError("refusing to overwrite an existing proof")
        binary = a.upstream / "stwo_cairo_prover/target/witness-opt-1/prove"
        if not binary.is_file():
            raise RuntimeError("pinned native prover binary missing; run explicit build first")
        env = dict(os.environ, RAYON_NUM_THREADS="2", CARGO_BUILD_JOBS="2")
        argv = [str(binary.resolve()), "--prover_input_path", str(corrected.resolve()),
                "--params_json", str(PROFILE_PATH.resolve()), "--proof_path", str(proof.resolve()),
                "--verify"]
        write_report(report_path, report)
        run = guarded_run(argv, cwd=ROOT, log_path=OUT / "small-profile-proving.txt",
                          timeout_seconds=a.timeout_seconds, max_rss_bytes=a.rss_mib * 1024 * 1024, env=env)
        report["stages"].append(run)
        write_report(report_path, report)
        if run["status"] != "success":
            raise RuntimeError(f"pinned native proving ended with {run['status']}")
        if not proof.is_file() or not 0 < proof.stat().st_size <= MAX_FILE_BYTES:
            raise RuntimeError("native verifier returned success but the proof is missing or oversized")
        report["proof"] = dict(bytes=proof.stat().st_size, sha256=digest(proof))
        report["native_proof_verified"] = True
        report["status"] = "native_small_profile_verified_application_binding_outstanding"
        return 0
    except Exception as exc:
        report["status"] = "one_shot_corrected_context_failed"
        report["error"] = str(exc)
        print(str(exc), file=sys.stderr, flush=True)
        return 1
    finally:
        frozen.unlink(missing_ok=True)
        corrected.unlink(missing_ok=True)
        write_report(report_path, report)
        print(json.dumps(report, indent=2), flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
