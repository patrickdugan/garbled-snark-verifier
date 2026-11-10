"""Verify frozen Cairo public-claim structure against an operator-pinned Shinigami policy.

A matching claim is UNAUTHENTICATED until a separately trusted native STARK verifier
has checked the exact proof. Never treat this offline comparison as a settlement token.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
from receipt_policy import CAIRO_P
from audit_execution import expected_csv_receipt

HERE = Path(__file__).resolve().parent
POLICIES = {p: HERE / "fixtures" / f"policy-{p}.json" for p in ("standalone", "bootloader")}
MAX_PROOF_BYTES = 128 << 20
MAX_PROGRAM_WORDS = 200_000


class ClaimMismatch(ValueError):
    pass


def integer(v, maximum, name):
    if type(v) is not int or v < 0 or v > maximum:
        raise ClaimMismatch(f"invalid {name}")
    return v


def entry_value(raw, label):
    if type(raw) is not list or len(raw) != 2:
        raise ClaimMismatch(f"{label}: expected [id, eight u32 limbs]")
    integer(raw[0], 0xffffffff, f"{label} id")
    limbs = raw[1]
    if type(limbs) is not list or len(limbs) != 8:
        raise ClaimMismatch(f"{label}: invalid limb count")
    value = sum(integer(x, 0xffffffff, f"{label} limb {i}") << (32*i)
                for i, x in enumerate(limbs))
    if value >= CAIRO_P:
        raise ClaimMismatch(f"{label}: noncanonical field value")
    return value


def load_policy(profile="standalone"):
    if profile not in POLICIES:
        raise ClaimMismatch("unrecognized source/proof profile")
    policy = json.loads(POLICIES[profile].read_text())
    if policy.get("schema") != 1 or policy.get("profile") != profile:
        raise ClaimMismatch("source/proof policy mismatch")
    n = policy.get("program_words")
    if type(n) is not int or n < 1 or n > MAX_PROGRAM_WORDS:
        raise ClaimMismatch("invalid pinned program length")
    h = policy.get("program_sha256_u256le")
    if type(h) is not str or len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
        raise ClaimMismatch("invalid pinned program hash")
    prefix = policy.get("bootloader_prefix")
    if profile == "standalone":
        if prefix != [] or policy.get("program_is_executable") is not True:
            raise ClaimMismatch("standalone executable policy is inconsistent")
    elif (type(prefix) is not list or len(prefix) != 3
          or policy.get("program_is_executable") is not False):
        raise ClaimMismatch("bootloader policy is inconsistent")
    if any(type(x) is not str or not x.isdecimal() for x in prefix):
        raise ClaimMismatch("noncanonical bootloader prefix")
    policy["expected_output"] = [int(x) for x in prefix] + expected_csv_receipt()
    if policy["output_stop"] - policy["output_start"] != len(policy["expected_output"]):
        raise ClaimMismatch("policy output segment size mismatch")
    return policy


def pcs_config(proof):
    if "stark_proof" in proof:
        raw = proof["stark_proof"]
    elif "extended_stark_proof" in proof:
        raw = proof["extended_stark_proof"]
        if type(raw) is not dict:
            raise ClaimMismatch("invalid extended proof")
        raw = raw.get("proof")
    else:
        raise ClaimMismatch("missing STARK proof")
    if type(raw) is dict and "config" not in raw and "0" in raw:
        raw = raw["0"]
    if type(raw) is not dict or type(raw.get("config")) is not dict:
        raise ClaimMismatch("missing authenticated PCS configuration")
    return raw["config"]


def audit_untrusted_claim(proof, policy):
    """Return evidence of a STRUCTURAL match, with all trust flags false."""
    if type(proof) is not dict:
        raise ClaimMismatch("proof JSON must be a mapping")
    if proof.get("preprocessed_trace_variant") != policy["preprocessed_trace_variant"]:
        raise ClaimMismatch("unexpected preprocessing")
    if integer(proof.get("channel_salt"), 0xffffffff, "channel salt") != policy["channel_salt"]:
        raise ClaimMismatch("unexpected channel salt")
    if pcs_config(proof) != policy["pcs_config"]:
        raise ClaimMismatch("unapproved FRI/PCS parameters")
    try:
        mem = proof["claim"]["public_data"]["public_memory"]
    except (KeyError, TypeError) as e:
        raise ClaimMismatch("missing public memory") from e
    if type(mem) is not dict:
        raise ClaimMismatch("invalid public memory")
    program = mem.get("program")
    if type(program) is not list or len(program) != policy["program_words"]:
        raise ClaimMismatch("public program length differs from pin")
    digest = sha256()
    for i, raw in enumerate(program):
        digest.update(entry_value(raw, f"program[{i}]").to_bytes(32, "little"))
    if digest.hexdigest() != policy["program_sha256_u256le"]:
        raise ClaimMismatch("public program differs from pinned executable/bootloader")
    output = mem.get("output")
    expected = policy["expected_output"]
    if type(output) is not list or len(output) != len(expected):
        raise ClaimMismatch("public output length differs from expected receipt")
    for i, (raw, desired) in enumerate(zip(output, expected)):
        if entry_value(raw, f"output[{i}]") != desired:
            raise ClaimMismatch(f"unexpected public output[{i}]")
    try:
        segment = mem["public_segments"]["output"]
        start = integer(segment["start_ptr"]["value"], (1<<31)-1, "output start")
        stop = integer(segment["stop_ptr"]["value"], (1<<31)-1, "output stop")
    except (KeyError, TypeError) as e:
        raise ClaimMismatch("missing output segment bounds") from e
    if (start, stop) != (policy["output_start"], policy["output_stop"]):
        raise ClaimMismatch("output segment differs from pinned execution")
    return {
        "profile": policy["profile"],
        "public_program_matched": True,
        "public_program_is_standalone_executable": policy["program_is_executable"],
        "public_program_sha256_u256le": digest.hexdigest(),
        "fixed_public_output_matched": True,
        "output_words": len(output),
        "pcs_profile_matched": True,
        "native_stark_proof_verified": False,
        "shinigami_executable_identity_authenticated": False,
        "bitcoin_application_state_verified": False,
        "settlement_authorized": False,
    }


def main():
    ap = argparse.ArgumentParser(description="Offline proof claim matching only; never authenticates a STARK")
    ap.add_argument("proof_json", type=Path)
    ap.add_argument("--profile", choices=tuple(POLICIES), default="standalone")
    a = ap.parse_args()
    if a.proof_json.stat().st_size > MAX_PROOF_BYTES:
        raise ClaimMismatch("proof exceeds inspection budget")
    proof = json.loads(a.proof_json.read_text())
    print(json.dumps(audit_untrusted_claim(proof, load_policy(a.profile)), indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print(f"CLAIM_BINDING_REJECTED: {exc}", file=sys.stderr)
        raise SystemExit(1)
