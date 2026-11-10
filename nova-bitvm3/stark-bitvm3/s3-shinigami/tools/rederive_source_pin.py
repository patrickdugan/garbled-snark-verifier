"""Re-derive a pinned public program and receipt from archived Cairo execution memory.

This is an offline integrity audit of trace bytes. It is NOT a STARK verifier.
The 121 MB bootloader input is streamed under its exact size cap.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import gzip
import json
from pathlib import Path
import sys
import zipfile
from claim_binding import ClaimMismatch, load_policy
from receipt_policy import CAIRO_P

LIMIT = 140 << 20


def memory_value(memory, addr):
    ident = memory["address_to_id"][addr]
    if type(ident) is not int or ident < 0:
        raise ClaimMismatch("invalid memory id")
    if ident < 1 << 30:
        value = memory["small_values"][ident]
    else:
        limbs = memory["f252_values"][ident - (1<<30)]
        if len(limbs) != 8 or any(type(w) is not int or w < 0 or w > 0xffffffff for w in limbs):
            raise ClaimMismatch("invalid f252 limbs")
        value = sum(w << (32*i) for i,w in enumerate(limbs))
    if type(value) is not int or not 0 <= value < CAIRO_P:
        raise ClaimMismatch("noncanonical memory field value")
    return value


def audit_source(archive, profile):
    policy = load_policy(profile)
    with zipfile.ZipFile(archive) as z:
        item = z.getinfo(policy["source_file"])
        if item.file_size > LIMIT:
            raise ClaimMismatch("compressed input exceeds budget")
        with z.open(policy["source_file"]) as raw:
            with gzip.GzipFile(fileobj=raw) as decompressed:
                data = decompressed.read(policy["source_input_bytes"] + 1)
    if len(data) != policy["source_input_bytes"]:
        raise ClaimMismatch("source input size mismatch")
    actual = sha256(data).hexdigest()
    if actual != policy["source_input_sha256"]:
        raise ClaimMismatch("source trace sha256 mismatch")
    j = json.loads(data)
    addresses = j["public_memory_addresses"]
    if len(addresses) != len(set(addresses)):
        raise ClaimMismatch("duplicate public memory address")
    present = set(addresses)
    count = policy["program_words"]
    if not set(range(1, count+1)).issubset(present):
        raise ClaimMismatch("pinned program address missing")
    start, stop = policy["output_start"], policy["output_stop"]
    if not set(range(start, stop)).issubset(present):
        raise ClaimMismatch("public output address missing")
    mem = j["memory"]
    digest = sha256()
    for i in range(1,count+1):
        digest.update(memory_value(mem,i).to_bytes(32,"little"))
    if digest.hexdigest() != policy["program_sha256_u256le"]:
        raise ClaimMismatch("source program digest mismatch")
    output = [memory_value(mem,addr) for addr in range(start,stop)]
    if output != policy["expected_output"]:
        raise ClaimMismatch("source output differs from fixed receipt")
    return {"profile":profile,"public_program_words":count,
            "program_sha256_u256le":digest.hexdigest(),"public_output_words":len(output),
            "compiled_executable_is_claimed_directly":policy["program_is_executable"],
            "native_stark_proof_verified":False,"settlement_authorized":False}


if __name__=="__main__":
    parser=argparse.ArgumentParser(description="Audit frozen public memory; no proof generation")
    parser.add_argument("archive",type=Path)
    parser.add_argument("--profile",required=True,choices=("standalone","bootloader"))
    args=parser.parse_args()
    try:
        print(json.dumps(audit_source(args.archive,args.profile),indent=2))
    except (KeyError,IndexError,TypeError,ValueError,OSError) as error:
        print(f"FROZEN_SOURCE_REJECTED: {error}",file=sys.stderr)
        raise SystemExit(1)
