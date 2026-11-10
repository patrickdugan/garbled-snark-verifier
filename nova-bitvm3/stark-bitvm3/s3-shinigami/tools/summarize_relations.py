#!/usr/bin/env python3
"""Fail-closed parser for one source-pinned Cairo relation-balance diagnostic.

This describes failed proving evidence. It never authorizes a Shinigami proof,
Bitcoin transaction, or Ark/UTXORef application state transition.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re

from summarize_lookup import field

EXPECTED_RESIDUAL = (1866027004, 1908263159, 1713629672, 1017174456)
SUMMARY_CAP_BYTES = 65536
MAX_RELATIONS = 128
LABEL = re.compile(r"^([A-Za-z][A-Za-z0-9_]*):$")
ENTRY = re.compile(r"^  \[([0-9, ]+)\] -> ([0-9]+)$")


def summarize(log: str, report: dict) -> dict:
    if (report.get("native_proof_verified") is not False
        or report.get("status") != "one_shot_small_profile_failed"):
        raise ValueError("native proof report must record the failed small-profile attempt")
    stages = report.get("stages")
    if (type(stages) is not list or len(stages) != 1
        or stages[0].get("status") != "command_failed"
        or stages[0].get("returncode") != 101):
        raise ValueError("unexpected native prover exit status")
    if "assertion " not in log or "left == right" not in log:
        raise ValueError("pinned native lookup assertion was not observed")
    lefts = re.findall(r"(?m)^  left: (.+)$", log)
    if len(lefts) != 1 or field(lefts[0]) != EXPECTED_RESIDUAL:
        raise ValueError("native residual differs from the pinned S3f baseline")
    if (log.count("S3_RELATIONS_BEGIN") != 1
        or log.count("S3_RELATIONS_END") != 1
        or log.count("S3_RELATIONS_TEXT_BEGIN") != 1
        or log.count("S3_RELATIONS_TEXT_END") != 1):
        raise ValueError("missing or repeated relation-tracker delimiters")
    captured = re.findall(
        r"S3_RELATIONS_TEXT_BEGIN\n(.*?)S3_RELATIONS_TEXT_END", log, re.S)
    flags = re.findall(r"(?m)^S3_RELATIONS_TRUNCATED (true|false)$", log)
    if len(captured) != 1 or len(flags) != 1:
        raise ValueError("incomplete relation summary")
    raw = captured[0]
    if not raw.strip() or len(raw.encode()) > SUMMARY_CAP_BYTES + 1:
        raise ValueError("empty or oversized bounded relation text")
    truncated = flags[0] == "true"
    current = None
    headings = []
    sample = {}
    anomalies = 0
    lines = raw.splitlines()
    for index,line in enumerate(lines):
        m = LABEL.fullmatch(line)
        if m:
            name = m.group(1)
            if name in sample or len(headings) >= MAX_RELATIONS:
                raise ValueError("duplicate relation or excess headings")
            current = name
            headings.append(name)
            sample[name] = []
            continue
        m = ENTRY.fullmatch(line)
        if m:
            if current is None:
                raise ValueError("tuple encountered before relation label")
            vector = [int(x) for x in m.group(1).replace(" ", "").split(",")]
            multiplicity = int(m.group(2))
            if any(not 0 <= x < 2**31-1 for x in vector):
                raise ValueError("noncanonical relation tuple limb")
            if not 0 < multiplicity < 2**31-1:
                raise ValueError("invalid nonzero residual multiplicity")
            anomalies += 1
            if len(sample[current]) < 4:
                sample[current].append(dict(values=vector, residual=multiplicity))
            continue
        if not truncated or index != len(lines)-1:
            raise ValueError("unrecognized relation summary line")
    if not headings or anomalies == 0:
        raise ValueError("relation tracker reported no anomalous tuple")
    if not truncated and any(not sample[k] for k in headings):
        raise ValueError("complete relation labels must have nonzero tuples")
    return {
        "stage":"S3h pinned Cairo relation multiplicity audit",
        "status":"diagnostic_of_failed_native_proof",
        "original_lookup_assertion_failed":True,
        "baseline_residual":list(EXPECTED_RESIDUAL),
        "relation_debug_output_truncated":truncated,
        "relation_inventory_complete":not truncated,
        "relations_observed":headings,
        "nonzero_relation_tuple_lines_observed":anomalies,
        "first_four_tuple_examples_per_relation":sample,
        "maximum_debug_text_bytes":SUMMARY_CAP_BYTES,
        "native_proof_verified":False,
        "s2_garbled_verification":False,
        "bitcoin_settlement_authorized":False,
        "ark_utxoref_application_authorized":False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = summarize(
        args.log.read_text(errors="replace"),
        json.loads(args.report.read_text()))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps({
        k:v for k,v in report.items() if k != "first_four_tuple_examples_per_relation"
    }, indent=2))


if __name__ == "__main__":
    main()
