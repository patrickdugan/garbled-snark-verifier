#!/usr/bin/env python3
"""Fail-closed parser for the S3m pinned XOR8 local LogUp experiment."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from summarize_relations import summarize
from summarize_lookup import field

COMPONENT = "verify_bitwise_xor_8"
ROWS = 65536
ENTRIES = 131072
EXPECTED_CLAIM = (2105135349, 1091656546, 1373784603, 2082926218)
SCOPE = "S3_LOCAL_SCOPE component=verify_bitwise_xor_8 partial=true"
PREPROCESS_SOURCE = "S3_LOCAL_PREPROCESS_SOURCE canonical_pinned_original"
COLS = re.compile(
    r"(?m)^S3_LOCAL_COLUMNS component=verify_bitwise_xor_8 preprocessed=(\d+) base=(\d+) rows=(\d+)$"
)
COUNTS = re.compile(r"(?m)^S3_LOCAL_ENTRIES count=(\d+)$")
LOGUP = re.compile(
    r"(?m)^S3_LOCAL_LOGUP recomputed=(.+?) claimed=(.+?) matches=(true|false)$"
)


def parse(log: str, report: dict) -> dict:
    if log.count(SCOPE) != 1:
        raise ValueError("missing or duplicated partial XOR8 scope marker")
    if log.count(PREPROCESS_SOURCE) != 1:
        raise ValueError("missing or duplicated native source-preprocessed-table marker")
    cols = COLS.findall(log)
    counts = COUNTS.findall(log)
    comparisons = LOGUP.findall(log)
    if len(cols) != 1 or len(counts) != 1 or len(comparisons) != 1:
        raise ValueError("missing or duplicated source-pinned XOR8 shape or LogUp data")
    pre, base, rows = [int(x) for x in cols[0]]
    nentries = int(counts[0])
    if (pre, base, rows, nentries) != (3, 2, ROWS, ENTRIES):
        raise ValueError("unexpected source trace or relation count for XOR8")
    recomputed = field(comparisons[0][0])
    claimed = field(comparisons[0][1])
    agrees = recomputed == claimed
    if claimed != EXPECTED_CLAIM:
        raise ValueError("native claimed XOR8 sum differs from frozen S3f input")
    if agrees != (comparisons[0][2] == "true"):
        raise ValueError("native comparison flag contradicts printed QM31 values")
    result = summarize(log, report)
    if "CommonLookupElements" not in result["relations_observed"]:
        raise ValueError("XOR8 native relation heading missing")
    result.update({
        "stage": "S3m source-pinned verify_bitwise_xor_8 local LogUp audit",
        "selected_component": COMPONENT,
        "component_trace_rows": rows,
        "preprocessed_columns": pre,
        "preprocessed_trace_source": "pinned native original before commitment lifting",
        "base_columns": base,
        "raw_relation_entries": nentries,
        "component_logup_recomputed": list(recomputed),
        "component_logup_claimed": list(claimed),
        "component_claim_sum_matches": agrees,
        "component_local_result_only": True,
        "relation_inventory_complete": False,
        "global_relation_balances_verified": False,
        "native_proof_verified": False,
        "garbled_cairo_proof_verified": False,
        "ark_utxoref_application_authorized": False,
        "bitcoin_settlement_authorized": False,
    })
    return result


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--log", required=True, type=Path)
    p.add_argument("--report", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    record = parse(args.log.read_text(errors="replace"),
                   json.loads(args.report.read_text()))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({
        k: v for k, v in record.items()
        if k != "first_four_tuple_examples_per_relation"
    }, indent=2))


if __name__ == "__main__":
    main()
