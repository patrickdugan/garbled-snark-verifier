#!/usr/bin/env python3
"""Parse one partial component-local relation audit, never an acceptance token."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re

from summarize_relations import summarize

SCOPE = "S3_LOCAL_SCOPE component=range_check_11 partial=true"
COLS = re.compile(r"(?m)^S3_LOCAL_COLUMNS component=range_check_11 preprocessed=(\d+) base=(\d+) rows=(\d+)$")
ENTRIES = re.compile(r"(?m)^S3_LOCAL_ENTRIES count=(\d+)$")


def parse(log: str, proof_report: dict) -> dict:
    if log.count(SCOPE) != 1:
        raise ValueError("missing or duplicate explicit partial-audit scope")
    counts = COLS.findall(log)
    entries = ENTRIES.findall(log)
    if len(counts) != 1 or len(entries) != 1:
        raise ValueError("missing or repeated selected column inventory")
    pre,base,rows = [int(x) for x in counts[0]]
    n_entries = int(entries[0])
    if not 1 <= pre <= 4 or not 1 <= base <= 4 or rows != 2048:
        raise ValueError("selected component exceeded fixed shape")
    if not 1 <= n_entries <= 2048:
        raise ValueError("selected component emitted unexpected number of tuples")
    result = summarize(log, proof_report)
    if "CommonLookupElements" not in result["relations_observed"]:
        raise ValueError("expected range-check relation absent from selected component")
    # A local relation balance is partial by construction: matching entries from
    # other Cairo components and public memory have not been accumulated here.
    result.update({
        "stage":"S3k source-pinned component-local relation diagnostic",
        "selected_component":"range_check_11",
        "component_trace_rows":2048,
        "source_preprocessed_columns":pre,
        "source_base_columns":base,
        "local_tuple_entries":n_entries,
        "component_local_result_only":True,
        "relation_inventory_complete":False,
        "global_relation_balances_verified":False,
        "native_proof_verified":False,
        "garbled_cairo_proof_verified":False,
        "ark_utxoref_application_authorized":False,
        "bitcoin_settlement_authorized":False,
    })
    return result


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--log",type=Path,required=True)
    ap.add_argument("--report",type=Path,required=True)
    ap.add_argument("--output",type=Path,required=True)
    args=ap.parse_args()
    result=parse(args.log.read_text(errors="replace"),
                 json.loads(args.report.read_text()))
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps({k:v for k,v in result.items()
                      if k not in ("first_four_tuple_examples_per_relation",)},indent=2))


if __name__=="__main__":
    main()
