#!/usr/bin/env python3
"""Fail-closed, unsigned-source accounting for the XOR8 zero-input tuple.

Requires the same native global proof rejection and local LogUp match as S3m.
An input-routing count is necessary but not sufficient to verify the caller AIR.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from instrument_xor8_counterparties import SOURCES
from summarize_xor8_relations import parse as parse_local

ROW = re.compile(r"(?m)^S3_XOR8_ZERO_USE source=([a-z0-9_]+) relation=([01]) count=(\d+)$")
EXPECTED_RELATIONS = {"0": 112558620, "1": 521092554}
M31 = 2**31 - 1
SUPPLY = -4096
MAX_COUNT = 1 << 27


def parse(log: str, native_report: dict) -> dict:
    local = parse_local(log, native_report)
    # Reuse the source-pinned producer's *same* 65,536-row LogUp comparison.
    if local.get("component_claim_sum_matches") is not True:
        raise ValueError("native local XOR8 claim differs from source relations")
    if local.get("relation_debug_output_truncated") is not False:
        raise ValueError("target zero-input supply must have complete local summary")
    if local.get("nonzero_relation_tuple_lines_observed") != 1:
        raise ValueError("expected one nonzero zero-input tuple in XOR8 table")
    entries = local.get("first_four_tuple_examples_per_relation", {}).get(
        "CommonLookupElements", [])
    if entries != [{"values":[112558620], "residual":M31+SUPPLY}]:
        raise ValueError("XOR8 local zero tuple differs from previous source evidence")
    if log.count("S3_XOR8_COUNTERPARTY_BEGIN") != 1 or log.count("S3_XOR8_COUNTERPARTY_END") != 1:
        raise ValueError("missing or duplicated native producer callsite inventory")
    rows = ROW.findall(log)
    if len(rows) != len(SOURCES)*2:
        raise ValueError("expected exactly two counters for each known source")
    ledger = {}
    for source, relation, count_str in rows:
        if source not in SOURCES or source in ledger and relation in ledger[source]:
            raise ValueError("unknown or duplicated producer caller")
        count = int(count_str)
        if count > MAX_COUNT:
            raise ValueError("unbounded caller count")
        ledger.setdefault(source, {})[relation] = count
    if set(ledger) != set(SOURCES) or any(set(ledger[s]) != set(EXPECTED_RELATIONS) for s in SOURCES):
        raise ValueError("source-relation counter inventory incomplete")
    # These counters are taken inside the original routing function before
    # incrementing the table. They do not prove matching AIR uses elsewhere.
    uses0 = sum(ledger[s]["0"] for s in SOURCES)
    uses1 = sum(ledger[s]["1"] for s in SOURCES)
    complete_source_attribution = ledger["other"]["0"] == 0 and ledger["other"]["1"] == 0
    local.update({
        "stage":"S3n zero-input source callsite attribution",
        "tuple":[112558620, 0, 0, 0],
        "table_signed_supply":SUPPLY,
        "caller_zero_input_counts":ledger,
        "caller_relation_tags":EXPECTED_RELATIONS,
        "caller_tag0_uses":uses0,
        "caller_tag1_uses":uses1,
        "caller_tag0_matches_table_supply":uses0+SUPPLY == 0,
        "unknown_direct_caller_uses":ledger["other"]["0"]+ledger["other"]["1"],
        "all_direct_caller_uses_attributed":complete_source_attribution,
        "counterpart_air_tuple_balances_verified":False,
        "cross_component_lookup_argument_verified":False,
        "native_proof_verified":False,
        "garbled_cairo_proof_verified":False,
        "bitcoin_settlement_authorized":False,
        "ark_utxoref_application_authorized":False,
    })
    return local


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--log",type=Path,required=True)
    p.add_argument("--report",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    data=parse(args.log.read_text(errors="replace"),
               json.loads(args.report.read_text()))
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(data,indent=2)+"\n")
    print(json.dumps({k:v for k,v in data.items()
        if k!="first_four_tuple_examples_per_relation"},indent=2))


if __name__=="__main__":
    main()
