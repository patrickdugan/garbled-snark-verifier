#!/usr/bin/env python3
"""Fail-closed accounting of the per-family lookup balance across all components (S3p).

parse_ledger() reads only the S3_LEDGER lines. Every sum the native run prints is
recomputed from the lines below it: tag sums into component sums, component and
public tag sums into family totals, families into the lookup total. A deleted,
duplicated or altered line therefore changes the result or is rejected.

A component whose evaluated LogUp sum differs from its native claim, or a family
with a nonzero QM31 total, is evidence and is reported, not rejected: that is what
the experiment looks for. Nothing here accepts a proof.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from summarize_lookup import field, modadd
from summarize_relations import EXPECTED_RESIDUAL

P = 2**31 - 1
ZERO = (0, 0, 0, 0)
QM = r"(\d+),(\d+),(\d+),(\d+)"
BOOL = r"(true|false)"
MAX_COMPONENTS = 66
MAX_TUPLE_LINES = 12
TRACKED = {1444891767: "MEMORY_ADDRESS_TO_ID", 1662111297: "MEMORY_ID_TO_BIG", 428564188: "OPCODES"}
BEGIN = "S3_LEDGER_BEGIN"
END = "S3_LEDGER_END"
LINE = {
    "capture": re.compile(r"^S3_LEDGER_CAPTURE columns=(\d+) cells=(\d+)$"),
    "component": re.compile(
        r"^S3_LEDGER_COMPONENT name=([a-z0-9_]+) log_size=(\d+) entries=(\d+) qm31=" + QM
        + " claimed=" + QM + " matches=" + BOOL + r" ms=(\d+)$"),
    "component_tag": re.compile(
        r"^S3_LEDGER_COMPONENT_TAG name=([a-z0-9_]+) tag=(\d+) entries=(\d+) "
        r"mult_sum_mod_p=(\d+) qm31=" + QM + "$"),
    "public": re.compile(
        r"^S3_LEDGER_PUBLIC entries=(\d+) qm31=" + QM + " native=" + QM + " matches=" + BOOL + "$"),
    "public_tag": re.compile(
        r"^S3_LEDGER_PUBLIC_TAG tag=(\d+) entries=(\d+) mult_sum_mod_p=(\d+) qm31=" + QM + "$"),
    "family": re.compile(
        r"^S3_LEDGER_FAMILY tag=(\d+) name=([A-Z0-9_]+) entries=(\d+) mult_sum_mod_p=(\d+) qm31="
        + QM + " zero=" + BOOL + "$"),
    "total": re.compile(
        r"^S3_LEDGER_TOTAL families_sum=" + QM + " component_claims_plus_public=" + QM
        + " global_lookup_sum=" + QM + " matches=" + BOOL + "$"),
    "tuples": re.compile(
        r"^S3_LEDGER_TUPLES tag=(\d+) name=([A-Z0-9_]+) distinct=(\d+) nonzero=(\d+) printed=(\d+)$"),
    "tuple": re.compile(r"^S3_LEDGER_TUPLE tag=(\d+) tuple=([0-9,]+) net_mod_p=(\d+)$"),
    "status": re.compile(
        r"^S3_LEDGER_STATUS evaluated=(\d+) skipped=(\d+) complete=" + BOOL + r" ms=(\d+) p=(\d+)$"),
    "skipped": re.compile(r"^S3_LEDGER_SKIPPED name=([a-z0-9_]+)$"),
    "unmatched": re.compile(
        r"^S3_LEDGER_UNMATCHED tag=(\d+) total=(\d+) in_public=(\d+) outside_public=(\d+)$"),
    "unmatched_section": re.compile(
        r"^S3_LEDGER_UNMATCHED_SECTION name=(program|safe_call|segments|output) entries=(\d+) unmatched=(\d+)$"),
    "unmatched_runs": re.compile(r"^S3_LEDGER_UNMATCHED_RUNS count=(\d+) printed=(\d+)$"),
    "unmatched_run": re.compile(r"^S3_LEDGER_UNMATCHED_RUN start=(\d+) len=(\d+)$"),
}
SECTIONS = ("program", "safe_call", "segments", "output")
MAX_RUN_LINES = 24
ADDRESS_TAG = 1444891767


def qm_value(parts) -> tuple:
    value = tuple(int(x) for x in parts)
    if len(value) != 4 or any(x >= P for x in value):
        raise ValueError("noncanonical QM31 limb")
    return value


def flag(text: str) -> bool:
    return text == "true"


def parse_ledger(log: str) -> dict:
    if log.count(BEGIN) != 1 or log.count(END) != 1 or log.index(BEGIN) > log.index(END):
        raise ValueError("missing or misordered ledger delimiters")
    block = log[log.index(BEGIN):log.index(END) + len(END)].splitlines()
    if block[0] != BEGIN or block[-1] != END:
        raise ValueError("ledger delimiters are not on their own lines")
    capture = components = public = total = status = None
    components = []
    public_tags = {}
    families = {}
    tuples_header = {}
    tuple_lines = {}
    skipped = []
    public_line = None
    unmatched = None
    sections = []
    runs_header = None
    run_lines = []
    for line in block[1:-1]:
        for kind, pattern in LINE.items():
            m = pattern.match(line)
            if m:
                break
        else:
            raise ValueError(f"unrecognized ledger line: {line[:60]}")
        g = m.groups()
        if kind == "capture":
            if capture is not None:
                raise ValueError("duplicate capture line")
            capture = (int(g[0]), int(g[1]))
        elif kind == "component":
            name = g[0]
            record = dict(name=name, log_size=int(g[1]), entries=int(g[2]), qm31=qm_value(g[3:7]),
                          claimed=qm_value(g[7:11]), matches=flag(g[11]), ms=int(g[12]), tags={})
            if (record["qm31"] == record["claimed"]) != record["matches"]:
                raise ValueError("component comparison flag contradicts its QM31 values")
            if any(c["name"] == name for c in components) and name != "memory_id_to_big":
                raise ValueError("duplicate component")
            components.append(record)
        elif kind == "component_tag":
            if not components or components[-1]["name"] != g[0]:
                raise ValueError("component tag line outside its component")
            tag = int(g[1])
            if tag in components[-1]["tags"]:
                raise ValueError("duplicate component tag")
            components[-1]["tags"][tag] = dict(entries=int(g[2]), mult=int(g[3]), qm31=qm_value(g[4:8]))
        elif kind == "public":
            if public_line is not None:
                raise ValueError("duplicate public line")
            public_line = dict(entries=int(g[0]), qm31=qm_value(g[1:5]), native=qm_value(g[5:9]),
                               matches=flag(g[9]))
        elif kind == "public_tag":
            tag = int(g[0])
            if tag in public_tags:
                raise ValueError("duplicate public tag")
            public_tags[tag] = dict(entries=int(g[1]), mult=int(g[2]), qm31=qm_value(g[3:7]))
        elif kind == "family":
            tag = int(g[0])
            if tag in families:
                raise ValueError("duplicate family")
            families[tag] = dict(name=g[1], entries=int(g[2]), mult=int(g[3]), qm31=qm_value(g[4:8]),
                                 zero=flag(g[8]))
            if (families[tag]["qm31"] == ZERO) != families[tag]["zero"]:
                raise ValueError("family zero flag contradicts its QM31 total")
        elif kind == "total":
            if total is not None:
                raise ValueError("duplicate total")
            total = dict(families_sum=qm_value(g[0:4]), claims_plus_public=qm_value(g[4:8]),
                         global_lookup_sum=qm_value(g[8:12]), matches=flag(g[12]))
        elif kind == "tuples":
            tag = int(g[0])
            if tag in tuples_header or tag not in TRACKED or g[1] != TRACKED[tag]:
                raise ValueError("unknown or duplicate tuple ledger")
            tuples_header[tag] = dict(distinct=int(g[2]), nonzero=int(g[3]), printed=int(g[4]))
            tuple_lines[tag] = []
        elif kind == "tuple":
            tag = int(g[0])
            if tag not in tuple_lines:
                raise ValueError("tuple line outside its ledger")
            values = tuple(int(x) for x in g[1].split(","))
            net = int(g[2])
            if any(x >= P for x in values) or not 0 < net < P:
                raise ValueError("malformed tuple line")
            tuple_lines[tag].append((values, net))
        elif kind == "status":
            if status is not None:
                raise ValueError("duplicate status")
            status = dict(evaluated=int(g[0]), skipped=int(g[1]), complete=flag(g[2]), ms=int(g[3]), p=int(g[4]))
        elif kind == "skipped":
            skipped.append(g[0])
        elif kind == "unmatched":
            if unmatched is not None:
                raise ValueError("duplicate unmatched summary")
            unmatched = dict(tag=int(g[0]), total=int(g[1]), in_public=int(g[2]), outside=int(g[3]))
        elif kind == "unmatched_section":
            sections.append((g[0], int(g[1]), int(g[2])))
        elif kind == "unmatched_runs":
            if runs_header is not None:
                raise ValueError("duplicate run header")
            runs_header = dict(count=int(g[0]), printed=int(g[1]))
        elif kind == "unmatched_run":
            run_lines.append((int(g[0]), int(g[1])))
    if None in (capture, public_line, total, status, unmatched, runs_header) or not components or not families:
        raise ValueError("incomplete ledger block")
    if status["p"] != P or status["evaluated"] != len(components) or status["skipped"] != len(skipped) \
            or status["complete"] != (not skipped) or len(components) + len(skipped) > MAX_COMPONENTS + 1:
        raise ValueError("ledger status does not match its component lines")

    # Recompute every sum from the lines below it.
    for c in components:
        if not c["tags"] or sum(t["entries"] for t in c["tags"].values()) != c["entries"] \
                or modadd(*(t["qm31"] for t in c["tags"].values())) != c["qm31"]:
            raise ValueError(f"component {c['name']} tag lines do not add up to its total")
    if not public_tags or sum(t["entries"] for t in public_tags.values()) != public_line["entries"] \
            or modadd(*(t["qm31"] for t in public_tags.values())) != public_line["qm31"]:
        raise ValueError("public tag lines do not add up to the public total")
    if (public_line["qm31"] == public_line["native"]) != public_line["matches"] \
            or public_line["qm31"] != public_line["native"]:
        raise ValueError("public-data decomposition differs from the native logup sum")
    expected_tags = {t for c in components for t in c["tags"]} | set(public_tags)
    if set(families) != expected_tags:
        raise ValueError("family inventory differs from the tags observed")
    for tag, family in families.items():
        parts = [c["tags"][tag] for c in components if tag in c["tags"]]
        if tag in public_tags:
            parts.append(public_tags[tag])
        if family["entries"] != sum(p["entries"] for p in parts) \
                or family["mult"] != sum(p["mult"] for p in parts) % P \
                or family["qm31"] != modadd(*(p["qm31"] for p in parts)):
            raise ValueError(f"family {tag} does not equal its component and public parts")
    families_sum = modadd(*(f["qm31"] for f in families.values()))
    claims_plus_public = modadd(*(c["claimed"] for c in components), public_line["native"])
    if total["families_sum"] != families_sum or total["claims_plus_public"] != claims_plus_public:
        raise ValueError("lookup totals differ from the recomputed sums")
    if total["matches"] != (families_sum == total["global_lookup_sum"] == claims_plus_public):
        raise ValueError("total comparison flag contradicts its QM31 values")
    if set(tuples_header) != set(TRACKED):
        raise ValueError("a tracked tuple ledger is missing")
    for tag, header in tuples_header.items():
        if header["printed"] != len(tuple_lines[tag]) or header["printed"] != min(header["nonzero"], MAX_TUPLE_LINES) \
                or header["nonzero"] > header["distinct"]:
            raise ValueError(f"tuple lines of tag {tag} do not match their header")
        if len({v for v, _ in tuple_lines[tag]}) != len(tuple_lines[tag]):
            raise ValueError("duplicate tuple line")

    if unmatched["tag"] != ADDRESS_TAG or unmatched["total"] != tuples_header[ADDRESS_TAG]["nonzero"]             or unmatched["in_public"] + unmatched["outside"] != unmatched["total"]:
        raise ValueError("unmatched address uses differ from the address tuple ledger")
    if [name for name, _, _ in sections] != list(SECTIONS):
        raise ValueError("public section inventory is incomplete or misordered")
    if sum(n for _, n, _ in sections) != public_tags[ADDRESS_TAG]["entries"]             or sum(u for _, _, u in sections) != unmatched["in_public"]             or any(u > n for _, n, u in sections):
        raise ValueError("public sections do not account for the unmatched address uses")
    if runs_header["printed"] != len(run_lines) or runs_header["printed"] != min(runs_header["count"], MAX_RUN_LINES)             or runs_header["count"] > max(unmatched["total"], 0) or (unmatched["total"] == 0) != (runs_header["count"] == 0):
        raise ValueError("run lines do not match their header")
    previous_end = -1
    for start, length in run_lines:
        if length < 1 or start <= previous_end:
            raise ValueError("unmatched runs are overlapping or unsorted")
        previous_end = start + length - 1
    if sum(length for _, length in run_lines) > unmatched["total"] or (
            runs_header["count"] == len(run_lines) and sum(length for _, length in run_lines) != unmatched["total"]):
        raise ValueError("run lengths do not account for the unmatched address uses")

    mismatching = [c["name"] for c in components if not c["matches"]]
    nonzero = {t: f for t, f in families.items() if not f["zero"]}
    return {
        "stage": "S3p per-family lookup balance across all components",
        "base_tree_columns": capture[0],
        "base_tree_cells": capture[1],
        "components_evaluated": len(components),
        "components_skipped": skipped,
        "ledger_complete": status["complete"],
        "all_component_claims_reproduced": not mismatching,
        "components_not_reproducing_claim": mismatching,
        "component_summary": [dict(name=c["name"], log_size=c["log_size"], entries=c["entries"],
                                   qm31=list(c["qm31"]), claimed=list(c["claimed"]),
                                   matches=c["matches"], ms=c["ms"]) for c in components],
        "public": dict(entries=public_line["entries"], qm31=list(public_line["qm31"]),
                       tags={str(t): dict(entries=v["entries"], mult_sum_mod_p=v["mult"], qm31=list(v["qm31"]))
                             for t, v in sorted(public_tags.items())}),
        "families": {str(t): dict(name=f["name"], entries=f["entries"], mult_sum_mod_p=f["mult"],
                                  qm31=list(f["qm31"]), zero=f["zero"]) for t, f in sorted(families.items())},
        "nonzero_family_tags": sorted(nonzero),
        "families_sum_qm31": list(families_sum),
        "component_claims_plus_public_qm31": list(claims_plus_public),
        "global_lookup_sum_qm31": list(total["global_lookup_sum"]),
        "families_reproduce_global_lookup_sum": total["matches"],
        "tuple_ledgers": {str(t): dict(name=TRACKED[t], distinct=h["distinct"], nonzero=h["nonzero"],
                                       first_nonzero=[dict(tuple=list(v), net_mod_p=n) for v, n in tuple_lines[t]])
                          for t, h in sorted(tuples_header.items())},
        "unmatched_address_uses": dict(
            total=unmatched["total"], in_public_memory=unmatched["in_public"],
            outside_public_memory=unmatched["outside"],
            sections={name: dict(public_entries=n, unmatched=u) for name, n, u in sections},
            sections_with_unmatched=[name for name, _, u in sections if u],
            sections_entirely_unmatched=[name for name, n, u in sections if n and u == n],
            runs=runs_header["count"], first_runs=[dict(start=a, length=n) for a, n in run_lines]),
        "elapsed_ms": status["ms"],
        "full_global_lookup_balance_verified": False,
        "native_proof_verified": False,
        "garbled_cairo_proof_verified": False,
        "bitcoin_settlement_authorized": False,
        "ark_utxoref_application_authorized": False,
    }


def check_native_rejection(log: str, report: dict) -> None:
    if (report.get("native_proof_verified") is not False
            or report.get("status") != "one_shot_small_profile_failed"):
        raise ValueError("native proof report must record the failed small-profile attempt")
    stages = report.get("stages")
    if (type(stages) is not list or len(stages) != 1 or stages[0].get("status") != "command_failed"
            or stages[0].get("returncode") != 101):
        raise ValueError("unexpected native prover exit status")
    if "assertion " not in log or "left == right" not in log:
        raise ValueError("pinned native lookup assertion was not observed")
    lefts = re.findall(r"(?m)^  left: (.+)$", log)
    if len(lefts) != 1 or field(lefts[0]) != EXPECTED_RESIDUAL:
        raise ValueError("native residual differs from the pinned S3f baseline")


def parse(log: str, report: dict) -> dict:
    check_native_rejection(log, report)
    result = parse_ledger(log)
    if tuple(result["global_lookup_sum_qm31"]) != EXPECTED_RESIDUAL:
        raise ValueError("ledger lookup sum differs from the pinned native residual")
    stage = report["stages"][0]
    limit = report.get("rss_budget_mib", 0) * 1024 * 1024
    if not 0 < stage["peak_rss_bytes"] <= limit <= 4096 * 1024 * 1024:
        raise ValueError("native diagnostic exceeded the 4 GiB sampled RSS cap")
    if not 0 < stage["elapsed_seconds"] <= min(report.get("deadline_seconds", 0), 120):
        raise ValueError("native diagnostic exceeded the 120 s runtime cap")
    result["resources"] = {
        "elapsed_seconds": stage["elapsed_seconds"], "peak_rss_bytes": stage["peak_rss_bytes"],
        "peak_vms_bytes": stage.get("peak_vms_bytes"), "rss_limit_bytes": limit,
        "timeout_seconds": report["deadline_seconds"], "native_exit_code": stage["returncode"],
    }
    result["global_native_lookup_assertion_failed"] = True
    result["baseline_residual"] = list(EXPECTED_RESIDUAL)
    return result


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--log", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    data = parse(args.log.read_text(errors="replace"), json.loads(args.report.read_text()))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(data, indent=2) + "\n")
    keep = ("stage", "components_evaluated", "ledger_complete", "all_component_claims_reproduced",
            "components_not_reproducing_claim", "nonzero_family_tags",
            "families_reproduce_global_lookup_sum", "resources", "global_native_lookup_assertion_failed",
            "native_proof_verified")
    print(json.dumps({k: data[k] for k in keep}, indent=2))


if __name__ == "__main__":
    main()
