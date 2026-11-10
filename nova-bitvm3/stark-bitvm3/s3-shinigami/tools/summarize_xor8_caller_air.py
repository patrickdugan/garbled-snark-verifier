#!/usr/bin/env python3
"""Fail-closed accounting of the XOR8 zero tuple from the bitwise_builtin caller AIR.

parse_caller() reads only the S3o lines. It recomputes the signed multiplicity ledger
and every negative control from the printed (tuple, multiplicity, count) groups, so a
missing, duplicated or altered line changes the result. parse() additionally requires
the S3m table audit pins and the same native global lookup rejection as S3n.

A balanced XOR8 tuple is one relation family of one component pair. It never accepts
a proof: the global QM31 residual, public memory and every other family stay open.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from instrument_xor8_caller_air import (
    BASE_COLUMNS, BEGIN, END, ENTRIES, ENTRIES_PER_ROW, FAMILIES, MAX_PRINTED_GROUPS,
    NEGATIVE_CONTROLS, PREPROCESSED_COLUMNS, ROWS, TABLE_ENTRIES, XOR8_SECOND_TAG, XOR8_TAG,
)
from summarize_lookup import modadd
from summarize_xor8_relations import parse as parse_local

P = 2**31 - 1
ZERO_TUPLE = (XOR8_TAG, 0, 0, 0)
QM = r"(\d+),(\d+),(\d+),(\d+)"
SHAPE = re.compile(r"(?m)^S3_CALLER_SHAPE rows=(\d+) base_columns=(\d+) preprocessed_columns=(\d+)$")
DIGEST = re.compile(r"(?m)^S3_CALLER_SOURCE_DIGEST blake2s=([0-9a-f]{64})$")
COUNTS = re.compile(r"(?m)^S3_CALLER_ENTRIES total=(\d+) per_row=(\d+) rows_with_one_xor8=(\d+)$")
FAMILY = re.compile(
    r"(?m)^S3_CALLER_FAMILY tag=(\d+) entries=(\d+) distinct_tuples=(\d+) "
    r"mult_sum_mod_p=(\d+) qm31=" + QM + "$")
LOGUP = re.compile(
    r"(?m)^S3_CALLER_LOGUP recomputed=" + QM + " claimed=" + QM + " family_sum=" + QM
    + r" matches=(true|false) family_sum_matches=(true|false)$")
CALLER_ENTRY = re.compile(r"(?m)^S3_XOR8_CALLER_ENTRY tuple=([0-9,]+) mult=(\d+) count=(\d+)$")
CALLER_LINES = re.compile(
    r"(?m)^S3_XOR8_CALLER_LINES printed=(\d+) distinct=(\d+) truncated=(true|false)$")
TABLE_SHAPE = re.compile(r"(?m)^S3_XOR8_TABLE_SHAPE entries=(\d+) zero_mult=(\d+) nonzero=(\d+)$")
TABLE_ENTRY = re.compile(r"(?m)^S3_XOR8_TABLE_ENTRY tuple=([0-9,]+) mult=(\d+) count=(\d+)$")
TABLE_LINES = re.compile(
    r"(?m)^S3_XOR8_TABLE_LINES printed=(\d+) distinct=(\d+) truncated=(true|false)$")
QM_LEDGER = re.compile(
    r"(?m)^S3_XOR8_LEDGER_QM31 caller=" + QM + " table=" + QM + " total=" + QM
    + r" zero=(true|false)$")
LEDGER = re.compile(
    r"(?m)^S3_XOR8_LEDGER baseline_nonzero_tuples=(\d+) caller_entries=(\d+) "
    r"caller_mult_total_mod_p=(\d+) table_mult_total_mod_p=(\d+)$")
NEGATIVE = re.compile(
    r"(?m)^S3_XOR8_NEGATIVE name=([a-z_]+) nonzero_tuples=(\d+) detected=(true|false)$")


def one(pattern: re.Pattern, log: str, what: str) -> tuple:
    found = pattern.findall(log)
    if len(found) != 1:
        raise ValueError(f"missing or duplicated {what}")
    return found[0]


def qm_value(parts) -> tuple[int, int, int, int]:
    value = tuple(int(x) for x in parts)
    if len(value) != 4 or any(x >= P for x in value):
        raise ValueError("noncanonical QM31 limb")
    return value


def groups(pattern: re.Pattern, lines: re.Pattern, log: str, what: str) -> list:
    found = [(tuple(int(x) for x in t.split(",")), int(m), int(c))
             for t, m, c in pattern.findall(log)]
    printed, distinct, truncated = one(lines, log, f"{what} line summary")
    if truncated != "false":
        raise ValueError(f"{what} listing was truncated")
    if (int(printed), int(distinct)) != (len(found), len(found)) or len(found) > MAX_PRINTED_GROUPS:
        raise ValueError(f"{what} listing is incomplete")
    if len({(t, m) for t, m, _ in found}) != len(found):
        raise ValueError(f"duplicate {what} group")
    for tuple_, mult, count in found:
        if len(tuple_) != 4 or any(x >= P for x in tuple_) or not 0 <= mult < P or count < 1:
            raise ValueError(f"malformed {what} group")
    return found


def signed(value: int) -> int:
    """Signed representative of an M31 residue."""
    return value if value <= P // 2 else value - P


def ledger_nonzero(*sides) -> dict:
    """Exact signed multiplicity per tuple modulo M31; zero nets are dropped."""
    net: dict = {}
    for side in sides:
        for tuple_, mult, count in side:
            net[tuple_] = (net.get(tuple_, 0) + mult * count) % P
    return {t: v for t, v in net.items() if v}


def negative_controls(caller: list, table: list) -> dict:
    """Deterministic mutations of the printed groups; each must leave a nonzero tuple."""
    def drop_one(side, index):
        out = list(side)
        t, m, c = out[index]
        out[index:index + 1] = [(t, m, c - 1)] if c > 1 else []
        return out

    def add_one(side, index):
        out = list(side)
        t, m, c = out[index]
        out[index] = (t, m, c + 1)
        return out

    def with_split(side, index, mutate):
        out = list(side)
        t, m, c = out[index]
        rest = [(t, m, c - 1)] if c > 1 else []
        return out[:index] + rest + [mutate(t, m)] + out[index + 1:]

    table_index = next(i for i, (_, m, _) in enumerate(table) if m)
    return {
        "missing_caller_entry": len(ledger_nonzero(drop_one(caller, 0), table)),
        "duplicated_caller_entry": len(ledger_nonzero(add_one(caller, 0), table)),
        "altered_caller_tuple": len(ledger_nonzero(
            with_split(caller, 0, lambda t, m: (t[:-1] + ((t[-1] + 1) % P,), m, 1)), table)),
        "altered_caller_multiplicity": len(ledger_nonzero(
            with_split(caller, 0, lambda t, m: (t, (m + 1) % P, 1)), table)),
        "missing_table_entry": len(ledger_nonzero(caller, drop_one(table, table_index))),
        "duplicated_table_entry": len(ledger_nonzero(caller, add_one(table, table_index))),
    }


def parse_caller(log: str) -> dict:
    if log.count(BEGIN) != 1 or log.count(END) != 1 or log.index(BEGIN) > log.index(END):
        raise ValueError("missing or misordered caller-AIR delimiters")
    block = log[log.index(BEGIN):log.index(END) + len(END)]
    rows, base, pre = (int(x) for x in one(SHAPE, block, "caller shape"))
    if (rows, base, pre) != (ROWS, BASE_COLUMNS, PREPROCESSED_COLUMNS):
        raise ValueError("unexpected bitwise_builtin source shape")
    digest = one(DIGEST, block, "source digest")
    total, per_row, one_xor8 = (int(x) for x in one(COUNTS, block, "entry counts"))
    if (total, per_row) != (ENTRIES, ENTRIES_PER_ROW):
        raise ValueError("bitwise_builtin AIR yielded an unexpected number of relation entries")
    if one_xor8 != ROWS:
        raise ValueError("a caller row does not carry exactly one XOR8 entry")

    families = {}
    for tag, entries, distinct, mult_sum, *limbs in FAMILY.findall(block):
        tag, entries = int(tag), int(entries)
        if tag in families or tag not in FAMILIES:
            raise ValueError("unknown or duplicated relation family")
        name, uses = FAMILIES[tag]
        if entries != ROWS * uses or int(mult_sum) != entries % P or not 1 <= int(distinct) <= entries:
            raise ValueError(f"{name} family does not match the pinned uses per row")
        families[tag] = dict(name=name, entries=entries, distinct_tuples=int(distinct),
                             mult_sum_mod_p=int(mult_sum), qm31=list(qm_value(limbs)))
    if set(families) != set(FAMILIES):
        raise ValueError("a bitwise_builtin relation family is missing")

    parts = one(LOGUP, block, "component LogUp comparison")
    recomputed, claimed, family_sum = (qm_value(parts[i:i + 4]) for i in (0, 4, 8))
    if modadd(*(tuple(f["qm31"]) for f in families.values())) != family_sum:
        raise ValueError("family sums do not add to the reported component total")
    if (recomputed == claimed) != (parts[12] == "true") or (family_sum == claimed) != (parts[13] == "true"):
        raise ValueError("comparison flag contradicts printed QM31 values")
    if recomputed != claimed or family_sum != claimed:
        raise ValueError("bitwise_builtin source LogUp differs from its native interaction claim")

    caller = groups(CALLER_ENTRY, CALLER_LINES, block, "caller")
    if sum(c for _, _, c in caller) != ROWS or sum(c for _, _, c in caller) != families[XOR8_TAG]["entries"]:
        raise ValueError("caller XOR8 entries do not account for every row")
    if any(t[0] != XOR8_TAG for t, _, _ in caller) or any(m != 1 for _, m, _ in caller):
        raise ValueError("caller AIR emitted an entry other than a positive XOR8 use")
    shape = tuple(int(x) for x in one(TABLE_SHAPE, block, "table shape"))
    table = groups(TABLE_ENTRY, TABLE_LINES, block, "table")
    if shape[0] != TABLE_ENTRIES or shape[1] + shape[2] != shape[0] or sum(c for _, _, c in table) != shape[2]:
        raise ValueError("table entries are not fully accounted for")
    if any(t[0] not in (XOR8_TAG, XOR8_SECOND_TAG) for t, _, _ in table) or any(m == 0 for _, m, _ in table):
        raise ValueError("unexpected table entry")

    net = ledger_nonzero(caller, table)
    baseline, caller_entries, caller_total, table_total = (
        int(x) for x in one(LEDGER, block, "ledger summary"))
    expected_caller_total = sum(m * c for _, m, c in caller) % P
    expected_table_total = sum(m * c for _, m, c in table) % P
    if (baseline, caller_entries, caller_total, table_total) != (
            len(net), ROWS, expected_caller_total, expected_table_total):
        raise ValueError("native ledger summary differs from the one recomputed from the listing")

    qparts = one(QM_LEDGER, block, "QM31 ledger")
    q_caller, q_table, q_total = (qm_value(qparts[i:i + 4]) for i in (0, 4, 8))
    if q_caller != tuple(families[XOR8_TAG]["qm31"]) or modadd(q_caller, q_table) != q_total:
        raise ValueError("QM31 ledger is inconsistent with the caller family sum")
    if (q_total == (0, 0, 0, 0)) != (qparts[12] == "true"):
        raise ValueError("QM31 ledger flag contradicts its printed total")

    reported = {}
    for name, nonzero, detected in NEGATIVE.findall(block):
        if name in reported or name not in NEGATIVE_CONTROLS:
            raise ValueError("unknown or duplicated negative control")
        reported[name] = (int(nonzero), detected == "true")
    if set(reported) != set(NEGATIVE_CONTROLS):
        raise ValueError("missing negative control")
    expected = negative_controls(caller, table)
    if any(reported[n][0] != expected[n] or reported[n][1] != (expected[n] > 0) for n in NEGATIVE_CONTROLS):
        raise ValueError("native negative control differs from the recomputed mutation")

    zero_only = all(t == ZERO_TUPLE for t, _, _ in caller)
    established = (zero_only and not net and q_total == (0, 0, 0, 0)
                   and all(v > 0 for v in expected.values())
                   and table == [(ZERO_TUPLE, P - ROWS, 1)])
    return {
        "stage": "S3o bitwise_builtin caller-AIR XOR8 cancellation",
        "component": "bitwise_builtin",
        "source_rows": rows,
        "base_columns_captured": base,
        "preprocessed_columns": pre,
        "source_digest_blake2s": digest,
        "caller_relation_entries": total,
        "caller_entries_per_row": per_row,
        "caller_rows_with_exactly_one_xor8_entry": one_xor8,
        "caller_families": {str(t): families[t] for t in sorted(families)},
        "component_logup_recomputed": list(recomputed),
        "component_logup_claimed": list(claimed),
        "component_claim_sum_matches": True,
        "component_families_account_for_full_claim": True,
        "caller_xor8_entries": ROWS,
        "caller_xor8_signed_total": signed(expected_caller_total),
        "caller_xor8_tuples": [dict(tuple=list(t), mult=m, count=c) for t, m, c in caller],
        "caller_xor8_all_zero_tuple": zero_only,
        "table_xor8_signed_total_mod_p": expected_table_total,
        "table_xor8_signed_total": signed(expected_table_total),
        "table_xor8_nonzero_entries": [dict(tuple=list(t), mult=m, count=c) for t, m, c in table],
        "table_entries_total": shape[0],
        "ledger_nonzero_tuples": len(net),
        "ledger_nonzero": [dict(tuple=list(t), net_mod_p=v) for t, v in sorted(net.items())],
        "ledger_qm31_caller": list(q_caller),
        "ledger_qm31_table": list(q_table),
        "ledger_qm31_total": list(q_total),
        "negative_controls_nonzero_tuples": expected,
        "xor8_zero_tuple_cancellation_established": established,
        "full_global_lookup_balance_verified": False,
        "native_proof_verified": False,
        "garbled_cairo_proof_verified": False,
        "bitcoin_settlement_authorized": False,
        "ark_utxoref_application_authorized": False,
    }


# Measured on the frozen standalone input (CI run 42834108025, commit ffe0596): the
# bitwise_builtin QM31 interaction claim under the native challenge, and the digest of
# the 89 captured base columns plus the sequence column.
FROZEN = {
    "component_claim": (1876312143, 249812616, 1375950257, 238553224),
    "source_digest": "6ea9ccb9974ec6bdaf50e14cdc7f9d826117d848f058a3d219682660fdf72f83",
}


def parse(log: str, report: dict, frozen: dict = FROZEN) -> dict:
    # S3m pins: native rejection, table claim equality and the single zero-tuple residual.
    local = parse_local(log, report)
    if local.get("component_claim_sum_matches") is not True:
        raise ValueError("native local XOR8 claim differs from source relations")
    if local.get("relation_debug_output_truncated") is not False:
        raise ValueError("table summary must be complete")
    if local.get("nonzero_relation_tuple_lines_observed") != 1:
        raise ValueError("expected one nonzero zero-input tuple in the XOR8 table")
    result = parse_caller(log)
    if tuple(result["component_logup_claimed"]) != tuple(frozen["component_claim"]):
        raise ValueError("bitwise_builtin native claim differs from the frozen-input measurement")
    if result["source_digest_blake2s"] != frozen["source_digest"]:
        raise ValueError("captured bitwise_builtin source rows differ from the frozen-input measurement")
    stage = report["stages"][0]
    limit = report.get("rss_budget_mib", 0) * 1024 * 1024
    if not 0 < stage["peak_rss_bytes"] <= limit <= 4096 * 1024 * 1024:
        raise ValueError("native diagnostic exceeded the 4 GiB sampled RSS cap")
    if not 0 < stage["elapsed_seconds"] <= min(report.get("deadline_seconds", 0), 120):
        raise ValueError("native diagnostic exceeded the 120 s runtime cap")
    local.update(result)
    local.update({
        "resources": {
            "elapsed_seconds": stage["elapsed_seconds"],
            "peak_rss_bytes": stage["peak_rss_bytes"],
            "peak_vms_bytes": stage.get("peak_vms_bytes"),
            "rss_limit_bytes": limit,
            "timeout_seconds": report["deadline_seconds"],
            "native_exit_code": stage["returncode"],
        },
        "global_native_lookup_assertion_failed": True,
    })
    return local


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--log", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    data = parse(args.log.read_text(errors="replace"), json.loads(args.report.read_text()))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(data, indent=2) + "\n")
    keep = ("stage", "xor8_zero_tuple_cancellation_established", "caller_xor8_signed_total",
            "table_xor8_signed_total", "ledger_nonzero_tuples", "component_claim_sum_matches",
            "resources", "global_native_lookup_assertion_failed", "native_proof_verified")
    print(json.dumps({k: data[k] for k in keep}, indent=2))


if __name__ == "__main__":
    main()
