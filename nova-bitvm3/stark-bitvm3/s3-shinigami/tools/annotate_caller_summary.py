#!/usr/bin/env python3
"""Publish the S3o result as GitHub Actions annotations.

Annotations of a public repository are readable through the unauthenticated REST API,
so the measured evidence is available without downloading an artifact. When the
summary is missing (the parser rejected the log), the raw S3_ marker lines are
published instead, so a failed attempt stays diagnosable.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

MAX_RAW_LINES = 80
MAX_MESSAGE = 6000
SUMMARY_KEYS = (
    "xor8_zero_tuple_cancellation_established", "caller_xor8_entries",
    "caller_xor8_signed_total", "table_xor8_signed_total", "caller_xor8_all_zero_tuple",
    "ledger_nonzero_tuples", "ledger_qm31_total", "component_claim_sum_matches",
    "caller_relation_entries", "caller_rows_with_exactly_one_xor8_entry",
    "negative_controls_nonzero_tuples", "source_digest_blake2s",
    "global_native_lookup_assertion_failed", "native_proof_verified",
    "full_global_lookup_balance_verified",
)


def escape(message: str) -> str:
    return message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def notice(title: str, message: str, level: str = "notice") -> str:
    return f"::{level} title={title}::{escape(message[:MAX_MESSAGE])}"


def load(path: Path):
    return json.loads(path.read_text()) if path.is_file() else None


def render(summary, log_text: str, instrument, report) -> list[str]:
    out = []
    if instrument:
        out.append(notice("S3O patch", json.dumps({
            "patch_sha256": instrument.get("patch_sha256"),
            "upstream_revision": instrument.get("upstream_revision"),
            "files": [(f["path"].rsplit("/", 1)[-1], f["before_sha256"][:16], f["diagnostic_sha256"][:16])
                      for f in instrument.get("source_file_hashes", [])],
        }, separators=(",", ":"))))
    if summary:
        out.append(notice("S3O result", json.dumps(
            {k: summary[k] for k in SUMMARY_KEYS if k in summary}, separators=(",", ":"))))
        out.append(notice("S3O families", json.dumps(
            summary.get("caller_families", {}), separators=(",", ":"))))
        out.append(notice("S3O resources", json.dumps(
            {"resources": summary.get("resources"),
             "component_logup_claimed": summary.get("component_logup_claimed"),
             "component_logup_recomputed": summary.get("component_logup_recomputed"),
             "residual": summary.get("baseline_residual")}, separators=(",", ":"))))
    else:
        lines = [l for l in log_text.splitlines() if l.startswith(("S3_CALLER", "S3_XOR8", "S3_LOCAL_LOGUP"))]
        out.append(notice("S3O raw markers", "\n".join(lines[:MAX_RAW_LINES]) or "no S3 marker lines", "error"))
        if report:
            stage = (report.get("stages") or [{}])[0]
            out.append(notice("S3O run", json.dumps({
                "status": report.get("status"), "stage_status": stage.get("status"),
                "returncode": stage.get("returncode"),
                "elapsed_seconds": stage.get("elapsed_seconds"),
                "peak_rss_bytes": stage.get("peak_rss_bytes")}, separators=(",", ":")), "error"))
    return out


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--summary", type=Path, required=True)
    p.add_argument("--log", type=Path, required=True)
    p.add_argument("--instrument", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    a = p.parse_args()
    log_text = a.log.read_text(errors="replace") if a.log.is_file() else ""
    for line in render(load(a.summary), log_text, load(a.instrument), load(a.report)):
        print(line)


if __name__ == "__main__":
    main()
