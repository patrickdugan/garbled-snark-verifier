#!/usr/bin/env python3
"""Audit a failed pinned-Cairo lookup check without accepting any proof."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re

P = 2**31 - 1
RE = re.compile(r"\((\d+) \+ (\d+)i\) \+ \((\d+) \+ (\d+)i\)u\Z")
COMP = re.compile(r"^S3_LOOKUP_COMPONENT ([a-z0-9_]+) (.+)$", re.M)


def field(value: str) -> tuple[int, int, int, int]:
    m=RE.fullmatch(value.strip())
    if not m:
        raise ValueError("unrecognized pinned Stwo secure-field debug encoding")
    values=tuple(int(v) for v in m.groups())
    if any(v >= P for v in values):
        raise ValueError("noncanonical reported secure field")
    return values


def modadd(*args: tuple[int, ...]) -> tuple[int, int, int, int]:
    if not args:
        return (0,0,0,0)
    return tuple(sum(x[i] for x in args) % P for i in range(4))


def parse(text: str, proof_report: dict) -> dict:
    if text.count("S3_LOOKUP_RESIDUAL_BEGIN") != 1 or text.count("S3_LOOKUP_RESIDUAL_END") != 1:
        raise ValueError("missing or repeated native residual diagnostic")
    if "assertion " not in text or "left == right" not in text:
        raise ValueError("original native lookup equality assertion did not fail")
    if proof_report.get("native_proof_verified") is not False or proof_report.get("status") != "one_shot_small_profile_failed":
        raise ValueError("native proof report does not identify the expected failed attempt")
    stages=proof_report.get("stages", [])
    if len(stages)!=1 or stages[0].get("status")!="command_failed":
        raise ValueError("unexpected attempt status")
    matches=re.findall(r"^S3_LOOKUP_TOTAL (.+)$",text,re.M)
    publics=re.findall(r"^S3_LOOKUP_PUBLIC (.+)$",text,re.M)
    if len(matches)!=1 or len(publics)!=1:
        raise ValueError("missing total or public memory contribution")
    total=field(matches[0])
    public=field(publics[0])
    entries=COMP.findall(text)
    if not entries or len(entries)>66:
        raise ValueError("component inventory missing or exceeds pinned gate set")
    components={}
    for name, value in entries:
        if name in components:
            raise ValueError("duplicate component")
        components[name]=field(value)
    recomputed=modadd(public, *components.values())
    if recomputed != total or total == (0,0,0,0):
        raise ValueError("failed to reconcile the nonzero native lookup residual")
    return dict(
        stage="S3 lookup-sum residual diagnostic",
        reported_total=list(total),
        public_memory_contribution=list(public),
        present_components={k:list(v) for k,v in sorted(components.items())},
        components_reported=len(components),
        recomputed_sum_matches_native=True,
        native_assertion_preserved=True,
        native_proof_verified=False,
        s2_garbled_proof_verified=False,
        ark_utxoref_application_authorized=False,
    )


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--log",type=Path,required=True)
    p.add_argument("--report",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    report=parse(a.log.read_text(errors="replace"),json.loads(a.report.read_text()))
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({k:v for k,v in report.items() if k!="present_components"},indent=2))


if __name__=="__main__":
    main()
