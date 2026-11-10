#!/usr/bin/env python3
"""Instrument one pinned upstream lookup_sum; verification assertions stay intact.

Opt-in diagnostic ONLY, applied to an ephemeral checkout with the exact pinned
git HEAD. Normal repo builds never modify upstream code or read this patch.
"""
from __future__ import annotations
import argparse
import difflib
import hashlib
from pathlib import Path
import re
import subprocess

REV = "467d5c6d4d6d526c1db8ff69c14f2de6d57f4d73"
SOURCE = "stwo_cairo_prover/crates/cairo-air/src/claims.rs"
FUNC = "pub fn lookup_sum("
CHECK = re.compile(r"interaction_claim\s*\.\s*(\w+)\s*\.as_ref\(\)\s*\.inspect\(\|ic\|")


def instrument(original: str) -> tuple[str, list[str]]:
    start = original.index(FUNC)
    opening = original.index("{", start)
    depth = 0
    stop = None
    for i in range(opening, len(original)):
        if original[i] == "{":
            depth += 1
        elif original[i] == "}":
            depth -= 1
            if depth == 0:
                stop = i + 1
                break
    if stop is None:
        raise ValueError("upstream lookup_sum function is incomplete")
    source = original[start:stop]
    if not source.endswith("    sum\n}"):
        raise ValueError("unrecognized upstream lookup_sum return")
    fields = CHECK.findall(source)
    if len(fields) != 66 or len(fields) != len(set(fields)):
        raise ValueError(f"lookup_sum inventory mismatch: {len(fields)} components")
    if source.count("sum += ic.claimed_sum;") != len(fields):
        raise ValueError("upstream lookup_sum changed its accumulation semantics")
    indent = "    "
    added = [
        indent+"if sum != SecureField::zero() {",
        indent+'    eprintln!("S3_LOOKUP_RESIDUAL_BEGIN");',
        indent+'    eprintln!("S3_LOOKUP_TOTAL {:?}", sum);',
        indent+'    eprintln!("S3_LOOKUP_PUBLIC {:?}", claim.public_data.logup_sum(common_lookup_elements));',
    ]
    for name in fields:
        added.extend([
            indent+f"    if let Some(ic) = interaction_claim.{name}.as_ref() {{",
            indent+f'        eprintln!("S3_LOOKUP_COMPONENT {name} {{:?}}", ic.claimed_sum);',
            indent+"    }",
        ])
    added.append(indent+'    eprintln!("S3_LOOKUP_RESIDUAL_END");')
    added.append(indent+"}")
    replacement=source[:-len("    sum\n}")]+"\n".join(added)+"\n    sum\n}"
    return original[:start]+replacement+original[stop:], fields


def prepare(root: Path, destination: Path) -> dict:
    root = root.resolve()
    head = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    if head != REV:
        raise ValueError(f"upstream checkout mismatch {head}")
    original = subprocess.check_output(["git", "-C", str(root), "show", f"HEAD:{SOURCE}"], text=True)
    path = root / SOURCE
    if path.read_text() != original:
        raise ValueError("refusing to replace pre-modified upstream source")
    modified, fields = instrument(original)
    path.write_text(modified)
    patch = "".join(difflib.unified_diff(
        original.splitlines(keepends=True), modified.splitlines(keepends=True),
        fromfile="a/" + SOURCE, tofile="b/" + SOURCE))
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(patch)
    return {
        "stage": "S3 lookup-sum diagnostic, source modification in ephemeral checkout only",
        "upstream_git_head": head,
        "source_path": SOURCE,
        "source_before_sha256": hashlib.sha256(original.encode()).hexdigest(),
        "source_after_sha256": hashlib.sha256(modified.encode()).hexdigest(),
        "patch_sha256": hashlib.sha256(patch.encode()).hexdigest(),
        "components": len(fields),
        "native_verification_completed": False,
        "assertions_unchanged": True,
    }


def main() -> None:
    import json
    ap=argparse.ArgumentParser()
    ap.add_argument("--upstream", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args=ap.parse_args()
    result=prepare(args.upstream, args.output)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
