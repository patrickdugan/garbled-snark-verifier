#!/usr/bin/env python3
"""Audit captured execution output against a fixed local fixture.

This checks serialization and policy matching. It does not verify a STARK or
authenticate a log received from an untrusted party.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import sys
from cases import cases, DOMAIN, FLAGS, CAIRO_P


def expected_csv_receipt() -> list[int]:
    fixture = cases()[0]
    tx = bytes.fromhex(fixture['raw_transaction'])
    digest = hashlib.sha256(hashlib.sha256(tx).digest()).digest()
    txid = int.from_bytes(digest, 'big')
    return [DOMAIN, 1, 1, FLAGS, *fixture['args'], 1, 0,
            txid % (1 << 128), txid >> 128]


def matches(words: list[int], expected: list[int]) -> bool:
    return (all(type(x) is int and 0 <= x < CAIRO_P for x in words)
            and words == expected)


def audit(text: str) -> dict:
    sections = re.findall(r'^Program output:\n(.*?)^Resources:', text, re.M | re.S)
    if len(sections) != 1:
        raise ValueError('expected exactly one complete execution-output section')
    raw = sections[0].strip().splitlines()
    if any(re.fullmatch(r'[0-9]+', line.strip()) is None for line in raw):
        raise ValueError('unexpected output word encoding')
    words = [int(line.strip()) for line in raw]
    expected = expected_csv_receipt()
    if not matches(words, expected):
        raise ValueError('public receipt differs from fixed CSV request and expected verdict')
    if re.search(r'^\s*syscalls:', text, re.M):
        raise ValueError('fixture unexpectedly executed a syscall')
    rejected = 0
    for i in range(len(words)):
        changed = words.copy()
        changed[i] = (changed[i] + 1) % CAIRO_P
        if matches(changed, expected):
            raise AssertionError('output mutation escaped policy matching')
        rejected += 1
    for changed in [words[:-1], words+[0], [CAIRO_P]+words[1:], [-1]+words[1:]]:
        if matches(changed, expected):
            raise AssertionError('shape/canonicality mutation escaped policy matching')
        rejected += 1
    return dict(receipt_words=len(words), receipt_matches_expected_request=True,
                policy_mutations_rejected=rejected, executed_syscalls_reported=0,
                output_felts=words, proof_verified=False,
                scope='captured execution-log serialization audit only')


def main() -> None:
    path = Path(sys.argv[1])
    report = audit(path.read_text())
    (path.parent/'receipt-audit.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
