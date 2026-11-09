#!/usr/bin/env python3
"""Prove an already recorded Shinigami bootloader input once, under RSS limits.

The frozen fixture is pinned to a known Scarb 2.18 / patched Shinigami
executable. This is laboratory evidence, not an Ark or UTXORef acceptance
token. No Nova or SP1 proving is performed.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

from guarded_process import guarded_run, write_report, MAX_FILE_BYTES

ROOT = Path(__file__).resolve().parents[1]
EXECUTION_ID = 2
EXPECTED_INPUT_BYTES = 121_452_932
EXPECTED_INPUT_SHA256 = '02c8508f635c7934b1a3ac13eedf5545ea4681f1a72edc51685c7b0fd5ccc031'
EXPECTED_EXECUTABLE_SHA256 = 'a9bdc409d2f7ee443ac62cabdc8df27fb44c85a435ca9350788bee890f61bef3'
EXPECTED_SHIM_SHA256 = '4b4d4d4c222948201702f70246b2b639ec7332c468aeac6573c36f2f73df7b8b'
EXPECTED_SOURCE_PATCH_SHA256 = 'e72675bc278e2bf3a20ea272a473ec54e000864aed40a2a6ace5983491a40119'
EXPECTED_PINS = {
    'shinigami': '7e8c05d60b4bd7ae91ddc18a42e8e13090286f0c',
    'ripemd160': 'cdc5ab58b0acc64db87e0b03851fb18213977dc8',
    'sha1': '280b4c64ae457fdc4bd7cd807efd17e8dced654e',
}
MAX_GZIP_BYTES = 20 * 1024 * 1024


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024*1024), b''):
            hasher.update(chunk)
    return hasher.hexdigest()


def restore_input(gz: Path, dest: Path, *, expected_bytes: int,
                  expected_sha256: str) -> dict:
    if not gz.is_file() or not 0 < gz.stat().st_size <= MAX_GZIP_BYTES:
        raise ValueError('frozen prover input is missing or oversized')
    if dest.exists():
        raise ValueError('execution input already exists; refusing overwrite or replay')
    dest.parent.mkdir(parents=True, exist_ok=True)
    temp = dest.with_suffix('.partial')
    h = hashlib.sha256()
    size = 0
    try:
        with gz.open('rb') as raw, gzip.GzipFile(fileobj=raw) as src, temp.open('xb') as sink:
            while chunk := src.read(1024 * 1024):
                size += len(chunk)
                if size > expected_bytes or size > MAX_FILE_BYTES:
                    raise ValueError('frozen input expands beyond declared byte budget')
                sink.write(chunk)
                h.update(chunk)
        if size != expected_bytes or h.hexdigest() != expected_sha256:
            raise ValueError('frozen prover input SHA-256 or byte count mismatch')
        temp.replace(dest)
        return dict(bytes=size, sha256=h.hexdigest(), compressed_bytes=gz.stat().st_size)
    finally:
        temp.unlink(missing_ok=True)


def validate_source(source: Path, compiled: Path) -> dict:
    pins = json.loads((source/'source-pins.json').read_text())
    if (pins.get('sources') != EXPECTED_PINS
        or pins.get('compat_patch_sha256') != EXPECTED_SOURCE_PATCH_SHA256
        or pins.get('sha256_shim_sha256') != EXPECTED_SHIM_SHA256):
        raise ValueError('frozen Shinigami source pins or SHA shim changed')
    source_exe = source/'shinigami_bitvm3_receipt.executable.json'
    if not source_exe.is_file() or digest(source_exe) != EXPECTED_EXECUTABLE_SHA256:
        raise ValueError('frozen executable differs from the S3 program pin')
    if not compiled.is_file() or digest(compiled) != EXPECTED_EXECUTABLE_SHA256:
        raise ValueError('rebuilt executable differs from the frozen program')
    return dict(executable_sha256=EXPECTED_EXECUTABLE_SHA256,
                compat_patch_sha256=EXPECTED_SOURCE_PATCH_SHA256,
                producer='Scarb 2.18.0 pinned native Stwo-Cairo (rev 467d5c6d)')


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument('--prove-saved', required=True, action='store_true',
                   help='explicitly authorize exactly one native-proof attempt')
    p.add_argument('--source', type=Path, default=ROOT/'out/frozen')
    p.add_argument('--rss-mib', type=int, default=4096)
    p.add_argument('--timeout-seconds', type=int, default=120)
    args = p.parse_args()
    if not (1024 <= args.rss_mib <= 5120 and 1 <= args.timeout_seconds <= 120):
        p.error('RSS budget 1024..5120 MiB; proving deadline 1..120 seconds')
    out = ROOT/'out'
    out.mkdir(parents=True, exist_ok=True)
    report = dict(schema=2, status='started', source_execution_id=EXECUTION_ID,
                  hypothesis='RLIMIT_AS rejected virtual reservations; test bounded RSS instead',
                  native_proof_verified=False, application_statement_authenticated=False,
                  cairo_program_identity_proof_bound=False, s2_boolean_import_verified=False,
                  garbled_verified=False, stages=[],
                  proof_runtime_limit_seconds=args.timeout_seconds,
                  process_group_rss_limit_mib=args.rss_mib,
                  limit_kind='observed process-group resident set (Linux /proc)',
                  caveat='sampled at 100ms; kernel OOM and shared-page accounting still apply')
    execution = ROOT/f'target/execute/shinigami_bitvm3_receipt/execution{EXECUTION_ID}'
    env = dict(os.environ, RAYON_NUM_THREADS='2', CARGO_BUILD_JOBS='2')
    try:
        report['pins'] = validate_source(args.source,
            ROOT/'target/dev/shinigami_bitvm3_receipt.executable.json')
        report['input'] = restore_input(args.source/'prover_input.json.gz',
            execution/'prover_input.json', expected_bytes=EXPECTED_INPUT_BYTES,
            expected_sha256=EXPECTED_INPUT_SHA256)
        write_report(out/'rss-proof-report.json', report)
        stage = guarded_run(['scarb','prove','--execution-id',str(EXECUTION_ID)],
            cwd=ROOT, log_path=out/'rss-proving.txt',
            timeout_seconds=args.timeout_seconds,
            max_rss_bytes=args.rss_mib*1024*1024, env=env)
        report['stages'].append(stage)
        write_report(out/'rss-proof-report.json', report)
        if stage['status'] != 'success':
            raise RuntimeError(f"prover stage ended with {stage['status']}; see rss-proving.txt")
        proof = execution/'proof/proof.json'
        if not proof.is_file() or not 0 < proof.stat().st_size <= MAX_FILE_BYTES:
            raise RuntimeError('expected bounded native proof file is missing')
        shutil.copyfile(proof, out/'native-proof.json')
        report['proof'] = dict(bytes=proof.stat().st_size, sha256=digest(proof))
        verification = guarded_run(['scarb','verify','--execution-id',str(EXECUTION_ID)],
            cwd=ROOT, log_path=out/'rss-verification.txt', timeout_seconds=30,
            max_rss_bytes=args.rss_mib*1024*1024, env=env)
        report['stages'].append(verification)
        if verification['status'] != 'success':
            raise RuntimeError(f"verification ended with {verification['status']}")
        report['native_proof_verified'] = True
        report['status'] = 'native_proof_verified_application_binding_outstanding'
        return 0
    except Exception as exc:
        report['status'] = 'one_shot_probe_failed'
        report['error'] = str(exc)
        print(str(exc), file=sys.stderr, flush=True)
        return 1
    finally:
        (execution/'prover_input.json').unlink(missing_ok=True)
        write_report(out/'rss-proof-report.json', report)
        print(json.dumps(report, indent=2), flush=True)


if __name__ == '__main__':
    raise SystemExit(main())
