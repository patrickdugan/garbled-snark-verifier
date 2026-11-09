#!/usr/bin/env python3
"""One bounded, opt-in native proof of Shinigami's short standalone CSV trace.

This execution-proof laboratory is not a Bitcoin spend, Ark, or UTXORef receipt.
S2's different Stwo verifier and the bootloader's program identity are unbound.
"""
from __future__ import annotations
import argparse
import gzip
import json
import os
from pathlib import Path
import re
import shutil
import sys

from guarded_process import guarded_run, write_report, MAX_FILE_BYTES
from prove_saved import (digest, EXPECTED_EXECUTABLE_SHA256, EXPECTED_PINS,
                         EXPECTED_SOURCE_PATCH_SHA256, EXPECTED_SHIM_SHA256)
from audit_execution import audit

ROOT = Path(__file__).resolve().parents[1]
EXECUTIONS = ROOT/'target/execute/shinigami_bitvm3_receipt'
OUT = ROOT/'out'


def find_fresh_execution(before: set[str], after: set[str]) -> tuple[int, str]:
    fresh = after - before
    if len(fresh) != 1:
        raise ValueError('expected exactly one new execution directory')
    name = fresh.pop()
    if not re.fullmatch(r'execution[1-9][0-9]*',name):
        raise ValueError('unexpected execution directory name')
    return int(name[len('execution'):]), name


def ensure_program_pin() -> dict:
    meta = json.loads((OUT/'source-pins.json').read_text())
    if (meta.get('sources') != EXPECTED_PINS
        or meta.get('compat_patch_sha256') != EXPECTED_SOURCE_PATCH_SHA256
        or meta.get('sha256_shim_sha256') != EXPECTED_SHIM_SHA256):
        raise ValueError('source pins or SHA-256 compatibility patch changed')
    executable = ROOT/'target/dev/shinigami_bitvm3_receipt.executable.json'
    if not executable.is_file() or digest(executable) != EXPECTED_EXECUTABLE_SHA256:
        raise ValueError('compiled executable differs from the tested S3 program')
    return dict(executable_sha256=EXPECTED_EXECUTABLE_SHA256,
                patch_sha256=EXPECTED_SOURCE_PATCH_SHA256,
                native_prover='Scarb 2.18.0')


def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument('--prove-once',required=True,action='store_true')
    p.add_argument('--rss-mib',type=int,default=4096)
    p.add_argument('--timeout-seconds',type=int,default=120)
    args=p.parse_args()
    if not 1024<=args.rss_mib<=5120 or not 1<=args.timeout_seconds<=120:
        p.error('RSS budget 1024..5120 MiB and deadline 1..120 seconds')
    OUT.mkdir(parents=True,exist_ok=True)
    report=dict(schema=1,stage='S3c: standalone Shinigami STARK experiment',
                status='started',
                hypothesis='157,303 standalone Cairo steps may prove within RSS budget',
                expected_producer='Scarb 2.18.0 / stwo-cairo 467d5c6d',
                limit_kind='userspace sampled process-group RSS',
                process_group_rss_limit_mib=args.rss_mib,
                runtime_timeout_seconds=args.timeout_seconds,
                native_proof_verified=False, application_statement_authenticated=False,
                independent_program_identity_authenticated=False,
                syscall_soundness_reviewed=False,
                s2_boolean_import_verified=False,garbled_verified=False,
                stages=[])
    env=dict(os.environ,RAYON_NUM_THREADS='2',CARGO_BUILD_JOBS='2')
    try:
        report['program_pin']=ensure_program_pin()
        before={d.name for d in EXECUTIONS.glob('execution*') if d.is_dir()}
        execution=guarded_run(['scarb','execute','--no-build','--target','standalone',
            '--output','standard','--arguments-file','out/csv_valid.args.json',
            '--print-program-output','--print-resource-usage'], cwd=ROOT,
            log_path=OUT/'standalone-proof-execution.txt',timeout_seconds=30,
            max_rss_bytes=args.rss_mib*1024*1024,env=env)
        report['stages'].append(execution)
        if execution['status']!='success':
            raise RuntimeError('standalone execution '+execution['status'])
        after={d.name for d in EXECUTIONS.glob('execution*') if d.is_dir()}
        number,name=find_fresh_execution(before,after)
        report['execution_id']=number
        (OUT/'standalone-proof-audit.json').write_text(json.dumps(
            audit((OUT/'standalone-proof-execution.txt').read_text()),indent=2)+'\n')
        proof_input=EXECUTIONS/name/'prover_input.json'
        if not proof_input.is_file() or not 0<proof_input.stat().st_size<=MAX_FILE_BYTES:
            raise RuntimeError('missing or oversized standalone prover input')
        report['prover_input']=dict(bytes=proof_input.stat().st_size,
                                    sha256=digest(proof_input))
        # Preserve the smaller exact input for future producer/verifier comparisons.
        with proof_input.open('rb') as src, (OUT/'standalone-prover-input.json.gz').open('wb') as dst:
            with gzip.GzipFile(fileobj=dst,mode='wb',mtime=0) as gz:
                shutil.copyfileobj(src,gz)
        if (OUT/'standalone-prover-input.json.gz').stat().st_size > MAX_FILE_BYTES:
            raise RuntimeError('compressed prover input exceeds file budget')
        report['prover_input']['compressed_bytes']=(OUT/'standalone-prover-input.json.gz').stat().st_size
        write_report(OUT/'standalone-proof-report.json',report)
        attempt=guarded_run(['scarb','prove','--execution-id',str(number)],
            cwd=ROOT,log_path=OUT/'standalone-proving.txt',
            timeout_seconds=args.timeout_seconds,max_rss_bytes=args.rss_mib*1024*1024,
            env=env)
        report['stages'].append(attempt)
        write_report(OUT/'standalone-proof-report.json',report)
        if attempt['status']!='success':
            raise RuntimeError('standalone proving '+attempt['status'])
        proof=EXECUTIONS/name/'proof/proof.json'
        if not proof.is_file() or not 0<proof.stat().st_size<=MAX_FILE_BYTES:
            raise RuntimeError('native proof missing or oversized')
        shutil.copyfile(proof,OUT/'standalone-native-proof.json')
        report['proof']=dict(bytes=proof.stat().st_size,sha256=digest(proof))
        verified=guarded_run(['scarb','verify','--execution-id',str(number)],
            cwd=ROOT,log_path=OUT/'standalone-verification.txt',timeout_seconds=30,
            max_rss_bytes=args.rss_mib*1024*1024,env=env)
        report['stages'].append(verified)
        if verified['status']!='success':
            raise RuntimeError('native verification '+verified['status'])
        report['native_proof_verified']=True
        report['status']='native_standalone_proof_verified_application_binding_outstanding'
        return 0
    except Exception as exc:
        report['status']='one_shot_probe_failed'
        report['error']=str(exc)
        print(str(exc),file=sys.stderr,flush=True)
        return 1
    finally:
        write_report(OUT/'standalone-proof-report.json',report)
        print(json.dumps(report,indent=2),flush=True)


if __name__=='__main__':
    raise SystemExit(main())
