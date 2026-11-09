#!/usr/bin/env python3
"""One opt-in native Stwo-Cairo run using an immutable small profile.

Runs the pinned native prover directly to set canonical_small and a reduced
FFT lifting size. Built-in --verify must accept the result. This is only
Cairo execution proof evidence, not a Shinigami/BitVM3 application receipt.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import sys

from check_low_memory_profile import (EXPECTED_STWO_CAIRO, check_profile,
                                      verify_upstream_checkout)
from guarded_process import guarded_run, write_report, MAX_FILE_BYTES
from prove_saved import (digest, restore_input, EXPECTED_EXECUTABLE_SHA256,
                         EXPECTED_SOURCE_PATCH_SHA256, EXPECTED_SHIM_SHA256,
                         EXPECTED_PINS)
from audit_execution import expected_csv_receipt

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/'out'
SOURCE_INPUT_BYTES = 9_624_654
SOURCE_INPUT_SHA256 = 'c3c3622b6c10fe54f2efbb9f48d4cbcedb96143b904aa29eaa8fb07e8b65eb55'
PROFILE_PATH = ROOT/'params/canonical-small-96.json'


def validate_frozen_source(source: Path) -> dict:
    report=json.loads((source/'standalone-proof-report.json').read_text())
    audit=json.loads((source/'standalone-proof-audit.json').read_text())
    pins=json.loads((source/'source-pins.json').read_text())
    if (report.get('program_pin',{}).get('executable_sha256') != EXPECTED_EXECUTABLE_SHA256
        or report.get('prover_input',{}).get('sha256') != SOURCE_INPUT_SHA256
        or report.get('prover_input',{}).get('bytes') != SOURCE_INPUT_BYTES):
        raise ValueError('frozen standalone input or compiled program mismatch')
    if (pins.get('sources') != EXPECTED_PINS
        or pins.get('compat_patch_sha256') != EXPECTED_SOURCE_PATCH_SHA256
        or pins.get('sha256_shim_sha256') != EXPECTED_SHIM_SHA256):
        raise ValueError('frozen source or SHA-256 shim mismatch')
    if (audit.get('receipt_matches_expected_request') is not True
        or audit.get('executed_syscalls_reported') != 0
        or audit.get('output_felts') != expected_csv_receipt()
        or audit.get('proof_verified') is not False):
        raise ValueError('frozen receipt audit differs from expected CSV transaction')
    return dict(input_sha256=SOURCE_INPUT_SHA256, executable_sha256=EXPECTED_EXECUTABLE_SHA256,
                shinigami_program_receipt_audited=True, runtime_syscalls_observed=0)


def check_frozen_input(path: Path) -> dict:
    data=json.loads(path.read_text())
    builtin=data['builtin_segments']
    if builtin.get('pedersen_builtin') is not None:
        raise ValueError('saved standalone execution uses the Pedersen builtin')
    if builtin.get('poseidon_builtin') is not None:
        raise ValueError('saved standalone execution uses Poseidon builtin')
    if len(data['memory']['address_to_id']) > 1<<20:
        raise ValueError('memory address-to-id table unexpectedly large')
    return dict(pedersen_builtin_absent=True,poseidon_builtin_absent=True,
                address_to_id_count=len(data['memory']['address_to_id']),
                pc_count=data['pc_count'])


def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument('--prove-small-once',action='store_true',required=True)
    p.add_argument('--source',type=Path,default=OUT/'frozen')
    p.add_argument('--upstream',type=Path,default=ROOT/'vendor/stwo-cairo')
    p.add_argument('--rss-mib',type=int,default=4096)
    p.add_argument('--timeout-seconds',type=int,default=120)
    a=p.parse_args()
    if not (1024 <= a.rss_mib <= 5120 and 1 <= a.timeout_seconds <= 120):
        p.error('RSS budget 1024..5120 MiB and deadline 1..120 seconds required')
    OUT.mkdir(parents=True,exist_ok=True)
    report=dict(schema=1,stage='S3d: direct native Stwo-Cairo canonical-small prover',
        status='started',native_proof_verified=False,
        application_statement_authenticated=False,
        bitcoin_consensus_and_dispute_verified=False,
        s2_boolean_garbled_verification=False,
        scope='one pinned standalone CSV trace; laboratory only',
        recorded_security='96-bit upstream nominal FRI PoW+queries',
        stages=[],rss_budget_mib=a.rss_mib,deadline_seconds=a.timeout_seconds)
    restored=OUT/'small-profile-prover-input.json'
    proof=OUT/'small-profile-native-proof.json'
    try:
        report['config']=check_profile(json.loads(PROFILE_PATH.read_text()))
        report['upstream_sha']=verify_upstream_checkout(a.upstream)
        report['source']=validate_frozen_source(a.source)
        report['input']=restore_input(a.source/'standalone-prover-input.json.gz',
            restored,expected_bytes=SOURCE_INPUT_BYTES,expected_sha256=SOURCE_INPUT_SHA256)
        report['trace']=check_frozen_input(restored)
        if proof.exists():
            raise ValueError('refusing to overwrite an existing proof')
        binary=a.upstream/'stwo_cairo_prover/target/witness-opt-1/prove'
        if not binary.is_file():
            raise RuntimeError('pinned native prover binary missing; run explicit build first')
        env=dict(os.environ,RAYON_NUM_THREADS='2',CARGO_BUILD_JOBS='2')
        argv=[str(binary.resolve()),'--prover_input_path',str(restored.resolve()),
              '--params_json',str(PROFILE_PATH.resolve()),'--proof_path',
              str(proof.resolve()),'--verify']
        write_report(OUT/'small-profile-report.json',report)
        run=guarded_run(argv,cwd=ROOT,log_path=OUT/'small-profile-proving.txt',
                        timeout_seconds=a.timeout_seconds,
                        max_rss_bytes=a.rss_mib*1024*1024,env=env)
        report['stages'].append(run)
        write_report(OUT/'small-profile-report.json',report)
        if run['status']!='success':
            raise RuntimeError(f"pinned native proving ended with {run['status']}")
        if not proof.is_file() or not 0<proof.stat().st_size<=MAX_FILE_BYTES:
            raise RuntimeError('native verifier returned success but output proof is missing or oversized')
        report['proof']=dict(bytes=proof.stat().st_size,sha256=digest(proof))
        report['native_proof_verified']=True
        report['status']='native_small_profile_verified_application_binding_outstanding'
        return 0
    except Exception as exc:
        report['status']='one_shot_small_profile_failed'
        report['error']=str(exc)
        print(str(exc),file=sys.stderr,flush=True)
        return 1
    finally:
        restored.unlink(missing_ok=True)
        write_report(OUT/'small-profile-report.json',report)
        print(json.dumps(report,indent=2),flush=True)


if __name__=='__main__':
    raise SystemExit(main())
