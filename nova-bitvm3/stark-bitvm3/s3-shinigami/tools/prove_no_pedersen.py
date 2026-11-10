#!/usr/bin/env python3
"""One opt-in Cairo proof with canonical_without_pedersen preprocessing.

Uses the same immutable standalone Shinigami trace and source-pinned native
producer as S3d, and retains the native --verify acceptance requirement.
No Bitcoin application or garbled acceptance flag is produced here.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys

from check_no_pedersen_profile import PROFILE, check
from check_low_memory_profile import verify_upstream_checkout
from guarded_process import guarded_run, write_report, MAX_FILE_BYTES
from prove_low_memory import (
    OUT, ROOT, SOURCE_INPUT_BYTES, SOURCE_INPUT_SHA256,
    validate_frozen_source, check_frozen_input
)
from prove_saved import restore_input, digest


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--prove-no-pedersen-once',action='store_true',required=True)
    ap.add_argument('--source',type=Path,default=OUT/'frozen')
    ap.add_argument('--upstream',type=Path,default=ROOT/'vendor/stwo-cairo')
    ap.add_argument('--rss-mib',type=int,default=4096)
    ap.add_argument('--timeout-seconds',type=int,default=120)
    a=ap.parse_args()
    if not (1024 <= a.rss_mib <= 4096 and 1 <= a.timeout_seconds <= 120):
        ap.error('RSS budget 1024..4096 MiB and deadline 1..120 seconds')
    OUT.mkdir(parents=True,exist_ok=True)
    restored=OUT/'no-pedersen-input.json'
    proof=OUT/'no-pedersen-native-proof.json'
    report_path=OUT/'no-pedersen-report.json'
    report=dict(schema=1,stage='S3: pinned native Cairo no-Pedersen fallback',
        status='started',native_proof_verified=False,application_statement_authenticated=False,
        s2_boolean_garbled_verification=False,bitcoin_consensus_and_dispute_verified=False,
        source_prover_revision='467d5c6d4d6d526c1db8ff69c14f2de6d57f4d73',
        proof_profile='canonical_without_pedersen',recorded_security='96-bit nominal FRI',
        rss_budget_mib=a.rss_mib,deadline_seconds=a.timeout_seconds,stages=[])
    try:
        report['upstream_sha']=verify_upstream_checkout(a.upstream)
        report['source']=validate_frozen_source(a.source)
        report['input']=restore_input(a.source/'standalone-prover-input.json.gz',
            restored,expected_bytes=SOURCE_INPUT_BYTES,expected_sha256=SOURCE_INPUT_SHA256)
        report['trace']=check_frozen_input(restored)
        data=json.loads(restored.read_text())
        report['config']=check(json.loads(PROFILE.read_text()),data['builtin_segments'])
        del data
        if proof.exists():
            raise ValueError('refusing to overwrite existing proof output')
        native=a.upstream/'stwo_cairo_prover/target/witness-opt-1/prove'
        if not native.is_file():
            raise RuntimeError('pinned native binary absent; build explicitly first')
        argv=[str(native.resolve()),'--prover_input_path',str(restored.resolve()),
              '--params_json',str(PROFILE.resolve()),
              '--proof_path',str(proof.resolve()),'--verify']
        write_report(report_path,report)
        result=guarded_run(argv,cwd=ROOT,log_path=OUT/'no-pedersen-proving.txt',
            timeout_seconds=a.timeout_seconds,max_rss_bytes=a.rss_mib*1024*1024,
            env=dict(os.environ,RAYON_NUM_THREADS='2',CARGO_BUILD_JOBS='2'))
        report['stages'].append(result)
        write_report(report_path,report)
        if result['status']!='success':
            raise RuntimeError(f"pinned native proving ended with {result['status']}")
        if not proof.is_file() or not 0<proof.stat().st_size<=MAX_FILE_BYTES:
            raise RuntimeError('missing or oversized native proof output')
        report['proof']=dict(bytes=proof.stat().st_size,sha256=digest(proof))
        report['native_proof_verified']=True
        report['status']='native_cairo_proof_verified_application_binding_outstanding'
        return 0
    except Exception as exc:
        report['status']='bounded_no_pedersen_trial_failed'
        report['error']=str(exc)
        print(str(exc),file=sys.stderr,flush=True)
        return 1
    finally:
        restored.unlink(missing_ok=True)
        write_report(report_path,report)
        print(json.dumps(report,indent=2),flush=True)


if __name__=="__main__":
    raise SystemExit(main())
