#!/usr/bin/env python3
"""Explicit, bounded native-proof probe. Never emits an application receipt token.

This uses Scarb 2.18's own pinned producer and verifier. Compatibility with the
separate S2 revision and application-statement authentication remain separate.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
MAX_FILE = 128 * 1024 * 1024


def child_limits() -> None:
    resource.setrlimit(resource.RLIMIT_AS, (6 * 1024**3, 6 * 1024**3))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE, MAX_FILE))


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--prove', action='store_true', required=True,
                        help='Explicitly permit one bounded native proof attempt')
    parser.parse_args()
    out = ROOT/'out'
    out.mkdir(exist_ok=True)
    report = dict(schema=1, stages=[], native_proof_verified=False,
                  application_statement_authenticated=False,
                  s2_boolean_import_verified=False, garbled_verified=False,
                  producer='Scarb 2.18.0 / stwo-cairo rev 467d5c6d',
                  memory_limit_bytes=6*1024**3, max_file_bytes=MAX_FILE)
    env = dict(os.environ, RAYON_NUM_THREADS='2', CARGO_BUILD_JOBS='2')
    def run(name: str, seconds: int, arguments: list[str]) -> None:
        start = time.monotonic()
        command = ['timeout', '--kill-after=5s', str(seconds)+'s', *arguments]
        with (out/(name+'.txt')).open('wb') as log:
            completed = subprocess.run(command, cwd=ROOT, env=env,
                                       stdout=log, stderr=subprocess.STDOUT,
                                       preexec_fn=child_limits, check=False)
        report['stages'].append(dict(name=name, command=arguments,
                                    timeout_seconds=seconds,
                                    elapsed_seconds=time.monotonic()-start,
                                    returncode=completed.returncode))
        if completed.returncode:
            raise RuntimeError(f'{name} exited {completed.returncode}; see {name}.txt')
    try:
        executions = ROOT/'target/execute/shinigami_bitvm3_receipt'
        before = set(executions.glob('execution*'))
        run('bootloader-execution', 60, [
            'scarb','execute','--no-build','--target','bootloader','--output','standard',
            '--arguments-file','out/csv_valid.args.json',
            '--print-program-output','--print-resource-usage','--json'])
        fresh = set(executions.glob('execution*')) - before
        if len(fresh) != 1:
            raise RuntimeError('expected exactly one fresh execution directory')
        directory = fresh.pop()
        execution_id = int(directory.name.removeprefix('execution'))
        prover_input = directory/'prover_input.json'
        size = prover_input.stat().st_size
        if size > MAX_FILE:
            raise RuntimeError('prover input exceeds bounded artifact size')
        report['prover_input'] = dict(bytes=size, sha256=digest(prover_input))
        with prover_input.open('rb') as source, (out/'prover_input.json.gz').open('wb') as target:
            with gzip.GzipFile(fileobj=target, mode='wb', mtime=0) as compressed:
                shutil.copyfileobj(source, compressed)
        run('native-proving', 120, ['scarb','prove','--execution-id',str(execution_id)])
        proof = directory/'proof/proof.json'
        if not proof.is_file() or proof.stat().st_size > MAX_FILE:
            raise RuntimeError('missing or oversized proof output')
        shutil.copyfile(proof, out/'native-proof.json')
        report['proof'] = dict(bytes=proof.stat().st_size, sha256=digest(proof))
        run('native-verification', 30, ['scarb','verify','--execution-id',str(execution_id)])
        report['native_proof_verified'] = True
        report['status'] = 'native_proof_verified_application_binding_outstanding'
        return 0
    except Exception as error:
        report['status'] = 'bounded_probe_failed'
        report['error'] = str(error)
        print(str(error), flush=True)
        return 1
    finally:
        (out/'native-proof-report.json').write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report, indent=2), flush=True)


if __name__ == '__main__':
    raise SystemExit(main())
