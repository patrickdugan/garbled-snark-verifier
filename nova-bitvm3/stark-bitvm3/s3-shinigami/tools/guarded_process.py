"""Run one opt-in prover under observed Linux process-group RSS limits.

RLIMIT_AS is intentionally absent. Memory-mapped address reservations are
not resident pages. Shared mappings may be counted more than once; reserve
headroom for the GitHub runner. This is a sampled guard, not a kernel cgroup.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import time

MAX_FILE_BYTES = 128 * 1024 * 1024
POLL_SECONDS = 0.10
PAGE_SIZE = os.sysconf('SC_PAGE_SIZE')


def group_memory(pgid: int) -> tuple[int, int, int]:
    """Cumulative RSS, virtual bytes, and process count in one process group."""
    rss = vms = count = 0
    for entry in os.scandir('/proc'):
        if not entry.name.isdecimal():
            continue
        try:
            if os.getpgid(int(entry.name)) != pgid:
                continue
            with open(f'/proc/{entry.name}/statm', encoding='ascii') as f:
                virtual_pages, resident_pages, *_ = map(int, f.read().split())
            vms += virtual_pages * PAGE_SIZE
            rss += resident_pages * PAGE_SIZE
            count += 1
        except (ProcessLookupError, FileNotFoundError, PermissionError):
            continue
    return rss, vms, count


def _child_limits() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE_BYTES, MAX_FILE_BYTES))


def _stop_group(pgid: int, proc: subprocess.Popen, grace_seconds: float = 1.5) -> None:
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def guarded_run(command: list[str], *, cwd: Path, log_path: Path,
                timeout_seconds: float, max_rss_bytes: int,
                env: dict[str, str] | None = None) -> dict:
    """One sampled process-tree run, including ordinary spawned children."""
    if not command or not 0 < timeout_seconds <= 600 or max_rss_bytes <= 0:
        raise ValueError('invalid guarded-run budget')
    if os.name != 'posix' or not Path('/proc').is_dir():
        raise RuntimeError('Linux /proc is required for fail-closed RSS accounting')
    log_path.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    peak_rss = peak_vms = peak_processes = samples = 0
    status = 'running'
    with log_path.open('wb') as log:
        proc = subprocess.Popen(command, cwd=cwd, env=env, stdout=log,
                                stderr=subprocess.STDOUT, start_new_session=True,
                                preexec_fn=_child_limits)
        pgid = proc.pid
        while True:
            elapsed = time.monotonic() - start
            try:
                rss, vms, processes = group_memory(pgid)
            except Exception:
                status = 'monitor_error'
                _stop_group(pgid, proc)
                break
            samples += 1
            peak_rss = max(peak_rss, rss)
            peak_vms = max(peak_vms, vms)
            peak_processes = max(peak_processes, processes)
            if rss > max_rss_bytes:
                status = 'rss_budget_exceeded'
                _stop_group(pgid, proc)
                break
            if elapsed >= timeout_seconds:
                status = 'timeout'
                _stop_group(pgid, proc)
                break
            exit_code = proc.poll()
            if exit_code is not None:
                if processes == 0 or elapsed >= timeout_seconds:
                    status = ('success' if exit_code == 0 and processes == 0
                              else 'child_lingered' if exit_code == 0 else 'command_failed')
                    if processes:
                        _stop_group(pgid, proc)
                    break
            time.sleep(POLL_SECONDS)
        if proc.poll() is None:
            _stop_group(pgid, proc)
        returncode = proc.wait()
    return dict(status=status, argv=command, returncode=returncode,
                elapsed_seconds=round(time.monotonic() - start, 3),
                peak_rss_bytes=peak_rss, peak_vms_bytes=peak_vms,
                peak_processes=peak_processes, samples=samples,
                rss_limit_bytes=max_rss_bytes, timeout_seconds=timeout_seconds,
                address_space_rlimit_applied=False,
                kernel_enforced_memory_limit=False)


def write_report(path: Path, report: dict) -> None:
    """Publish status atomically, including failures."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    temp.replace(path)
