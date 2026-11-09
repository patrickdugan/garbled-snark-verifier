#!/usr/bin/env python3
"""Wire pinned local sources together without changing Shinigami engine code."""
from pathlib import Path
import difflib
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PINS = {
    'shinigami': '7e8c05d60b4bd7ae91ddc18a42e8e13090286f0c',
    'ripemd160': 'cdc5ab58b0acc64db87e0b03851fb18213977dc8',
    'sha1': '280b4c64ae457fdc4bd7cd807efd17e8dced654e',
}


def main():
    out = ROOT/'out'
    out.mkdir(exist_ok=True)
    for name, expected in PINS.items():
        actual = subprocess.check_output(
            ['git','-C',str(ROOT/'vendor'/name),'rev-parse','HEAD'], text=True).strip()
        if actual != expected:
            raise SystemExit(f'{name}: expected {expected}, got {actual}')
    path = ROOT/'vendor/shinigami/Scarb.toml'
    original = path.read_text()
    modified = original
    for name, repo in [('ripemd160','ripemd160_cairo'),('sha1','sha1_cairo')]:
        old = f'{name} = {{ git = "https://github.com/j1mbo64/{repo}.git" }}'
        if modified.count(old) != 1:
            raise SystemExit(f'Unexpected dependency declaration for {name}')
        modified = modified.replace(old, f'{name} = {{ path = "../{name}" }}')
    path.write_text(modified)
    (out/'dependency-paths.patch').write_text(''.join(difflib.unified_diff(
        original.splitlines(True), modified.splitlines(True),
        fromfile='pinned-shinigami/Scarb.toml', tofile='local-paths/Scarb.toml')))
    (out/'source-pins.json').write_text(json.dumps(PINS,indent=2)+'\n')
    print('Verified all source pins; replaced two dependency URLs with pinned local paths.')


if __name__=='__main__':
    main()
