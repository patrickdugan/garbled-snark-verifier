#!/usr/bin/env python3
"""Pin sources and record the standalone SHA-256 compatibility patch."""
from pathlib import Path
import difflib
import hashlib
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
    vendor = ROOT/'vendor/shinigami'
    patches = []
    def patch(path, transform):
        original = subprocess.check_output(['git','-C',str(vendor),'show','HEAD:'+path], text=True)
        current = (vendor/path).read_text()
        modified = transform(original)
        if current not in (original, modified):
            raise SystemExit('unexpected local source change: '+path)
        (vendor/path).write_text(modified)
        patches.extend(difflib.unified_diff(original.splitlines(True),modified.splitlines(True),
                       fromfile='pinned/'+path,tofile='standalone/'+path))
    def manifest(original):
        for name, repo in [('ripemd160','ripemd160_cairo'),('sha1','sha1_cairo')]:
            old = f'{name} = {{ git = "https://github.com/j1mbo64/{repo}.git" }}'
            if original.count(old) != 1:
                raise SystemExit('Unexpected dependency declaration: '+name)
            original = original.replace(old, f'{name} = {{ path = "../{name}" }}')
        return original
    patch('Scarb.toml',manifest)
    shim=(ROOT/'compat/sha256.cairo').read_text()
    anchor='use core::sha256::compute_sha256_byte_array;'
    def replace(original, replacement):
        if original.count(anchor)!=1:
            raise SystemExit('Unexpected SHA-256 import layout')
        return original.replace(anchor,replacement)
    patch('packages/utils/src/hash.cairo',lambda s:replace(s,shim))
    for path in ['packages/engine/src/hash_cache.cairo','packages/engine/src/hash_tag.cairo']:
        patch(path,lambda s:replace(s,'use shinigami_utils::hash::compute_sha256_byte_array;'))
    patch_text=''.join(patches)
    (out/'standalone-compat.patch').write_text(patch_text)
    (out/'source-pins.json').write_text(json.dumps({
        'sources':PINS,'sha256_shim_sha256':hashlib.sha256(shim.encode()).hexdigest(),
        'compat_patch_sha256':hashlib.sha256(patch_text.encode()).hexdigest(),
        'engine_logic_changed':False,'hash_imports_changed':True,
    },indent=2)+'\n')
    vectors=[b'',b'abc']+[bytes((i*17+3)%256 for i in range(n))
                          for n in (1,31,32,55,56,63,64,65,127,128)]
    tests=['use shinigami_utils::hash::{compute_sha256_byte_array, double_sha256};']
    for index,data in enumerate(vectors):
        literal='"'+''.join(f'\\x{x:02x}' for x in data)+'"'
        digest=hashlib.sha256(data).digest()
        words=','.join(hex(int.from_bytes(digest[i:i+4],'big')) for i in range(0,32,4))
        double=int.from_bytes(hashlib.sha256(digest).digest(),'big')
        tests += ['#[test]',f'fn sha256_oracle_{index}() {{',f'    let data={literal};',
                  f'    assert(compute_sha256_byte_array(@data)==[{words}], \'sha256 mismatch\');',
                  f'    assert(double_sha256(@data)=={hex(double)}, \'double sha256 mismatch\');','}']
    (ROOT/'src/hash_tests.cairo').write_text('\n'.join(tests)+'\n')
    print('Pinned sources; recorded local SHA-256 import patch; generated 12 independent hash tests.')


if __name__=='__main__':
    main()
