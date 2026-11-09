#!/usr/bin/env python3
"""Independent arithmetic/hash vectors. These are NOT STARK proof fixtures."""
import argparse
import hashlib
from pathlib import Path
import random
import struct

P = (1 << 31) - 1
ROOT = Path(__file__).resolve().parent


def cm(a, b):
    return ((a[0]*b[0]-a[1]*b[1]) % P, (a[0]*b[1]+a[1]*b[0]) % P)


def qm(a, b):
    # Direct extension product, independent of the circuit's Karatsuba schedule.
    ac, bd = cm(a[:2], b[:2]), cm(a[2:], b[2:])
    ad, bc = cm(a[:2], b[2:]), cm(a[2:], b[:2])
    r = cm((2, 1), bd)
    return ((ac[0]+r[0]) % P, (ac[1]+r[1]) % P,
            (ad[0]+bc[0]) % P, (ad[1]+bc[1]) % P)


def inverse(a):
    out = (1, 0, 0, 0)
    n = P**4-2
    while n:
        if n & 1:
            out = qm(out, a)
        a = qm(a, a)
        n >>= 1
    return out


def h(data):
    return hashlib.blake2s(data).digest()


def u32s(xs):
    return b''.join(struct.pack('<I', x) for x in xs)


def text(data):
    return data.hex() or '-'


def make_vectors():
    rng = random.Random(430119)
    lines = ['# S0 component vectors; not complete STARK proofs.']
    for n in [0, 1, 4, 32, 37, 40, 52, 63, 64, 65, 96, 128, 129, 256]:
        data = bytes(rng.randrange(256) for _ in range(n))
        lines.append(f'blake {text(data)} {h(data).hex()}')
    # Literal upstream vector: core/vcs/blake2_hash.rs::single_hash_test.
    assert h(b'a').hex() == '4a0d129873403037c2cd9b9048203687f6233fb6738956e0349bd4320fec3e90'
    lines.append(f'blake 61 {h(b"a").hex()}')
    edge = [0, 1, 2, P-1, P-2, P//2, 1<<30]
    pairs = [(a,b) for a in edge for b in edge]
    pairs += [(rng.randrange(P), rng.randrange(P)) for _ in range(96)]
    for a,b in pairs:
        lines.append(f'field {a} {b} {(a+b)%P} {(a-b)%P} {(a*b)%P}')
    qs = [(0,0,0,0), (1,0,0,0), (0,1,0,0), (0,0,1,0), (P-1,)*4]
    qs += [tuple(rng.randrange(P) for _ in range(4)) for _ in range(24)]
    for a in qs:
        b = tuple(rng.randrange(P) for _ in range(4))
        lines.append('qm ' + ' '.join(map(str, (*a,*b,*qm(a,b)))))
    for a in qs[:5] + qs[5:9]:
        inv = inverse(a) if any(a) else (0,0,0,0)
        lines.append('inverse ' + ' '.join(map(str, (*a,*inv,int(any(a))))))
    # Literal upstream channel KATs, not values copied from our gate implementation.
    upstream = [(u32s([0x33334444,0x11112222]), 'bc9e3fc1d24e8897956d3359327397249d6bcacd224d927404e7ba4a77dc6ece'),
                (u32s(range(1,10)), '7091768357bb1bb3346fdab6b357d7fa46b8fbe32c2e4324a0ffc294cbf9a1c7')]
    for data, expected in upstream:
        digest = h(bytes(32)+data)
        assert digest.hex() == expected
        draws = [h(digest+struct.pack('<I', i)+b'\0') for i in range(3)]
        w = struct.unpack('<8I', draws[2])
        challenge = [(w[2*i]+2*w[2*i+1])%P for i in range(4)]
        lines.append('channel ' + ' '.join([data.hex(),digest.hex(),draws[0].hex(),draws[1].hex(),*map(str,challenge)]))
    rows = [u32s([i+1, (i+5)**2]) for i in range(8)]
    levels = [[h(row) for row in rows]]
    while len(levels[-1]) > 1:
        layer = levels[-1]
        levels.append([h(layer[i]+layer[i+1]) for i in range(0,len(layer),2)])
    for index in (0,3,7):
        siblings = [levels[d][(index>>d)^1].hex() for d in range(3)]
        lines.append('merkle ' + ' '.join(['3',str(index),rows[index].hex(),','.join(siblings),levels[-1][0].hex()]))
    digest = h(b'component PoW vector')
    nbits = 8
    prefix = h(struct.pack('<I',0x12345678)+bytes(12)+digest+struct.pack('<I',nbits))
    nonce = 0
    while h(prefix+struct.pack('<Q',nonce))[0] != 0:
        nonce += 1
    assert h(prefix+struct.pack('<Q',nonce+1))[0] != 0
    lines.append(f'pow {digest.hex()} {nbits} {nonce}')
    return '\n'.join(lines)+'\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    path = ROOT/'core/tests/vectors.txt'
    data = make_vectors()
    expected = (ROOT/'vectors.sha256').read_text().strip()
    if hashlib.sha256(data.encode()).hexdigest() != expected:
        raise SystemExit('reference vector digest differs; review generator changes')
    if args.check:
        if path.read_text() != data:
            raise SystemExit('component vectors differ; review changes before regenerating')
    else:
        path.write_text(data)
    print(f'{len(data.splitlines())-1} independently generated component vectors; upstream hash/channel KATs match')

if __name__ == '__main__':
    main()
