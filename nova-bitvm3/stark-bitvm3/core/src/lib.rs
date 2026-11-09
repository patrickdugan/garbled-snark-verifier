//! S0: Boolean primitives for a pinned Stwo standard-Blake2s verifier.
//! This crate does not expose verify_stark: an authenticated Merkle opening is
//! only one check in a STARK verifier. All shapes are public circuit parameters.
//! External field encodings MUST go through `decode_m31` / `decode_qm31` and the
//! returned validity wires MUST reach the final acceptance wire.

pub const P: u32 = 0x7fff_ffff;
pub type Bits<W> = Vec<W>;
pub type Qm<W> = [Bits<W>; 4];

/// Implemented by the repository adapter and the dependency-free test backend.
/// No method branches on a private input's value.
pub trait Gates {
    type W: Copy + Eq;
    fn constant(&mut self, bit: bool) -> Self::W;
    fn xor(&mut self, a: Self::W, b: Self::W) -> Self::W;
    fn and(&mut self, a: Self::W, b: Self::W) -> Self::W;
}

pub fn constant<B: Gates>(b: &mut B, x: u64, n: usize) -> Bits<B::W> {
    assert!(n <= 64);
    (0..n).map(|i| b.constant((x >> i) & 1 != 0)).collect()
}
pub fn bytes<B: Gates>(b: &mut B, data: &[u8]) -> Bits<B::W> {
    data.iter().flat_map(|&x| constant(b, x as u64, 8)).collect()
}
fn not<B: Gates>(b: &mut B, a: B::W) -> B::W {
    let one = b.constant(true);
    b.xor(a, one)
}
fn all<B: Gates>(b: &mut B, values: impl IntoIterator<Item = B::W>) -> B::W {
    values.into_iter().fold(b.constant(true), |a, v| b.and(a, v))
}
pub fn equal<B: Gates>(b: &mut B, a: &[B::W], c: &[B::W]) -> B::W {
    assert_eq!(a.len(), c.len());
    let mut ok = b.constant(true);
    for (&x, &y) in a.iter().zip(c) {
        let d = b.xor(x, y);
        let same = not(b, d);
        ok = b.and(ok, same);
    }
    ok
}
fn select<B: Gates>(b: &mut B, sel: B::W, a: B::W, c: B::W) -> B::W {
    let d = b.xor(a, c);
    let d = b.and(sel, d);
    b.xor(a, d)
}
fn xor_words<B: Gates>(b: &mut B, a: &[B::W], c: &[B::W]) -> Bits<B::W> {
    assert_eq!(a.len(), c.len());
    a.iter().zip(c).map(|(&x, &y)| b.xor(x, y)).collect()
}
fn add_carry<B: Gates>(b: &mut B, a: &[B::W], c: &[B::W], mut carry: B::W, n: usize) -> (Bits<B::W>, B::W) {
    let zero = b.constant(false);
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(zero);
        let y = c.get(i).copied().unwrap_or(zero);
        let xc = b.xor(x, carry);
        let yc = b.xor(y, carry);
        out.push(b.xor(x, yc));
        let t = b.and(xc, yc);
        carry = b.xor(carry, t);
    }
    (out, carry)
}
fn add<B: Gates>(b: &mut B, a: &[B::W], c: &[B::W], n: usize) -> Bits<B::W> {
    let zero = b.constant(false);
    add_carry(b, a, c, zero, n).0
}
fn sub_p<B: Gates>(b: &mut B, a: &[B::W]) -> Bits<B::W> {
    assert_eq!(a.len(), 32);
    let inv_p = constant(b, (!P) as u64, 32);
    let one = b.constant(true);
    let (diff, ge) = add_carry(b, a, &inv_p, one, 32);
    a.iter().zip(diff).map(|(&x, y)| select(b, ge, x, y)).collect()
}

/// Exact for every unsigned 32-bit value, including 0xffffffff.
pub fn reduce_u32<B: Gates>(b: &mut B, a: &[B::W]) -> Bits<B::W> {
    assert_eq!(a.len(), 32);
    let folded = add(b, &a[..31], &a[31..], 32);
    sub_p(b, &folded)[..31].to_vec()
}
/// Rejects P, 2^31 and all noncanonical aliases; never silently reduces input.
pub fn decode_m31<B: Gates>(b: &mut B, raw: &[B::W]) -> (Bits<B::W>, B::W) {
    assert_eq!(raw.len(), 32);
    let all_one = all(b, raw[..31].iter().copied());
    let below_p = not(b, all_one);
    let high_zero = not(b, raw[31]);
    (raw[..31].to_vec(), b.and(below_p, high_zero))
}
pub fn m31_add<B: Gates>(b: &mut B, a: &[B::W], c: &[B::W]) -> Bits<B::W> {
    assert_eq!((a.len(), c.len()), (31, 31));
    let sum = add(b, a, c, 32);
    let sum = sub_p(b, &sum);
    sub_p(b, &sum)[..31].to_vec()
}
pub fn m31_sub<B: Gates>(b: &mut B, a: &[B::W], c: &[B::W]) -> Bits<B::W> {
    assert_eq!((a.len(), c.len()), (31, 31));
    // P-c is the one's complement within 31 bits. m31_add canonicalizes P.
    let neg: Vec<_> = c.iter().map(|&x| not(b, x)).collect();
    m31_add(b, a, &neg)
}
pub fn m31_mul<B: Gates>(b: &mut B, a: &[B::W], c: &[B::W]) -> Bits<B::W> {
    assert_eq!((a.len(), c.len()), (31, 31));
    let zero = b.constant(false);
    let mut prod = vec![zero; 62];
    for (i, &ci) in c.iter().enumerate() {
        let mut row = vec![zero; i];
        row.extend(a.iter().map(|&ai| b.and(ai, ci)));
        // Low i bits are unaffected; keep the adder bounded to the live suffix.
        let suffix = add(b, &prod[i..], &row[i..], 62 - i);
        prod[i..].copy_from_slice(&suffix);
    }
    m31_add(b, &prod[..31], &prod[31..])
}
pub fn decode_qm31<B: Gates>(b: &mut B, raw: &[B::W]) -> (Qm<B::W>, B::W) {
    assert_eq!(raw.len(), 128);
    let mut ok = b.constant(true);
    let a = std::array::from_fn(|i| {
        let (a, valid) = decode_m31(b, &raw[32 * i..32 * (i + 1)]);
        ok = b.and(ok, valid);
        a
    });
    (a, ok)
}
pub fn qm31_add<B: Gates>(b: &mut B, a: &Qm<B::W>, c: &Qm<B::W>) -> Qm<B::W> {
    std::array::from_fn(|i| m31_add(b, &a[i], &c[i]))
}
pub fn qm31_sub<B: Gates>(b: &mut B, a: &Qm<B::W>, c: &Qm<B::W>) -> Qm<B::W> {
    std::array::from_fn(|i| m31_sub(b, &a[i], &c[i]))
}
fn cm_mul<B: Gates>(b: &mut B, a: &[Bits<B::W>], c: &[Bits<B::W>]) -> [Bits<B::W>; 2] {
    let ac = m31_mul(b, &a[0], &c[0]);
    let bd = m31_mul(b, &a[1], &c[1]);
    let ab = m31_add(b, &a[0], &a[1]);
    let cd = m31_add(b, &c[0], &c[1]);
    let cross = m31_mul(b, &ab, &cd);
    let cross = m31_sub(b, &cross, &ac);
    let cross = m31_sub(b, &cross, &bd);
    [m31_sub(b, &ac, &bd), cross]
}
/// Stwo tower: i^2=-1, u^2=2+i; order [a,b,c,d] = (a+bi)+(c+di)u.
pub fn qm31_mul<B: Gates>(b: &mut B, a: &Qm<B::W>, c: &Qm<B::W>) -> Qm<B::W> {
    let ac = cm_mul(b, &a[..2], &c[..2]);
    let bd = cm_mul(b, &a[2..], &c[2..]);
    let ab = [m31_add(b, &a[0], &a[2]), m31_add(b, &a[1], &a[3])];
    let cd = [m31_add(b, &c[0], &c[2]), m31_add(b, &c[1], &c[3])];
    let cross = cm_mul(b, &ab, &cd);
    let r0 = m31_add(b, &bd[0], &bd[0]);
    let r0 = m31_sub(b, &r0, &bd[1]);
    let r1 = m31_add(b, &bd[1], &bd[1]);
    let r1 = m31_add(b, &r1, &bd[0]);
    let hi0 = m31_sub(b, &cross[0], &ac[0]);
    let hi0 = m31_sub(b, &hi0, &bd[0]);
    let hi1 = m31_sub(b, &cross[1], &ac[1]);
    let hi1 = m31_sub(b, &hi1, &bd[1]);
    [m31_add(b, &ac[0], &r0), m31_add(b, &ac[1], &r1), hi0, hi1]
}
/// An inverse witness is sound only when this bit is conjoined into acceptance.
/// Zero denominators fail the product-equals-one check.
pub fn check_qm31_inverse<B: Gates>(b: &mut B, a: &Qm<B::W>, inv: &Qm<B::W>) -> B::W {
    let product = qm31_mul(b, a, inv);
    let mut one = constant(b, 1, 31);
    one.extend((0..93).map(|_| b.constant(false)));
    equal(b, &product.concat(), &one)
}

const IV: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
const SIGMA: [[usize; 16]; 10] = [
    [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
    [14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
    [11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],
    [7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],
    [9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],
    [2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],
    [12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],
    [13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
    [6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],
    [10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0],
];
fn rotr<W: Copy>(a: &[W], n: usize) -> Bits<W> {
    (0..32).map(|i| a[(i + n) % 32]).collect()
}
#[allow(clippy::too_many_arguments)]
fn g<B: Gates>(b: &mut B, v: &mut [Bits<B::W>], a: usize, c: usize, d: usize, e: usize, x: &[B::W], y: &[B::W]) {
    let t = add(b, &v[a], &v[c], 32);
    v[a] = add(b, &t, x, 32);
    v[e] = rotr(&xor_words(b, &v[e], &v[a]), 16);
    v[d] = add(b, &v[d], &v[e], 32);
    v[c] = rotr(&xor_words(b, &v[c], &v[d]), 12);
    let t = add(b, &v[a], &v[c], 32);
    v[a] = add(b, &t, y, 32);
    v[e] = rotr(&xor_words(b, &v[e], &v[a]), 8);
    v[d] = add(b, &v[d], &v[e], 32);
    v[c] = rotr(&xor_words(b, &v[c], &v[d]), 7);
}
/// Standard unkeyed Blake2s-256. Byte and word bits are little-endian.
/// Message length is a public circuit parameter, not a private input.
pub fn blake2s<B: Gates>(b: &mut B, message: &[B::W]) -> Bits<B::W> {
    assert_eq!(message.len() % 8, 0);
    let n = message.len() / 8;
    let mut h: Vec<_> = IV.iter().enumerate().map(|(i, &v)| constant(b, (v ^ if i == 0 {0x01010020} else {0}) as u64, 32)).collect();
    let blocks = n.div_ceil(64).max(1);
    for block in 0..blocks {
        let end = n.min((block + 1) * 64);
        let mut chunk = message[block * 512..end * 8].to_vec();
        chunk.resize(512, b.constant(false));
        let m: Vec<_> = chunk.chunks_exact(32).map(|x| x.to_vec()).collect();
        let mut v = h.clone();
        v.extend(IV.iter().map(|&x| constant(b, x as u64, 32)));
        let t0 = constant(b, end as u64 & 0xffff_ffff, 32);
        let t1 = constant(b, (end as u64) >> 32, 32);
        v[12] = xor_words(b, &v[12], &t0);
        v[13] = xor_words(b, &v[13], &t1);
        if block + 1 == blocks { v[14] = v[14].iter().map(|&x| not(b, x)).collect(); }
        for s in SIGMA {
            for (j, [a,c,d,e]) in [[0,4,8,12],[1,5,9,13],[2,6,10,14],[3,7,11,15],[0,5,10,15],[1,6,11,12],[2,7,8,13],[3,4,9,14]].into_iter().enumerate() {
                g(b, &mut v, a, c, d, e, &m[s[2*j]], &m[s[2*j+1]]);
            }
        }
        for i in 0..8 {
            let t = xor_words(b, &v[i], &v[i+8]);
            h[i] = xor_words(b, &h[i], &t);
        }
    }
    h.concat()
}

pub struct Channel<W> { pub digest: Bits<W>, draws: u32 }
impl<W: Copy + Eq> Channel<W> {
    pub fn new<B: Gates<W=W>>(b: &mut B) -> Self { Self { digest: vec![b.constant(false);256], draws:0 } }
    /// Standard Stwo mix_u32s/mix_felts/mix_hash after exact LE serialization.
    pub fn mix<B: Gates<W=W>>(&mut self, b: &mut B, data: &[W]) {
        assert_eq!(data.len() % 32, 0);
        let mut msg = self.digest.clone();
        msg.extend_from_slice(data);
        self.digest = blake2s(b, &msg);
        self.draws = 0;
    }
    pub fn draw_u32s<B: Gates<W=W>>(&mut self, b: &mut B) -> Bits<W> {
        let mut msg = self.digest.clone();
        msg.extend(constant(b, self.draws as u64, 32));
        msg.extend(constant(b, 0, 8)); // Upstream draw/mix domain separation.
        self.draws = self.draws.checked_add(1).expect("public draw count overflow");
        blake2s(b, &msg)
    }
    pub fn draw_qm31<B: Gates<W=W>>(&mut self, b: &mut B) -> Qm<W> {
        let words = self.draw_u32s(b);
        let base: Vec<_> = words.chunks_exact(32).map(|w| reduce_u32(b,w)).collect();
        std::array::from_fn(|i| {
            let twice = m31_add(b, &base[2*i+1], &base[2*i+1]);
            m31_add(b, &base[2*i], &twice)
        })
    }
    pub fn check_pow<B: Gates<W=W>>(&self, b: &mut B, n_bits: usize, nonce: &[W]) -> W {
        assert!(n_bits <= 128);
        assert_eq!(nonce.len(),64);
        let mut msg = bytes(b, &[0x78,0x56,0x34,0x12,0,0,0,0,0,0,0,0,0,0,0,0]);
        msg.extend_from_slice(&self.digest);
        msg.extend(constant(b,n_bits as u64,32));
        let mut first = blake2s(b,&msg);
        first.extend_from_slice(nonce);
        let hash = blake2s(b,&first);
        let zeros: Vec<_> = hash[..n_bits].iter().map(|&w| not(b,w)).collect();
        all(b,zeros)
    }
}

/// Single, uniform-height path for the STANDARD Blake2s lifted Merkle hasher.
/// This is NOT the mixed-height PCS verifier or a STARK verifier. Bind `root`
/// to the expected statement/transcript; a prover-chosen free root is unsound.
/// All external field words and all high index bits are checked in the circuit.
pub fn merkle_opening<B: Gates>(b: &mut B, row: &[B::W], index: &[B::W], siblings: &[Bits<B::W>], root: &[B::W]) -> B::W {
    assert_eq!(row.len() % 32,0);
    assert_eq!(index.len(),32);
    assert_eq!(root.len(),256);
    assert!(siblings.len() <= 30);
    let mut ok = b.constant(true);
    for word in row.chunks_exact(32) {
        let (_, valid) = decode_m31(b,word);
        ok = b.and(ok,valid);
    }
    for &high in &index[siblings.len()..] {
        let is_zero = not(b,high);
        ok = b.and(ok,is_zero);
    }
    let mut hash = blake2s(b,row);
    for (level, sibling) in siblings.iter().enumerate() {
        assert_eq!(sibling.len(),256);
        let left: Vec<_> = hash.iter().zip(sibling).map(|(&a,&c)| select(b,index[level],a,c)).collect();
        let right: Vec<_> = hash.iter().zip(sibling).map(|(&a,&c)| select(b,index[level],c,a)).collect();
        hash = blake2s(b,&[left,right].concat());
    }
    let matches = equal(b,&hash,root);
    b.and(ok,matches)
}
