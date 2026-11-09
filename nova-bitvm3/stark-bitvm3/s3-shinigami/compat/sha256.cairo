// Standalone SHA-256 compatibility shim. No Starknet syscalls or unchecked hints.
// Output words and all message bytes use the SHA-256 big-endian convention.
const SHA256_K: [u32; 64] = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
];
fn sha_add(x: u32, y: u32) -> u32 {
    let sum: u64 = x.into() + y.into();
    (sum % 0x100000000).try_into().unwrap()
}
fn sha_rotr(x: u32, divisor: u64) -> u32 {
    let wide: u64 = x.into();
    (wide / divisor + (wide % divisor) * (0x100000000 / divisor)).try_into().unwrap()
}
pub fn compute_sha256_byte_array(message: @ByteArray) -> [u32; 8] {
    assert(message.len() <= 1048576, 'sha256 input budget');
    let length: u64 = message.len().into();
    let mut padded: ByteArray = "";
    for i in 0..message.len() { padded.append_byte(message[i]); };
    padded.append_byte(0x80);
    while padded.len() % 64 != 56 { padded.append_byte(0); };
    padded.append_word((length * 8).into(), 8);
    let mut state: [u32; 8] = [
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
    ];
    for block in 0..padded.len()/64 {
        let mut words: Array<u32> = array![];
        for i in 0..16 {
            let base = block*64+i*4;
            let b0: u32 = padded[base].into();
            let b1: u32 = padded[base+1].into();
            let b2: u32 = padded[base+2].into();
            let b3: u32 = padded[base+3].into();
            words.append(b0*0x1000000+b1*0x10000+b2*0x100+b3);
        };
        for i in 16..64 {
            let x = *words.at(i-15);
            let y = *words.at(i-2);
            let s0 = sha_rotr(x,128) ^ sha_rotr(x,262144) ^ (x/8);
            let s1 = sha_rotr(y,131072) ^ sha_rotr(y,524288) ^ (y/1024);
            words.append(sha_add(sha_add(*words.at(i-16),s0),sha_add(*words.at(i-7),s1)));
        };
        let [a0,b0,c0,d0,e0,f0,g0,h0] = state;
        let mut a=a0; let mut b=b0; let mut c=c0; let mut d=d0;
        let mut e=e0; let mut f=f0; let mut g=g0; let mut h=h0;
        for i in 0..64 {
            let s1=sha_rotr(e,64)^sha_rotr(e,2048)^sha_rotr(e,33554432);
            let ch=(e&f)^((0xffffffff^e)&g);
            let t1=sha_add(sha_add(sha_add(h,s1),ch),sha_add(*SHA256_K.span().at(i),*words.at(i)));
            let s0=sha_rotr(a,4)^sha_rotr(a,8192)^sha_rotr(a,4194304);
            let maj=(a&b)^(a&c)^(b&c);
            let t2=sha_add(s0,maj);
            h=g; g=f; f=e; e=sha_add(d,t1);
            d=c; c=b; b=a; a=sha_add(t1,t2);
        };
        state=[sha_add(a0,a),sha_add(b0,b),sha_add(c0,c),sha_add(d0,d),
               sha_add(e0,e),sha_add(f0,f),sha_add(g0,g),sha_add(h0,h)];
    };
    state
}
