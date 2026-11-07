//! `Blake3KoalaBear`: SP1 6.9.0's proof configuration (`IopCtx`) with every
//! hash replaced by BLAKE3.
//!
//! The field (KoalaBear), its degree-4 extension, the AIRs, the jagged PCS,
//! BaseFold and the zerocheck/LogUp-GKR protocols are SP1's unchanged. Only
//! the three places a hash appears change:
//!
//! - Merkle leaves: [`LeafHasher`] (each field element as 4 little-endian
//!   bytes, the row hashed with BLAKE3);
//! - Merkle nodes: BLAKE3 of the 64-byte concatenation of the two children;
//! - Fiat-Shamir: `SerializingChallenger32<Blake3Transcript>` (Plonky3 `HashChallenger` semantics),
//!   which hashes everything observed since the last squeeze together with the
//!   previous output, and samples field elements by rejection from 31-bit
//!   words (KoalaBear has p = 2^31 - 2^24 + 1).
//!
//! The digest is `Hash<KoalaBear, u8, 32>`, 32 bytes.
//!
//! Each role has its own counter of BLAKE3 compression-function calls, so a
//! verifier run reports exactly how many compressions a garbled verifier of
//! the same proof has to evaluate.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use slop_challenger::{CanObserve, CanSample, IopCtx, SerializingChallenger32};
use slop_algebra::PrimeField32;
use slop_symmetric::{CryptographicHasher, Hash, PseudoCompressionFunction};
use sp1_primitives::{SP1ExtensionField, SP1Field};

/// Domain separation for the transcript: the challenger starts from these bytes.
pub const TRANSCRIPT_DOMAIN: &[u8] = b"garbled-snark-verifier/nova-bitvm3/m13/blake3-koalabear/v1";

pub const ROLE_LEAF: usize = 0;
pub const ROLE_NODE: usize = 1;
pub const ROLE_TRANSCRIPT: usize = 2;
pub const ROLE_NAMES: [&str; 3] = ["merkle_leaf", "merkle_node", "transcript"];

/// Per role: hash calls, compression-function calls, bytes hashed.
pub static CALLS: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
pub static COMPRESSIONS: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
pub static BYTES: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];

/// Number of BLAKE3 compression-function calls for one hash of `len` bytes:
/// 1024-byte chunks of 64-byte blocks (at least one block per chunk), plus
/// one parent compression per internal node of the chunk tree.
pub fn blake3_compressions(len: usize) -> u64 {
    if len == 0 {
        return 1;
    }
    let chunks = len.div_ceil(1024);
    let mut blocks = 0u64;
    for c in 0..chunks {
        let l = (len - c * 1024).min(1024);
        blocks += l.div_ceil(64).max(1) as u64;
    }
    blocks + (chunks as u64 - 1)
}

pub fn reset_counters() {
    for r in 0..3 {
        CALLS[r].store(0, Ordering::SeqCst);
        COMPRESSIONS[r].store(0, Ordering::SeqCst);
        BYTES[r].store(0, Ordering::SeqCst);
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashCounts {
    pub calls: u64,
    pub compressions: u64,
    pub bytes: u64,
}

pub fn read_counters() -> [HashCounts; 3] {
    std::array::from_fn(|r| HashCounts {
        calls: CALLS[r].load(Ordering::SeqCst),
        compressions: COMPRESSIONS[r].load(Ordering::SeqCst),
        bytes: BYTES[r].load(Ordering::SeqCst),
    })
}

/// BLAKE3 over bytes, counted under role `ROLE`.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Blake3<const ROLE: usize>;

impl<const ROLE: usize> CryptographicHasher<u8, [u8; 32]> for Blake3<ROLE> {
    fn hash_iter<I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = u8>,
    {
        let bytes: Vec<u8> = input.into_iter().collect();
        CALLS[ROLE].fetch_add(1, Ordering::Relaxed);
        COMPRESSIONS[ROLE].fetch_add(blake3_compressions(bytes.len()), Ordering::Relaxed);
        BYTES[ROLE].fetch_add(bytes.len() as u64, Ordering::Relaxed);
        *blake3::hash(&bytes).as_bytes()
    }
}

pub type Digest = Hash<SP1Field, u8, 32>;

/// Merkle leaf hash: each KoalaBear element as its canonical 4-byte
/// little-endian encoding, the row hashed with BLAKE3. Implemented for both
/// digest spellings the SP1 Merkle prover asks for (`[u8; 32]` and `Digest`).
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeafHasher;

impl CryptographicHasher<SP1Field, [u8; 32]> for LeafHasher {
    fn hash_iter<I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = SP1Field>,
    {
        Blake3::<ROLE_LEAF>.hash_iter(input.into_iter().flat_map(|x| x.as_canonical_u32().to_le_bytes()))
    }
}

impl CryptographicHasher<SP1Field, Digest> for LeafHasher {
    fn hash_iter<I>(&self, input: I) -> Digest
    where
        I: IntoIterator<Item = SP1Field>,
    {
        let out: [u8; 32] = CryptographicHasher::<SP1Field, [u8; 32]>::hash_iter(self, input);
        out.into()
    }
}

/// Merkle node hash: BLAKE3 of left || right (64 bytes, one compression).
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeCompressor;

impl PseudoCompressionFunction<[u8; 32], 2> for NodeCompressor {
    fn compress(&self, input: [[u8; 32]; 2]) -> [u8; 32] {
        Blake3::<ROLE_NODE>.hash_iter(input[0].into_iter().chain(input[1]))
    }
}

impl PseudoCompressionFunction<Digest, 2> for NodeCompressor {
    fn compress(&self, input: [Digest; 2]) -> Digest {
        let [l, r] = input;
        let l: [u8; 32] = l.into();
        let r: [u8; 32] = r.into();
        PseudoCompressionFunction::<[u8; 32], 2>::compress(self, [l, r]).into()
    }
}

/// Byte transcript with the semantics of Plonky3's `HashChallenger<u8, H, 32>`
/// (observing clears pending output; a squeeze hashes everything observed
/// since the last squeeze, keeps the 32-byte output as the start of the next
/// input, and hands output bytes out last-first), with serde so proofs that
/// carry the configuration type serialize.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Blake3Transcript {
    input_buffer: Vec<u8>,
    output_buffer: Vec<u8>,
}

impl Blake3Transcript {
    pub fn new(initial_state: Vec<u8>) -> Self {
        Self { input_buffer: initial_state, output_buffer: Vec::new() }
    }

    fn flush(&mut self) {
        let inputs: Vec<u8> = self.input_buffer.drain(..).collect();
        let output = Blake3::<ROLE_TRANSCRIPT>.hash_iter(inputs);
        self.output_buffer = output.to_vec();
        self.input_buffer.extend(output);
    }
}

impl CanObserve<u8> for Blake3Transcript {
    fn observe(&mut self, value: u8) {
        self.output_buffer.clear();
        self.input_buffer.push(value);
    }
}

impl CanSample<u8> for Blake3Transcript {
    fn sample(&mut self) -> u8 {
        if self.output_buffer.is_empty() {
            self.flush();
        }
        self.output_buffer.pop().expect("output buffer is non-empty after a flush")
    }
}

pub type Blake3Challenger = SerializingChallenger32<SP1Field, Blake3Transcript>;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Blake3KoalaBear;

impl IopCtx for Blake3KoalaBear {
    type F = SP1Field;
    type EF = SP1ExtensionField;
    type Digest = Digest;
    type Challenger = Blake3Challenger;
    type Hasher = LeafHasher;
    type Compressor = NodeCompressor;

    fn default_hasher_and_compressor() -> (Self::Hasher, Self::Compressor) {
        (LeafHasher, NodeCompressor)
    }

    fn default_challenger() -> Self::Challenger {
        SerializingChallenger32::new(Blake3Transcript::new(TRANSCRIPT_DOMAIN.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compression_count_matches_blake3_structure() {
        assert_eq!(blake3_compressions(0), 1);
        assert_eq!(blake3_compressions(64), 1);
        assert_eq!(blake3_compressions(65), 2);
        assert_eq!(blake3_compressions(1024), 16);
        assert_eq!(blake3_compressions(1025), 18); // 16 + 1 blocks, 1 parent
        assert_eq!(blake3_compressions(4096), 4 * 16 + 3);
    }
}
