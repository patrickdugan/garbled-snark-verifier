//! Native checker for Taproot (BIP 341) and Tapscript (BIP 342) signature rules, and the
//! compile-time Taproot pieces: annex, control block, script-path commitment, OP_SUCCESS.
//!
//! Mirrors `src/script/interpreter.cpp`: SignatureHashSchnorr, CheckSchnorrSignature,
//! EvalChecksigTapscript (validation-weight budget, empty-signature and unknown-pubkey-type
//! rules), VerifyTaprootCommitment, ComputeTapleafHash/ComputeTaprootMerkleRoot, IsOpSuccess.
//! Error strings are Core's ScriptError names.

use crate::sigcheck::{flags as f, SResult, SigVersion, Tx};
use secp256k1::{schnorr, Message, Parity, Scalar, Secp256k1, VerifyOnly, XOnlyPublicKey};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

fn ctx() -> &'static Secp256k1<VerifyOnly> {
    static C: OnceLock<Secp256k1<VerifyOnly>> = OnceLock::new();
    C.get_or_init(Secp256k1::verification_only)
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

pub fn tagged(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let t = sha256(tag);
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    h.update(msg);
    h.finalize().into()
}

fn compact(n: usize, out: &mut Vec<u8>) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend((n as u16).to_le_bytes());
        }
        0x10000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend((n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend((n as u64).to_le_bytes());
        }
    }
}

/// Everything a Taproot spend's signature checks need beyond the transaction.
#[derive(Clone, Debug)]
pub struct TapInfo {
    pub annex: Option<Vec<u8>>,
    /// Script path: the tapleaf hash of the executed script.
    pub tapleaf: Option<[u8; 32]>,
    /// Script path: GetSerializeSize(witness stack) + 50.
    pub budget: i64,
}

pub const VALIDATION_WEIGHT_PER_SIGOP_PASSED: i64 = 50;
pub const VALIDATION_WEIGHT_OFFSET: i64 = 50;
pub const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;
pub const TAPROOT_CONTROL_BASE_SIZE: usize = 33;
pub const TAPROOT_CONTROL_NODE_SIZE: usize = 32;
pub const TAPROOT_CONTROL_MAX_NODE_COUNT: usize = 128;

/// SignatureHashSchnorr. `ext` is `Some((tapleaf, codeseparator position))` for Tapscript.
/// None for an undefined hash type or SIGHASH_SINGLE without a matching output.
pub fn sighash(
    tx: &Tx,
    spent: &[(i64, Vec<u8>)],
    n_in: usize,
    hash_type: u8,
    annex: Option<&[u8]>,
    ext: Option<([u8; 32], u32)>,
) -> Option<[u8; 32]> {
    if !(hash_type <= 0x03 || (0x81..=0x83).contains(&hash_type)) {
        return None;
    }
    let output_type = if hash_type == 0 { 1 } else { hash_type & 3 };
    let acp = hash_type & 0x80 != 0;
    let mut m = vec![0x00, hash_type];
    m.extend(tx.version.to_le_bytes());
    m.extend(tx.locktime.to_le_bytes());
    if !acp {
        let (mut p, mut a, mut s, mut q) = (vec![], vec![], vec![], vec![]);
        for (i, x) in tx.inputs.iter().enumerate() {
            p.extend(x.prev_txid);
            p.extend(x.prev_vout.to_le_bytes());
            a.extend(spent[i].0.to_le_bytes());
            compact(spent[i].1.len(), &mut s);
            s.extend(&spent[i].1);
            q.extend(x.sequence.to_le_bytes());
        }
        for d in [p, a, s, q] {
            m.extend(sha256(&d));
        }
    }
    let out_bytes = |o: &crate::sigcheck::TxOut| {
        let mut v = o.value.to_le_bytes().to_vec();
        compact(o.script_pubkey.len(), &mut v);
        v.extend(&o.script_pubkey);
        v
    };
    if output_type == 1 {
        let o: Vec<u8> = tx.outputs.iter().flat_map(out_bytes).collect();
        m.extend(sha256(&o));
    }
    m.push(2 * ext.is_some() as u8 + annex.is_some() as u8);
    if acp {
        let x = &tx.inputs[n_in];
        m.extend(x.prev_txid);
        m.extend(x.prev_vout.to_le_bytes());
        m.extend(spent[n_in].0.to_le_bytes());
        compact(spent[n_in].1.len(), &mut m);
        m.extend(&spent[n_in].1);
        m.extend(x.sequence.to_le_bytes());
    } else {
        m.extend((n_in as u32).to_le_bytes());
    }
    if let Some(an) = annex {
        let mut v = vec![];
        compact(an.len(), &mut v);
        v.extend(an);
        m.extend(sha256(&v));
    }
    if output_type == 3 {
        let o = tx.outputs.get(n_in)?;
        m.extend(sha256(&out_bytes(o)));
    }
    if let Some((leaf, pos)) = ext {
        m.extend(leaf);
        m.push(0x00); // key_version
        m.extend(pos.to_le_bytes());
    }
    Some(tagged(b"TapSighash", &m))
}

/// The hash type a BIP-340 signature of 64 or 65 bytes signs with.
pub fn sig_hash_type(sig: &[u8]) -> SResult<u8> {
    match sig.len() {
        64 => Ok(0),
        65 if sig[64] == 0 => Err("SCHNORR_SIG_HASHTYPE"),
        65 => Ok(sig[64]),
        _ => Err("SCHNORR_SIG_SIZE"),
    }
}

/// CheckSchnorrSignature: encoding, hash type, BIP-340 verification.
pub fn check_schnorr(sig: &[u8], key: &[u8; 32], msg: impl FnOnce(u8) -> Option<[u8; 32]>) -> SResult<()> {
    let ht = sig_hash_type(sig)?;
    let h = msg(ht).ok_or("SCHNORR_SIG_HASHTYPE")?;
    let pk = XOnlyPublicKey::from_slice(key).map_err(|_| "SCHNORR_SIG")?;
    let s = schnorr::Signature::from_slice(&sig[..64]).map_err(|_| "SCHNORR_SIG")?;
    ctx().verify_schnorr(&s, &Message::from_digest(h), &pk).map_err(|_| "SCHNORR_SIG")
}

/// One signature check of a Taproot spend. Key path (`SigVersion::Taproot`): the signature must
/// be valid for the output key. Tapscript: EvalChecksigTapscript. `budget` is the remaining
/// validation weight. `csp` is the machine's codeseparator register: 0 for none, else the
/// opcode position plus one. Returns the pushed success bit.
#[allow(clippy::too_many_arguments)]
pub fn checksig(
    sig: &[u8],
    key: &[u8],
    sv: SigVersion,
    csp: u64,
    info: &TapInfo,
    budget: &std::cell::Cell<i64>,
    fl: u32,
    tx: &Tx,
    spent: &[(i64, Vec<u8>)],
    n_in: usize,
) -> SResult<bool> {
    let annex = info.annex.as_deref();
    match sv {
        SigVersion::Taproot => {
            let k: &[u8; 32] = key.try_into().map_err(|_| "SCHNORR_SIG")?;
            check_schnorr(sig, k, |ht| sighash(tx, spent, n_in, ht, annex, None))?;
            Ok(true)
        }
        SigVersion::Tapscript => {
            let success = !sig.is_empty();
            if success {
                budget.set(budget.get() - VALIDATION_WEIGHT_PER_SIGOP_PASSED);
                if budget.get() < 0 {
                    return Err("TAPSCRIPT_VALIDATION_WEIGHT");
                }
            }
            if key.is_empty() {
                return Err("PUBKEYTYPE");
            } else if key.len() == 32 {
                if success {
                    let leaf = info.tapleaf.expect("tapscript has a tapleaf");
                    let pos = if csp == 0 { u32::MAX } else { (csp - 1) as u32 };
                    check_schnorr(sig, key.try_into().unwrap(), |ht| sighash(tx, spent, n_in, ht, annex, Some((leaf, pos))))?;
                }
            } else if fl & f::DISCOURAGE_UPGRADABLE_PUBKEYTYPE != 0 {
                return Err("DISCOURAGE_UPGRADABLE_PUBKEYTYPE");
            }
            Ok(success)
        }
        _ => unreachable!("legacy signatures go through sigcheck"),
    }
}

/// ComputeTapleafHash.
pub fn tapleaf_hash(leaf_version: u8, script: &[u8]) -> [u8; 32] {
    let mut m = vec![leaf_version];
    compact(script.len(), &mut m);
    m.extend(script);
    tagged(b"TapLeaf", &m)
}

/// VerifyTaprootCommitment: control block path to the merkle root, then
/// `Q == P + H_TapTweak(P || root)·G` with Q's parity in the control byte.
pub fn verify_commitment(control: &[u8], program: &[u8], tapleaf: &[u8; 32]) -> bool {
    let Ok(p) = XOnlyPublicKey::from_slice(&control[1..33]) else { return false };
    let Ok(q) = XOnlyPublicKey::from_slice(program) else { return false };
    let mut k = *tapleaf;
    for node in control[33..].chunks(32) {
        let (a, b) = if k[..] < node[..] { (&k[..], node) } else { (node, &k[..]) };
        k = tagged(b"TapBranch", &[a, b].concat());
    }
    let t = tagged(b"TapTweak", &[&control[1..33], &k[..]].concat());
    let Ok(tweak) = Scalar::from_be_bytes(t) else { return false };
    let parity = if control[0] & 1 == 1 { Parity::Odd } else { Parity::Even };
    p.tweak_add_check(ctx(), &q, parity, tweak)
}

/// IsOpSuccess.
pub fn is_op_success(op: u8) -> bool {
    op == 80 || op == 98 || (126..=129).contains(&op) || (131..=134).contains(&op) || (137..=138).contains(&op) || (141..=142).contains(&op) || (149..=153).contains(&op) || (187..=254).contains(&op)
}

/// GetSerializeSize of a witness stack.
pub fn witness_size(stack: &[Vec<u8>]) -> i64 {
    let mut v = vec![];
    compact(stack.len(), &mut v);
    let mut n = v.len();
    for e in stack {
        let mut c = vec![];
        compact(e.len(), &mut c);
        n += c.len() + e.len();
    }
    n as i64
}
