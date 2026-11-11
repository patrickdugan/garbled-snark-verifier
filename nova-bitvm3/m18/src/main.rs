use m18_utxo_window::cost::*;
use m18_utxo_window::elem::{f_to_le, fu, F};
use m18_utxo_window::native::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::Instant;

fn die(m: &str) -> ! {
  eprintln!("{m}");
  std::process::exit(1)
}

fn hex_rev(h: &[u8]) -> String {
  let mut v = h.to_vec();
  v.reverse();
  hex::encode(v)
}

fn unhex_rev(s: &str) -> [u8; 32] {
  let mut v = hex::decode(s).unwrap();
  v.reverse();
  v.try_into().unwrap()
}

const HEIGHTS: std::ops::RangeInclusive<u64> = 975_067..=975_072;

/// fixtures <data-dir> <out.json>: heights, hashes, raw sizes and SHA-256 of each raw file.
fn fixtures(dir: &str, out: &str) {
  let heights = std::fs::read_to_string(format!("{dir}/heights.txt")).unwrap();
  let hash_of = |h: u64| -> String {
    heights.lines().find_map(|l| l.strip_prefix(&format!("{h} "))).unwrap().trim().to_string()
  };
  let mut blocks = vec![];
  for h in HEIGHTS {
    let raw = std::fs::read(format!("{dir}/{h}.raw")).unwrap();
    let hdr: [u8; 80] = raw[..80].try_into().unwrap();
    assert_eq!(hex_rev(&sha256d(&hdr)), hash_of(h), "header hash of {h}");
    blocks.push(json!({
      "height": h, "hash": hash_of(h), "prev_hash": hex_rev(&hdr[4..36]),
      "raw_bytes": raw.len(), "raw_sha256": hex::encode(Sha256::digest(&raw)),
    }));
  }
  let doc = json!({
    "source": "mempool.space /api/block-height/{h} and /api/block/{hash}/raw, mainnet",
    "note": "raw blocks are not committed; headers match the six headers of the M16 payment input",
    "previous_block": {"height": 975_066, "hash": hash_of(975_066)},
    "blocks": blocks,
  });
  std::fs::write(out, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
}

struct Pay1 {
  txid: [u8; 32],
  vout: u32,
  value: u64,
  script_len: u32,
  script_sha: [u8; 32],
}

fn read_pay1(path: &str) -> Pay1 {
  let b = std::fs::read(path).unwrap();
  let p = b.windows(4).position(|w| w == b"PAY1").expect("PAY1 record");
  Pay1 {
    txid: b[p + 48..p + 80].try_into().unwrap(),
    vout: u32::from_le_bytes(b[p + 80..p + 84].try_into().unwrap()),
    value: u64::from_le_bytes(b[p + 84..p + 92].try_into().unwrap()),
    script_len: u32::from_le_bytes(b[p + 92..p + 96].try_into().unwrap()),
    script_sha: b[p + 96..p + 128].try_into().unwrap(),
  }
}

/// run <data-dir> <blocks.json> <m16-public.bin> <out.json>
fn run(dir: &str, fix: &str, m16: &str, out: &str) {
  let fx: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(fix).unwrap()).unwrap();
  let prev = unhex_rev(fx["previous_block"]["hash"].as_str().unwrap());
  let t0 = Instant::now();
  let mut w = Window::new(prev, true);
  let mut stats = vec![];
  let mut raws = vec![];
  for b in fx["blocks"].as_array().unwrap() {
    let h = b["height"].as_u64().unwrap();
    let raw = std::fs::read(format!("{dir}/{h}.raw")).unwrap();
    if hex::encode(Sha256::digest(&raw)) != b["raw_sha256"].as_str().unwrap() {
      die(&format!("raw file of {h} does not match the fixture"));
    }
    let st = w.process_block(h, &raw).unwrap_or_else(|e| die(&e));
    if st.hash != b["hash"].as_str().unwrap() {
      die(&format!("block {h} hash differs from the fixture"));
    }
    eprintln!("{h}: {} txs, {} creates, {} in-window spends, {:.1} s", st.transactions, st.creates, st.spends_in_window, st.seconds);
    stats.push(st);
    raws.push(raw);
  }
  let wall = t0.elapsed().as_secs_f64();
  let root = w.map.root();

  // The M16 payment output and every window output paying the same script.
  let pay = read_pay1(m16);
  let mut script: Option<Vec<u8>> = None;
  for raw in &raws {
    for tx in &parse_block(raw).unwrap().txs {
      for o in &tx.outputs {
        if o.script.len() == pay.script_len as usize && Sha256::digest(&o.script)[..] == pay.script_sha {
          script.get_or_insert(o.script.clone());
        }
      }
    }
  }
  let script = script.unwrap_or_else(|| die("no window output has the PAY1 script"));
  let m16_proof = w.map.membership(&pay.txid, pay.vout);
  let m16_status = match &m16_proof {
    None => json!({"in_map": false}),
    Some(p) => json!({
      "in_map": true, "spent": p.leaf.spent, "leaf_index": p.path.index,
      "membership_proof_verifies": verify_membership(&root, &outpoint_key(&pay.txid, pay.vout), p),
      "value_sats": p.leaf.value, "matches_pay1_value": p.leaf.value == pay.value,
    }),
  };
  let bal = w.map.balance_of_script(&script);
  let bal_sum = verify_balance(&root, &bal, Some(&script)).unwrap_or_else(|e| die(&format!("balance proof: {e:?}")));
  assert_eq!(bal_sum, bal.unspent_sum);
  let entries: Vec<_> = bal
    .entries
    .iter()
    .map(|e| {
      json!({
        "txid": display_hex(&e.txid), "vout": e.vout, "value_sats": e.proof.leaf.value,
        "spent": e.proof.leaf.spent, "leaf_index": e.proof.path.index,
      })
    })
    .collect();
  let sum = |f: fn(&BlockStats) -> u64| stats.iter().map(f).sum::<u64>();
  let doc = json!({
    "window": {"first": 975_067, "last": 975_072, "previous_hash": display_hex(&prev)},
    "blocks": stats,
    "totals": {
      "transactions": sum(|s| s.transactions), "nonwitness_bytes": sum(|s| s.nonwitness_bytes),
      "sha256_blocks_txs": sum(|s| s.sha256_blocks_txs),
      "sha256_blocks_txid_final": sum(|s| s.sha256_blocks_txid_final),
      "inputs": sum(|s| s.inputs), "outputs": sum(|s| s.outputs), "creates": sum(|s| s.creates),
      "spends_in_window": sum(|s| s.spends_in_window), "spends_before_window": sum(|s| s.spends_before_window),
      "merkle_merges": sum(|s| s.merkle_merges), "sha256_blocks_merkle": sum(|s| s.sha256_blocks_merkle),
      "sha256_blocks_header": sum(|s| s.sha256_blocks_header),
      "absorb_steps_c1": sum(|s| s.absorb_steps_c1), "absorb_steps_c4": sum(|s| s.absorb_steps_c4),
      "absorb_steps_c8": sum(|s| s.absorb_steps_c8),
    },
    "final_map": {
      "root_le_hex": hex::encode(f_to_le(&root)), "leaves": w.map.len(), "depth": D,
      "last_block_hash": display_hex(&w.prev_hash),
    },
    "wall_seconds_all_blocks_with_proof_checks": wall,
    "m16_output": {
      "txid_display": display_hex(&pay.txid), "vout": pay.vout, "pay1_value_sats": pay.value, "status": m16_status,
    },
    "same_script": {
      "script_hex": hex::encode(&script), "script_sha256": hex::encode(pay.script_sha),
      "entries": entries, "count": bal.entries.len(),
      "unspent_count": bal.entries.iter().filter(|e| !e.proof.leaf.spent).count(),
      "balance_at_975072_sats": bal_sum, "balance_proof_verifies": true,
    },
  });
  std::fs::write(out, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
  println!("{}", serde_json::to_string_pretty(&doc["totals"]).unwrap());
  println!("m16 output: {}", doc["m16_output"]);
  println!("script: {}", doc["same_script"]);
  println!("wall {wall:.1} s, root {}", doc["final_map"]["root_le_hex"]);
}

/// cost <out.json>: constraint counts.
fn cost(out: &str) {
  let sha = sha256_compression_constraints();
  let p2 = poseidon_constraints(2);
  let p3 = poseidon_constraints(3);
  let p6 = poseidon_constraints(6);
  // One map op at depth 32, on a native map with a few hundred leaves, witness checked.
  let mut m = UtxoMap::new();
  let mk = |n: u32| {
    let mut t = [0u8; 32];
    t[..4].copy_from_slice(&n.to_le_bytes());
    t[31] = (n % 251) as u8;
    t
  };
  for i in 0..300 {
    m.create(&mk(i), i % 4, 1000 + i as u64, &[i as u8]).unwrap();
  }
  let cp = m.create(&mk(1000), 0, 4242, &[7, 7]).unwrap();
  let cw = CreateWit::from_proof(&cp, &mk(1000), 0);
  let rb = cp.root_before;
  let ra = cp.root_after;
  let (create_n, create_ok, got) = count(|cs| {
    let mut g = G::new(cs);
    let r = g.alloc(rb);
    create_gadget(&mut g, &cw, &r).get_value().unwrap()
  });
  assert!(create_ok, "create gadget unsatisfied");
  assert_eq!(got, ra, "create gadget root differs from native");
  let sp = m.spend_in_window(&mk(5), 1).unwrap();
  let sw = SpendWit::from_proof(&sp, &mk(5), 1);
  let (rb2, ra2) = (sp.root_before, sp.root_after);
  let (spend_n, spend_ok, got2) = count(|cs| {
    let mut g = G::new(cs);
    let r = g.alloc(rb2);
    spend_gadget(&mut g, &sw, &r).get_value().unwrap()
  });
  assert!(spend_ok, "spend gadget unsatisfied");
  assert_eq!(got2, ra2);
  let (key, np) = m.spend_before_window(&mk(2000), 3).unwrap();
  let _ = key;
  let nw = SpendWit {
    txid_lo: m18_utxo_window::elem::f_from_le(&mk(2000)[..16]),
    txid_hi: m18_utxo_window::elem::f_from_le(&mk(2000)[16..]),
    vout: 3,
    leaf: LeafW::from(&np.leaf),
    idx: np.path.index,
    sibs: np.path.siblings.clone(),
  };
  let rn = m.root();
  let (non_n, non_ok, _) = count(|cs| {
    let mut g = G::new(cs);
    let r = g.alloc(rn);
    nonmember_gadget(&mut g, &nw, &r);
  });
  assert!(non_ok, "non-membership gadget unsatisfied");
  // A false claim must not satisfy: the key's predecessor proof against a present key.
  let present = mk(10);
  let pp = m.membership(&present, 10 % 4).unwrap();
  let bad = SpendWit {
    txid_lo: m18_utxo_window::elem::f_from_le(&present[..16]),
    txid_hi: m18_utxo_window::elem::f_from_le(&present[16..]),
    vout: (10 % 4) as u64,
    leaf: LeafW::from(&pp.leaf),
    idx: pp.path.index,
    sibs: pp.path.siblings.clone(),
  };
  let (_, bad_ok, _) = count(|cs| {
    let mut g = G::new(cs);
    let r = g.alloc(rn);
    nonmember_gadget(&mut g, &bad, &r);
  });
  assert!(!bad_ok, "a before-window claim for a present key satisfied the circuit");
  let step: Vec<_> = [0usize, 1, 4, 8].iter().map(|&c| (c, bench_step_constraints(c))).collect();
  let doc = json!({
    "sha256_compression": sha,
    "poseidon_2_inputs": p2, "poseidon_3_inputs": p3, "poseidon_6_inputs": p6,
    "depth": D,
    "map_create": create_n, "map_spend_in_window": spend_n, "map_nonmember_before_window": non_n,
    "create_gadget_satisfied_and_root_matches_native": true,
    "false_before_window_claim_unsatisfiable": true,
    "bench_step_constraints_by_c": step.iter().map(|(c, n)| json!({"c": c, "constraints": n})).collect::<Vec<_>>(),
  });
  std::fs::write(out, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
  println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}

type E1 = nova_snark::provider::PallasEngine;
type E2 = nova_snark::provider::VestaEngine;
type Pp = nova_snark::nova::PublicParams<E1, E2, BenchStep>;
type Rs = nova_snark::nova::RecursiveSNARK<E1, E2, BenchStep>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, nova_snark::provider::ipa_pc::EvaluationEngine<E1>>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, nova_snark::provider::ipa_pc::EvaluationEngine<E2>>;

/// fold <steps> <out.json>: time Nova folding of c compressions + one create.
fn fold(steps: usize, cs: &[usize], out: &str) {
  use nova_snark::traits::snark::RelaxedR1CSSNARKTrait;
  let mut rows = vec![];
  for &c in cs {
    let mut m = UtxoMap::new();
    let mk = |n: u32| {
      let mut t = [0u8; 32];
      t[..4].copy_from_slice(&n.to_le_bytes());
      t[31] = 0x5a;
      t
    };
    for i in 0..100 {
      m.create(&mk(i), 0, 500, &[i as u8]).unwrap();
    }
    let z0root = m.root();
    let mut seed = 0x9e3779b97f4a7c15u64;
    let mut next = || {
      seed ^= seed << 13;
      seed ^= seed >> 7;
      seed ^= seed << 17;
      seed
    };
    let witnesses: Vec<BenchStep> = (0..steps)
      .map(|i| {
        let id = mk(10_000 + i as u32);
        let p = m.create(&id, (i % 3) as u32, 1000 + i as u64, &[1, 2, 3, i as u8]).unwrap();
        let mut blocks = vec![[0u8; 64]; c];
        for b in blocks.iter_mut() {
          for byte in b.iter_mut() {
            *byte = next() as u8;
          }
        }
        BenchStep { blocks, op: CreateWit::from_proof(&p, &id, (i % 3) as u32) }
      })
      .collect();
    let n_cons = bench_step_constraints(c);
    let (iv_lo, iv_hi) = sha_iv_halves();
    let z0 = vec![z0root, iv_lo, iv_hi];
    let t = Instant::now();
    let pp = Pp::setup(&BenchStep::blank(c), &*S1::ck_floor(), &*S2::ck_floor()).unwrap();
    let setup = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let mut rs = Rs::new(&pp, &witnesses[0], &z0).unwrap();
    let mut times = vec![];
    for w in &witnesses {
      let ts = Instant::now();
      rs.prove_step(&pp, w).unwrap_or_else(|e| die(&format!("prove_step: {e:?}")));
      times.push(ts.elapsed().as_secs_f64());
    }
    let total = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let zn = rs.verify(&pp, steps, &z0).unwrap_or_else(|e| die(&format!("verify: {e:?}")));
    let verify = t.elapsed().as_secs_f64();
    assert_eq!(zn[0], m.root(), "folded root differs from the native root");
    let steady: Vec<f64> = times[1..].to_vec();
    let per_step = steady.iter().sum::<f64>() / steady.len() as f64;
    let row = json!({
      "c": c, "steps": steps, "step_constraints": n_cons, "setup_seconds": setup,
      "total_prove_seconds": total, "first_step_seconds": times[0],
      "seconds_per_step_steady": per_step,
      "seconds_per_million_constraints": per_step / (n_cons as f64 / 1e6),
      "verify_seconds": verify, "final_root_matches_native": true, "step_seconds": times,
    });
    println!("{row}");
    rows.push(row);
    let _ = fu(0);
  }
  std::fs::write(out, serde_json::to_string_pretty(&json!({"rows": rows})).unwrap() + "\n").unwrap();
}

fn main() {
  let a: Vec<String> = std::env::args().collect();
  match a.get(1).map(|s| s.as_str()) {
    Some("fixtures") => fixtures(&a[2], &a[3]),
    Some("run") => run(&a[2], &a[3], &a[4], &a[5]),
    Some("cost") => cost(&a[2]),
    Some("fold") => {
      let cs: Vec<usize> = a[3].split(',').map(|x| x.parse().unwrap()).collect();
      fold(a[2].parse().unwrap(), &cs, &a[4])
    }
    _ => die("usage: m18 fixtures|run|cost|fold ..."),
  }
  let _: Option<F> = None;
}
