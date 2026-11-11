//! Boolean acceptance of a large trusted program without materializing its whole value table.
//!
//! Constraints are split into shards. Each shard becomes a small program over only the variables it
//! touches, together with those variables' pins, so memory stays bounded and shards run in parallel.
//! A variable that no constraint touches is still range-checked in a shard of its own, so the
//! conjunction of all shards accepts exactly when the monolithic program does. Index 0..2 (zero, one
//! and the `u` constant) keep their positions and are re-pinned by every shard.
use crate::direct;
use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use stwo_bitvm3_lowering::{Constraint as C, Limits, Program, Value};

fn vars(c: &C) -> Vec<usize> {
    match c {
        C::Add { a, b, out } | C::Sub { a, b, out } | C::Mul { a, b, out } | C::PointwiseMul { a, b, out } => {
            vec![*a, *b, *out]
        }
        C::Eq { a, b } => vec![*a, *b],
        C::TripleXor { inputs, out } => inputs.iter().copied().chain([*out]).collect(),
        C::M31ToU32 { input, out } => vec![*input, *out],
        C::BlakeG { inputs, outputs } => inputs.iter().chain(outputs).copied().collect(),
        C::Permutation { inputs, outputs } => inputs.iter().chain(outputs).copied().collect(),
        C::Output { input } => vec![*input],
    }
}

fn remap(c: &C, f: &impl Fn(usize) -> usize) -> C {
    match c {
        C::Add { a, b, out } => C::Add { a: f(*a), b: f(*b), out: f(*out) },
        C::Sub { a, b, out } => C::Sub { a: f(*a), b: f(*b), out: f(*out) },
        C::Mul { a, b, out } => C::Mul { a: f(*a), b: f(*b), out: f(*out) },
        C::PointwiseMul { a, b, out } => C::PointwiseMul { a: f(*a), b: f(*b), out: f(*out) },
        C::Eq { a, b } => C::Eq { a: f(*a), b: f(*b) },
        C::TripleXor { inputs, out } => C::TripleXor { inputs: inputs.map(f), out: f(*out) },
        C::M31ToU32 { input, out } => C::M31ToU32 { input: f(*input), out: f(*out) },
        C::BlakeG { inputs, outputs } => C::BlakeG { inputs: inputs.map(f), outputs: outputs.map(f) },
        C::Permutation { inputs, outputs } => C::Permutation {
            inputs: inputs.iter().map(|v| f(*v)).collect(),
            outputs: outputs.iter().map(|v| f(*v)).collect(),
        },
        C::Output { input } => C::Output { input: f(*input) },
    }
}

fn limits() -> Limits {
    Limits { max_vars: 1 << 22, max_constraints: 1 << 22, max_permutation: 1 << 22, max_permutation_work: usize::MAX / 4 }
}

/// Lowers one shard: the given constraints, or, with none, a group of otherwise unreferenced variables.
fn run_shard(program: &Program, values: &[Value], constraints: &[C], extra_vars: &[usize]) -> Result<(bool, u64)> {
    let mut order: BTreeSet<usize> = extra_vars.iter().copied().filter(|v| *v >= 3).collect();
    for c in constraints {
        order.extend(vars(c).into_iter().filter(|v| *v >= 3));
    }
    let map: BTreeMap<usize, usize> = order.iter().enumerate().map(|(i, g)| (*g, 3 + i)).collect();
    let f = |v: usize| if v < 3 { v } else { map[&v] };
    let local: Vec<C> = constraints.iter().map(|c| remap(c, &f)).collect();
    let bindings: Vec<(usize, Value)> =
        order.iter().filter_map(|g| program.bindings().get(g).map(|val| (map[g], *val))).collect();
    let sub = Program::new(3 + order.len(), local, bindings, limits())?;
    let mut local_values: Vec<Value> = vec![values[0], values[1], values[2]];
    local_values.extend(order.iter().map(|g| values[*g]));
    let (ok, ands, _xors) = direct::run(&sub, &local_values)?;
    Ok((ok, ands))
}

/// Returns (accepted, number of shards, summed non-free ANDs including per-shard decode duplication).
pub fn run(program: &Program, values: &[Value], shard_size: usize, threads: usize) -> Result<(bool, usize, u64)> {
    anyhow::ensure!(values.len() == program.n_vars(), "witness length {} != {}", values.len(), program.n_vars());
    let constraints = program.constraints();
    let mut used = BTreeSet::new();
    for c in constraints {
        used.extend(vars(c));
    }
    let unused: Vec<usize> = (3..program.n_vars()).filter(|v| !used.contains(v)).collect();
    // (start, end, is_var_group)
    let mut jobs: Vec<(usize, usize, bool)> = Vec::new();
    for start in (0..constraints.len()).step_by(shard_size) {
        jobs.push((start, (start + shard_size).min(constraints.len()), false));
    }
    for start in (0..unused.len()).step_by(shard_size * 4) {
        jobs.push((start, (start + shard_size * 4).min(unused.len()), true));
    }
    let next = AtomicUsize::new(0);
    let results = std::sync::Mutex::new((true, 0u64, 0usize));
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    if i >= jobs.len() {
                        break;
                    }
                    let (s, e, is_vars) = jobs[i];
                    let out = if is_vars {
                        run_shard(program, values, &[], &unused[s..e])
                    } else {
                        run_shard(program, values, &constraints[s..e], &[])
                    };
                    let mut guard = results.lock().unwrap();
                    match out {
                        Ok((ok, ands)) => {
                            guard.0 &= ok;
                            guard.1 += ands;
                        }
                        Err(_) => guard.0 = false,
                    }
                    guard.2 += 1;
                }
            });
        }
    });
    let (ok, ands, shards) = results.into_inner().unwrap();
    Ok((ok, shards, ands))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo_bitvm3_core::P;
    use stwo_bitvm3_lowering::fixture::all_gate_fixture;

    #[test]
    fn sharding_never_changes_the_verdict() {
        let (program, values) = all_gate_fixture();
        let (whole, _, _) = direct::run(&program, &values).unwrap();
        assert!(whole, "the all-gate fixture must be accepted");
        for size in [1, 2, 3, 1000] {
            let (ok, shards, _) = run(&program, &values, size, 3).unwrap();
            assert!(ok, "shard size {size} rejected an accepted witness");
            assert!(shards >= 1);
        }
        let mut rejected = 0;
        for i in 0..values.len() {
            for limb in 0..4 {
                for replacement in [(values[i][limb] + 1) % P, P, u32::MAX] {
                    let mut bad = values.clone();
                    bad[i][limb] = replacement;
                    let (whole, _, _) = direct::run(&program, &bad).unwrap();
                    for size in [1, 4] {
                        let (sharded, _, _) = run(&program, &bad, size, 2).unwrap();
                        assert_eq!(whole, sharded, "var {i} limb {limb} value {replacement} shard size {size}");
                    }
                    rejected += usize::from(!whole);
                }
            }
        }
        assert!(rejected > 0, "no mutation was rejected, so the comparison has no teeth");
    }
}
