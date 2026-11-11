//! S6: the final verifier as a function of its typed inputs, lowered in pieces.
//!
//! `Function` (lowering crate) orders the gates so that each one runs after everything it reads. A plan cuts
//! the gates into pieces. Unlike the relation pieces of S4, these are not independent: a piece reads values
//! that earlier pieces computed, so each piece names what it reads from outside (typed inputs and carried
//! variables) and what it must hand on. Pieces form a dependency graph and run as soon as the pieces they
//! read from are done.
//!
//! Cutting the evaluation order into consecutive chunks makes that graph a chain: every chunk continues
//! something the previous one started. The plan instead cuts by dependency depth. Gates are put in layers
//! by how long the longest chain of gates below them is; inside a layer, gates that feed each other form a
//! component, and components of one layer cannot depend on each other. A piece is a set of whole
//! components of one layer, or a run of one component too large for a piece. So a verifier that checks
//! many queries has many pieces per layer that run side by side.
//!
//! This module holds the plan, the scheduler and the direct (plain Boolean) executor. The garbling
//! executor in `gfunc.rs` runs the same plan on the half-gates engine.
use crate::direct::{Direct, Wire};
use anyhow::{Result, bail, ensure};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use stwo_bitvm3_core::{Gates, Qm};
use stwo_bitvm3_lowering::{Constraint as C, Env, Function, Kind, Value};

/// Wire identities of typed input bits: the same in every piece, so aliases of an input stay aliases.
pub const INPUT_ID_BASE: u64 = 1 << 62;
/// Wire identities issued inside a piece start here; pieces never share one.
pub fn first_id(piece: usize) -> u64 {
    ((piece as u64) + 1) << 36
}

/// Rough non-free AND cost of a gate, only used to cut pieces of similar size.
fn estimate(gate: &C) -> u64 {
    match gate {
        C::Add { .. } | C::Sub { .. } => 600,
        C::Mul { .. } => 18_000,
        C::PointwiseMul { .. } => 7_800,
        C::Eq { .. } => 124,
        C::TripleXor { .. } | C::M31ToU32 { .. } => 100,
        C::BlakeG { .. } => 400,
        C::Permutation { inputs, .. } => {
            let w = inputs.len().max(2).next_power_of_two() as u64;
            let log = w.trailing_zeros() as u64;
            w / 2 * log * (log + 1) / 2 * 372 * 2
        }
        C::Output { .. } => 0,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Origin {
    Unused,
    Constant,
    Input(u32),
    /// Defined by the step with this index.
    Step(u32),
}

pub struct PieceSpec {
    /// Indices into `Function::steps`, ascending.
    pub steps: Vec<u32>,
    /// Typed inputs (indices into `Function::inputs`) this piece reads.
    pub inputs: Vec<u32>,
    /// The subset of `inputs` whose canonical check happens in this piece (the lowest piece reading them).
    pub checks: Vec<u32>,
    /// Variables defined by other pieces that this piece reads.
    pub carried: Vec<usize>,
    /// Variables defined here that other pieces read.
    pub writes: Vec<usize>,
    /// The pieces that define `carried`; all have lower indices.
    pub deps: Vec<usize>,
    /// Estimated non-free ANDs of the piece.
    pub cost: u64,
}

pub struct Plan<'a> {
    pub f: &'a Function,
    pub pieces: Vec<PieceSpec>,
    /// Per variable, how many pieces read it as a carried value.
    pub readers: Vec<u32>,
    /// Number of depth layers the gates were put in.
    pub layers: usize,
}

pub struct PlanStats {
    pub pieces: usize,
    pub layers: usize,
    pub carried_variables: usize,
    /// Largest number of carried variables alive at once when pieces run in index order.
    pub max_live: usize,
    /// Length of the longest dependency chain of pieces.
    pub depth: usize,
    /// Estimated work of all pieces and of the heaviest dependency chain; their ratio bounds the speed-up
    /// more threads can give.
    pub total_cost: u64,
    pub critical_cost: u64,
    pub inputs_read: usize,
    pub inputs_unread: usize,
}

/// Depth layers a plan aims for; more layers mean smaller components and more stages. For the final
/// verifier (gate depth 2,988) 512 layers with pieces of a million ANDs leave a heaviest chain of about a
/// tenth of the work; finer plans gain little and hand many more wires between pieces.
pub const DEFAULT_LAYERS: usize = 512;

impl<'a> Plan<'a> {
    #[cfg(test)]
    pub fn new(f: &'a Function, and_budget: u64, max_steps: usize) -> Result<Self> {
        Self::layered(f, and_budget, max_steps, DEFAULT_LAYERS)
    }

    /// `and_budget` and `max_steps` bound a piece; `target_layers` sets the layer width.
    pub fn layered(f: &'a Function, and_budget: u64, max_steps: usize, target_layers: usize) -> Result<Self> {
        let (steps, n) = (f.steps(), f.n_vars());
        ensure!(steps.len() < u32::MAX as usize, "too many steps");
        let mut origin = vec![Origin::Unused; n];
        for v in f.constants().keys() {
            origin[*v] = Origin::Constant;
        }
        for (i, (v, _)) in f.inputs().iter().enumerate() {
            origin[*v] = Origin::Input(i as u32);
        }
        // Depth of a step: one more than the deepest step it reads from.
        let mut depth = vec![0u32; steps.len()];
        for (si, step) in steps.iter().enumerate() {
            for v in step.reads() {
                match origin[v] {
                    Origin::Step(t) => depth[si] = depth[si].max(depth[t as usize] + 1),
                    Origin::Unused => bail!("a step reads variable {v}, which has no value"),
                    _ => {}
                }
            }
            for v in step.defines() {
                ensure!(origin[v] == Origin::Unused, "variable {v} is defined twice");
                origin[v] = Origin::Step(si as u32);
            }
        }
        let deepest = depth.iter().copied().max().unwrap_or(0) as usize;
        let width = (deepest + 1).div_ceil(target_layers.max(1)).max(1) as u32;
        let layer = |si: usize| depth[si] / width;
        let layers = deepest / width as usize + 1;

        // Components: steps of one layer joined when one reads what the other defines.
        let mut parent: Vec<u32> = (0..steps.len() as u32).collect();
        fn find(parent: &mut [u32], mut x: u32) -> u32 {
            while parent[x as usize] != x {
                parent[x as usize] = parent[parent[x as usize] as usize];
                x = parent[x as usize];
            }
            x
        }
        for (si, step) in steps.iter().enumerate() {
            for v in step.reads() {
                if let Origin::Step(t) = origin[v] {
                    if layer(t as usize) == layer(si) {
                        let (a, b) = (find(&mut parent, si as u32), find(&mut parent, t));
                        // The smaller index becomes the root, so a component is named by its first step.
                        if a != b {
                            parent[a.max(b) as usize] = a.min(b);
                        }
                    }
                }
            }
        }
        let mut order: Vec<(u32, u32, u32)> =
            (0..steps.len()).map(|si| (layer(si), find(&mut parent, si as u32), si as u32)).collect();
        order.sort_unstable();

        // Pieces: whole components of a layer packed up to the budget; a component over the budget is cut
        // into consecutive runs. Piece indices grow with the layer and along a cut component.
        let mut groups: Vec<Vec<u32>> = Vec::new();
        let mut bin: Vec<u32> = Vec::new();
        let (mut bin_cost, mut bin_layer) = (0u64, u32::MAX);
        let mut at = 0usize;
        while at < order.len() {
            let (l, root, _) = order[at];
            let mut end = at;
            let mut cost = 0u64;
            while end < order.len() && order[end].0 == l && order[end].1 == root {
                cost += estimate(&steps[order[end].2 as usize].gate);
                end += 1;
            }
            let component: Vec<u32> = order[at..end].iter().map(|x| x.2).collect();
            at = end;
            let fits = bin_layer == l && bin_cost + cost <= and_budget && bin.len() + component.len() <= max_steps;
            if !bin.is_empty() && !fits {
                groups.push(std::mem::take(&mut bin));
                bin_cost = 0;
            }
            if cost > and_budget || component.len() > max_steps {
                let mut run: Vec<u32> = Vec::new();
                let mut run_cost = 0u64;
                for si in component {
                    run.push(si);
                    run_cost += estimate(&steps[si as usize].gate);
                    if run_cost >= and_budget || run.len() >= max_steps {
                        groups.push(std::mem::take(&mut run));
                        run_cost = 0;
                    }
                }
                if !run.is_empty() {
                    groups.push(run);
                }
            } else {
                bin.extend(component);
                bin_cost += cost;
                bin_layer = l;
            }
        }
        if !bin.is_empty() {
            groups.push(bin);
        }

        let mut piece_of = vec![u32::MAX; steps.len()];
        for (p, group) in groups.iter_mut().enumerate() {
            group.sort_unstable();
            for si in group.iter() {
                piece_of[*si as usize] = p as u32;
            }
        }
        let mut first_reader = vec![false; f.inputs().len()];
        let mut pieces: Vec<PieceSpec> = Vec::with_capacity(groups.len());
        for (p, group) in groups.into_iter().enumerate() {
            let (mut inputs, mut carried, mut deps) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
            for si in &group {
                for v in steps[*si as usize].reads() {
                    match origin[v] {
                        Origin::Input(i) => {
                            inputs.insert(i);
                        }
                        Origin::Step(t) if piece_of[t as usize] as usize != p => {
                            let q = piece_of[t as usize] as usize;
                            ensure!(q < p, "piece {p} reads from the later piece {q}");
                            carried.insert(v);
                            deps.insert(q);
                        }
                        Origin::Step(t) => ensure!(t < *si, "a step reads a value its own piece defines later"),
                        _ => {}
                    }
                }
            }
            let mut checks = Vec::new();
            for i in &inputs {
                if !std::mem::replace(&mut first_reader[*i as usize], true) {
                    checks.push(*i);
                }
            }
            pieces.push(PieceSpec {
                cost: group.iter().map(|si| estimate(&steps[*si as usize].gate)).sum(),
                steps: group,
                inputs: inputs.into_iter().collect(),
                checks,
                carried: carried.into_iter().collect(),
                writes: Vec::new(),
                deps: deps.into_iter().collect(),
            });
        }
        let mut readers = vec![0u32; n];
        let mut writes: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); pieces.len()];
        for piece in &pieces {
            for v in &piece.carried {
                readers[*v] += 1;
                if let Origin::Step(t) = origin[*v] {
                    writes[piece_of[t as usize] as usize].insert(*v);
                }
            }
        }
        for (piece, w) in pieces.iter_mut().zip(writes) {
            piece.writes = w.into_iter().collect();
        }
        Ok(Self { f, pieces, readers, layers })
    }

    pub fn stats(&self) -> PlanStats {
        let mut left = self.readers.clone();
        let (mut live, mut max_live) = (0usize, 0usize);
        let mut level = vec![0usize; self.pieces.len()];
        let mut heaviest = vec![0u64; self.pieces.len()];
        let mut read = vec![false; self.f.inputs().len()];
        for (p, piece) in self.pieces.iter().enumerate() {
            level[p] = 1 + piece.deps.iter().map(|d| level[*d]).max().unwrap_or(0);
            heaviest[p] = piece.cost + piece.deps.iter().map(|d| heaviest[*d]).max().unwrap_or(0);
            live += piece.writes.len();
            max_live = max_live.max(live);
            for v in &piece.carried {
                left[*v] -= 1;
                if left[*v] == 0 {
                    live -= 1;
                }
            }
            for i in &piece.inputs {
                read[*i as usize] = true;
            }
        }
        let inputs_read = read.iter().filter(|r| **r).count();
        PlanStats {
            pieces: self.pieces.len(),
            layers: self.layers,
            carried_variables: self.pieces.iter().map(|p| p.writes.len()).sum(),
            max_live,
            depth: level.into_iter().max().unwrap_or(0),
            total_cost: self.pieces.iter().map(|p| p.cost).sum(),
            critical_cost: heaviest.into_iter().max().unwrap_or(0),
            inputs_read,
            inputs_unread: read.len() - inputs_read,
        }
    }
}

/// Variables of one piece: what it was handed and what it defines; constants are made on demand.
pub struct PieceEnv<'f, W> {
    pub map: HashMap<usize, Qm<W>>,
    constants: &'f BTreeMap<usize, Value>,
    zero: W,
    one: W,
}
impl<W: Copy> Env<W> for PieceEnv<'_, W> {
    fn get(&self, var: usize) -> Qm<W> {
        if let Some(q) = self.map.get(&var) {
            return q.clone();
        }
        let value = self.constants.get(&var).expect("the plan hands a piece every variable it reads");
        std::array::from_fn(|i| (0..31).map(|j| if (value[i] >> j) & 1 != 0 { self.one } else { self.zero }).collect())
    }
    fn set(&mut self, var: usize, value: Qm<W>) {
        self.map.insert(var, value);
    }
}

/// Lowers one piece on any backend. `raw_input(i)` gives the wires of typed input `i` and `carried(var)`
/// the wires of a variable an earlier piece defined. Returns the piece's check wire and its variables.
pub fn lower_piece<'f, B: Gates>(
    b: &mut B, f: &'f Function, spec: &PieceSpec, raw_input: impl Fn(u32) -> Vec<B::W>, carried: impl Fn(usize) -> Qm<B::W>,
) -> (B::W, PieceEnv<'f, B::W>) {
    let mut env = PieceEnv { map: HashMap::new(), constants: f.constants(), zero: b.constant(false), one: b.constant(true) };
    let mut ok = b.constant(true);
    for i in &spec.inputs {
        let (var, kind): (usize, Kind) = f.inputs()[*i as usize];
        let raw = raw_input(*i);
        if spec.checks.binary_search(i).is_ok() {
            let (value, valid) = Function::input(b, kind, &raw);
            ok = b.and(ok, valid);
            env.map.insert(var, value);
        } else {
            env.map.insert(var, Function::place(b, kind, &raw));
        }
    }
    for var in &spec.carried {
        env.map.insert(*var, carried(*var));
    }
    for si in &spec.steps {
        let valid = Function::apply(b, &f.steps()[*si as usize], &mut env);
        ok = b.and(ok, valid);
    }
    (ok, env)
}

/// Values handed from piece to piece, dropped when their last reader is done.
pub struct Store<T> {
    slots: Mutex<HashMap<usize, Arc<T>>>,
    left: Vec<AtomicU32>,
}
impl<T> Store<T> {
    pub fn new(plan: &Plan) -> Self {
        Self { slots: Mutex::new(HashMap::new()), left: plan.readers.iter().map(|r| AtomicU32::new(*r)).collect() }
    }
    pub fn put(&self, var: usize, value: T) {
        self.slots.lock().unwrap().insert(var, Arc::new(value));
    }
    pub fn get(&self, var: usize) -> Arc<T> {
        self.slots.lock().unwrap().get(&var).expect("dependencies ran first").clone()
    }
    /// One reader of `var` is done.
    pub fn release(&self, var: usize) {
        if self.left[var].fetch_sub(1, Ordering::SeqCst) == 1 {
            self.slots.lock().unwrap().remove(&var);
        }
    }
}

/// Runs `job` for every piece on `threads` threads, a piece only after the pieces it depends on, lowest
/// ready index first. Results come back in piece order. The first error stops the run.
pub fn run_dag<T: Send>(deps: &[Vec<usize>], threads: usize, job: impl Fn(usize) -> Result<T> + Sync) -> Result<Vec<T>> {
    struct State<T> {
        ready: BinaryHeap<Reverse<usize>>,
        missing: Vec<usize>,
        results: Vec<Option<T>>,
        running: usize,
        done: usize,
        error: Option<anyhow::Error>,
    }
    let n = deps.len();
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (p, d) in deps.iter().enumerate() {
        for q in d {
            dependents[*q].push(p);
        }
    }
    let state = Mutex::new(State {
        ready: (0..n).filter(|p| deps[*p].is_empty()).map(Reverse).collect(),
        missing: deps.iter().map(|d| d.len()).collect(),
        results: (0..n).map(|_| None).collect(),
        running: 0,
        done: 0,
        error: None,
    });
    let wake = Condvar::new();
    std::thread::scope(|scope| {
        for _ in 0..threads.max(1) {
            scope.spawn(|| {
                loop {
                    let p = {
                        let mut s = state.lock().unwrap();
                        loop {
                            if s.error.is_some() || s.done == n {
                                return;
                            }
                            if let Some(Reverse(p)) = s.ready.pop() {
                                s.running += 1;
                                break p;
                            }
                            if s.running == 0 {
                                // Nothing ready, nothing running, not done: the graph has a cycle.
                                s.error = Some(anyhow::anyhow!("pieces depend on each other in a cycle"));
                                wake.notify_all();
                                return;
                            }
                            s = wake.wait(s).unwrap();
                        }
                    };
                    let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| job(p)))
                        .unwrap_or_else(|_| Err(anyhow::anyhow!("piece {p} panicked")));
                    let mut s = state.lock().unwrap();
                    s.running -= 1;
                    match out {
                        Ok(value) => {
                            s.results[p] = Some(value);
                            s.done += 1;
                            for q in &dependents[p] {
                                s.missing[*q] -= 1;
                                if s.missing[*q] == 0 {
                                    s.ready.push(Reverse(*q));
                                }
                            }
                        }
                        Err(e) => {
                            if s.error.is_none() {
                                s.error = Some(e.context(format!("piece {p}")));
                            }
                        }
                    }
                    wake.notify_all();
                }
            });
        }
    });
    let state = state.into_inner().unwrap();
    if let Some(e) = state.error {
        return Err(e);
    }
    Ok(state.results.into_iter().map(|r| r.expect("every piece ran")).collect())
}

fn value_of(q: &Qm<Wire>) -> Value {
    std::array::from_fn(|i| q[i].iter().enumerate().fold(0u32, |x, (j, w)| x | (u32::from(w.bit()) << j)))
}

pub struct DirectRun {
    pub accepted: bool,
    pub rejecting_pieces: usize,
    /// Non-free ANDs of all pieces and of the chain that combines their check wires.
    pub ands: u64,
    #[allow(dead_code)]
    pub xors: u64,
    /// Computed variables compared with the reference assignment, and how many differed.
    pub compared: u64,
    pub mismatches: u64,
}

/// Evaluates the function on `input` (its typed input bits). With `reference`, every variable a piece
/// defines is compared with the reference assignment (upstream's own witness).
pub fn run_direct(plan: &Plan, input: &[bool], reference: Option<&[Value]>, threads: usize) -> Result<DirectRun> {
    let f = plan.f;
    ensure!(input.len() == f.input_bits(), "input length {} != {}", input.len(), f.input_bits());
    let store: Store<Qm<Wire>> = Store::new(plan);
    let deps: Vec<Vec<usize>> = plan.pieces.iter().map(|p| p.deps.clone()).collect();
    let results = run_dag(&deps, threads, |p| {
        let spec = &plan.pieces[p];
        let mut b = Direct::with_first_id(first_id(p));
        let held: HashMap<usize, Arc<Qm<Wire>>> = spec.carried.iter().map(|v| (*v, store.get(*v))).collect();
        let raw_input = |i: u32| -> Vec<Wire> {
            let (_, kind) = f.inputs()[i as usize];
            let at = f.offset(i as usize);
            (at..at + kind.bits()).map(|bit| Wire::new(INPUT_ID_BASE + bit as u64, input[bit])).collect()
        };
        let (ok, mut env) = lower_piece(&mut b, f, spec, raw_input, |v| (*held[&v]).clone());
        let (mut compared, mut mismatches) = (0u64, 0u64);
        if let Some(reference) = reference {
            for si in &spec.steps {
                for v in f.steps()[*si as usize].defines() {
                    compared += 1;
                    mismatches += u64::from(value_of(&env.map[&v]) != reference[v]);
                }
            }
        }
        for v in &spec.writes {
            store.put(*v, env.map.remove(v).expect("a piece defines what it writes"));
        }
        for v in &spec.carried {
            store.release(*v);
        }
        Ok((ok.bit(), b.ands, b.xors, compared, mismatches, !ok.is_constant()))
    })?;
    Ok(DirectRun {
        accepted: results.iter().all(|r| r.0),
        rejecting_pieces: results.iter().filter(|r| !r.0).count(),
        // The pieces' check wires are ANDed into the one acceptance wire.
        ands: results.iter().map(|r| r.1).sum::<u64>() + (results.iter().filter(|r| r.5).count() as u64).saturating_sub(1),
        xors: results.iter().map(|r| r.2).sum(),
        compared: results.iter().map(|r| r.3).sum(),
        mismatches: results.iter().map(|r| r.4).sum(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo_bitvm3_lowering::{Limits, fixture::function_fixture, testing::evaluate};

    #[test]
    fn pieces_compute_what_the_whole_function_computes() {
        let (n, gates, constants, values) = function_fixture();
        let f = Function::new(n, gates, constants, Limits::default()).unwrap();
        let honest = f.encode(&values).unwrap();
        let (_, whole) = evaluate(&f, &honest);
        for (budget, max_steps, layers) in [(1, 1, 128), (1, 3, 2), (u64::MAX, usize::MAX, 1), (u64::MAX, usize::MAX, 128), (30_000, 4, 3)] {
            let plan = Plan::layered(&f, budget, max_steps, layers).unwrap();
            assert_eq!(plan.pieces.iter().map(|p| p.steps.len()).sum::<usize>(), f.steps().len());
            let run = run_direct(&plan, &honest, Some(&whole), 3).unwrap();
            assert!(run.accepted && run.mismatches == 0 && run.compared > 0, "budget {budget} steps {max_steps} layers {layers}");
            // Every single-bit change of the input gives the monolithic verdict and the monolithic values.
            for bit in 0..honest.len() {
                let mut input = honest.clone();
                input[bit] = !input[bit];
                let (ok, expected) = evaluate(&f, &input);
                let run = run_direct(&plan, &input, Some(&expected), 2).unwrap();
                assert_eq!(run.accepted, ok, "bit {bit}");
                assert_eq!(run.mismatches, 0, "bit {bit}");
            }
        }
        // One piece or many: the same gates, hence the same AND count.
        let one_plan = Plan::layered(&f, u64::MAX, usize::MAX, 1).unwrap();
        assert_eq!(one_plan.pieces.len(), 1);
        let one = run_direct(&one_plan, &honest, None, 1).unwrap();
        let many = run_direct(&Plan::new(&f, 1, 1).unwrap(), &honest, None, 2).unwrap();
        assert_eq!(one.ands, many.ands);
    }

    #[test]
    fn scheduler_respects_dependencies_and_reports_cycles() {
        let order = Mutex::new(Vec::new());
        let deps = vec![vec![], vec![0], vec![0], vec![1, 2], vec![3]];
        run_dag(&deps, 4, |p| {
            order.lock().unwrap().push(p);
            Ok(())
        })
        .unwrap();
        let order = order.into_inner().unwrap();
        let at = |p: usize| order.iter().position(|x| *x == p).unwrap();
        for (p, d) in deps.iter().enumerate() {
            assert!(d.iter().all(|q| at(*q) < at(p)));
        }
        assert!(run_dag::<()>(&[vec![1], vec![0]], 2, |_| Ok(())).is_err());
        assert!(run_dag::<()>(&[vec![], vec![0]], 2, |p| if p == 0 { anyhow::bail!("no") } else { Ok(()) }).is_err());
    }
}
