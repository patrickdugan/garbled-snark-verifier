#!/usr/bin/env python3
"""Source-pinned per-family balance of the whole Cairo lookup argument; proof stays rejected.

S3o balanced one relation family of one component pair. This stage evaluates every
active component's pinned AIR, through upstream's unmodified relation evaluator, on the
original base rows, and adds the public-data terms the native lookup_sum adds. The
result is, per relation tag, the signed multiplicity total and the QM31 sum under the
native challenge, and a per-tuple ledger for the memory and opcode relations.

Base rows are captured once, by wrapping the producer's tree builder: every component
hands its evaluations to `extend_evals`, which forwards them unchanged after copying
them. Nothing is interpolated, no preprocessing or interaction tree is reconstructed,
and each component is evaluated on its own with its preprocessed columns generated on
demand and dropped afterwards. Every component's evaluated LogUp sum is compared with
its own native claimed sum, and the family totals must add up to the native lookup sum.
The original global lookup assertion is unchanged and still rejects the proof.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
from pathlib import Path
import re
import subprocess

from instrument_local_relations import REV, SOURCE, TRACKER_SOURCE
from instrument_relations import instrument as base_prover_instrument
from instrument_xor8_relations import replace_once

COMPONENTS_SOURCE = "stwo_cairo_prover/crates/cairo-air/src/cairo_components.rs"
RELATIONS_SOURCE = "stwo_cairo_prover/crates/cairo-air/src/relations.rs"
EXPECTED_FIELDS = 66
EXPECTED_VECTOR_FIELDS = ("memory_id_to_big",)
TIME_BUDGET_SECONDS = 90
MAX_TUPLES_PRINTED = 12
MAX_RUNS_PRINTED = 24
TRACKED_TAGS = {1444891767: "MEMORY_ADDRESS_TO_ID", 1662111297: "MEMORY_ID_TO_BIG",
                428564188: "OPCODES"}
# Tags that no relations.rs constant names; taken from the S3m and S3o audits.
KNOWN_TAGS = {95781001: "VERIFY_BITWISE_XOR_9", 112558620: "VERIFY_BITWISE_XOR_8",
              521092554: "VERIFY_BITWISE_XOR_8_B"}
UPSTREAM_TRACKER_CALL = "track_and_summarize_cairo_relations"
LEDGER_CALL = "track_memory_ledger"
OLD_CALL = """                &commitment_scheme, &component_builder, &claim.public_data,
            );"""
NEW_CALL = """                &commitment_scheme, &component_builder, &claim.public_data,
                &preprocessed_trace, &interaction_elements,
                lookup_sum(&claim, &interaction_elements, &interaction_claim),
            );"""
WRITE_OLD = "    let (claim, interaction_generator) = cairo_claim_generator.write_trace(&mut tree_builder);\n"
WRITE_NEW = """    #[cfg(feature = "relation-tracker")]
    let (claim, interaction_generator) = {
        let mut capturing =
            crate::debug_tools::relation_tracker::CapturingTreeBuilder::new(&mut tree_builder);
        let traced = cairo_claim_generator.write_trace(&mut capturing);
        capturing.finish();
        traced
    };
    #[cfg(not(feature = "relation-tracker"))]
    let (claim, interaction_generator) = cairo_claim_generator.write_trace(&mut tree_builder);
"""

LEDGER_RUST = r"""

/// Diagnostic-only copy of the complete base tree, one vector per column in commitment
/// order, taken where the producer hands each component's evaluations to the tree
/// builder. The evaluations are forwarded unchanged.
static BASE_TREE_SOURCE: std::sync::OnceLock<Vec<Vec<BaseField>>> = std::sync::OnceLock::new();
static EMPTY_COLUMN: Vec<BaseField> = Vec::new();

pub struct CapturingTreeBuilder<'a, T> {
    inner: &'a mut T,
    columns: Vec<Vec<BaseField>>,
}

impl<'a, T> CapturingTreeBuilder<'a, T> {
    pub fn new(inner: &'a mut T) -> Self {
        Self { inner, columns: Vec::new() }
    }

    pub fn finish(self) {
        assert!(BASE_TREE_SOURCE.set(self.columns).is_ok(), "base tree source captured twice");
    }
}

impl<T: crate::witness::utils::TreeBuilder<SimdBackend>>
    crate::witness::utils::TreeBuilder<SimdBackend> for CapturingTreeBuilder<'_, T>
{
    fn extend_evals(
        &mut self,
        columns: Vec<stwo::prover::poly::circle::CircleEvaluation<
            SimdBackend, BaseField, stwo::prover::poly::BitReversedOrder,
        >>,
    ) -> stwo::core::pcs::TreeSubspan {
        let start = self.columns.len();
        for column in &columns {
            let rows = column.values.to_cpu();
            assert_eq!(rows.len(), 1usize << column.domain.log_size(), "base column row count");
            self.columns.push(rows);
        }
        let span = self.inner.extend_evals(columns);
        assert_eq!(
            (span.col_start, span.col_end),
            (start, self.columns.len()),
            "captured columns differ from the tree builder's allocation"
        );
        span
    }
}

fn relation_name(tag: u32) -> &'static str {
    match tag {
@@NAMES@@
        _ => "UNKNOWN",
    }
}

#[derive(Clone, Copy)]
struct Agg {
    entries: u64,
    mult: u64,
    sum: stwo::core::fields::qm31::SecureField,
}

impl Agg {
    fn new() -> Self {
        Self { entries: 0, mult: 0, sum: stwo::core::fields::qm31::SecureField::zero() }
    }

    fn add(&mut self, mult: M31, term: stwo::core::fields::qm31::SecureField) {
        self.entries += 1;
        self.mult = (self.mult + mult.0 as u64) % stwo::core::fields::m31::P as u64;
        self.sum += term;
    }
}

fn qm_text(value: stwo::core::fields::qm31::SecureField) -> String {
    let limbs = value.to_m31_array();
    format!("{},{},{},{}", limbs[0].0, limbs[1].0, limbs[2].0, limbs[3].0)
}

fn trimmed(values: &[M31]) -> Vec<u32> {
    let mut out: Vec<u32> = values.iter().map(|v| v.0).collect();
    while out.last() == Some(&0) {
        out.pop();
    }
    out
}

struct Ledger<'a> {
    base: &'a Vec<Vec<BaseField>>,
    n_preprocessed: usize,
    preprocessed_trace: &'a stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTrace,
    lookup: &'a cairo_air::relations::CommonLookupElements,
    started: std::time::Instant,
    complete: bool,
    skipped: Vec<String>,
    evaluated: usize,
    families: std::collections::BTreeMap<u32, Agg>,
    tuples: std::collections::BTreeMap<u32, std::collections::BTreeMap<Vec<u32>, u32>>,
    claims: stwo::core::fields::qm31::SecureField,
}

impl Ledger<'_> {
    fn record(&mut self, tag: u32, values: &[M31], mult: M31, term: stwo::core::fields::qm31::SecureField,
              local: &mut std::collections::BTreeMap<u32, Agg>) {
        local.entry(tag).or_insert_with(Agg::new).add(mult, term);
        self.families.entry(tag).or_insert_with(Agg::new).add(mult, term);
        if let Some(ledger) = self.tuples.get_mut(&tag) {
            let slot = ledger.entry(trimmed(values)).or_insert(0);
            *slot = ((*slot as u64 + mult.0 as u64) % stwo::core::fields::m31::P as u64) as u32;
        }
    }

    fn component<E: stwo_constraint_framework::FrameworkEval>(
        &mut self,
        name: &str,
        component: &stwo_constraint_framework::FrameworkComponent<E>,
    ) {
        use stwo::core::air::Component as _;
        use stwo::core::fields::{qm31::SecureField, FieldExpOps};
        use stwo_constraint_framework::{Relation, ORIGINAL_TRACE_IDX};

        if self.started.elapsed().as_secs() >= @@BUDGET@@ {
            self.complete = false;
            self.skipped.push(name.to_string());
            return;
        }
        let began = std::time::Instant::now();
        let log_size = component.trace_log_degree_bounds()[ORIGINAL_TRACE_IDX]
            .first().copied().unwrap_or(0);
        let generated: Vec<(usize, Vec<BaseField>)> = component.preprocessed_column_indices()
            .iter()
            .map(|&index| {
                let column = self.preprocessed_trace.columns.get(index)
                    .expect("source-pinned preprocessing index is out of range");
                (index, column.gen_column_simd().values.to_cpu())
            })
            .collect();
        let mut preprocessed_view: Vec<&Vec<BaseField>> = vec![&EMPTY_COLUMN; self.n_preprocessed];
        for (index, rows) in &generated {
            preprocessed_view[*index] = rows;
        }
        let base_view: Vec<&Vec<BaseField>> = self.base.iter().collect();
        let view: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed_view, base_view, Vec::new()]);
        // Upstream's own evaluator: exact AIR, bit-reversed masks, no re-implementation.
        let entries = add_to_relation_entries(component, &view);
        let lookup = self.lookup;
        let denominators: Vec<SecureField> = entries.iter().map(|entry| {
            assert_eq!(entry.relation, "CommonLookupElements");
            let value: SecureField = lookup.combine(&entry.values);
            assert_ne!(value, SecureField::zero(), "zero LogUp denominator");
            value
        }).collect();
        let inverses = SecureField::batch_inverse(&denominators);
        let mut local: std::collections::BTreeMap<u32, Agg> = std::collections::BTreeMap::new();
        let mut total = SecureField::zero();
        for (entry, inverse) in entries.iter().zip(inverses.iter()) {
            let term = SecureField::from_m31(entry.mult, M31::zero(), M31::zero(), M31::zero())
                * *inverse;
            total += term;
            self.record(entry.values[0].0, &entry.values, entry.mult, term, &mut local);
        }
        let claimed = component.claimed_sum();
        self.claims += claimed;
        self.evaluated += 1;
        eprintln!(
            "S3_LEDGER_COMPONENT name={} log_size={} entries={} qm31={} claimed={} matches={} ms={}",
            name, log_size, entries.len(), qm_text(total), qm_text(claimed), total == claimed,
            began.elapsed().as_millis()
        );
        for (tag, agg) in &local {
            eprintln!(
                "S3_LEDGER_COMPONENT_TAG name={} tag={} entries={} mult_sum_mod_p={} qm31={}",
                name, tag, agg.entries, agg.mult, qm_text(agg.sum)
            );
        }
    }
}

/// Evaluates every active component on its captured base rows, adds the public-data
/// terms exactly as the native lookup_sum does, and balances the result per relation tag.
pub fn track_memory_ledger<MC: MerkleChannel>(
    commitment_scheme: &CommitmentSchemeProver<'_, SimdBackend, MC>,
    components: &CairoComponents,
    public_data: &PublicData,
    preprocessed_trace: &stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTrace,
    common_lookup: &cairo_air::relations::CommonLookupElements,
    global_sum: stwo::core::fields::qm31::SecureField,
) -> RelationSummary
where
    SimdBackend: BackendForChannel<MC>,
{
    use stwo::core::fields::m31::P;
    use stwo::core::fields::{qm31::SecureField, FieldExpOps};
    use stwo_constraint_framework::{Relation, ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX};

    let source = commitment_scheme.trace().polys;
    assert_eq!(source.len(), 3);
    let base = BASE_TREE_SOURCE.get().expect("base tree source was never captured");
    assert_eq!(base.len(), source[ORIGINAL_TRACE_IDX].len(), "captured base tree width");
    let cells: usize = base.iter().map(|column| column.len()).sum();
    eprintln!("S3_LEDGER_BEGIN");
    eprintln!("S3_LEDGER_CAPTURE columns={} cells={}", base.len(), cells);

    let mut ledger = Ledger {
        base,
        n_preprocessed: source[PREPROCESSED_TRACE_IDX].len(),
        preprocessed_trace,
        lookup: common_lookup,
        started: std::time::Instant::now(),
        complete: true,
        skipped: Vec::new(),
        evaluated: 0,
        families: std::collections::BTreeMap::new(),
        tuples: std::collections::BTreeMap::new(),
        claims: SecureField::zero(),
    };
    for tag in [@@TRACKED@@] {
        ledger.tuples.insert(tag, std::collections::BTreeMap::new());
    }

@@CALLS@@

    // Public data, term by term as in PublicData::logup_sum.
    let mut public: Vec<(u32, Vec<M31>, M31)> = Vec::new();
    let mut public_pairs: Vec<(u32, u32)> = Vec::new();
    for (address, id, value) in public_data.public_memory.get_entries(
        public_data.initial_state.pc.0, public_data.initial_state.ap.0, public_data.final_state.ap.0,
    ) {
        public_pairs.push((address, id));
        public.push((
            cairo_air::relations::MEMORY_ADDRESS_TO_ID_RELATION_ID.0,
            vec![cairo_air::relations::MEMORY_ADDRESS_TO_ID_RELATION_ID,
                 M31::from_u32_unchecked(address), M31::from_u32_unchecked(id)],
            M31::one(),
        ));
        public.push((
            cairo_air::relations::MEMORY_ID_TO_BIG_RELATION_ID.0,
            [[cairo_air::relations::MEMORY_ID_TO_BIG_RELATION_ID, M31::from_u32_unchecked(id)].as_slice(),
             split_f252(value).as_slice()].concat(),
            M31::one(),
        ));
    }
    let opcodes = cairo_air::relations::OPCODES_RELATION_ID;
    public.push((opcodes.0,
                 std::iter::once(opcodes).chain(public_data.final_state.values()).collect(), M31::one()));
    public.push((opcodes.0,
                 std::iter::once(opcodes).chain(public_data.initial_state.values()).collect(), -M31::one()));
    let denominators: Vec<SecureField> = public.iter().map(|(_, values, _)| {
        let value: SecureField = common_lookup.combine(values);
        assert_ne!(value, SecureField::zero(), "zero public LogUp denominator");
        value
    }).collect();
    let inverses = SecureField::batch_inverse(&denominators);
    let mut public_local: std::collections::BTreeMap<u32, Agg> = std::collections::BTreeMap::new();
    let mut public_total = SecureField::zero();
    for ((tag, values, mult), inverse) in public.iter().zip(inverses.iter()) {
        let term = SecureField::from_m31(*mult, M31::zero(), M31::zero(), M31::zero()) * *inverse;
        public_total += term;
        ledger.record(*tag, values, *mult, term, &mut public_local);
    }
    let native_public = public_data.logup_sum(common_lookup);
    eprintln!(
        "S3_LEDGER_PUBLIC entries={} qm31={} native={} matches={}",
        public.len(), qm_text(public_total), qm_text(native_public), public_total == native_public
    );
    for (tag, agg) in &public_local {
        eprintln!(
            "S3_LEDGER_PUBLIC_TAG tag={} entries={} mult_sum_mod_p={} qm31={}",
            tag, agg.entries, agg.mult, qm_text(agg.sum)
        );
    }

    let mut families_sum = SecureField::zero();
    for (tag, agg) in &ledger.families {
        families_sum += agg.sum;
        eprintln!(
            "S3_LEDGER_FAMILY tag={} name={} entries={} mult_sum_mod_p={} qm31={} zero={}",
            tag, relation_name(*tag), agg.entries, agg.mult, qm_text(agg.sum),
            agg.sum == SecureField::zero()
        );
    }
    let claims_with_public = ledger.claims + native_public;
    eprintln!(
        "S3_LEDGER_TOTAL families_sum={} component_claims_plus_public={} global_lookup_sum={} matches={}",
        qm_text(families_sum), qm_text(claims_with_public), qm_text(global_sum),
        families_sum == global_sum && claims_with_public == global_sum
    );
    for (tag, tuples) in &ledger.tuples {
        let nonzero: Vec<(&Vec<u32>, &u32)> = tuples.iter().filter(|(_, net)| **net != 0).collect();
        let printed = nonzero.len().min(@@PRINTED@@);
        eprintln!(
            "S3_LEDGER_TUPLES tag={} name={} distinct={} nonzero={} printed={}",
            tag, relation_name(*tag), tuples.len(), nonzero.len(), printed
        );
        for (values, net) in nonzero.iter().take(@@PRINTED@@) {
            eprintln!(
                "S3_LEDGER_TUPLE tag={} tuple={} net_mod_p={}",
                tag, values.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(","), net
            );
        }
    }
    // Which public-memory section do the unmatched address uses belong to? The entries
    // come out of get_entries in section order: program, safe call, segment ranges, output.
    let program_len = public_data.public_memory.program.len();
    let output_len = public_data.public_memory.output.len();
    assert!(public_pairs.len() >= program_len + 2 + output_len, "public section sizes");
    let segments_len = public_pairs.len() - program_len - 2 - output_len;
    let section_names = ["program", "safe_call", "segments", "output"];
    let section_sizes = [program_len, 2, segments_len, output_len];
    let mut section_of: std::collections::HashMap<(u32, u32), usize> = std::collections::HashMap::new();
    let mut boundary = 0usize;
    for (section, size) in section_sizes.iter().enumerate() {
        for pair in &public_pairs[boundary..boundary + size] {
            section_of.insert(*pair, section);
        }
        boundary += size;
    }
    let address_tag = cairo_air::relations::MEMORY_ADDRESS_TO_ID_RELATION_ID.0;
    let mut unmatched: Vec<(u32, u32)> = ledger.tuples[&address_tag].iter()
        .filter(|(_, net)| **net != 0)
        .map(|(key, _)| (key[1], key.get(2).copied().unwrap_or(0)))
        .collect();
    unmatched.sort_unstable();
    let mut per_section = [0usize; 4];
    let mut outside = 0usize;
    for pair in &unmatched {
        match section_of.get(pair) {
            Some(section) => per_section[*section] += 1,
            None => outside += 1,
        }
    }
    eprintln!(
        "S3_LEDGER_UNMATCHED tag={} total={} in_public={} outside_public={}",
        address_tag, unmatched.len(), unmatched.len() - outside, outside
    );
    for section in 0..4 {
        eprintln!(
            "S3_LEDGER_UNMATCHED_SECTION name={} entries={} unmatched={}",
            section_names[section], section_sizes[section], per_section[section]
        );
    }
    let mut runs: Vec<(u32, u32)> = Vec::new();
    for (address, _) in &unmatched {
        if let Some((start, len)) = runs.last_mut() {
            if *start + *len == *address {
                *len += 1;
                continue;
            }
        }
        runs.push((*address, 1));
    }
    eprintln!("S3_LEDGER_UNMATCHED_RUNS count={} printed={}", runs.len(), runs.len().min(@@RUNS@@));
    for (start, len) in runs.iter().take(@@RUNS@@) {
        eprintln!("S3_LEDGER_UNMATCHED_RUN start={} len={}", start, len);
    }
    eprintln!(
        "S3_LEDGER_STATUS evaluated={} skipped={} complete={} ms={} p={}",
        ledger.evaluated, ledger.skipped.len(), ledger.complete,
        ledger.started.elapsed().as_millis(), P
    );
    for name in &ledger.skipped {
        eprintln!("S3_LEDGER_SKIPPED name={}", name);
    }
    eprintln!("S3_LEDGER_END");
    RelationSummary::summarize_relations(&[]).cleaned()
}
"""


def component_fields(components_source: str) -> list[tuple[str, str]]:
    start = components_source.index("pub struct CairoComponents")
    body = components_source[start:components_source.index("\n}", start)]
    fields = []
    for name, kind in re.findall(r"(?m)^\s*pub ([a-z0-9_]+):\s*(Option|Vec)<", body):
        fields.append((name, "option" if kind == "Option" else "vector"))
    if len(fields) != EXPECTED_FIELDS:
        raise ValueError("pinned CairoComponents field count changed")
    if tuple(n for n, k in fields if k == "vector") != EXPECTED_VECTOR_FIELDS:
        raise ValueError("pinned CairoComponents vector fields changed")
    if len({n for n, _ in fields}) != len(fields):
        raise ValueError("duplicate CairoComponents field")
    return fields


def relation_names(relations_source: str) -> dict[int, str]:
    names = {int(v): n for n, v in re.findall(
        r"pub const ([A-Z0-9_]+)_RELATION_ID: M31 = M31::from_u32_unchecked\((\d+)\);",
        relations_source)}
    if names.get(1444891767) != "MEMORY_ADDRESS_TO_ID" or names.get(1662111297) != "MEMORY_ID_TO_BIG" \
            or names.get(428564188) != "OPCODES":
        raise ValueError("pinned relation ids changed")
    for tag, name in KNOWN_TAGS.items():
        if tag in names:
            raise ValueError("relation tag naming overlaps the pinned constants")
        names[tag] = name
    return names


def render_rust(fields: list[tuple[str, str]], names: dict[int, str]) -> str:
    calls = []
    for name, kind in fields:
        if kind == "option":
            calls.append(f'    if let Some(component) = &components.{name} {{ ledger.component("{name}", component); }}')
        else:
            calls.append(f'    for component in &components.{name} {{ ledger.component("{name}", component); }}')
    arms = "\n".join(f'        {tag} => "{name}",' for tag, name in sorted(names.items()))
    code = (LEDGER_RUST.replace("@@NAMES@@", arms).replace("@@CALLS@@", "\n".join(calls))
            .replace("@@BUDGET@@", str(TIME_BUDGET_SECONDS))
            .replace("@@TRACKED@@", ", ".join(str(t) for t in sorted(TRACKED_TAGS)))
            .replace("@@PRINTED@@", str(MAX_TUPLES_PRINTED))
            .replace("@@RUNS@@", str(MAX_RUNS_PRINTED)))
    if "@@" in code:
        raise ValueError("unfilled template placeholder")
    return code


def instrument_prover(source: str) -> str:
    patched = base_prover_instrument(source)
    if patched.count(UPSTREAM_TRACKER_CALL) != 2:
        raise ValueError("pinned tracker call/import shape changed")
    patched = patched.replace(UPSTREAM_TRACKER_CALL, LEDGER_CALL)
    patched = replace_once(patched, OLD_CALL, NEW_CALL)
    patched = replace_once(patched, WRITE_OLD, WRITE_NEW)
    if patched.count("debug_assert_eq!(") != source.count("debug_assert_eq!(") + 1:
        raise ValueError("native lookup equality was modified")
    return patched


def instrument_tracker(source: str, components_source: str, relations_source: str) -> str:
    anchor = "pub fn track_cairo_relations<"
    if source.count(anchor) != 1 or LEDGER_CALL in source or "CapturingTreeBuilder" in source:
        raise ValueError("pinned upstream relation tracker shape changed")
    rust = render_rust(component_fields(components_source), relation_names(relations_source))
    return source + rust


def prepare(root: Path, destination: Path) -> dict:
    root = root.resolve()
    actual = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    if actual != REV:
        raise ValueError(f"upstream revision changed: {actual}")

    def pristine(path: str) -> str:
        original = subprocess.check_output(["git", "-C", str(root), "show", f"HEAD:{path}"], text=True)
        if (root / path).read_text() != original:
            raise ValueError(f"upstream file was already modified: {path}")
        return original

    components_source = pristine(COMPONENTS_SOURCE)
    relations_source = pristine(RELATIONS_SOURCE)
    updated = []
    patches = []
    for path, transform in (
        (SOURCE, instrument_prover),
        (TRACKER_SOURCE, lambda text: instrument_tracker(text, components_source, relations_source)),
    ):
        original = pristine(path)
        modified = transform(original)
        patches.append("".join(difflib.unified_diff(
            original.splitlines(keepends=True), modified.splitlines(keepends=True),
            fromfile="a/" + path, tofile="b/" + path)))
        updated.append((path, original, modified))
    # Nothing changes until the complete source pin has passed.
    for path, _, modified in updated:
        (root / path).write_text(modified)
    patch = "".join(patches)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(patch)
    fields = component_fields(components_source)
    return {
        "stage": "S3p source-pinned per-family balance of the whole lookup argument",
        "upstream_revision": REV,
        "compiled_components": len(fields),
        "tracked_tuple_tags": {str(t): n for t, n in sorted(TRACKED_TAGS.items())},
        "capture": "producer tree builder wrapped; every extend_evals forwarded unchanged after a copy",
        "air_evaluator": "upstream stwo_constraint_framework::relation_tracker::add_to_relation_entries",
        "time_budget_seconds": TIME_BUDGET_SECONDS,
        "source_file_hashes": [{
            "path": path,
            "before_sha256": hashlib.sha256(before.encode()).hexdigest(),
            "diagnostic_sha256": hashlib.sha256(after.encode()).hexdigest(),
        } for path, before, after in updated],
        "read_only_source_hashes": [{
            "path": path, "sha256": hashlib.sha256(text.encode()).hexdigest(),
        } for path, text in ((COMPONENTS_SOURCE, components_source), (RELATIONS_SOURCE, relations_source))],
        "patch_sha256": hashlib.sha256(patch.encode()).hexdigest(),
        "original_commitment_input_unchanged": True,
        "original_global_lookup_assertion_unchanged": True,
        "full_stark_proof_verified": False,
        "bitcoin_application_authorized": False,
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--upstream", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    print(json.dumps(prepare(args.upstream, args.output), indent=2))


if __name__ == "__main__":
    main()
