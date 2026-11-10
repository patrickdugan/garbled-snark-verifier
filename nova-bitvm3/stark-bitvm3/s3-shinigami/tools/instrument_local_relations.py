#!/usr/bin/env python3
"""Opt-in component-local source-pinned Stwo-Cairo relation evaluator.

Reconstruct only the exact preprocessed/base columns requested by range_check_11,
on its canonical 2048-row circle domain. Use upstream's unmodified
add_to_relation_entries evaluator. Do not touch the proof arithmetic, and do
not accept the failed native lookup sum. An ephemeral checkout is mandatory.
"""
from __future__ import annotations
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import subprocess

from instrument_relations import REV, SOURCE, TRACKER_SOURCE, instrument

COMPONENT = "range_check_11"
TRACKER_NAME = "track_local_range_check_11_relations"
UPSTREAM_NAME = "track_and_summarize_cairo_relations"
SCOPE_LABEL = "S3_LOCAL_SCOPE component=range_check_11 partial=true"

LOCAL_RUST = r"""

/// Diagnostic-only reconstruction for the source-pinned 2048-row range_check_11.
/// Only this component's columns are reconstructed. Its relation summary is
/// partial, since counterparty components and public memory remain excluded.
pub fn track_local_range_check_11_relations<MC: MerkleChannel>(
    commitment_scheme: &CommitmentSchemeProver<'_, SimdBackend, MC>,
    components: &CairoComponents,
    _public_data: &PublicData,
    common_lookup: &cairo_air::relations::CommonLookupElements,
    claimed_sum: stwo::core::fields::qm31::SecureField,
) -> RelationSummary
where
    SimdBackend: BackendForChannel<MC>,
{
    use stwo::core::air::Component as _;
    use stwo_constraint_framework::{ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX};

    let component = components.range_check_11.as_ref()
        .expect("range_check_11 must be active in this pinned Shinigami fixture");
    let logs = component.trace_log_degree_bounds();
    let log_size = cairo_air::components::range_check_11::LOG_SIZE;
    assert_eq!(log_size, 11, "source-pinned local component shape changed");
    assert_eq!(logs[ORIGINAL_TRACE_IDX], vec![log_size]);
    assert!(component.trace_locations().len() >= 2);
    assert_eq!(component.preprocessed_column_indices().len(), 1);

    let source = commitment_scheme.trace().polys;
    assert_eq!(source.len(), 3);
    let mut indices = vec![Vec::<usize>::new(), Vec::<usize>::new()];
    indices[PREPROCESSED_TRACE_IDX]
        .extend_from_slice(component.preprocessed_column_indices());
    for span in component.trace_locations() {
        if span.tree_index == ORIGINAL_TRACE_IDX {
            indices[ORIGINAL_TRACE_IDX].extend(span.col_start..span.col_end);
        }
    }
    for (tree, selected) in indices.iter_mut().enumerate() {
        selected.sort_unstable();
        selected.dedup();
        assert!(!selected.is_empty() && selected.len() <= 4,
                "bounded component requires one through four columns");
        assert!(selected.iter().all(|&i| i < source[tree].len()),
                "selected component column index out of bounds");
    }

    let mut reconstructed: TreeVec<Vec<Vec<BaseField>>> = TreeVec::new(vec![
        vec![Vec::new(); source[PREPROCESSED_TRACE_IDX].len()],
        vec![Vec::new(); source[ORIGINAL_TRACE_IDX].len()],
        Vec::new(),
    ]);
    let domain = CanonicCoset::new(log_size).circle_domain();
    for tree in [PREPROCESSED_TRACE_IDX, ORIGINAL_TRACE_IDX] {
        for &index in &indices[tree] {
            let polynomial = source[tree][index];
            let coeffs = reduce_degree(polynomial.evals.clone().interpolate());
            assert!(coeffs.log_size() <= log_size,
                    "source polynomial exceeds selected component trace degree");
            let rows = coeffs.evaluate(domain).values.to_cpu();
            assert_eq!(rows.len(), 1usize << log_size);
            reconstructed[tree][index] = rows;
        }
    }

    eprintln!(
        "S3_LOCAL_COLUMNS component=range_check_11 preprocessed={} base={} rows={}",
        indices[PREPROCESSED_TRACE_IDX].len(),
        indices[ORIGINAL_TRACE_IDX].len(),
        1usize << log_size
    );
    let view: TreeVec<Vec<&Vec<BaseField>>> = TreeVec::new(
        reconstructed.iter().map(|cols| cols.iter().collect()).collect()
    );
    // Exact upstream framework evaluator and bit-reversed mask semantics.
    let entries = add_to_relation_entries(component, &view);
    eprintln!("S3_LOCAL_ENTRIES count={}", entries.len());
    // The exact upstream LogUp relation uses one signed multiplicity divided
    // by the Fiat-Shamir-combined tuple. Compare the reconstructed component
    // sum against its native interaction claim before checking the global sum.
    use stwo::core::fields::{qm31::SecureField, FieldExpOps};
    use stwo_constraint_framework::Relation;
    let mut reconstructed_sum = SecureField::zero();
    for entry in &entries {
        assert_eq!(entry.relation, "CommonLookupElements");
        let denominator: SecureField = common_lookup.combine(&entry.values);
        assert_ne!(denominator, SecureField::zero(), "zero local LogUp denominator");
        let m = SecureField::from_m31(
            entry.mult, M31::zero(), M31::zero(), M31::zero(),
        );
        reconstructed_sum += m * denominator.inverse();
    }
    eprintln!(
        "S3_LOCAL_LOGUP recomputed={:?} claimed={:?} matches={}",
        reconstructed_sum, claimed_sum, reconstructed_sum == claimed_sum
    );
    RelationSummary::summarize_relations(&entries).cleaned()
}
"""


def instrument_prover(source: str) -> str:
    patched = instrument(source)
    if patched.count(UPSTREAM_NAME) != 2:
        raise ValueError("pinned tracker call/import shape changed")
    patched = patched.replace(UPSTREAM_NAME, TRACKER_NAME)
    old_call = """                &commitment_scheme, &component_builder, &claim.public_data,
            );"""
    new_call = """                &commitment_scheme, &component_builder, &claim.public_data,
                &interaction_elements,
                interaction_claim.range_check_11
                    .as_ref().expect("missing native range_check_11 claim").claimed_sum,
            );"""
    if patched.count(old_call) != 1:
        raise ValueError("source-pinned native tracker invocation changed")
    patched = patched.replace(old_call, new_call)
    needle = '            eprintln!("S3_RELATIONS_TEXT_BEGIN");'
    if patched.count(needle) != 1:
        raise ValueError("pinned summary-output shape changed")
    patched = patched.replace(needle,
        '            eprintln!("'+SCOPE_LABEL+'");\n'+needle)
    if patched.count('debug_assert_eq!(') != source.count('debug_assert_eq!(') + 1:
        raise ValueError("native lookup equality was modified")
    return patched


def instrument_tracker(source: str) -> str:
    anchor = "pub fn track_cairo_relations<"
    if source.count(anchor) != 1 or TRACKER_NAME in source:
        raise ValueError("pinned upstream relation tracker shape changed")
    if source.count("pub fn track_and_summarize_cairo_relations<") != 1:
        raise ValueError("upstream full tracker missing")
    return source + LOCAL_RUST


def prepare(root: Path, destination: Path) -> dict:
    root = root.resolve()
    head = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    if head != REV:
        raise ValueError(f"upstream mismatch: {head}")
    updated = {}
    patch = ""
    for path, transformer in [
        (SOURCE, instrument_prover),
        (TRACKER_SOURCE, instrument_tracker),
    ]:
        original = subprocess.check_output(
            ["git", "-C", str(root), "show", f"HEAD:{path}"], text=True)
        if (root/path).read_text() != original:
            raise ValueError(f"pre-modified pinned source: {path}")
        modified = transformer(original)
        updated[path] = modified
        patch += "".join(difflib.unified_diff(
            original.splitlines(keepends=True),
            modified.splitlines(keepends=True),
            fromfile="a/"+path, tofile="b/"+path))
    # No changes until both source files have passed their shape checks.
    for path, modified in updated.items():
        (root/path).write_text(modified)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(patch)
    return {
        "stage":"S3k targeted component-local range_check_11 relation audit",
        "upstream_sha":REV,
        "selected_component":COMPONENT,
        "selected_rows":2048,
        "maximum_columns_per_tree":4,
        "source_equivalence":"uses upstream add_to_relation_entries and native interaction challenge on canonical component domain",
        "claimed_sum_comparison":"exact signed LogUp sum from reconstructed source tuples vs native component interaction claim",
        "full_relation_inventory":False,
        "patch_sha256":hashlib.sha256(patch.encode()).hexdigest(),
        "prover_original_lookup_assertion_preserved":True,
        "native_proof_verified":False,
        "bitcoin_application_authorized":False,
    }


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--upstream",type=Path,required=True)
    ap.add_argument("--output",type=Path,required=True)
    args=ap.parse_args()
    print(json.dumps(prepare(args.upstream,args.output),indent=2))


if __name__=="__main__":
    main()
