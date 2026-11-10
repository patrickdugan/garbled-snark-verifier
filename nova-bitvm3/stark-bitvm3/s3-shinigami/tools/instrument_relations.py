#!/usr/bin/env python3
"""Source-pinned, diagnostic-only hook for Cairo relation multiplicities.

Apply to a pristine *ephemeral* checkout of stwo-cairo at the declared revision.
The native lookup assertion is retained in debug builds; only the feature-gated
diagnostic is moved ahead of it, after the interaction commitment is available.
The relation tracker interpolates traces and may be costly. The caller must use
a process-tree RSS/time guard and enable the upstream relation-tracker feature.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
from pathlib import Path
import subprocess

REV = "467d5c6d4d6d526c1db8ff69c14f2de6d57f4d73"
SOURCE = "stwo_cairo_prover/crates/prover/src/prover.rs"
TRACKER_SOURCE = "stwo_cairo_prover/crates/prover/src/debug_tools/relation_tracker.rs"
# Upstream's degree reduction shortened constant columns to two evaluations.
# The evaluator subsequently indexed them using their original trace row count.
TRACKER_OLD = """                let coeffs = reduce_degree(poly.evals.clone().interpolate());
                coeffs
                    .evaluate(CanonicCoset::new(coeffs.log_size()).circle_domain())
                    .values
                    .to_cpu()
"""
TRACKER_NEW = """                // Preserve the original trace domain when reconstructing rows.
                // Reducing the coefficient degree must not reduce the row count:
                // the relation evaluator indexes using the component trace domain.
                let original_domain = poly.evals.domain;
                let coeffs = reduce_degree(poly.evals.clone().interpolate());
                coeffs
                    .evaluate(original_domain)
                    .values
                    .to_cpu()
"""
# The generic pinned RelationTrackerEvaluator rejects interaction-column reads
# (INTERACTION_TRACE_IDX=2). Reconstructing that tree is wasted work and can
# exceed the 4 GiB diagnostic cap. Keep its original proof commitment intact.
TRACKER_MAP_OLD = "    let evals = commitment_scheme.trace().polys.map(|interaction_tree| {"
TRACKER_MAP_NEW = """    let mut trace_polys = commitment_scheme.trace().polys;
    assert_eq!(trace_polys.len(), stwo_constraint_framework::INTERACTION_TRACE_IDX + 1);
    // The relation evaluator only accesses preprocessed/base trace columns.
    // This affects diagnostic reconstruction after the full proof commitment.
    trace_polys[stwo_constraint_framework::INTERACTION_TRACE_IDX].clear();
    let evals = trace_polys.map(|interaction_tree| {"""
FEATURE = "stwo-cairo-prover/relation-tracker"
OLD_LOOKUP = """    // Validate lookup argument.
    debug_assert_eq!(
        lookup_sum(&claim, &interaction_elements, &interaction_claim),
        SecureField::zero()
    );
"""
OLD_TRACKER = """    // TODO(Ohad): move to a testing routine.
    #[cfg(feature = "relation-tracker")]
    {
        use crate::debug_tools::relation_tracker::track_and_summarize_cairo_relations;
        let summary = track_and_summarize_cairo_relations(
            &commitment_scheme,
            &component_builder,
            &claim.public_data,
        );
        tracing::info!("Relations summary: {:?}", summary);
    }
"""
# Do not lower this limit by configuration without reviewing diagnostic coverage.
TEXT_CAP = 64 * 1024
NEW_LOOKUP = """    // In a normal prover build the native assertion remains here, unchanged.
    // The opt-in relation audit must run after the interaction trace is committed;
    // that feature alone postpones this exact assertion to just after the audit.
    #[cfg(not(feature = "relation-tracker"))]
""" + OLD_LOOKUP

NEW_TRACKER = """    // This diagnostic is for failed proof research, compiled only with
    // --features stwo-cairo-prover/relation-tracker. Preserve the native
    // lookup assertion below; a nonzero sum never authorizes a proof.
    #[cfg(feature = "relation-tracker")]
    {
        if lookup_sum(&claim, &interaction_elements, &interaction_claim)
            != SecureField::zero()
        {
            use crate::debug_tools::relation_tracker::track_and_summarize_cairo_relations;
            use std::fmt::Write as _;
            struct LimitedReport {
                text: String,
                cap: usize,
                truncated: bool,
            }
            impl std::fmt::Write for LimitedReport {
                fn write_str(&mut self, fragment: &str) -> std::fmt::Result {
                    let available = self.cap.saturating_sub(self.text.len());
                    if fragment.len() <= available {
                        self.text.push_str(fragment);
                        Ok(())
                    } else {
                        let mut length = available;
                        while !fragment.is_char_boundary(length) { length -= 1; }
                        self.text.push_str(&fragment[..length]);
                        self.truncated = true;
                        Err(std::fmt::Error)
                    }
                }
            }
            eprintln!("S3_RELATIONS_BEGIN");
            let summary = track_and_summarize_cairo_relations(
                &commitment_scheme, &component_builder, &claim.public_data,
            );
            let mut output = LimitedReport {
                text: String::new(), cap: 65536, truncated: false,
            };
            let _ = write!(&mut output, "{:?}", summary);
            eprintln!("S3_RELATIONS_TEXT_BEGIN");
            eprint!("{}", output.text);
            if !output.text.ends_with('\\n') { eprintln!(); }
            eprintln!("S3_RELATIONS_TEXT_END");
            eprintln!("S3_RELATIONS_TRUNCATED {}", output.truncated);
            eprintln!("S3_RELATIONS_END");
        }
    }
    #[cfg(feature = "relation-tracker")]
""" + OLD_LOOKUP


def instrument(source: str) -> str:
    if source.count(OLD_LOOKUP) != 1 or source.count(OLD_TRACKER) != 1:
        raise ValueError("pinned prover source layout changed")
    if source.index(OLD_LOOKUP) >= source.index(OLD_TRACKER):
        raise ValueError("unexpected lookup/trace order")
    if source.count("    interaction_claim.mix_into(channel);") != 1:
        raise ValueError("unexpected interaction commitment shape")
    if source.count("    tree_builder.commit(channel);") != 2:
        raise ValueError("upstream tree commit shape changed")
    if "assert_constraints" in source[source.index(OLD_LOOKUP):source.index(OLD_TRACKER)]:
        raise ValueError("unexpected instrumentation")
    patched = source.replace(OLD_LOOKUP, NEW_LOOKUP).replace(OLD_TRACKER, NEW_TRACKER)
    if patched.count("debug_assert_eq!(") != source.count("debug_assert_eq!(") + 1:
        raise AssertionError("native assertion count changed unexpectedly")
    if patched.count("lookup_sum(&claim, &interaction_elements, &interaction_claim)") != (
        source.count("lookup_sum(&claim, &interaction_elements, &interaction_claim)") + 2
    ):
        raise AssertionError("lookup expression changed unexpectedly")
    return patched


def restore_tracker_domain(source: str) -> str:
    if source.count(TRACKER_OLD) != 1:
        raise ValueError("source-pinned relation tracker row-domain layout changed")
    if source.count(".evaluate(CanonicCoset::new(coeffs.log_size()).circle_domain())") != 1:
        raise ValueError("upstream reduced-row tracker expression changed")
    return source.replace(TRACKER_OLD, TRACKER_NEW)


def skip_unused_interaction_reconstruction(source: str) -> str:
    if source.count(TRACKER_MAP_OLD) != 1:
        raise ValueError("unexpected upstream trace-reconstruction layout")
    return source.replace(TRACKER_MAP_OLD, TRACKER_MAP_NEW)


def prepare(root: Path, destination: Path) -> dict:
    root = root.resolve()
    head = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    if head != REV:
        raise ValueError(f"upstream checkout mismatch: {head}")
    original = subprocess.check_output(
        ["git", "-C", str(root), "show", f"HEAD:{SOURCE}"], text=True)
    path = root / SOURCE
    if path.read_text() != original:
        raise ValueError("pinned source was already modified")
    tracker_original = subprocess.check_output(
        ["git", "-C", str(root), "show", f"HEAD:{TRACKER_SOURCE}"], text=True)
    tracker_path = root / TRACKER_SOURCE
    if tracker_path.read_text() != tracker_original:
        raise ValueError("pinned relation tracker source was already modified")
    modified = instrument(original)
    tracker_modified = skip_unused_interaction_reconstruction(restore_tracker_domain(tracker_original))
    # Validate both files before changing either ephemeral upstream file.
    path.write_text(modified)
    tracker_path.write_text(tracker_modified)
    patch = "".join(difflib.unified_diff(
        original.splitlines(keepends=True), modified.splitlines(keepends=True),
        fromfile="a/"+SOURCE, tofile="b/"+SOURCE))
    patch += "".join(difflib.unified_diff(
        tracker_original.splitlines(keepends=True),
        tracker_modified.splitlines(keepends=True),
        fromfile="a/"+TRACKER_SOURCE, tofile="b/"+TRACKER_SOURCE))
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(patch)
    return {
        "stage": "S3h opt-in relation multiplicity audit",
        "upstream_git_head": head,
        "feature": FEATURE,
        "source": SOURCE,
        "source_before_sha256": hashlib.sha256(original.encode()).hexdigest(),
        "source_after_sha256": hashlib.sha256(modified.encode()).hexdigest(),
        "tracker_source": TRACKER_SOURCE,
        "tracker_before_sha256": hashlib.sha256(tracker_original.encode()).hexdigest(),
        "tracker_after_sha256": hashlib.sha256(tracker_modified.encode()).hexdigest(),
        "tracker_row_count_preserved": True,
        "interaction_tree_reconstruction_skipped": True,
        "framework_relation_evaluator_reads_interaction_tree": False,
        "patch_sha256": hashlib.sha256(patch.encode()).hexdigest(),
        "max_debug_output_bytes": TEXT_CAP,
        "native_lookup_assertion_preserved": True,
        "native_proof_verified": False,
        "bitcoin_application_authorized": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.upstream, args.output), indent=2))


if __name__ == "__main__":
    main()
