#!/usr/bin/env python3
"""Pinned two-tree local audit of verify_bitwise_xor_8 (65,536 rows).

The proof relation, transcript, and global LogUp assertion are unchanged.
Source modifications occur only inside an ephemeral pinned upstream checkout.
The selected component has 3 preprocessing masks, 2 base masks, and 2
relation entries per row. Its output is always partial diagnostic evidence.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
from pathlib import Path
import subprocess

from instrument_local_relations import (
    LOCAL_RUST, REV, SOURCE, TRACKER_SOURCE,
    instrument_prover as base_prover, instrument_tracker as base_tracker,
)

WITNESS_SOURCE = "stwo_cairo_prover/crates/prover/src/witness/cairo_claim_generator.rs"
COMPONENT = "verify_bitwise_xor_8"
TRACKER_NAME = "track_local_verify_bitwise_xor_8_relations"
LOG_SIZE = 16
ROWS = 1 << LOG_SIZE
PREPROCESSED = 3
BASE = 2
ENTRIES = ROWS * 2
SCOPE_LABEL = "S3_LOCAL_SCOPE component=verify_bitwise_xor_8 partial=true"


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise ValueError(f"source-pinned XOR8 component shape changed: {old[:90]}")
    return source.replace(old, new)


def xor_rust() -> str:
    """Specialize the already-tested source-pinned component-local collector."""
    original = LOCAL_RUST
    if original.count("range_check_11") != 6:
        raise ValueError("source-pinned range-check collector changed")
    updated = original.replace("range_check_11", COMPONENT)
    updated = replace_once(updated, "2048-row", "65536-row")
    updated = replace_once(
        updated, 'assert_eq!(log_size, 11,', 'assert_eq!(log_size, 16,')
    updated = replace_once(
        updated,
        "assert_eq!(logs[ORIGINAL_TRACE_IDX], vec![log_size]);",
        "assert_eq!(logs[ORIGINAL_TRACE_IDX], vec![log_size; 2]);",
    )
    updated = replace_once(
        updated,
        "assert_eq!(component.preprocessed_column_indices().len(), 1);",
        "assert_eq!(component.preprocessed_column_indices().len(), 3);",
    )
    updated = replace_once(
        updated,
        """    _public_data: &PublicData,
    common_lookup: &cairo_air::relations::CommonLookupElements,""",
        """    _public_data: &PublicData,
    preprocessed_trace: &stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTrace,
    common_lookup: &cairo_air::relations::CommonLookupElements,""",
    )
    old_reconstruction = """    let domain = CanonicCoset::new(log_size).circle_domain();
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
    }"""
    new_reconstruction = """    let domain = CanonicCoset::new(log_size).circle_domain();
    // The prover's pinned preprocessed trace is the original source of these
    // three XOR8 columns. The commitment tree may lift their polynomials onto
    // a larger domain, so its coefficients cannot be restricted to 16 bits.
    // Recover the exact canonical 65536-row values directly from the SAME
    // pinned preprocessed trace that was used to build the commitment.
    let expected_ids = ["bitwise_xor_8_0", "bitwise_xor_8_1", "bitwise_xor_8_2"];
    for (slot, &index) in component.preprocessed_column_indices().iter().enumerate() {
        let column = preprocessed_trace.columns.get(index)
            .expect("source-pinned XOR8 preprocessing index is out of range");
        assert_eq!(column.id().id, expected_ids[slot], "wrong XOR8 table column");
        assert_eq!(column.log_size(), log_size, "wrong source preprocessed domain");
        let rows = column.gen_column_simd().values.to_cpu();
        assert_eq!(rows.len(), 1usize << log_size);
        reconstructed[PREPROCESSED_TRACE_IDX][index] = rows;
    }
    eprintln!("S3_LOCAL_PREPROCESS_SOURCE canonical_pinned_original");
    // The producer's original base column evaluations are captured before
    // the tree builder interpolates and potentially lifts them for commitment.
    // They are the exact values passed into the native commitment unchanged.
    let source_rows = XOR8_SOURCE.get()
        .expect("XOR8 original 65536-row base source was never captured");
    assert_eq!(source_rows.len(), indices[ORIGINAL_TRACE_IDX].len());
    assert_eq!(source_rows.len(), 2);
    for (slot, &index) in indices[ORIGINAL_TRACE_IDX].iter().enumerate() {
        assert_eq!(source_rows[slot].len(), 1usize << log_size);
        reconstructed[ORIGINAL_TRACE_IDX][index] = source_rows[slot].clone();
    }
    eprintln!("S3_LOCAL_BASE_SOURCE captured_native_write_trace");"""
    updated = replace_once(updated, old_reconstruction, new_reconstruction)
    old_inversion = """    let mut reconstructed_sum = SecureField::zero();
    for entry in &entries {
        assert_eq!(entry.relation, "CommonLookupElements");
        let denominator: SecureField = common_lookup.combine(&entry.values);
        assert_ne!(denominator, SecureField::zero(), "zero local LogUp denominator");
        let m = SecureField::from_m31(
            entry.mult, M31::zero(), M31::zero(), M31::zero(),
        );
        reconstructed_sum += m * denominator.inverse();
    }"""
    new_inversion = """    // The 65536-row XOR8 table yields two relations per row. Batch inverse
    // requires one inversion for the entire source-derived denominator set,
    // preserving exact QM31 arithmetic and avoiding a 120s per-entry loop.
    assert_eq!(entries.len(), 131072, "pinned XOR8 relation count changed");
    let denominators: Vec<SecureField> = entries.iter().map(|entry| {
        assert_eq!(entry.relation, "CommonLookupElements");
        let denominator: SecureField = common_lookup.combine(&entry.values);
        assert_ne!(denominator, SecureField::zero(), "zero local LogUp denominator");
        denominator
    }).collect();
    let inverses = SecureField::batch_inverse(&denominators);
    assert_eq!(inverses.len(), entries.len());
    let mut reconstructed_sum = SecureField::zero();
    for (entry, inverse) in entries.iter().zip(inverses.iter()) {
        let m = SecureField::from_m31(
            entry.mult, M31::zero(), M31::zero(), M31::zero(),
        );
        reconstructed_sum += m * *inverse;
    }"""
    updated = replace_once(updated, old_inversion, new_inversion)
    updated += r"""

/// Diagnostic-only, immutable source capture before native base commitment.
/// The original `extend_evals(columns)` receives precisely the same values.
static XOR8_SOURCE: std::sync::OnceLock<Vec<Vec<BaseField>>> =
    std::sync::OnceLock::new();

pub fn capture_xor8_source(
    columns: &[stwo::prover::poly::circle::CircleEvaluation<
        SimdBackend, BaseField, stwo::prover::poly::BitReversedOrder,
    >],
) {
    let domain = CanonicCoset::new(16).circle_domain();
    assert_eq!(columns.len(), 2, "pinned native XOR8 trace must have two columns");
    let mut rows = Vec::with_capacity(2);
    for column in columns {
        assert_eq!(column.domain, domain, "XOR8 base column domain is noncanonical");
        let data = column.values.to_cpu();
        assert_eq!(data.len(), 65536, "XOR8 base source row count changed");
        rows.push(data);
    }
    assert!(XOR8_SOURCE.set(rows).is_ok(), "XOR8 source captured twice");
}
"""
    return updated


def instrument_witness(source: str) -> str:
    old = """        let (verify_bitwise_xor_8_claim, verify_bitwise_xor_8_interaction_gen) = self
            .verify_bitwise_xor_8
            .map(|gen| {
                let (trace, claim, interaction_gen) = gen.write_trace();
                tree_builder.extend_evals(trace.to_evals());
                (claim, interaction_gen)
            })
            .unzip();"""
    new = """        let (verify_bitwise_xor_8_claim, verify_bitwise_xor_8_interaction_gen) = self
            .verify_bitwise_xor_8
            .map(|gen| {
                let (trace, claim, interaction_gen) = gen.write_trace();
                let original_columns = trace.to_evals();
                #[cfg(feature = "relation-tracker")]
                crate::debug_tools::relation_tracker::capture_xor8_source(&original_columns);
                tree_builder.extend_evals(original_columns);
                (claim, interaction_gen)
            })
            .unzip();"""
    return replace_once(source, old, new)


def instrument_prover(source: str) -> str:
    patched = base_prover(source)
    if patched.count("track_local_range_check_11_relations") != 2:
        raise ValueError("source-pinned native local tracker references changed")
    patched = patched.replace("track_local_range_check_11_relations", TRACKER_NAME)
    patched = replace_once(
        patched, "interaction_claim.range_check_11",
        "interaction_claim.verify_bitwise_xor_8",
    )
    patched = replace_once(
        patched, '"missing native range_check_11 claim"',
        '"missing native verify_bitwise_xor_8 claim"',
    )
    patched = replace_once(
        patched,
        "S3_LOCAL_SCOPE component=range_check_11 partial=true",
        SCOPE_LABEL,
    )
    patched = replace_once(
        patched,
        """                &commitment_scheme, &component_builder, &claim.public_data,
                &interaction_elements,""",
        """                &commitment_scheme, &component_builder, &claim.public_data,
                &preprocessed_trace,
                &interaction_elements,""",
    )
    if patched.count("debug_assert_eq!(") != source.count("debug_assert_eq!(") + 1:
        raise ValueError("upstream global lookup assertion changed")
    return patched


def instrument_tracker(source: str) -> str:
    base = base_tracker(source)
    if not base.endswith(LOCAL_RUST):
        raise ValueError("upstream local tracker append point changed")
    return base[:-len(LOCAL_RUST)] + xor_rust()


def prepare(root: Path, output: Path) -> dict:
    root = root.resolve()
    actual = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    if actual != REV:
        raise ValueError(f"pinned upstream Git revision changed: {actual}")
    files = []
    patches = []
    for path, transform in [
        (SOURCE, instrument_prover),
        (TRACKER_SOURCE, instrument_tracker),
        (WITNESS_SOURCE, instrument_witness),
    ]:
        original = subprocess.check_output(
            ["git", "-C", str(root), "show", f"HEAD:{path}"], text=True)
        if (root / path).read_text() != original:
            raise ValueError(f"upstream source was modified before audit: {path}")
        changed = transform(original)
        patches.append("".join(difflib.unified_diff(
            original.splitlines(keepends=True),
            changed.splitlines(keepends=True),
            fromfile="a/"+path,
            tofile="b/"+path,
        )))
        files.append((path, original, changed))
    # Validate both sources before modifying either file in the ephemeral checkout.
    for path, _, changed in files:
        (root / path).write_text(changed)
    patch = "".join(patches)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(patch)
    return {
        "stage":"S3m component-local verify_bitwise_xor_8 LogUp audit",
        "source_revision":REV,
        "target_component":COMPONENT,
        "rows":ROWS,
        "expected_source_entries":ENTRIES,
        "expected_preprocessed_columns":PREPROCESSED,
        "expected_base_columns":BASE,
        "batch_inversion":True,
        "preprocessed_source":"same pinned PreProcessedTrace object used by native commitment",
        "base_source":"exact source rows captured before source-native extend_evals commitment",
        "base_row_count_check":65536,
        "producer_write_trace_transform":"feature-gated observation only; original native trace columns committed unchanged",
        "preprocessed_row_domain_check":True,
        "source_file_hashes":[{
            "path":path,
            "original_sha256":hashlib.sha256(before.encode()).hexdigest(),
            "diagnostic_sha256":hashlib.sha256(after.encode()).hexdigest(),
        } for path,before,after in files],
        "patch_sha256":hashlib.sha256(patch.encode()).hexdigest(),
        "native_global_lookup_assertion_preserved":True,
        "relation_inventory_complete":False,
        "native_stark_proof_verified":False,
        "bitcoin_settlement_authorized":False,
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--upstream", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    print(json.dumps(prepare(args.upstream, args.output), indent=2))


if __name__ == "__main__":
    main()
