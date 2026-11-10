#!/usr/bin/env python3
"""Source-pinned caller-AIR audit of the XOR8 zero tuple; native proof stays rejected.

S3n attributed all 4,096 zero-input XOR8 requests to bitwise_builtin by counting
producer calls. This stage instead evaluates the pinned bitwise_builtin AIR itself,
through upstream's unmodified relation evaluator, on the original 4,096 base rows.
Those rows are copied from the exact evaluations handed to the native tree builder
(canonical circle-domain, bit-reversed order), before interpolation or commitment.

Composed on top of the S3m local XOR8 table audit, whose reconstructed signed table
entries are kept so the caller and the table are balanced in one process:
  * an exact signed multiplicity ledger modulo M31 per XOR8 tuple, and
  * the same two sides summed as QM31 under the native interaction challenge.
The component's complete LogUp sum (all four relation families it uses) is compared
with its native interaction claim, so no partial sum is held against a full claim.
The original global lookup assertion is unchanged and still rejects the proof.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
from pathlib import Path
import subprocess

from instrument_local_relations import REV, SOURCE, TRACKER_SOURCE
from instrument_xor8_relations import (
    WITNESS_SOURCE, instrument_prover as xor8_prover,
    instrument_tracker as xor8_tracker, instrument_witness as xor8_witness,
    replace_once,
)

COMPONENT = "bitwise_builtin"
LOG_SIZE = 12
ROWS = 1 << LOG_SIZE
BASE_COLUMNS = 89
PREPROCESSED_COLUMNS = 1
XOR8_TAG = 112558620
XOR8_SECOND_TAG = 521092554
# Pinned bitwise_builtin::RELATION_USES_PER_ROW, with the relation tags the producer
# broadcasts (witness/components/bitwise_builtin.rs) and the AIR evaluates.
FAMILIES = {
    1444891767: ("MemoryAddressToId", 5),
    1662111297: ("MemoryIdToBig", 5),
    95781001: ("VerifyBitwiseXor_9", 27),
    XOR8_TAG: ("VerifyBitwiseXor_8", 1),
}
ENTRIES_PER_ROW = sum(uses for _, uses in FAMILIES.values())
ENTRIES = ROWS * ENTRIES_PER_ROW
TABLE_ENTRIES = 131072
MAX_PRINTED_GROUPS = 64
NEGATIVE_CONTROLS = (
    "missing_caller_entry", "duplicated_caller_entry", "altered_caller_tuple",
    "altered_caller_multiplicity", "missing_table_entry", "duplicated_table_entry",
)
BEGIN = "S3_CALLER_BEGIN component=bitwise_builtin"
END = "S3_CALLER_END"

BITWISE_OLD = """        let (bitwise_builtin_claim, bitwise_builtin_interaction_gen) = self
            .bitwise_builtin
            .map(|gen| {
                let (trace, claim, interaction_gen) = gen.write_trace(
                    self.memory_address_to_id.as_ref().unwrap(),
                    self.memory_id_to_big.as_ref().unwrap(),
                    self.verify_bitwise_xor_9.as_ref().unwrap(),
                    self.verify_bitwise_xor_8.as_ref().unwrap(),
                );
                tree_builder.extend_evals(trace.to_evals());
                (claim, interaction_gen)
            })
            .unzip();"""
BITWISE_NEW = """        let (bitwise_builtin_claim, bitwise_builtin_interaction_gen) = self
            .bitwise_builtin
            .map(|gen| {
                let (trace, claim, interaction_gen) = gen.write_trace(
                    self.memory_address_to_id.as_ref().unwrap(),
                    self.memory_id_to_big.as_ref().unwrap(),
                    self.verify_bitwise_xor_9.as_ref().unwrap(),
                    self.verify_bitwise_xor_8.as_ref().unwrap(),
                );
                let original_columns = trace.to_evals();
                #[cfg(feature = "relation-tracker")]
                crate::debug_tools::relation_tracker::capture_bitwise_builtin_source(
                    &original_columns,
                );
                tree_builder.extend_evals(original_columns);
                (claim, interaction_gen)
            })
            .unzip();"""

STASH_OLD = """    eprintln!(
        "S3_LOCAL_LOGUP recomputed={:?} claimed={:?} matches={}",
        reconstructed_sum, claimed_sum, reconstructed_sum == claimed_sum
    );
    RelationSummary::summarize_relations(&entries).cleaned()"""
STASH_NEW = """    eprintln!(
        "S3_LOCAL_LOGUP recomputed={:?} claimed={:?} matches={}",
        reconstructed_sum, claimed_sum, reconstructed_sum == claimed_sum
    );
    // Diagnostic-only: keep the table's signed entries for the S3o caller ledger.
    let table_entries: Vec<(Vec<M31>, M31)> =
        entries.iter().map(|e| (e.values.clone(), e.mult)).collect();
    assert!(XOR8_TABLE_ENTRIES.set(table_entries).is_ok(), "XOR8 table entries stashed twice");
    RelationSummary::summarize_relations(&entries).cleaned()"""

CALL_OLD = """            let summary = track_local_verify_bitwise_xor_8_relations(
                &commitment_scheme, &component_builder, &claim.public_data,
                &preprocessed_trace,
                &interaction_elements,
                interaction_claim.verify_bitwise_xor_8
                    .as_ref().expect("missing native verify_bitwise_xor_8 claim").claimed_sum,
            );
"""
CALL_NEW = CALL_OLD + """            crate::debug_tools::relation_tracker::track_bitwise_builtin_xor8_caller(
                &commitment_scheme, &component_builder, &preprocessed_trace,
                &interaction_elements,
                interaction_claim.bitwise_builtin
                    .as_ref().expect("missing native bitwise_builtin claim").claimed_sum,
            );
"""

CALLER_RUST = r"""

/// Diagnostic-only copy of the original bitwise_builtin base rows. They come from the
/// exact evaluations passed to the native tree builder, captured before it
/// interpolates or commits them; the commitment input is not modified.
static BITWISE_BUILTIN_SOURCE: std::sync::OnceLock<Vec<Vec<BaseField>>> =
    std::sync::OnceLock::new();

/// Diagnostic-only signed (tuple, multiplicity) entries of the verify_bitwise_xor_8
/// table, evaluated by its local audit and kept for the caller-side ledger.
static XOR8_TABLE_ENTRIES: std::sync::OnceLock<Vec<(Vec<M31>, M31)>> =
    std::sync::OnceLock::new();

pub fn capture_bitwise_builtin_source(
    columns: &[stwo::prover::poly::circle::CircleEvaluation<
        SimdBackend, BaseField, stwo::prover::poly::BitReversedOrder,
    >],
) {
    assert_eq!(columns.len(), 89, "pinned bitwise_builtin trace must have 89 columns");
    let log_size = columns[0].domain.log_size();
    let domain = CanonicCoset::new(log_size).circle_domain();
    let mut rows = Vec::with_capacity(columns.len());
    for column in columns {
        assert_eq!(column.domain, domain, "bitwise_builtin base column domain is noncanonical");
        let data = column.values.to_cpu();
        assert_eq!(data.len(), 1usize << log_size, "bitwise_builtin base row count changed");
        rows.push(data);
    }
    assert!(BITWISE_BUILTIN_SOURCE.set(rows).is_ok(), "bitwise_builtin source captured twice");
}

/// Evaluates the pinned bitwise_builtin AIR on its original rows with upstream's
/// relation evaluator, then balances its positive XOR8 entries against the XOR8 table.
pub fn track_bitwise_builtin_xor8_caller<MC: MerkleChannel>(
    commitment_scheme: &CommitmentSchemeProver<'_, SimdBackend, MC>,
    components: &CairoComponents,
    preprocessed_trace: &stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTrace,
    common_lookup: &cairo_air::relations::CommonLookupElements,
    claimed_sum: stwo::core::fields::qm31::SecureField,
) where
    SimdBackend: BackendForChannel<MC>,
{
    use std::collections::{BTreeMap, BTreeSet};
    use stwo::core::air::Component as _;
    use stwo::core::fields::m31::P;
    use stwo::core::fields::{qm31::SecureField, FieldExpOps};
    use stwo_constraint_framework::{Relation, ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX};

    const XOR8_TAG: u32 = 112558620;
    let qm = |value: SecureField| {
        let limbs = value.to_m31_array();
        format!("{},{},{},{}", limbs[0].0, limbs[1].0, limbs[2].0, limbs[3].0)
    };
    let tuple_text = |values: &[u32]| {
        values.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(",")
    };
    let denominator = |values: &[M31]| -> SecureField {
        let value: SecureField = common_lookup.combine(values);
        assert_ne!(value, SecureField::zero(), "zero caller LogUp denominator");
        value
    };
    let term = |mult: M31, inverse: SecureField| {
        SecureField::from_m31(mult, M31::zero(), M31::zero(), M31::zero()) * inverse
    };

    let component = components.bitwise_builtin.as_ref()
        .expect("bitwise_builtin must be active in this pinned Shinigami fixture");
    let logs = component.trace_log_degree_bounds();
    let log_size = logs[ORIGINAL_TRACE_IDX][0];
    assert_eq!(logs[ORIGINAL_TRACE_IDX], vec![log_size; 89]);
    assert_eq!(component.preprocessed_column_indices().len(), 1);
    let rows = 1usize << log_size;

    let source = commitment_scheme.trace().polys;
    assert_eq!(source.len(), 3);
    let mut base_indices = Vec::<usize>::new();
    for span in component.trace_locations() {
        if span.tree_index == ORIGINAL_TRACE_IDX {
            base_indices.extend(span.col_start..span.col_end);
        }
    }
    base_indices.sort_unstable();
    base_indices.dedup();
    let captured = BITWISE_BUILTIN_SOURCE.get()
        .expect("bitwise_builtin original base rows were never captured");
    assert_eq!(base_indices.len(), 89);
    assert_eq!(captured.len(), 89);
    assert!(base_indices.iter().all(|&i| i < source[ORIGINAL_TRACE_IDX].len()),
            "bitwise_builtin column index out of bounds");

    let mut reconstructed: TreeVec<Vec<Vec<BaseField>>> = TreeVec::new(vec![
        vec![Vec::new(); source[PREPROCESSED_TRACE_IDX].len()],
        vec![Vec::new(); source[ORIGINAL_TRACE_IDX].len()],
        Vec::new(),
    ]);
    for (slot, &index) in base_indices.iter().enumerate() {
        assert_eq!(captured[slot].len(), rows);
        reconstructed[ORIGINAL_TRACE_IDX][index] = captured[slot].clone();
    }
    // The one preprocessed column is the pinned sequence column of the same domain,
    // generated by the same PreProcessedTrace object the native commitment used.
    let pre_index = component.preprocessed_column_indices()[0];
    let column = preprocessed_trace.columns.get(pre_index)
        .expect("source-pinned bitwise_builtin preprocessing index is out of range");
    assert_eq!(column.id().id, format!("seq_{}", log_size), "wrong bitwise_builtin sequence column");
    assert_eq!(column.log_size(), log_size, "wrong source preprocessed domain");
    let sequence = column.gen_column_simd().values.to_cpu();
    assert_eq!(sequence.len(), rows);
    reconstructed[PREPROCESSED_TRACE_IDX][pre_index] = sequence;

    eprintln!("S3_CALLER_BEGIN component=bitwise_builtin");
    eprintln!("S3_CALLER_SHAPE rows={} base_columns={} preprocessed_columns={}",
              rows, base_indices.len(), 1);
    let mut digest_bytes = Vec::<u8>::with_capacity(90 * rows * 4);
    for column_rows in captured.iter().chain(std::iter::once(&reconstructed[PREPROCESSED_TRACE_IDX][pre_index])) {
        for value in column_rows {
            digest_bytes.extend_from_slice(&value.0.to_le_bytes());
        }
    }
    let mut hasher = stwo::core::vcs::blake2_hash::Blake2sHasher::new();
    hasher.update(&digest_bytes);
    eprintln!("S3_CALLER_SOURCE_DIGEST blake2s={}", hasher.finalize());

    let view: TreeVec<Vec<&Vec<BaseField>>> = TreeVec::new(
        reconstructed.iter().map(|cols| cols.iter().collect()).collect()
    );
    // Upstream's own evaluator: exact AIR, bit-reversed masks, no re-implementation.
    let entries = add_to_relation_entries(component, &view);
    assert!(!entries.is_empty() && entries.len() % rows == 0,
            "bitwise_builtin must yield the same number of relation entries per row");
    let per_row = entries.len() / rows;
    let mut rows_with_one_xor8 = 0usize;
    for row_entries in entries.chunks(per_row) {
        let xor8_in_row = row_entries.iter().filter(|e| e.values[0].0 == XOR8_TAG).count();
        if xor8_in_row == 1 { rows_with_one_xor8 += 1; }
    }
    eprintln!("S3_CALLER_ENTRIES total={} per_row={} rows_with_one_xor8={}",
              entries.len(), per_row, rows_with_one_xor8);

    let denominators: Vec<SecureField> = entries.iter().map(|entry| {
        assert_eq!(entry.relation, "CommonLookupElements");
        denominator(&entry.values)
    }).collect();
    let inverses = SecureField::batch_inverse(&denominators);
    assert_eq!(inverses.len(), entries.len());

    struct Family { entries: u64, mult_sum: u64, tuples: BTreeSet<Vec<u32>>, sum: SecureField }
    let mut families: BTreeMap<u32, Family> = BTreeMap::new();
    let mut total = SecureField::zero();
    for (entry, inverse) in entries.iter().zip(inverses.iter()) {
        let contribution = term(entry.mult, *inverse);
        total += contribution;
        let family = families.entry(entry.values[0].0).or_insert_with(|| Family {
            entries: 0, mult_sum: 0, tuples: BTreeSet::new(), sum: SecureField::zero(),
        });
        family.entries += 1;
        family.mult_sum = (family.mult_sum + entry.mult.0 as u64) % P as u64;
        family.tuples.insert(entry.values.iter().map(|v| v.0).collect());
        family.sum += contribution;
    }
    let mut family_total = SecureField::zero();
    for (tag, family) in &families {
        family_total += family.sum;
        eprintln!(
            "S3_CALLER_FAMILY tag={} entries={} distinct_tuples={} mult_sum_mod_p={} qm31={}",
            tag, family.entries, family.tuples.len(), family.mult_sum, qm(family.sum)
        );
    }
    eprintln!(
        "S3_CALLER_LOGUP recomputed={} claimed={} family_sum={} matches={} family_sum_matches={}",
        qm(total), qm(claimed_sum), qm(family_total),
        total == claimed_sum, family_total == claimed_sum
    );

    // Positive XOR8 entries produced by the AIR, grouped by exact (tuple, multiplicity).
    let caller: Vec<(Vec<M31>, M31)> = entries.iter()
        .filter(|e| e.values[0].0 == XOR8_TAG)
        .map(|e| (e.values.clone(), e.mult))
        .collect();
    let mut caller_groups: BTreeMap<(Vec<u32>, u32), u64> = BTreeMap::new();
    for (values, mult) in &caller {
        *caller_groups.entry((values.iter().map(|v| v.0).collect(), mult.0)).or_insert(0) += 1;
    }
    for ((values, mult), count) in caller_groups.iter().take(64) {
        eprintln!("S3_XOR8_CALLER_ENTRY tuple={} mult={} count={}", tuple_text(values), mult, count);
    }
    eprintln!("S3_XOR8_CALLER_LINES printed={} distinct={} truncated={}",
              caller_groups.len().min(64), caller_groups.len(), caller_groups.len() > 64);

    // The XOR8 table's signed entries from the S3m local audit, same process.
    let table = XOR8_TABLE_ENTRIES.get()
        .expect("XOR8 table entries were not kept by the local audit");
    let nonzero_table: Vec<&(Vec<M31>, M31)> = table.iter().filter(|(_, m)| !m.is_zero()).collect();
    let mut table_groups: BTreeMap<(Vec<u32>, u32), u64> = BTreeMap::new();
    for (values, mult) in &nonzero_table {
        *table_groups.entry((values.iter().map(|v| v.0).collect(), mult.0)).or_insert(0) += 1;
    }
    eprintln!("S3_XOR8_TABLE_SHAPE entries={} zero_mult={} nonzero={}",
              table.len(), table.len() - nonzero_table.len(), nonzero_table.len());
    for ((values, mult), count) in table_groups.iter().take(64) {
        eprintln!("S3_XOR8_TABLE_ENTRY tuple={} mult={} count={}", tuple_text(values), mult, count);
    }
    eprintln!("S3_XOR8_TABLE_LINES printed={} distinct={} truncated={}",
              table_groups.len().min(64), table_groups.len(), table_groups.len() > 64);

    let table_denominators: Vec<SecureField> = nonzero_table.iter()
        .map(|(values, _)| denominator(values)).collect();
    let table_inverses = SecureField::batch_inverse(&table_denominators);
    let mut table_sum = SecureField::zero();
    for ((_, mult), inverse) in nonzero_table.iter().zip(table_inverses.iter()) {
        table_sum += term(*mult, *inverse);
    }
    let caller_sum = families.get(&XOR8_TAG).map(|f| f.sum).unwrap_or_else(SecureField::zero);
    let balance = caller_sum + table_sum;
    eprintln!("S3_XOR8_LEDGER_QM31 caller={} table={} total={} zero={}",
              qm(caller_sum), qm(table_sum), qm(balance), balance == SecureField::zero());

    // Exact signed multiplicity ledger modulo M31 over both sides, then deterministic
    // negative controls on the real rows: tampering must leave a nonzero tuple.
    let ledger_nonzero = |caller_side: &[(Vec<M31>, M31)], table_side: &[(Vec<M31>, M31)]| -> usize {
        let mut ledger: BTreeMap<Vec<u32>, u64> = BTreeMap::new();
        for (values, mult) in caller_side.iter().chain(table_side.iter()) {
            let slot = ledger.entry(values.iter().map(|v| v.0).collect()).or_insert(0);
            *slot = (*slot + mult.0 as u64) % P as u64;
        }
        ledger.values().filter(|net| **net != 0).count()
    };
    let baseline = ledger_nonzero(&caller, table);
    let caller_total = caller.iter().fold(0u64, |acc, (_, m)| (acc + m.0 as u64) % P as u64);
    let table_total = table.iter().fold(0u64, |acc, (_, m)| (acc + m.0 as u64) % P as u64);
    eprintln!(
        "S3_XOR8_LEDGER baseline_nonzero_tuples={} caller_entries={} caller_mult_total_mod_p={} table_mult_total_mod_p={}",
        baseline, caller.len(), caller_total, table_total
    );
    let first_nonzero = table.iter().position(|(_, m)| !m.is_zero())
        .expect("XOR8 table has no nonzero-multiplicity entry");
    let mut missing_caller = caller.clone();
    missing_caller.pop();
    let mut duplicated_caller = caller.clone();
    duplicated_caller.push(caller[0].clone());
    let mut altered_tuple = caller.clone();
    let last = altered_tuple[0].0.len() - 1;
    altered_tuple[0].0[last] += M31::one();
    let mut altered_mult = caller.clone();
    altered_mult[0].1 += M31::one();
    let mut missing_table = table.clone();
    missing_table.remove(first_nonzero);
    let mut duplicated_table = table.clone();
    duplicated_table.push(table[first_nonzero].clone());
    let controls = [
        ("missing_caller_entry", ledger_nonzero(&missing_caller, table)),
        ("duplicated_caller_entry", ledger_nonzero(&duplicated_caller, table)),
        ("altered_caller_tuple", ledger_nonzero(&altered_tuple, table)),
        ("altered_caller_multiplicity", ledger_nonzero(&altered_mult, table)),
        ("missing_table_entry", ledger_nonzero(&caller, &missing_table)),
        ("duplicated_table_entry", ledger_nonzero(&caller, &duplicated_table)),
    ];
    for (name, nonzero) in controls {
        eprintln!("S3_XOR8_NEGATIVE name={} nonzero_tuples={} detected={}", name, nonzero, nonzero > 0);
    }
    eprintln!("S3_CALLER_END");
}
"""


def instrument_prover(source: str) -> str:
    patched = replace_once(xor8_prover(source), CALL_OLD, CALL_NEW)
    if patched.count("track_bitwise_builtin_xor8_caller") != 1:
        raise ValueError("bitwise_builtin caller call must appear exactly once")
    if patched.count("debug_assert_eq!(") != source.count("debug_assert_eq!(") + 1:
        raise ValueError("upstream global lookup assertion changed")
    return patched


def instrument_tracker(source: str) -> str:
    patched = replace_once(xor8_tracker(source), STASH_OLD, STASH_NEW)
    return patched + CALLER_RUST


def instrument_witness(source: str) -> str:
    patched = replace_once(xor8_witness(source), BITWISE_OLD, BITWISE_NEW)
    if patched.count("capture_bitwise_builtin_source(") != 1:
        raise ValueError("bitwise_builtin source capture must appear exactly once")
    if patched.count("tree_builder.extend_evals(original_columns);") != 2:
        raise ValueError("native tree-builder commitment calls changed")
    return patched


def prepare(root: Path, destination: Path) -> dict:
    root = root.resolve()
    actual = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    if actual != REV:
        raise ValueError(f"upstream revision changed: {actual}")
    patches = []
    updated = []
    for path, transform in (
        (SOURCE, instrument_prover),
        (TRACKER_SOURCE, instrument_tracker),
        (WITNESS_SOURCE, instrument_witness),
    ):
        original = subprocess.check_output(
            ["git", "-C", str(root), "show", f"HEAD:{path}"], text=True)
        if (root / path).read_text() != original:
            raise ValueError(f"upstream file was already modified: {path}")
        modified = transform(original)
        patches.append("".join(difflib.unified_diff(
            original.splitlines(keepends=True),
            modified.splitlines(keepends=True),
            fromfile="a/" + path, tofile="b/" + path,
        )))
        updated.append((path, original, modified))
    # Nothing changes until the complete three-file source pin has passed.
    for path, _, modified in updated:
        (root / path).write_text(modified)
    patch = "".join(patches)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(patch)
    return {
        "stage": "S3o source-pinned bitwise_builtin caller-AIR XOR8 cancellation",
        "upstream_revision": REV,
        "target_component": COMPONENT,
        "rows": ROWS,
        "base_columns_captured": BASE_COLUMNS,
        "preprocessed_columns": PREPROCESSED_COLUMNS,
        "expected_caller_entries": ENTRIES,
        "relation_families": {str(tag): {"name": name, "uses_per_row": uses}
                              for tag, (name, uses) in sorted(FAMILIES.items())},
        "selected_relation_tags": {"0": XOR8_TAG, "1": XOR8_SECOND_TAG},
        "selected_tuple": [XOR8_TAG, 0, 0, 0],
        "air_evaluator": "upstream stwo_constraint_framework::relation_tracker::add_to_relation_entries",
        "base_source": "exact 89 base columns captured at CairoClaimGenerator.write_trace before unchanged tree_builder.extend_evals",
        "composed_with": "S3m verify_bitwise_xor_8 local audit (signed table entries kept in process)",
        "source_file_hashes": [{
            "path": path,
            "before_sha256": hashlib.sha256(original.encode()).hexdigest(),
            "diagnostic_sha256": hashlib.sha256(modified.encode()).hexdigest(),
        } for path, original, modified in updated],
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
