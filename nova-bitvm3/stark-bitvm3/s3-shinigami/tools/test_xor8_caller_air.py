"""Proof-free checks for the bitwise_builtin caller-AIR XOR8 ledger and its patch shape."""
from __future__ import annotations
from pathlib import Path
import unittest

from instrument_xor8_caller_air import (
    BITWISE_NEW, BITWISE_OLD, CALL_NEW, CALL_OLD, CALLER_RUST, ENTRIES, ENTRIES_PER_ROW,
    FAMILIES, NEGATIVE_CONTROLS, ROWS, STASH_NEW, STASH_OLD, XOR8_TAG,
    instrument_prover, instrument_tracker, instrument_witness,
)
from summarize_lookup import modadd
from summarize_xor8_caller_air import (
    FROZEN, P, ZERO_TUPLE, ledger_nonzero, negative_controls, parse, parse_caller, signed,
)
from test_xor8_relations import PROVER, TRACKER, WITNESS, native_log, native_report

Z = ZERO_TUPLE
FAMILY_QM = {
    1444891767: (1, 2, 3, 4),
    1662111297: (5, 6, 7, 8),
    95781001: (9, 10, 11, 12),
    XOR8_TAG: (11, 22, 33, 44),
}
DIGEST = "ab" * 32
SYNTHETIC_FROZEN = {"component_claim": modadd(*FAMILY_QM.values()), "source_digest": DIGEST}


def qm(v):
    return ",".join(str(x) for x in v)


def caller_block(*, caller=((Z, 1, 4096),), table=((Z, P - 4096, 1),), zero_mult=None,
                 family_qm=None, negatives=None, claimed=None, q_total=None):
    family_qm = dict(FAMILY_QM if family_qm is None else family_qm)
    total_family = modadd(*family_qm.values())
    claimed = total_family if claimed is None else claimed
    negatives = negative_controls(list(caller), list(table)) if negatives is None else negatives
    table_qm = tuple((P - x) % P for x in family_qm[XOR8_TAG])
    q_total = modadd(family_qm[XOR8_TAG], table_qm) if q_total is None else q_total
    nonzero = sum(c for _, _, c in table)
    zero_mult = 131072 - nonzero if zero_mult is None else zero_mult
    net = ledger_nonzero(list(caller), list(table))
    caller_total = sum(m * c for _, m, c in caller) % P
    table_total = sum(m * c for _, m, c in table) % P
    lines = ["S3_CALLER_BEGIN component=bitwise_builtin",
             f"S3_CALLER_SHAPE rows={ROWS} base_columns=89 preprocessed_columns=1",
             f"S3_CALLER_SOURCE_DIGEST blake2s={DIGEST}",
             f"S3_CALLER_ENTRIES total={ENTRIES} per_row={ENTRIES_PER_ROW} rows_with_one_xor8={ROWS}"]
    for tag, (name, uses) in sorted(FAMILIES.items()):
        entries = ROWS * uses
        lines.append(f"S3_CALLER_FAMILY tag={tag} entries={entries} distinct_tuples=1 "
                     f"mult_sum_mod_p={entries % P} qm31={qm(family_qm[tag])}")
    flag = lambda x: "true" if x else "false"
    lines.append(f"S3_CALLER_LOGUP recomputed={qm(total_family)} claimed={qm(claimed)} "
                 f"family_sum={qm(total_family)} matches={flag(total_family == claimed)} "
                 f"family_sum_matches={flag(total_family == claimed)}")
    for t, m, c in caller:
        lines.append(f"S3_XOR8_CALLER_ENTRY tuple={qm(t)} mult={m} count={c}")
    lines.append(f"S3_XOR8_CALLER_LINES printed={len(caller)} distinct={len(caller)} truncated=false")
    lines.append(f"S3_XOR8_TABLE_SHAPE entries=131072 zero_mult={zero_mult} nonzero={nonzero}")
    for t, m, c in table:
        lines.append(f"S3_XOR8_TABLE_ENTRY tuple={qm(t)} mult={m} count={c}")
    lines.append(f"S3_XOR8_TABLE_LINES printed={len(table)} distinct={len(table)} truncated=false")
    lines.append(f"S3_XOR8_LEDGER_QM31 caller={qm(family_qm[XOR8_TAG])} table={qm(table_qm)} "
                 f"total={qm(q_total)} zero={flag(q_total == (0, 0, 0, 0))}")
    lines.append(f"S3_XOR8_LEDGER baseline_nonzero_tuples={len(net)} caller_entries={ROWS} "
                 f"caller_mult_total_mod_p={caller_total} table_mult_total_mod_p={table_total}")
    for name in NEGATIVE_CONTROLS:
        lines.append(f"S3_XOR8_NEGATIVE name={name} nonzero_tuples={negatives[name]} "
                     f"detected={flag(negatives[name] > 0)}")
    lines.append("S3_CALLER_END")
    return "\n".join(lines) + "\n"


def full_log(block=None):
    base = native_log(truncated=False).replace(
        "  [112558620, 20, 31, 11] -> 2147483646", "  [112558620] -> 2147479551")
    return (caller_block() if block is None else block) + base


def with_stage_resources(report, elapsed=19.2, rss=1_606_266_880):
    return {**report, "rss_budget_mib": 4096, "deadline_seconds": 120,
            "stages": [{**report["stages"][0], "elapsed_seconds": elapsed,
                        "peak_rss_bytes": rss, "peak_vms_bytes": rss + 1}]}


class CallerPatchTests(unittest.TestCase):
    def test_native_commitment_input_is_unchanged(self):
        patched = instrument_witness(WITNESS + "\n" + BITWISE_OLD)
        self.assertIn("let original_columns = trace.to_evals();", patched)
        self.assertEqual(patched.count("tree_builder.extend_evals(original_columns);"), 2)
        self.assertIn("capture_bitwise_builtin_source(\n", patched)
        self.assertNotIn("tree_builder.extend_evals(trace.to_evals());", patched)
        self.assertIn('#[cfg(feature = "relation-tracker")]', BITWISE_NEW)

    def test_pinned_source_changes_rejected(self):
        base = WITNESS + "\n" + BITWISE_OLD
        for bad in (
            base.replace("self.verify_bitwise_xor_8.as_ref().unwrap(),", "other_state,", 2),
            base + "\n" + BITWISE_OLD,
            WITNESS,
            base.replace(".bitwise_builtin\n", ".other_builtin\n"),
        ):
            with self.assertRaises(ValueError):
                instrument_witness(bad)
        with self.assertRaises(ValueError):
            instrument_prover(PROVER.replace("    // Validate lookup argument.", "    // new."))
        with self.assertRaises(ValueError):
            instrument_tracker(TRACKER.replace("track_cairo_relations<", "track_wrong<"))
        with self.assertRaises(ValueError):
            instrument_tracker(TRACKER + TRACKER)

    def test_prover_call_follows_local_table_audit_and_keeps_native_assertion(self):
        patched = instrument_prover(PROVER)
        self.assertEqual(patched.count("track_bitwise_builtin_xor8_caller("), 1)
        self.assertLess(patched.index("track_local_verify_bitwise_xor_8_relations("),
                        patched.index("track_bitwise_builtin_xor8_caller("))
        self.assertIn("interaction_claim.bitwise_builtin", patched)
        self.assertIn("#[cfg(not(feature = \"relation-tracker\"))]", patched)
        self.assertEqual(patched.count("debug_assert_eq!("), 2)
        self.assertTrue(CALL_NEW.startswith(CALL_OLD))

    def test_tracker_keeps_table_entries_without_changing_the_local_sum(self):
        patched = instrument_tracker(TRACKER)
        self.assertEqual(patched.count("XOR8_TABLE_ENTRIES.set(table_entries)"), 1)
        self.assertLess(patched.index("S3_LOCAL_LOGUP recomputed"),
                        patched.index("XOR8_TABLE_ENTRIES.set(table_entries)"))
        self.assertTrue(patched.endswith(CALLER_RUST))
        self.assertIn("reconstructed_sum += m * *inverse;", patched)
        self.assertIn("RelationSummary::summarize_relations(&entries).cleaned()", STASH_NEW)
        self.assertEqual(STASH_NEW.replace(STASH_NEW[STASH_NEW.index("    // Diagnostic-only"):
                                                      STASH_NEW.index("    RelationSummary::")], ""),
                         STASH_OLD)

    def test_rust_uses_upstream_evaluator_on_captured_rows(self):
        code = CALLER_RUST
        self.assertIn("add_to_relation_entries(component, &view)", code)
        self.assertIn("BITWISE_BUILTIN_SOURCE.get()", code)
        self.assertIn("assert_eq!(logs[ORIGINAL_TRACE_IDX], vec![log_size; 89]);", code)
        self.assertIn("format!(\"seq_{}\", log_size)", code)
        self.assertIn("column.gen_column_simd().values.to_cpu()", code)
        self.assertIn("assert_eq!(column.domain, domain", code)
        self.assertIn("SecureField::batch_inverse(&denominators)", code)
        self.assertIn("const XOR8_TAG: u32 = 112558620;", code)
        for name in NEGATIVE_CONTROLS:
            self.assertIn(f'"{name}"', code)
        self.assertNotIn("unsafe", code)
        self.assertEqual(code.count("static BITWISE_BUILTIN_SOURCE"), 1)
        self.assertEqual(code.count("static XOR8_TABLE_ENTRIES"), 1)


class LedgerTests(unittest.TestCase):
    def test_exact_balance_over_every_caller_row(self):
        self.assertEqual(ledger_nonzero([(Z, 1, 4096)], [(Z, P - 4096, 1)]), {})
        result = parse_caller(caller_block())
        self.assertTrue(result["xor8_zero_tuple_cancellation_established"])
        self.assertEqual(result["caller_xor8_signed_total"], 4096)
        self.assertEqual(result["table_xor8_signed_total"], -4096)
        self.assertEqual(result["ledger_nonzero_tuples"], 0)
        self.assertEqual(result["ledger_qm31_total"], [0, 0, 0, 0])
        self.assertTrue(result["caller_xor8_all_zero_tuple"])
        self.assertEqual(result["caller_rows_with_exactly_one_xor8_entry"], 4096)
        self.assertEqual(result["caller_relation_entries"], 155648)

    def test_mutations_leave_a_nonzero_tuple(self):
        caller, table = [(Z, 1, 4096)], [(Z, P - 4096, 1)]
        self.assertEqual(negative_controls(caller, table), {
            "missing_caller_entry": 1, "duplicated_caller_entry": 1,
            "altered_caller_tuple": 2, "altered_caller_multiplicity": 1,
            "missing_table_entry": 1, "duplicated_table_entry": 1,
        })
        altered = (XOR8_TAG, 0, 0, 1)
        self.assertEqual(set(ledger_nonzero([(Z, 1, 4095), (altered, 1, 1)], table)), {Z, altered})
        self.assertEqual(ledger_nonzero([(Z, 1, 4096)], []), {Z: 4096})
        self.assertEqual(ledger_nonzero([(Z, 1, 4096)], [(Z, P - 4096, 2)]), {Z: P - 4096})

    def test_modular_arithmetic_wraps_at_m31(self):
        self.assertEqual(ledger_nonzero([(Z, P - 1, 1)], [(Z, 1, 1)]), {})
        self.assertEqual(ledger_nonzero([(Z, P, 7)], []), {})

    def test_missing_duplicated_or_altered_lines_are_rejected(self):
        good = caller_block()
        for before, after in [
            ("mult=1 count=4096", "mult=1 count=4095"),
            ("mult=1 count=4096", "mult=1 count=4097"),
            ("mult=1 count=4096", "mult=2 count=4096"),
            ("tuple=112558620,0,0,0 mult=1", "tuple=112558620,0,0,1 mult=1"),
            ("tuple=112558620,0,0,0 mult=2147479551", "tuple=112558620,0,0,1 mult=2147479551"),
            ("mult=2147479551 count=1", "mult=2147479551 count=2"),
            ("mult=2147479551 count=1", "mult=2147479550 count=1"),
            ("S3_XOR8_TABLE_ENTRY", "S3_XOR8_TABLE_ENTRX"),
            ("S3_XOR8_CALLER_ENTRY", "S3_XOR8_CALLER_ENTRX"),
        ]:
            with self.assertRaises(ValueError, msg=before + " -> " + after):
                parse_caller(good.replace(before, after, 1))
        entry = [l for l in good.splitlines() if l.startswith("S3_XOR8_CALLER_ENTRY")][0]
        with self.assertRaises(ValueError):
            parse_caller(good.replace(entry + "\n", entry + "\n" + entry + "\n"))
        table = [l for l in good.splitlines() if l.startswith("S3_XOR8_TABLE_ENTRY")][0]
        with self.assertRaises(ValueError):
            parse_caller(good.replace(table + "\n", ""))

    def test_shape_and_family_counts_are_pinned(self):
        good = caller_block()
        for before, after in [
            (f"rows={ROWS} base_columns=89", f"rows={ROWS} base_columns=88"),
            ("preprocessed_columns=1", "preprocessed_columns=2"),
            (f"total={ENTRIES}", f"total={ENTRIES - 1}"),
            (f"rows_with_one_xor8={ROWS}", f"rows_with_one_xor8={ROWS - 1}"),
            ("tag=95781001 entries=110592", "tag=95781001 entries=110591"),
            ("tag=112558620 entries=4096", "tag=112558620 entries=4097"),
            ("tag=1444891767", "tag=1444891768"),
            ("blake2s=" + DIGEST, "blake2s=" + "g" * 64),
            ("truncated=false", "truncated=true"),
            ("S3_CALLER_END", "S3_CALLER_FIN"),
        ]:
            with self.assertRaises(ValueError, msg=before):
                parse_caller(good.replace(before, after, 1))
        with self.assertRaises(ValueError):
            parse_caller(good + good)

    def test_caller_tuple_other_than_zero_tuple_is_not_a_cancellation(self):
        other = (XOR8_TAG, 20, 31, 11)
        block = caller_block(caller=((Z, 1, 4095), (other, 1, 1)),
                             table=((Z, P - 4096, 1),))
        result = parse_caller(block)
        self.assertFalse(result["xor8_zero_tuple_cancellation_established"])
        self.assertEqual(result["ledger_nonzero_tuples"], 2)
        self.assertFalse(result["caller_xor8_all_zero_tuple"])

    def test_nonunit_or_foreign_caller_entries_rejected(self):
        with self.assertRaises(ValueError):
            parse_caller(caller_block(caller=((Z, 2, 4096),)))
        with self.assertRaises(ValueError):
            parse_caller(caller_block(caller=(((95781001, 0, 0, 0), 1, 4096),)))

    def test_component_claim_mismatch_is_not_accepted(self):
        with self.assertRaises(ValueError):
            parse_caller(caller_block(claimed=(1, 2, 3, 4)))
        with self.assertRaises(ValueError):
            parse_caller(caller_block().replace(
                "mult_sum_mod_p=110592 qm31=9,10,11,12",
                "mult_sum_mod_p=110592 qm31=9,10,11,13"))

    def test_qm31_total_and_flags_must_agree(self):
        with self.assertRaises(ValueError):
            parse_caller(caller_block(q_total=(1, 0, 0, 0)))
        good = caller_block()
        with self.assertRaises(ValueError):
            parse_caller(good.replace("zero=true", "zero=false"))
        with self.assertRaises(ValueError):
            parse_caller(good.replace("matches=true", "matches=false", 1))

    def test_negative_controls_are_independently_recomputed(self):
        good = caller_block()
        with self.assertRaises(ValueError):
            parse_caller(good.replace("name=altered_caller_tuple nonzero_tuples=2",
                                      "name=altered_caller_tuple nonzero_tuples=1"))
        with self.assertRaises(ValueError):
            parse_caller(good.replace("name=missing_table_entry nonzero_tuples=1 detected=true",
                                      "name=missing_table_entry nonzero_tuples=0 detected=false"))
        with self.assertRaises(ValueError):
            parse_caller(good.replace("S3_XOR8_NEGATIVE name=missing_table_entry", "S3_XOR8_NEGATIVE name=unknown"))
        with self.assertRaises(ValueError):
            parse_caller(good.replace("S3_XOR8_NEGATIVE name=duplicated_table_entry nonzero_tuples=1 detected=true\n", ""))

    def test_native_ledger_summary_is_cross_checked(self):
        good = caller_block()
        with self.assertRaises(ValueError):
            parse_caller(good.replace("baseline_nonzero_tuples=0", "baseline_nonzero_tuples=1"))
        with self.assertRaises(ValueError):
            parse_caller(good.replace("caller_mult_total_mod_p=4096", "caller_mult_total_mod_p=4095"))


class NativeEvidenceTests(unittest.TestCase):
    def test_full_evidence_requires_s3m_pins_and_resource_caps(self):
        report = with_stage_resources(native_report())
        result = parse(full_log(), report, SYNTHETIC_FROZEN)
        self.assertTrue(result["xor8_zero_tuple_cancellation_established"])
        self.assertTrue(result["global_native_lookup_assertion_failed"])
        self.assertFalse(result["full_global_lookup_balance_verified"])
        self.assertFalse(result["native_proof_verified"])
        self.assertFalse(result["bitcoin_settlement_authorized"])
        self.assertEqual(result["resources"]["native_exit_code"], 101)
        for report_bad in (
            with_stage_resources(native_report(), rss=5 * 1024**3),
            with_stage_resources(native_report(), elapsed=121.0),
            {**with_stage_resources(native_report()), "native_proof_verified": True},
        ):
            with self.assertRaises(ValueError):
                parse(full_log(), report_bad, SYNTHETIC_FROZEN)

    def test_native_global_rejection_is_still_required(self):
        report = with_stage_resources(native_report())
        with self.assertRaises(ValueError):
            parse(full_log().replace("1866027004", "1866027003"), report, SYNTHETIC_FROZEN)
        with self.assertRaises(ValueError):
            parse(full_log().replace("assertion left == right failed", "ok"), report, SYNTHETIC_FROZEN)
        with self.assertRaises(ValueError):
            parse(full_log().replace("matches=true", "matches=false"), report, SYNTHETIC_FROZEN)


REAL_BLOCK = (Path(__file__).parent / "fixtures" / "s3o-caller-block.txt").read_text()


class MeasuredBlockTests(unittest.TestCase):
    """The log block printed by the native diagnostic on the frozen standalone input."""

    def test_measured_block_establishes_cancellation_and_matches_ci_annotations(self):
        result = parse_caller(REAL_BLOCK)
        self.assertTrue(result["xor8_zero_tuple_cancellation_established"])
        self.assertEqual(result["caller_xor8_tuples"],
                         [dict(tuple=list(Z), mult=1, count=4096)])
        self.assertEqual(result["caller_xor8_signed_total"], 4096)
        self.assertEqual(result["table_xor8_signed_total"], -4096)
        self.assertEqual(result["ledger_nonzero_tuples"], 0)
        self.assertEqual(result["ledger_qm31_total"], [0, 0, 0, 0])
        self.assertEqual(tuple(result["component_logup_claimed"]), FROZEN["component_claim"])
        self.assertEqual(result["source_digest_blake2s"], FROZEN["source_digest"])
        self.assertEqual({t: (f["entries"], f["distinct_tuples"]) for t, f in result["caller_families"].items()},
                         {"95781001": (110592, 8481), "112558620": (4096, 1),
                          "1444891767": (20480, 20480), "1662111297": (20480, 9431)})
        self.assertEqual(result["negative_controls_nonzero_tuples"], {
            "missing_caller_entry": 1, "duplicated_caller_entry": 1,
            "altered_caller_tuple": 2, "altered_caller_multiplicity": 1,
            "missing_table_entry": 1, "duplicated_table_entry": 1})

    def test_full_parse_with_frozen_pins(self):
        result = parse(full_log(REAL_BLOCK), with_stage_resources(native_report()))
        self.assertTrue(result["xor8_zero_tuple_cancellation_established"])
        self.assertFalse(result["full_global_lookup_balance_verified"])
        with self.assertRaises(ValueError):
            parse(full_log(REAL_BLOCK.replace("6ea9ccb9", "6ea9ccb8")),
                  with_stage_resources(native_report()))
        with self.assertRaises(ValueError):
            parse(full_log(REAL_BLOCK.replace("recomputed=1876312143", "recomputed=1876312144")
                           .replace("claimed=1876312143", "claimed=1876312144")),
                  with_stage_resources(native_report()))

    def test_every_single_line_deletion_or_duplication_is_rejected(self):
        lines = REAL_BLOCK.rstrip(chr(10)).split(chr(10))
        for index in range(len(lines)):
            deleted = chr(10).join(lines[:index] + lines[index + 1:]) + chr(10)
            duplicated = chr(10).join(lines[:index + 1] + lines[index:]) + chr(10)
            for label, text in (("delete", deleted), ("duplicate", duplicated)):
                with self.assertRaises(ValueError, msg=f"{label} line {index}: {lines[index][:60]}"):
                    parse_caller(text)

    def test_every_digit_change_in_a_ledger_input_is_rejected(self):
        for before, after in [
            ("tuple=112558620,0,0,0 mult=1 count=4096", "tuple=112558620,0,0,0 mult=1 count=4095"),
            ("tuple=112558620,0,0,0 mult=2147479551 count=1", "tuple=112558620,0,0,0 mult=2147479550 count=1"),
            ("tuple=112558620,0,0,0 mult=1 count=4096", "tuple=112558620,0,0,1 mult=1 count=4096"),
            ("tag=112558620 entries=4096", "tag=112558620 entries=4095"),
            ("caller=42348298,", "caller=42348299,"),
            ("total=0,0,0,0 zero=true", "total=0,0,0,1 zero=true"),
        ]:
            self.assertEqual(REAL_BLOCK.count(before), 1, before)
            with self.assertRaises(ValueError, msg=before):
                parse_caller(REAL_BLOCK.replace(before, after))

    def test_signed_representative(self):
        self.assertEqual((signed(4096), signed(P - 4096), signed(0)), (4096, -4096, 0))


class AnnotationTests(unittest.TestCase):
    def test_summary_is_published_compactly_and_newlines_are_escaped(self):
        from annotate_caller_summary import escape, render
        summary = parse(full_log(), with_stage_resources(native_report()), SYNTHETIC_FROZEN)
        lines = render(summary, "", {"patch_sha256": "ab", "upstream_revision": "cd",
                                     "source_file_hashes": []}, None)
        self.assertTrue(all(l.startswith("::notice title=S3O") for l in lines))
        self.assertTrue(all(chr(10) not in l for l in lines))
        self.assertIn('"xor8_zero_tuple_cancellation_established":true', lines[1])
        self.assertEqual(escape("a%b" + chr(10) + "c"), "a%25b%0Ac")

    def test_missing_summary_publishes_raw_markers_as_error(self):
        from annotate_caller_summary import render
        raw = chr(10).join(["S3_CALLER_BEGIN x", "unrelated", "S3_XOR8_LEDGER y"]) + chr(10)
        lines = render(None, raw, None,
                       {"status": "one_shot_small_profile_failed",
                        "stages": [{"status": "command_failed", "returncode": 101}]})
        self.assertTrue(lines[0].startswith("::error title=S3O raw markers::"))
        self.assertIn("S3_CALLER_BEGIN x%0AS3_XOR8_LEDGER y", lines[0])
        self.assertNotIn("unrelated", lines[0])


if __name__ == "__main__":
    unittest.main()
