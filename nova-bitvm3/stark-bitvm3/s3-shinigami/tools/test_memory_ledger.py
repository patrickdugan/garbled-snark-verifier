"""Proof-free checks for the S3p whole-lookup family ledger: patch shape and strict parser."""
from __future__ import annotations
import unittest

from instrument_memory_ledger import (
    EXPECTED_FIELDS, LEDGER_CALL, MAX_TUPLES_PRINTED, NEW_CALL, OLD_CALL, TIME_BUDGET_SECONDS,
    TRACKED_TAGS, WRITE_NEW, WRITE_OLD, component_fields, instrument_prover, instrument_tracker,
    relation_names, render_rust,
)
from summarize_lookup import modadd
from summarize_memory_ledger import P, TRACKED, parse, parse_ledger
from summarize_relations import EXPECTED_RESIDUAL
from test_xor8_caller_air import with_stage_resources
from test_xor8_relations import PROVER, TRACKER, native_log, native_report

ADDR, BIG, OPCODES = 1444891767, 1662111297, 428564188
XOR9 = 95781001
RES = tuple(EXPECTED_RESIDUAL)
NEG = lambda v: tuple((P - x) % P for x in v)


def qm(v):
    return ",".join(str(x) for x in v)


def b(x):
    return "true" if x else "false"


COMPONENTS_SOURCE = (
    "pub struct CairoComponents {\n"
    + "".join(f"    pub field_{i}: Option<field_{i}::Component>,\n" for i in range(64))
    + "    pub long_field:\n        Option<long_field::Component>,\n"
    + "    pub memory_id_to_big: Vec<memory_id_to_big::Component>,\n}\n"
)
RELATIONS_SOURCE = (
    "pub const MEMORY_ADDRESS_TO_ID_RELATION_ID: M31 = M31::from_u32_unchecked(1444891767);\n"
    "pub const MEMORY_ID_TO_BIG_RELATION_ID: M31 = M31::from_u32_unchecked(1662111297);\n"
    "pub const OPCODES_RELATION_ID: M31 = M31::from_u32_unchecked(428564188);\n"
    "pub const RANGE_CHECK_9_9_RELATION_ID: M31 = M31::from_u32_unchecked(517791011);\n"
)
PROVER_WITH_WRITE = "    // base trace\n" + WRITE_OLD + PROVER


def ledger_block(*, claimed_alpha=None, public_native=None, mutate_family=None, global_sum=None,
                 skipped=(), tuple_nonzero=(1, (7, 8, 9)), unmatched=((), (1, 0, 0, 1))):
    """Two components, public data and four families; family BIG carries the residual."""
    alpha_tags = {ADDR: (4, 4, (1, 2, 3, 4)), OPCODES: (2, 0, (5, 5, 5, 5)),
                  XOR9: (5, 5, (7, 7, 7, 7)), BIG: (3, 3, RES)}
    table_tags = {XOR9: (5, P - 5, NEG((7, 7, 7, 7))), ADDR: (6, P - 6, NEG((4, 5, 6, 7)))}
    public_tags = {ADDR: (2, 2, (3, 3, 3, 3)), OPCODES: (2, 0, NEG((5, 5, 5, 5)))}
    components = [("alpha", 5, alpha_tags), ("table", 6, table_tags)]
    lines = ["S3_LEDGER_BEGIN", "S3_LEDGER_CAPTURE columns=40 cells=123456"]
    claims = []
    for name, log_size, tags in components:
        total = modadd(*(v[2] for v in tags.values()))
        claimed = claimed_alpha if (name == "alpha" and claimed_alpha is not None) else total
        claims.append(claimed)
        lines.append(f"S3_LEDGER_COMPONENT name={name} log_size={log_size} entries={sum(v[0] for v in tags.values())} "
                     f"qm31={qm(total)} claimed={qm(claimed)} matches={b(total == claimed)} ms=12")
        for tag, (entries, mult, q) in sorted(tags.items()):
            lines.append(f"S3_LEDGER_COMPONENT_TAG name={name} tag={tag} entries={entries} "
                         f"mult_sum_mod_p={mult} qm31={qm(q)}")
    public_total = modadd(*(v[2] for v in public_tags.values()))
    native = public_total if public_native is None else public_native
    lines.append(f"S3_LEDGER_PUBLIC entries={sum(v[0] for v in public_tags.values())} qm31={qm(public_total)} "
                 f"native={qm(native)} matches={b(public_total == native)}")
    for tag, (entries, mult, q) in sorted(public_tags.items()):
        lines.append(f"S3_LEDGER_PUBLIC_TAG tag={tag} entries={entries} mult_sum_mod_p={mult} qm31={qm(q)}")
    families = {}
    for tag in sorted({t for _, _, tags in components for t in tags} | set(public_tags)):
        parts = [tags[tag] for _, _, tags in components if tag in tags]
        if tag in public_tags:
            parts.append(public_tags[tag])
        families[tag] = (sum(p[0] for p in parts), sum(p[1] for p in parts) % P, modadd(*(p[2] for p in parts)))
    if mutate_family:
        families[mutate_family[0]] = mutate_family[1]
    names = {ADDR: "MEMORY_ADDRESS_TO_ID", BIG: "MEMORY_ID_TO_BIG", OPCODES: "OPCODES", XOR9: "VERIFY_BITWISE_XOR_9"}
    for tag, (entries, mult, q) in sorted(families.items()):
        lines.append(f"S3_LEDGER_FAMILY tag={tag} name={names[tag]} entries={entries} mult_sum_mod_p={mult} "
                     f"qm31={qm(q)} zero={b(q == (0, 0, 0, 0))}")
    families_sum = modadd(*(f[2] for f in families.values()))
    claims_plus_public = modadd(*claims, native)
    g = families_sum if global_sum is None else global_sum
    lines.append(f"S3_LEDGER_TOTAL families_sum={qm(families_sum)} component_claims_plus_public={qm(claims_plus_public)} "
                 f"global_lookup_sum={qm(g)} matches={b(families_sum == g == claims_plus_public)}")
    nonzero, tuple_values = tuple_nonzero
    unmatched_addresses, section_entries = unmatched
    lines.append(f"S3_LEDGER_TUPLES tag={ADDR} name=MEMORY_ADDRESS_TO_ID distinct=10 "
                 f"nonzero={len(unmatched_addresses)} printed={min(len(unmatched_addresses), 12)}")
    for address in sorted(unmatched_addresses)[:12]:
        lines.append(f"S3_LEDGER_TUPLE tag={ADDR} tuple={ADDR},{address},{address + 1} net_mod_p=1")
    lines.append(f"S3_LEDGER_TUPLES tag={BIG} name=MEMORY_ID_TO_BIG distinct={max(3, nonzero)} nonzero={nonzero} printed={min(nonzero, 12)}")
    for _ in range(min(nonzero, 12)):
        lines.append(f"S3_LEDGER_TUPLE tag={BIG} tuple={qm(tuple_values)} net_mod_p=2147483646")
        tuple_values = tuple(v + 1 for v in tuple_values)
    lines.append(f"S3_LEDGER_TUPLES tag={OPCODES} name=OPCODES distinct=2 nonzero=0 printed=0")
    # Public section sizes (they must add to the 2 public address entries) and the unmatched split.
    per_section = [0, 0, 0, 0]
    for address in unmatched_addresses:
        per_section[0 if address < 100 else 3] += 1
    for name, entries, count in zip(("program", "safe_call", "segments", "output"), section_entries, per_section):
        lines.append(f"S3_LEDGER_UNMATCHED_SECTION name={name} entries={entries} unmatched={count}")
    runs = []
    for address in sorted(unmatched_addresses):
        if runs and runs[-1][0] + runs[-1][1] == address:
            runs[-1][1] += 1
        else:
            runs.append([address, 1])
    lines.insert(len(lines) - 4, f"S3_LEDGER_UNMATCHED tag={ADDR} total={len(unmatched_addresses)} "
                 f"in_public={len(unmatched_addresses)} outside_public=0")
    lines.append(f"S3_LEDGER_UNMATCHED_RUNS count={len(runs)} printed={min(len(runs), 24)}")
    for start, length in runs[:24]:
        lines.append(f"S3_LEDGER_UNMATCHED_RUN start={start} len={length}")
    lines.append(f"S3_LEDGER_STATUS evaluated=2 skipped={len(skipped)} complete={b(not skipped)} ms=900 p={P}")
    for name in skipped:
        lines.append(f"S3_LEDGER_SKIPPED name={name}")
    lines.append("S3_LEDGER_END")
    return "\n".join(lines) + "\n"


def full_log(block=None):
    return (ledger_block() if block is None else block) + native_log(truncated=False)


class PatchTests(unittest.TestCase):
    def test_component_inventory_is_pinned_and_generated(self):
        fields = component_fields(COMPONENTS_SOURCE)
        self.assertEqual(len(fields), EXPECTED_FIELDS)
        self.assertEqual([n for n, k in fields if k == "vector"], ["memory_id_to_big"])
        self.assertIn(("long_field", "option"), fields)
        code = render_rust(fields, relation_names(RELATIONS_SOURCE))
        self.assertEqual(code.count("if let Some(component) = &components."), 65)
        self.assertEqual(code.count("for component in &components.memory_id_to_big {"), 1)
        self.assertEqual(code.count("ledger.component(\""), 66)
        self.assertIn("1444891767 => \"MEMORY_ADDRESS_TO_ID\"", code)
        self.assertIn("95781001 => \"VERIFY_BITWISE_XOR_9\"", code)
        self.assertNotIn("@@", code)

    def test_changed_component_or_relation_shape_rejected(self):
        for bad in (
            COMPONENTS_SOURCE.replace("    pub field_0: Option<field_0::Component>,\n", ""),
            COMPONENTS_SOURCE.replace("Vec<memory_id_to_big", "Option<memory_id_to_big"),
            COMPONENTS_SOURCE.replace("pub field_1:", "pub field_0:"),
            COMPONENTS_SOURCE.replace("    pub memory_id_to_big: Vec<memory_id_to_big::Component>,\n",
                                      "    pub memory_id_to_big: Vec<memory_id_to_big::Component>,\n"
                                      "    pub extra: Vec<extra::Component>,\n"),
        ):
            with self.assertRaises(ValueError):
                component_fields(bad)
        with self.assertRaises(ValueError):
            relation_names(RELATIONS_SOURCE.replace("1444891767", "1444891768"))
        with self.assertRaises(ValueError):
            relation_names(RELATIONS_SOURCE + "pub const X_RELATION_ID: M31 = M31::from_u32_unchecked(95781001);\n")

    def test_tree_builder_wrapper_forwards_commitment_input_unchanged(self):
        patched = instrument_prover(PROVER_WITH_WRITE)
        self.assertIn("CapturingTreeBuilder::new(&mut tree_builder)", patched)
        self.assertIn("capturing.finish();", patched)
        self.assertIn('#[cfg(not(feature = "relation-tracker"))]', patched)
        self.assertEqual(patched.count("cairo_claim_generator.write_trace("), 2)
        self.assertEqual(patched.count("tree_builder.commit(channel);"), 2)
        self.assertEqual(patched.count("debug_assert_eq!("), 2)
        self.assertEqual(patched.count(LEDGER_CALL), 2)
        self.assertIn("lookup_sum(&claim, &interaction_elements, &interaction_claim),", patched)
        self.assertTrue(NEW_CALL.startswith(OLD_CALL[:-len("            );")]))
        self.assertIn("traced", WRITE_NEW)

    def test_changed_prover_shape_rejected(self):
        for bad in (
            PROVER_WITH_WRITE.replace("write_trace(&mut tree_builder)", "write_trace(&mut other)"),
            PROVER_WITH_WRITE + WRITE_OLD,
            PROVER,
            PROVER_WITH_WRITE.replace("    // Validate lookup argument.", "    // new."),
        ):
            with self.assertRaises(ValueError):
                instrument_prover(bad)
        with self.assertRaises(ValueError):
            instrument_tracker(TRACKER.replace("track_cairo_relations<", "track_wrong<"),
                               COMPONENTS_SOURCE, RELATIONS_SOURCE)
        with self.assertRaises(ValueError):
            instrument_tracker(TRACKER, COMPONENTS_SOURCE.replace("Vec<", "Option<"), RELATIONS_SOURCE)

    def test_rust_uses_the_upstream_evaluator_and_native_public_decomposition(self):
        code = instrument_tracker(TRACKER, COMPONENTS_SOURCE, RELATIONS_SOURCE)
        self.assertIn("add_to_relation_entries(component, &view)", code)
        self.assertIn("column.values.to_cpu()", code)
        self.assertIn("assert_eq!(base.len(), source[ORIGINAL_TRACE_IDX].len()", code)
        self.assertIn("component.claimed_sum()", code)
        self.assertIn("public_data.logup_sum(common_lookup)", code)
        self.assertIn("cairo_air::relations::OPCODES_RELATION_ID", code)
        self.assertIn("-M31::one()", code)
        self.assertIn(f">= {TIME_BUDGET_SECONDS}", code)
        self.assertIn("for tag in [" + ", ".join(str(t) for t in sorted(TRACKED_TAGS)) + "]", code)
        self.assertIn(f".min({MAX_TUPLES_PRINTED})", code)
        self.assertIn("generate_column", code.replace("gen_column_simd", "generate_column"))
        self.assertNotIn("unsafe", code)
        self.assertEqual(code.count("static BASE_TREE_SOURCE"), 1)
        self.assertEqual(TRACKED, {ADDR: "MEMORY_ADDRESS_TO_ID", BIG: "MEMORY_ID_TO_BIG", OPCODES: "OPCODES"})


class LedgerParserTests(unittest.TestCase):
    def test_family_balance_and_residual_localization(self):
        result = parse_ledger(ledger_block())
        self.assertEqual(result["nonzero_family_tags"], [BIG])
        self.assertTrue(result["all_component_claims_reproduced"])
        self.assertTrue(result["families_reproduce_global_lookup_sum"])
        self.assertTrue(result["ledger_complete"])
        self.assertEqual(result["global_lookup_sum_qm31"], list(RES))
        self.assertEqual(result["families"][str(XOR9)]["zero"], True)
        self.assertEqual(result["families"][str(ADDR)]["qm31"], [0, 0, 0, 0])
        self.assertEqual(result["tuple_ledgers"][str(BIG)]["nonzero"], 1)
        self.assertFalse(result["full_global_lookup_balance_verified"])
        self.assertFalse(result["native_proof_verified"])

    def test_unmatched_address_uses_are_classified_by_public_section(self):
        clean = parse_ledger(ledger_block())["unmatched_address_uses"]
        self.assertEqual((clean["total"], clean["runs"], clean["sections_with_unmatched"]), (0, 0, []))
        result = parse_ledger(ledger_block(unmatched=((5, 120), (1, 0, 0, 1))))["unmatched_address_uses"]
        self.assertEqual((result["total"], result["in_public_memory"], result["outside_public_memory"]), (2, 2, 0))
        self.assertEqual(result["sections_with_unmatched"], ["program", "output"])
        self.assertEqual(result["sections_entirely_unmatched"], ["program", "output"])
        self.assertEqual(result["first_runs"], [dict(start=5, length=1), dict(start=120, length=1)])
        text = ledger_block(unmatched=((5, 120), (1, 0, 0, 1)))
        for before, after in [
            ("S3_LEDGER_UNMATCHED tag=1444891767 total=2 in_public=2 outside_public=0",
             "S3_LEDGER_UNMATCHED tag=1444891767 total=2 in_public=1 outside_public=0"),
            ("S3_LEDGER_UNMATCHED tag=1444891767 total=2 in_public=2 outside_public=0",
             "S3_LEDGER_UNMATCHED tag=1444891767 total=3 in_public=3 outside_public=0"),
            ("name=program entries=1 unmatched=1", "name=program entries=0 unmatched=1"),
            ("name=output entries=1 unmatched=1", "name=output entries=1 unmatched=0"),
            ("S3_LEDGER_UNMATCHED_RUN start=120 len=1", "S3_LEDGER_UNMATCHED_RUN start=120 len=2"),
            ("S3_LEDGER_UNMATCHED_RUN start=120 len=1", "S3_LEDGER_UNMATCHED_RUN start=5 len=1"),
            ("S3_LEDGER_UNMATCHED_RUNS count=2 printed=2", "S3_LEDGER_UNMATCHED_RUNS count=1 printed=2"),
        ]:
            self.assertEqual(text.count(before), 1, before)
            with self.assertRaises(ValueError, msg=before):
                parse_ledger(text.replace(before, after))

    def test_a_component_that_misses_its_claim_is_reported_not_rejected(self):
        result = parse_ledger(ledger_block(claimed_alpha=(1, 1, 1, 1)))
        self.assertEqual(result["components_not_reproducing_claim"], ["alpha"])
        self.assertFalse(result["all_component_claims_reproduced"])
        self.assertFalse(result["families_reproduce_global_lookup_sum"])

    def test_every_single_line_deletion_or_duplication_is_rejected(self):
        lines = ledger_block().rstrip("\n").split("\n")
        for index in range(len(lines)):
            deleted = "\n".join(lines[:index] + lines[index + 1:]) + "\n"
            duplicated = "\n".join(lines[:index + 1] + lines[index:]) + "\n"
            for label, text in (("delete", deleted), ("duplicate", duplicated)):
                with self.assertRaises(ValueError, msg=f"{label} line {index}: {lines[index][:70]}"):
                    parse_ledger(text)

    def test_altered_sums_and_counts_are_rejected(self):
        good = ledger_block()
        for before, after in [
            ("tag=95781001 entries=5 mult_sum_mod_p=5 qm31=7,7,7,7", "tag=95781001 entries=6 mult_sum_mod_p=5 qm31=7,7,7,7"),
            ("tag=95781001 entries=5 mult_sum_mod_p=5 qm31=7,7,7,7", "tag=95781001 entries=5 mult_sum_mod_p=4 qm31=7,7,7,7"),
            ("tag=95781001 entries=5 mult_sum_mod_p=5 qm31=7,7,7,7", "tag=95781001 entries=5 mult_sum_mod_p=5 qm31=7,7,7,8"),
            ("evaluated=2", "evaluated=3"),
            ("columns=40 cells=123456", "columns=40 cells=12345x"),
            ("name=alpha log_size=5 entries=14", "name=alpha log_size=5 entries=15"),
            ("S3_LEDGER_PUBLIC entries=4", "S3_LEDGER_PUBLIC entries=5"),
            ("zero=true", "zero=false"),
            ("nonzero=1 printed=1", "nonzero=1 printed=0"),
            ("net_mod_p=2147483646", "net_mod_p=0"),
        ]:
            self.assertGreaterEqual(good.count(before), 1, before)
            with self.assertRaises(ValueError, msg=before):
                parse_ledger(good.replace(before, after, 1))

    def test_public_decomposition_must_equal_native(self):
        with self.assertRaises(ValueError):
            parse_ledger(ledger_block(public_native=(9, 9, 9, 9)))

    def test_family_totals_must_equal_their_parts(self):
        with self.assertRaises(ValueError):
            parse_ledger(ledger_block(mutate_family=(XOR9, (10, 0, (1, 0, 0, 0)))))
        with self.assertRaises(ValueError):
            parse_ledger(ledger_block(mutate_family=(ADDR, (8, 8, (1, 2, 3, 4)))))

    def test_skipped_components_keep_the_ledger_incomplete(self):
        result = parse_ledger(ledger_block(skipped=("late_component",)))
        self.assertFalse(result["ledger_complete"])
        self.assertEqual(result["components_skipped"], ["late_component"])
        with self.assertRaises(ValueError):
            parse_ledger(ledger_block(skipped=("late_component",)).replace("skipped=1", "skipped=0"))

    def test_tuple_listing_is_bounded_and_unique(self):
        many = parse_ledger(ledger_block(tuple_nonzero=(40, (7, 8, 9))))
        self.assertEqual(many["tuple_ledgers"][str(BIG)]["nonzero"], 40)
        self.assertEqual(len(many["tuple_ledgers"][str(BIG)]["first_nonzero"]), MAX_TUPLES_PRINTED)


class NativeEvidenceTests(unittest.TestCase):
    def test_full_parse_requires_rejection_pinned_residual_and_caps(self):
        report = with_stage_resources(native_report())
        result = parse(full_log(), report)
        self.assertTrue(result["global_native_lookup_assertion_failed"])
        self.assertEqual(result["baseline_residual"], list(EXPECTED_RESIDUAL))
        self.assertEqual(result["resources"]["native_exit_code"], 101)
        self.assertFalse(result["native_proof_verified"])
        for bad_report in (
            with_stage_resources(native_report(), rss=5 * 1024**3),
            with_stage_resources(native_report(), elapsed=121.0),
            {**with_stage_resources(native_report()), "native_proof_verified": True},
        ):
            with self.assertRaises(ValueError):
                parse(full_log(), bad_report)
        with self.assertRaises(ValueError):
            parse(full_log().replace("1866027004", "1866027003"), report)
        with self.assertRaises(ValueError):
            parse(full_log().replace("assertion left == right failed", "ok"), report)
        with self.assertRaises(ValueError):
            parse(full_log(ledger_block(global_sum=(1, 2, 3, 4))), report)


class AnnotationTests(unittest.TestCase):
    def test_ledger_result_is_published_compactly(self):
        from annotate_caller_summary import render_ledger
        summary = parse(full_log(), with_stage_resources(native_report()))
        lines = render_ledger(summary, "", {"patch_sha256": "ab", "upstream_revision": "cd",
                                            "source_file_hashes": []}, None)
        self.assertTrue(all(l.startswith("::notice title=S3P") for l in lines))
        self.assertTrue(all(chr(10) not in l for l in lines))
        self.assertIn('"nonzero_family_tags":[1662111297]', lines[1])
        self.assertIn('"all_component_claims_reproduced":true', lines[1])

    def test_missing_summary_publishes_ledger_markers_as_error(self):
        from annotate_caller_summary import render_ledger
        raw = chr(10).join(["S3_LEDGER_BEGIN", "unrelated", "S3_LEDGER_COMPONENT name=x"]) + chr(10)
        lines = render_ledger(None, raw, None, {"status": "one_shot_small_profile_failed",
                                                "stages": [{"status": "command_failed", "returncode": 101}]})
        self.assertTrue(lines[0].startswith("::error title=S3P raw markers::"))
        self.assertIn("S3_LEDGER_BEGIN%0AS3_LEDGER_COMPONENT name=x", lines[0])
        self.assertNotIn("unrelated", lines[0])


if __name__ == "__main__":
    unittest.main()
