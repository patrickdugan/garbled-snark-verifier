"""Proof-free tests of source-pinned component-local relation reconstruction."""
from __future__ import annotations
import unittest

from instrument_relations import OLD_LOOKUP, OLD_TRACKER
from instrument_local_relations import (
    instrument_prover, instrument_tracker, LOCAL_RUST, SCOPE_LABEL,
)
from summarize_local_relations import parse

PROVER = (
    "    tree_builder.commit(channel);\n"
    + OLD_LOOKUP
    + "    interaction_claim.mix_into(channel);\n"
    + "    tree_builder.commit(channel);\n"
    + "    let component_builder = CairoComponents::new(...);\n"
    + OLD_TRACKER
)
TRACKER = (
    "pub fn track_and_summarize_cairo_relations<MC: MerkleChannel>(x: ()) {}\n"
    "pub fn track_cairo_relations<MC: MerkleChannel>(x: ()) {}\n"
)

def failed_report():
    return {
        "native_proof_verified": False,
        "status": "one_shot_small_profile_failed",
        "stages": [{"status": "command_failed", "returncode": 101}],
    }

def native_log():
    return (
        "S3_RELATIONS_BEGIN\n"
        "S3_LOCAL_COLUMNS component=range_check_11 preprocessed=1 base=1 rows=2048\n"
        "S3_LOCAL_ENTRIES count=2048\n"
        "S3_LOCAL_LOGUP recomputed=(18 + 2i) + (3 + 4i)u claimed=(18 + 2i) + (3 + 4i)u matches=true\n"
        + SCOPE_LABEL + "\n"
        "S3_RELATIONS_TEXT_BEGIN\n"
        "CommonLookupElements:\n  [991608089, 2] -> 2147483646\n"
        "S3_RELATIONS_TEXT_END\n"
        "S3_RELATIONS_TRUNCATED false\n"
        "S3_RELATIONS_END\n"
        "thread main panicked: assertion left == right failed\n"
        "  left: (1866027004 + 1908263159i) + (1713629672 + 1017174456i)u\n"
        " right: (0 + 0i) + (0 + 0i)u\n"
    )

class LocalRelationTests(unittest.TestCase):
    def test_feature_hook_pins_one_partial_component(self):
        p=instrument_prover(PROVER)
        self.assertIn(SCOPE_LABEL,p)
        self.assertIn("&interaction_elements,",p)
        self.assertIn('interaction_claim.range_check_11',p)
        self.assertEqual(p.count("track_local_range_check_11_relations"),2)
        self.assertEqual(p.count("debug_assert_eq!("),2)
        self.assertEqual(p.count("interaction_claim.mix_into(channel);"),1)
        self.assertIn("#[cfg(not(feature = \"relation-tracker\"))]",p)

    def test_selected_columns_and_canonical_domain(self):
        p=instrument_tracker(TRACKER)
        self.assertIn("cairo_air::components::range_check_11::LOG_SIZE",p)
        self.assertIn("let domain = CanonicCoset::new(log_size).circle_domain();",p)
        self.assertIn("component.preprocessed_column_indices()",p)
        self.assertIn("component.trace_locations()",p)
        self.assertIn("add_to_relation_entries(component, &view)",p)
        self.assertIn("common_lookup.combine(&entry.values)",p)
        self.assertIn("denominator.inverse()",p)
        self.assertIn("S3_LOCAL_LOGUP recomputed=",p)
        self.assertIn("assert!(coeffs.log_size() <= log_size",p)
        self.assertIn("indices[ORIGINAL_TRACE_IDX].extend",p)
        self.assertNotIn("track_and_summarize_cairo_relations",LOCAL_RUST)

    def test_source_shape_drift_fails(self):
        with self.assertRaises(ValueError):
            instrument_prover(PROVER.replace("    // Validate lookup argument.", "    // changed check"))
        with self.assertRaises(ValueError):
            instrument_tracker(TRACKER + TRACKER)
        with self.assertRaises(ValueError):
            instrument_tracker(TRACKER.replace("pub fn track_cairo_relations<","pub fn custom_tracker<"))

    def test_diagnostic_is_always_partial_and_never_authorizes(self):
        r=parse(native_log(),failed_report())
        self.assertEqual(r["selected_component"],"range_check_11")
        self.assertEqual(r["component_trace_rows"],2048)
        self.assertEqual(r["source_preprocessed_columns"],1)
        self.assertEqual(r["source_base_columns"],1)
        self.assertTrue(r["component_local_result_only"])
        self.assertTrue(r["component_claim_sum_matches"])
        self.assertEqual(r["component_logup_recomputed"],[18,2,3,4])
        self.assertEqual(r["component_logup_claimed"],[18,2,3,4])
        self.assertFalse(r["relation_inventory_complete"])
        self.assertFalse(r["global_relation_balances_verified"])
        self.assertFalse(r["native_proof_verified"])
        self.assertFalse(r["bitcoin_settlement_authorized"])

    def test_component_logup_mismatch_is_recorded_without_acceptance(self):
        different = native_log().replace(
            "claimed=(18 + 2i) + (3 + 4i)u matches=true",
            "claimed=(19 + 2i) + (3 + 4i)u matches=false",
        )
        result = parse(different, failed_report())
        self.assertFalse(result["component_claim_sum_matches"])
        self.assertFalse(result["native_proof_verified"])
        self.assertFalse(result["global_relation_balances_verified"])

    def test_inconsistent_native_logup_flag_is_rejected(self):
        with self.assertRaises(ValueError):
            parse(native_log().replace("matches=true","matches=false"), failed_report())
        with self.assertRaises(ValueError):
            parse(native_log().replace("S3_LOCAL_LOGUP", "S3_LOCAL_OTHER"), failed_report())
        with self.assertRaises(ValueError):
            parse(native_log() + "S3_LOCAL_LOGUP recomputed=(1 + 0i) + (0 + 0i)u claimed=(1 + 0i) + (0 + 0i)u matches=true\n",failed_report())

    def test_diagnostic_requires_failed_original_assertion(self):
        with self.assertRaises(ValueError):
            parse(native_log().replace("assertion left == right","assertion x != y"),failed_report())
        with self.assertRaises(ValueError):
            parse(native_log(),{**failed_report(),"native_proof_verified":True})
        with self.assertRaises(ValueError):
            parse(native_log().replace("1866027004","1866027003"),failed_report())

    def test_partial_scope_and_shape_mutations_fail(self):
        for before,after in [
            (SCOPE_LABEL, SCOPE_LABEL.replace("partial=true","partial=false")),
            ("rows=2048","rows=4096"),
            ("preprocessed=1","preprocessed=0"),
            ("base=1","base=5"),
            ("count=2048","count=999999"),
            ("CommonLookupElements:","Unrelated:"),
            ("S3_LOCAL_ENTRIES count=2048",""),
        ]:
            with self.assertRaises(ValueError,msg=before):
                parse(native_log().replace(before,after),failed_report())


if __name__=="__main__":
    unittest.main()
