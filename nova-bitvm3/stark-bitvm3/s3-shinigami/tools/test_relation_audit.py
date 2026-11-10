"""Proof-free tests for a bounded, feature-gated native Cairo relation audit."""
import unittest

from instrument_relations import (
    OLD_LOOKUP, OLD_TRACKER, TRACKER_OLD, TRACKER_NEW,
    instrument, restore_tracker_domain,
)
from summarize_relations import summarize

CHECK = (
    "    tree_builder.commit(channel);\n"
    + OLD_LOOKUP
    + "    interaction_claim.mix_into(channel);\n"
    + "    tree_builder.commit(channel);\n"
    + "    let component_builder = CairoComponents::new(...);\n"
    + OLD_TRACKER
)


def source_error(source: str) -> bool:
    try:
        instrument(source)
    except (ValueError, AssertionError):
        return True
    return False


def report():
    return {
        "native_proof_verified":False,
        "status":"one_shot_small_profile_failed",
        "stages":[{"status":"command_failed","returncode":101}]
    }


def log(truncated=False):
    content = "MemoryAddressToId:\n  [1, 2] -> 1\nMemoryIdToBig:\n  [10, 20, 30] -> 2147483646\n"
    if truncated:
        content += "  [10"
    return (
        "S3_RELATIONS_BEGIN\n"
        "S3_RELATIONS_TEXT_BEGIN\n"
        + content
        + ("\n" if truncated else "")
        + "S3_RELATIONS_TEXT_END\n"
        + f"S3_RELATIONS_TRUNCATED {str(truncated).lower()}\n"
        + "S3_RELATIONS_END\n"
        + "thread main panicked: assertion left == right failed\n"
        + "  left: (1866027004 + 1908263159i) + (1713629672 + 1017174456i)u\n"
        + " right: (0 + 0i) + (0 + 0i)u\n"
    )


class RelationAuditTests(unittest.TestCase):
    def test_instrument_preserves_native_check(self):
        modified=instrument(CHECK)
        self.assertIn('S3_RELATIONS_TEXT_BEGIN',modified)
        self.assertEqual(modified.count("debug_assert_eq!("),2)
        self.assertEqual(modified.count("tree_builder.commit(channel);"),2)
        self.assertEqual(modified.count("lookup_sum(&claim, &interaction_elements, &interaction_claim)"),3)
        self.assertIn('#[cfg(not(feature = "relation-tracker"))]', modified)
        self.assertEqual(modified.count("RelationSummary"),0)

    def test_tracker_domain_retains_full_evaluation_length(self):
        altered = restore_tracker_domain(TRACKER_OLD)
        self.assertEqual(altered, TRACKER_NEW)
        self.assertIn("let original_domain = poly.evals.domain;", altered)
        self.assertIn(".evaluate(original_domain)", altered)
        self.assertNotIn(".evaluate(CanonicCoset::new(coeffs.log_size()).circle_domain())", altered)

    def test_tracker_patch_fails_on_changed_domain_source(self):
        with self.assertRaises(ValueError):
            restore_tracker_domain(TRACKER_OLD.replace("poly.evals.clone()", "poly.evals.to_owned()"))
        with self.assertRaises(ValueError):
            restore_tracker_domain(TRACKER_OLD + TRACKER_OLD)

    def test_source_fail_closed(self):
        self.assertTrue(source_error(CHECK.replace("    tree_builder.commit(channel);\n","",1)))
        self.assertTrue(source_error(CHECK.replace("    // Validate lookup argument.","    // Altered lookup argument.")))
        self.assertTrue(source_error(CHECK.replace("    interaction_claim.mix_into(channel);\n","")))
        self.assertTrue(source_error(CHECK.replace('        tracing::info!("Relations summary: {:?}", summary);',
                                                   '        // removed original tracker;')))

    def test_reconcile_failed_proof(self):
        got=summarize(log(),report())
        self.assertEqual(got["relations_observed"],["MemoryAddressToId","MemoryIdToBig"])
        self.assertEqual(got["nonzero_relation_tuple_lines_observed"],2)
        self.assertEqual(got["first_four_tuple_examples_per_relation"]["MemoryIdToBig"][0]["residual"],2147483646)
        self.assertTrue(got["relation_inventory_complete"])
        self.assertFalse(got["native_proof_verified"])
        self.assertFalse(got["bitcoin_settlement_authorized"])

    def test_truncated_report_marks_incomplete(self):
        got=summarize(log(truncated=True),report())
        self.assertTrue(got["relation_debug_output_truncated"])
        self.assertFalse(got["relation_inventory_complete"])

    def test_truncated_flag_required(self):
        with self.assertRaises(ValueError):
            summarize(log(truncated=True).replace("S3_RELATIONS_TRUNCATED true","S3_RELATIONS_TRUNCATED false"), report())
        with self.assertRaises(ValueError):
            summarize(log().replace("S3_RELATIONS_TEXT_END",""),report())

    def test_reject_wrong_native_residual_or_success(self):
        with self.assertRaises(ValueError):
            summarize(log().replace("1866027004","1866027005"),report())
        with self.assertRaises(ValueError):
            summarize(log(),{**report(),"native_proof_verified":True})
        with self.assertRaises(ValueError):
            summarize(log(),{**report(),"stages":[{"status":"timeout","returncode":-15}]})

    def test_reject_duplicate_relation_and_invalid_tuple(self):
        with self.assertRaises(ValueError):
            summarize(log().replace("MemoryIdToBig:","MemoryAddressToId:"),report())
        with self.assertRaises(ValueError):
            summarize(log().replace("2147483646","2147483647"),report())
        with self.assertRaises(ValueError):
            summarize(log().replace("  [1, 2] -> 1","  [1, 2] -> 0"),report())


if __name__ == "__main__":
    unittest.main()
