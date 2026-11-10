"""Proof-free regression suite for source-pinned XOR8 local relation auditing."""
from __future__ import annotations

import unittest

from instrument_xor8_relations import (
    COMPONENT, ENTRIES, LOG_SIZE, PREPROCESSED, BASE, ROWS,
    xor_rust, instrument_prover, instrument_tracker, SCOPE_LABEL,
)
from instrument_local_relations import LOCAL_RUST
from instrument_relations import OLD_LOOKUP, OLD_TRACKER
from summarize_xor8_relations import parse, EXPECTED_CLAIM

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


def native_report():
    return {
        "native_proof_verified":False,
        "status":"one_shot_small_profile_failed",
        "stages":[{"status":"command_failed","returncode":101}]
    }


def qm(v):
    return f"({v[0]} + {v[1]}i) + ({v[2]} + {v[3]}i)u"


def native_log(recomputed=EXPECTED_CLAIM, claimed=EXPECTED_CLAIM, flag=True, truncated=True):
    raw = "CommonLookupElements:\n  [112558620, 20, 31, 11] -> 2147483646\n"
    if truncated:
        raw += "  [112558620,"
    return (
        "S3_RELATIONS_BEGIN\n"
        "S3_LOCAL_COLUMNS component=verify_bitwise_xor_8 preprocessed=3 base=2 rows=65536\n"
        "S3_LOCAL_ENTRIES count=131072\n"
        f"S3_LOCAL_LOGUP recomputed={qm(recomputed)} claimed={qm(claimed)} matches={str(flag).lower()}\n"
        + SCOPE_LABEL + "\n"
        "S3_RELATIONS_TEXT_BEGIN\n"
        + raw
        + ("\n" if truncated else "")
        + "S3_RELATIONS_TEXT_END\n"
        + f"S3_RELATIONS_TRUNCATED {str(truncated).lower()}\n"
        + "S3_RELATIONS_END\n"
        + "thread main panicked: assertion left == right failed\n"
        "  left: (1866027004 + 1908263159i) + (1713629672 + 1017174456i)u\n"
        " right: (0 + 0i) + (0 + 0i)u\n"
    )


class Xor8ComponentTests(unittest.TestCase):
    def test_source_bound_component_shape(self):
        self.assertEqual((COMPONENT, LOG_SIZE, ROWS, PREPROCESSED, BASE, ENTRIES),
            ("verify_bitwise_xor_8",16,65536,3,2,131072))
        patched=xor_rust()
        self.assertIn("let log_size = cairo_air::components::verify_bitwise_xor_8::LOG_SIZE",patched)
        self.assertIn("assert_eq!(logs[ORIGINAL_TRACE_IDX], vec![log_size; 2]);",patched)
        self.assertIn("assert_eq!(component.preprocessed_column_indices().len(), 3);",patched)
        self.assertIn("SecureField::batch_inverse(&denominators)",patched)
        self.assertIn("assert_eq!(entries.len(), 131072",patched)
        self.assertIn("zero local LogUp denominator",patched)
        self.assertIn("add_to_relation_entries(component, &view)",patched)
        self.assertNotIn("range_check_11",patched)
        self.assertEqual(LOCAL_RUST.count("range_check_11"),6)

    def test_local_prover_reuses_native_assertion(self):
        src=instrument_prover(PROVER)
        self.assertEqual(src.count("track_local_verify_bitwise_xor_8_relations"),2)
        self.assertIn("interaction_claim.verify_bitwise_xor_8",src)
        self.assertIn(SCOPE_LABEL,src)
        self.assertEqual(src.count("debug_assert_eq!("),2)
        self.assertIn("#[cfg(not(feature = \"relation-tracker\"))]",src)
        tracker=instrument_tracker(TRACKER)
        self.assertTrue(tracker.endswith(xor_rust()))
        self.assertNotIn(LOCAL_RUST,tracker)

    def test_changed_upstream_shape_rejected(self):
        with self.assertRaises(ValueError):
            instrument_prover(PROVER.replace("    // Validate lookup argument.", "    // new lookup style."))
        with self.assertRaises(ValueError):
            instrument_tracker(TRACKER.replace("track_cairo_relations<","track_wrong_relations<"))
        with self.assertRaises(ValueError):
            instrument_tracker(TRACKER+TRACKER)

    def test_matching_local_claim_is_only_partial(self):
        result=parse(native_log(),native_report())
        self.assertEqual(result["selected_component"],COMPONENT)
        self.assertTrue(result["component_claim_sum_matches"])
        self.assertTrue(result["relation_debug_output_truncated"])
        self.assertFalse(result["relation_inventory_complete"])
        self.assertEqual(result["raw_relation_entries"],ENTRIES)
        self.assertEqual(result["preprocessed_columns"],3)
        self.assertEqual(result["base_columns"],2)
        self.assertFalse(result["global_relation_balances_verified"])
        self.assertFalse(result["native_proof_verified"])
        self.assertFalse(result["bitcoin_settlement_authorized"])

    def test_mismatch_is_evidence_and_not_approval(self):
        changed=(EXPECTED_CLAIM[0]+1, *EXPECTED_CLAIM[1:])
        result=parse(native_log(recomputed=changed,flag=False),native_report())
        self.assertFalse(result["component_claim_sum_matches"])
        self.assertEqual(tuple(result["component_logup_claimed"]),EXPECTED_CLAIM)
        self.assertFalse(result["ark_utxoref_application_authorized"])

    def test_native_shape_and_stale_challenge_rejected(self):
        for before,after in [
            ("preprocessed=3","preprocessed=1"),
            ("base=2","base=3"),
            ("rows=65536","rows=2048"),
            ("count=131072","count=4096"),
            (SCOPE_LABEL, SCOPE_LABEL.replace("partial=true","partial=false")),
            ("S3_LOCAL_LOGUP","S3_LOCAL_OTHER"),
            ("CommonLookupElements:","OtherRelation:"),
        ]:
            with self.assertRaises(ValueError,msg=before):
                parse(native_log().replace(before,after),native_report())
        stale=tuple((v+1) % (2**31-1) for v in EXPECTED_CLAIM)
        with self.assertRaises(ValueError):
            parse(native_log(recomputed=stale,claimed=stale),native_report())

    def test_corrupted_comparison_flag_and_proof_state_rejected(self):
        with self.assertRaises(ValueError):
            parse(native_log(flag=False),native_report())
        with self.assertRaises(ValueError):
            parse(native_log(),{**native_report(),"native_proof_verified":True})
        with self.assertRaises(ValueError):
            parse(native_log().replace("1866027004","1866027003"),native_report())
        with self.assertRaises(ValueError):
            parse(native_log()+f"S3_LOCAL_LOGUP recomputed={qm(EXPECTED_CLAIM)} claimed={qm(EXPECTED_CLAIM)} matches=true\n",native_report())

    def test_untruncated_small_summary(self):
        result=parse(native_log(truncated=False),native_report())
        self.assertFalse(result["relation_debug_output_truncated"])
        self.assertEqual(result["nonzero_relation_tuple_lines_observed"],1)


if __name__ == "__main__":
    unittest.main()
