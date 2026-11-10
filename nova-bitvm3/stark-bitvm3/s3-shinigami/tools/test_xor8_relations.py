"""Proof-free regression suite for source-pinned XOR8 local relation auditing."""
from __future__ import annotations

import unittest

from instrument_xor8_relations import (
    COMPONENT, ENTRIES, LOG_SIZE, PREPROCESSED, BASE, ROWS,
    xor_rust, instrument_prover, instrument_tracker, instrument_witness, SCOPE_LABEL,
)
from instrument_local_relations import LOCAL_RUST
from instrument_relations import OLD_LOOKUP, OLD_TRACKER
from summarize_xor8_relations import parse, EXPECTED_CLAIM, BASE_SOURCE, PREPROCESS_SOURCE

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
WITNESS = """        let (verify_bitwise_xor_8_claim, verify_bitwise_xor_8_interaction_gen) = self
            .verify_bitwise_xor_8
            .map(|gen| {
                let (trace, claim, interaction_gen) = gen.write_trace();
                tree_builder.extend_evals(trace.to_evals());
                (claim, interaction_gen)
            })
            .unzip();"""


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
        "S3_LOCAL_PREPROCESS_SOURCE canonical_pinned_original\n"
        + BASE_SOURCE + "\n"
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
        self.assertIn("let expected_ids = [\"bitwise_xor_8_0\"",patched)
        self.assertIn("preprocessed_trace.columns.get(index)",patched)
        self.assertIn("column.gen_column_simd().values.to_cpu()",patched)
        self.assertIn("S3_LOCAL_PREPROCESS_SOURCE canonical_pinned_original",patched)
        self.assertIn("S3_LOCAL_BASE_SOURCE captured_native_write_trace",patched)
        self.assertNotIn("base source polynomial exceeds selected component degree",patched)
        self.assertIn("assert_eq!(entries.len(), 131072",patched)
        self.assertIn("captured_native_write_trace",patched)
        self.assertIn("XOR8_SOURCE.get()",patched)
        self.assertIn("pub fn capture_xor8_source(",patched)
        self.assertIn("XOR8_SOURCE.set(rows)",patched)
        self.assertIn("zero local LogUp denominator",patched)
        self.assertIn("add_to_relation_entries(component, &view)",patched)
        self.assertNotIn("range_check_11",patched)
        self.assertEqual(LOCAL_RUST.count("range_check_11"),6)

    def test_local_prover_reuses_native_assertion(self):
        src=instrument_prover(PROVER)
        self.assertEqual(src.count("track_local_verify_bitwise_xor_8_relations"),2)
        self.assertIn("interaction_claim.verify_bitwise_xor_8",src)
        self.assertIn("&preprocessed_trace,",src)
        self.assertIn("S3_LOCAL_PREPROCESS_SOURCE",xor_rust())
        self.assertIn(SCOPE_LABEL,src)
        self.assertEqual(src.count("debug_assert_eq!("),2)
        self.assertIn("#[cfg(not(feature = \"relation-tracker\"))]",src)
        tracker=instrument_tracker(TRACKER)
        self.assertTrue(tracker.endswith(xor_rust()))
        self.assertNotIn(LOCAL_RUST,tracker)

    def test_source_preprocessed_columns_have_exact_pin_and_shape(self):
        code=xor_rust()
        self.assertEqual(code.count("bitwise_xor_8_0"),1)
        self.assertEqual(code.count("bitwise_xor_8_1"),1)
        self.assertEqual(code.count("bitwise_xor_8_2"),1)
        self.assertIn("assert_eq!(column.log_size(), log_size",code)
        self.assertIn("expected_ids[slot]",code)
        self.assertIn("reconstructed[PREPROCESSED_TRACE_IDX][index] = rows",code)
        self.assertIn("reconstructed[ORIGINAL_TRACE_IDX][index] = source_rows[slot].clone()",code)
        self.assertIn("XOR8_SOURCE.get()",code)

    def test_exact_source_rows_captured_without_mutating_commitment(self):
        patched = instrument_witness(WITNESS)
        self.assertIn("let original_columns = trace.to_evals();",patched)
        self.assertIn("capture_xor8_source(&original_columns);",patched)
        self.assertIn("tree_builder.extend_evals(original_columns);",patched)
        self.assertIn('#[cfg(feature = "relation-tracker")]',patched)
        self.assertNotIn("tree_builder.extend_evals(trace.to_evals());",patched)
        with self.assertRaises(ValueError):
            instrument_witness(WITNESS.replace("tree_builder.extend_evals(trace.to_evals());",
                                               "tree_builder.extend_evals(another_trace);"))
        with self.assertRaises(ValueError):
            instrument_witness(WITNESS + WITNESS)

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
        self.assertEqual(result["preprocessed_trace_source"],
                         "pinned native original before commitment lifting")
        self.assertEqual(result["base_columns"],2)
        self.assertEqual(result["base_trace_source"],
           "pinned native original rows captured before extend_evals commitment")
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
            (PREPROCESS_SOURCE,"S3_LOCAL_PREPROCESS_SOURCE lifted_commitment"),
            ("CommonLookupElements:","OtherRelation:"),
            (BASE_SOURCE,BASE_SOURCE.replace("captured_native_write_trace","committed_lifted")),
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
