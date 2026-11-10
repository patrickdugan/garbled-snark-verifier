"""Proof-free checks for the public segment context correction (S3q)."""
from __future__ import annotations
import copy
import unittest

from prove_corrected_context import ALL_PRESENT, BUILTIN_ORDER, correct_context, derive_present

# The frozen standalone CSV input: three builtins with segments, eight keys listed.
SEGMENTS = {
    "add_mod_builtin": None,
    "bitwise_builtin": {"begin_addr": 357832, "stop_ptr": 378312},
    "output": {"begin_addr": 292275, "stop_ptr": 292296},
    "mul_mod_builtin": None,
    "pedersen_builtin": None,
    "poseidon_builtin": None,
    "range_check96_builtin": None,
    "range_check_builtin": {"begin_addr": 292296, "stop_ptr": 357832},
}
EXPECTED = [True, False, True, False, True, False, False, False, False, False, False]


def sample():
    return {
        "state_transitions": {"initial_state": {"pc": 1, "ap": 169859, "fp": 169859}},
        "memory": {"address_to_id": [1, 2, 3]},
        "public_memory_addresses": list(range(1, 170)),
        "builtin_segments": copy.deepcopy(SEGMENTS),
        "public_segment_context": {"present": list(ALL_PRESENT)},
        "pc_count": 7670,
    }


class ContextTests(unittest.TestCase):
    def test_canonical_order_has_eleven_builtins_output_first(self):
        self.assertEqual(len(BUILTIN_ORDER), 11)
        self.assertEqual(BUILTIN_ORDER[0], "output")
        self.assertEqual(BUILTIN_ORDER.index("range_check_builtin"), 2)
        self.assertEqual(BUILTIN_ORDER.index("bitwise_builtin"), 4)

    def test_derives_the_three_builtin_layout(self):
        self.assertEqual(derive_present(SEGMENTS), EXPECTED)
        everything = {name: {"begin_addr": 1, "stop_ptr": 2} for name in BUILTIN_ORDER}
        self.assertEqual(derive_present(everything), ALL_PRESENT)

    def test_unknown_builtin_or_missing_output_is_rejected(self):
        with self.assertRaises(ValueError):
            derive_present({**SEGMENTS, "mystery_builtin": {"begin_addr": 1, "stop_ptr": 2}})
        with self.assertRaises(ValueError):
            derive_present({**SEGMENTS, "output": None})
        with self.assertRaises(ValueError):
            derive_present({k: v for k, v in SEGMENTS.items() if k != "output"})
        # an unknown key that is null does not count as a builtin
        self.assertEqual(derive_present({**SEGMENTS, "mystery_builtin": None}), EXPECTED)

    def test_correction_changes_only_the_context_field(self):
        data = sample()
        original = copy.deepcopy(data)
        report = correct_context(data)
        self.assertEqual(report["before"], ALL_PRESENT)
        self.assertEqual(report["after"], EXPECTED)
        self.assertEqual(report["present_builtins"], ["output", "range_check_builtin", "bitwise_builtin"])
        self.assertEqual(report["public_memory_addresses_in_input"], 169)
        self.assertEqual(data["public_segment_context"], {"present": EXPECTED})
        original["public_segment_context"] = data["public_segment_context"]
        self.assertEqual(data, original)

    def test_only_the_all_present_default_is_corrected(self):
        already = sample()
        already["public_segment_context"]["present"] = list(EXPECTED)
        with self.assertRaises(ValueError):
            correct_context(already)
        other = sample()
        other["public_segment_context"]["present"][3] = False
        with self.assertRaises(ValueError):
            correct_context(other)

    def test_nothing_to_correct_when_all_builtins_are_present(self):
        data = sample()
        data["builtin_segments"] = {name: {"begin_addr": 1, "stop_ptr": 2} for name in BUILTIN_ORDER}
        with self.assertRaises(ValueError):
            correct_context(data)

    def test_malformed_context_shapes_are_rejected(self):
        for bad in (None, [], {"present": list(ALL_PRESENT), "extra": 1}, {}):
            data = sample()
            data["public_segment_context"] = bad
            with self.assertRaises(ValueError):
                correct_context(data)


class AnnotationTests(unittest.TestCase):
    def test_context_report_is_published_compactly(self):
        from annotate_caller_summary import render_context
        report = {"status": "native_small_profile_verified_application_binding_outstanding",
                  "native_proof_verified": True, "application_statement_authenticated": False,
                  "program_identity_bound": False,
                  "context_correction": {"before": ALL_PRESENT, "after": EXPECTED},
                  "proof": {"bytes": 1, "sha256": "ab"}, "stages": [{"status": "success", "returncode": 0}]}
        lines = render_context(report)
        self.assertTrue(all(l.startswith("::notice title=S3Q") for l in lines))
        self.assertTrue(all(chr(10) not in l for l in lines))
        self.assertIn('"native_proof_verified":true', lines[0])
        failed = render_context({**report, "native_proof_verified": False, "error": "x"})
        self.assertTrue(all(l.startswith("::error title=S3Q") for l in failed))
        self.assertTrue(render_context(None)[0].startswith("::error title=S3Q run"))


if __name__ == "__main__":
    unittest.main()
