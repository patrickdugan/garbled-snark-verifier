"""Offline checks for the fail-closed, source-pinned lookup diagnostic."""
import unittest
from instrument_lookup import instrument
from summarize_lookup import parse, P


def source_fixture():
    prefix = (
        "pub fn lookup_sum(claim: &CairoClaim, common_lookup_elements: &CommonLookupElements, "
        "interaction_claim: &CairoInteractionClaim) -> SecureField {\n"
        "    let mut sum = SecureField::zero();\n"
        "    sum += claim.public_data.logup_sum(common_lookup_elements);\n"
    )
    for i in range(66):
        prefix += (f"    interaction_claim.component_{i}.as_ref().inspect(|ic| {{\n"
                   "        sum += ic.claimed_sum;\n"
                   "    });\n")
    return prefix + "    sum\n}\n"


class LookupInstrumentationTests(unittest.TestCase):
    def test_inventory_is_checked_and_original_body_preserved(self):
        src=source_fixture()
        edited,fields=instrument(src)
        self.assertEqual(len(fields),66)
        self.assertEqual(edited.count("S3_LOOKUP_COMPONENT "),66)
        self.assertIn("    sum\n}",edited)
        self.assertIn("sum += claim.public_data.logup_sum(common_lookup_elements);",edited)
        self.assertEqual(edited.count("sum += ic.claimed_sum;"),66)
        self.assertEqual(edited.count("S3_LOOKUP_TOTAL"),1)

    def test_changed_inventory_fails(self):
        src=source_fixture().replace("component_65", "component_0")
        with self.assertRaises(ValueError):
            instrument(src)
        with self.assertRaises(ValueError):
            instrument(source_fixture().replace("component_65.as_ref().inspect", "component_65.as_ref().map"))

    @staticmethod
    def debug(v):
        return f"({v[0]} + {v[1]}i) + ({v[2]} + {v[3]}i)u"

    def report(self):
        return {"status":"one_shot_small_profile_failed",
                "native_proof_verified":False,
                "stages":[{"status":"command_failed"}]}

    def log(self):
        return ("\nS3_LOOKUP_RESIDUAL_BEGIN\n"
                "S3_LOOKUP_TOTAL "+self.debug((14,2,3,4))+"\n"
                "S3_LOOKUP_PUBLIC "+self.debug((8,1,1,1))+"\n"
                "S3_LOOKUP_COMPONENT test "+self.debug((6,1,2,3))+"\n"
                "S3_LOOKUP_RESIDUAL_END\n"
                "thread 'main' panicked: assertion left == right failed\n")

    def test_modular_sum_works_and_has_no_acceptance(self):
        result=parse(self.log(),self.report())
        self.assertTrue(result["recomputed_sum_matches_native"])
        self.assertFalse(result["native_proof_verified"])
        self.assertEqual(result["components_reported"],1)

    def test_missing_diagnostic_and_bad_policy_fail(self):
        with self.assertRaises(ValueError):
            parse(self.log().replace("S3_LOOKUP_RESIDUAL_END",""),self.report())
        with self.assertRaises(ValueError):
            parse(self.log(),{**self.report(),"native_proof_verified":True})
        with self.assertRaises(ValueError):
            parse(self.log().replace("S3_LOOKUP_TOTAL (14", "S3_LOOKUP_TOTAL (15"),self.report())

    def test_noncanonical_component_fails(self):
        with self.assertRaises(ValueError):
            parse(self.log().replace("COMPONENT test (6",f"COMPONENT test ({P}"),self.report())


if __name__=="__main__":
    unittest.main()
