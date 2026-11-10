"""No-Pedersen fallback profile remains an explicit, independently checked option."""
import json
from pathlib import Path
import unittest

from check_no_pedersen_profile import EXPECTED, PROFILE, check


class ProfileTests(unittest.TestCase):
    def test_exact_source_pinned_no_pedersen_profile(self):
        result=check(json.loads(PROFILE.read_text()),{"pedersen_builtin":None})
        self.assertEqual(result["lifting_log"],26)
        self.assertEqual(result["nominal_fri_security_bits"],96)
        self.assertFalse(result["native_proof_verified"])
        self.assertFalse(result["production_security_reviewed"])

    def test_forbid_pedersen_builtin_even_when_empty(self):
        for builtin in ({"begin_addr":0,"stop_ptr":0}, {}, 0):
            with self.assertRaises(ValueError):
                check(EXPECTED,{"pedersen_builtin":builtin})
        with self.assertRaises(ValueError):
            check(EXPECTED,{"poseidon_builtin":None})

    def test_parameter_and_boolean_alias_mutations_rejected(self):
        for section,key,value in [
            ("root","preprocessed_trace","canonical_small"),
            ("root","channel_hash","poseidon252"),
            ("root","channel_salt",1),
            ("root","store_polynomials_coefficients",True),
            ("root","include_all_preprocessed_columns",True),
            ("pcs","lifting_log_size",22),
            ("pcs","pow_bits",25),
            ("pcs","lifting_log_size",True),
            ("fri","n_queries",71),
            ("fri","n_queries",True),
            ("fri","log_blowup_factor",2),
        ]:
            d=json.loads(PROFILE.read_text())
            sub = d if section=="root" else d["pcs_config"] if section=="pcs" else d["pcs_config"]["fri_config"]
            sub[key] = value
            with self.assertRaises(ValueError,msg=f"{section}.{key}={value}"):
                check(d,{"pedersen_builtin":None})


if __name__=="__main__":
    unittest.main()
