"""Fast static checks for the source-pinned lower-memory proving hypothesis."""
import json
import tempfile
from pathlib import Path
import unittest

from check_low_memory_profile import (check_profile, EXPECTED_PROFILE, CANONICAL,
                                      CANONICAL_SMALL)
from prove_low_memory import check_frozen_input


class SmallProfileTests(unittest.TestCase):
    def load(self):
        return json.loads(EXPECTED_PROFILE.resolve().read_text())

    def test_exact_pinned_profile_and_nominal_security(self):
        stats=check_profile(self.load())
        self.assertEqual(stats['nominal_fri_security_bits'],96)
        self.assertEqual(stats['twiddle_domain_size_ratio'],64)
        self.assertGreater(stats['cells_ratio'],50)
        self.assertEqual(stats['canonical_small_cells'],CANONICAL_SMALL)
        self.assertEqual(stats['canonical_cells'],CANONICAL)
        self.assertFalse(stats['actually_proved'])

    def test_reject_lower_security_or_unpinned_preprocessing(self):
        p=self.load();p['pcs_config']['fri_config']['n_queries']=3
        with self.assertRaises(ValueError): check_profile(p)
        p=self.load();p['preprocessed_trace']='canonical_without_pedersen'
        with self.assertRaises(ValueError): check_profile(p)
        p=self.load();p['pcs_config']['lifting_log_size']=19
        with self.assertRaises(ValueError): check_profile(p)
        p=self.load();p['include_all_preprocessed_columns']=True
        with self.assertRaises(ValueError): check_profile(p)
        p=self.load();p['unexpected']=True
        with self.assertRaises(ValueError): check_profile(p)

    def test_receipt_input_preflight_rejects_pedersen_or_oversize(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'input.json'
            data=dict(builtin_segments=dict(pedersen_builtin=None,poseidon_builtin=None),
                      memory=dict(address_to_id=list(range(8))),pc_count=7)
            path.write_text(json.dumps(data))
            self.assertTrue(check_frozen_input(path)['pedersen_builtin_absent'])
            data['builtin_segments']['pedersen_builtin']={}
            path.write_text(json.dumps(data))
            with self.assertRaises(ValueError): check_frozen_input(path)


if __name__=='__main__':
    unittest.main()
