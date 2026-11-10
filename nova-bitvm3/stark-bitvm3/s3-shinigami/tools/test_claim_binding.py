"""Fast synthetic mutation tests for public-memory policy, without proof generation."""
import copy
from hashlib import sha256
import unittest
from claim_binding import ClaimMismatch, load_policy, audit_untrusted_claim


def limbs(n):
    return [(n >> (32*i)) & 0xffffffff for i in range(8)]


class ClaimBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pinned_standalone = load_policy("standalone")
        cls.pinned_bootloader = load_policy("bootloader")
        cls.words = [0x40780017fff7fff, 11, 0x1104800180018000, 0xc10]

    def fixture(self, profile="standalone"):
        p = copy.deepcopy(load_policy(profile))
        p["program_words"] = len(self.words)
        p["program_sha256_u256le"] = sha256(
            b"".join(x.to_bytes(32, "little") for x in self.words)).hexdigest()
        claim = {
            "channel_salt": p["channel_salt"],
            "preprocessed_trace_variant": p["preprocessed_trace_variant"],
            "stark_proof": {"config": copy.deepcopy(p["pcs_config"])},
            "claim": {"public_data": {"public_memory": {
                "program": [[i, limbs(x)] for i, x in enumerate(self.words)],
                "output": [[i, limbs(x)] for i, x in enumerate(p["expected_output"])],
                "public_segments": {"output": {
                    "start_ptr": {"value": p["output_start"]},
                    "stop_ptr": {"value": p["output_stop"]},
                }}
            }}}
        }
        return p, claim

    def reject(self, policy, claim):
        with self.assertRaises(ClaimMismatch):
            audit_untrusted_claim(claim, policy)

    def test_pinned_provenance(self):
        self.assertEqual(self.pinned_standalone["program_words"], 169856)
        self.assertEqual(self.pinned_bootloader["program_words"], 3182)
        self.assertEqual(self.pinned_standalone["program_sha256_u256le"],
                         "ef98c72eff798d04a235c395be190c38b536a584a9dd5f66692e2174ac5b8b7f")
        self.assertEqual(len(self.pinned_standalone["expected_output"]), 21)
        self.assertEqual(len(self.pinned_bootloader["expected_output"]), 24)

    def test_structurally_matching_profiles_are_never_authenticated(self):
        for name in ("standalone", "bootloader"):
            policy, claim = self.fixture(name)
            report = audit_untrusted_claim(claim, policy)
            self.assertTrue(report["public_program_matched"])
            self.assertTrue(report["fixed_public_output_matched"])
            self.assertFalse(report["native_stark_proof_verified"])
            self.assertFalse(report["shinigami_executable_identity_authenticated"])
            self.assertFalse(report["settlement_authorized"])

    def test_program_changes(self):
        policy, claim = self.fixture()
        for idx in range(len(self.words)):
            c = copy.deepcopy(claim)
            c["claim"]["public_data"]["public_memory"]["program"][idx][1][0] ^= 1
            self.reject(policy, c)

    def test_all_public_output_changes(self):
        policy, claim = self.fixture()
        for idx in range(len(policy["expected_output"])):
            c = copy.deepcopy(claim)
            c["claim"]["public_data"]["public_memory"]["output"][idx][1][0] ^= 1
            self.reject(policy, c)

    def test_noncanonical_limbs_and_ids(self):
        policy, claim = self.fixture()
        for idx, value in [(0, True), (1, -1), (7, 0xffffffff)]:
            c = copy.deepcopy(claim)
            c["claim"]["public_data"]["public_memory"]["program"][0][1][idx] = value
            self.reject(policy, c)
        c = copy.deepcopy(claim)
        c["claim"]["public_data"]["public_memory"]["program"][0][0] = -1
        self.reject(policy, c)

    def test_output_segment_changes(self):
        policy, claim = self.fixture()
        for field in ("start_ptr", "stop_ptr"):
            c = copy.deepcopy(claim)
            c["claim"]["public_data"]["public_memory"]["public_segments"]["output"][field]["value"] += 1
            self.reject(policy, c)

    def test_profile_and_channel_mutations(self):
        policy, claim = self.fixture()
        for key, changed in (("channel_salt", 1), ("preprocessed_trace_variant", "canonical")):
            c = copy.deepcopy(claim)
            c[key] = changed
            self.reject(policy, c)
        for key, changed in (("pow_bits", 0), ("lifting_log_size", None)):
            c = copy.deepcopy(claim)
            c["stark_proof"]["config"][key] = changed
            self.reject(policy, c)
        c = copy.deepcopy(claim)
        c["stark_proof"]["config"]["fri_config"]["n_queries"] = 3
        self.reject(policy, c)

    def test_missing_fields_and_shape(self):
        policy, claim = self.fixture()
        for missing in ("claim", "stark_proof"):
            c = copy.deepcopy(claim)
            c.pop(missing)
            self.reject(policy, c)
        c = copy.deepcopy(claim)
        c["claim"]["public_data"]["public_memory"]["program"].pop()
        self.reject(policy, c)
        c = copy.deepcopy(claim)
        c["claim"]["public_data"]["public_memory"]["output"].append([1, limbs(0)])
        self.reject(policy, c)

    def test_extended_proof_envelope(self):
        policy, claim = self.fixture()
        claim["extended_stark_proof"] = {"proof": claim.pop("stark_proof")}
        self.assertTrue(audit_untrusted_claim(claim, policy)["public_program_matched"])


if __name__ == "__main__":
    unittest.main()
