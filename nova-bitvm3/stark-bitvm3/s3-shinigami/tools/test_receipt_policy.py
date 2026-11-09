"""Proof-free public receipt tests for the scoped CSV and SHA256 hashlock pilots."""
import unittest
from hashlib import sha256
from receipt_policy import (
    ExpectedRequest, expected_receipt, audit_words, byte_array_words,
    CAIRO_P, CSV_SCRIPT, HASHLOCK_PREFIX, HASHLOCK_SUFFIX, MAX_MONEY,
)


def tx(script_sig=b"", sequence=10, version=2):
    assert len(script_sig) <= 75
    return (version.to_bytes(4, "little") + b"\x01" + bytes.fromhex("11"*32)
            + b"\x00\x00\x00\x00" + bytes([len(script_sig)]) + script_sig
            + sequence.to_bytes(4, "little") + b"\x01" + (900).to_bytes(8, "little")
            + b"\x01\x51" + (0).to_bytes(4, "little"))


class PublicBinding(unittest.TestCase):
    def csv(self):
        return ExpectedRequest(1, 1, tx(), 1000, CSV_SCRIPT, 100)

    def hashlock(self):
        preimage = b"utxoref-s3"
        return ExpectedRequest(2, 6, tx(bytes([len(preimage)])+preimage), 1000,
            HASHLOCK_PREFIX+sha256(preimage).digest()+HASHLOCK_SUFFIX, 100)

    def test_csv_matches_saved_receipt(self):
        import json
        from cases import cases
        from audit_execution import expected_csv_receipt
        x = expected_receipt(self.csv())
        self.assertEqual(len(x), 21)
        self.assertEqual(x, expected_csv_receipt())
        self.assertEqual(cases()[0]["args"], self.csv().cairo_words())
        report = audit_words(x, x)
        self.assertTrue(report["public_output_matches_expected"])
        self.assertFalse(report["proof_verified"])
        self.assertFalse(report["application_state_verified"])

    def test_hashlock_binding(self):
        from cases import cases
        req = self.hashlock()
        x = expected_receipt(req)
        self.assertGreater(len(x), len(expected_receipt(self.csv())))
        self.assertNotEqual(x, expected_receipt(self.csv()))
        self.assertEqual(req.cairo_words(), cases()[5]["args"])
        self.assertTrue(audit_words(x, x)["public_output_matches_expected"])

    def test_every_word_mutation_rejected(self):
        for req in [self.csv(), self.hashlock()]:
            x = expected_receipt(req)
            for i in range(len(x)):
                bad = x.copy()
                bad[i] = (bad[i]+1) % CAIRO_P
                with self.assertRaises(ValueError, msg=f"case={req.application} word={i}"):
                    audit_words(bad, x)

    def test_noncanonical_and_malformed_outputs_rejected(self):
        x = expected_receipt(self.csv())
        for bad in [x[:-1], x+[0], [CAIRO_P]+x[1:], [-1]+x[1:]]:
            with self.assertRaises(ValueError):
                audit_words(bad, x)
        bad = x.copy()
        bad[0] = True
        with self.assertRaises(ValueError):
            audit_words(bad, x)

    def test_script_profiles_reject_substitution(self):
        req = self.csv()
        for script in [b"\x51", b"\x5a\xb2\x75\x52", b"\x5a\xb2\x75", b"\x5a\xb2\x75\xac"]:
            with self.assertRaises(ValueError):
                expected_receipt(ExpectedRequest(1, 1, req.raw_transaction, 1000, script, 100))
        req = self.hashlock()
        for script in [b"\xa8\x20" + b"\0"*32 + b"\x88",
                       b"\xa8\x21" + b"\0"*32 + b"\x87", b"\xac"]:
            with self.assertRaises(ValueError):
                expected_receipt(ExpectedRequest(2, 6, req.raw_transaction, 1000, script, 100))

    def test_transaction_context_is_bound(self):
        req = self.csv()
        original = expected_receipt(req)
        for modified in [
            ExpectedRequest(1, 2, req.raw_transaction, 1000, req.prevout_script, 100),
            ExpectedRequest(1, 1, req.raw_transaction, 1001, req.prevout_script, 100),
            ExpectedRequest(1, 1, req.raw_transaction, 1000, req.prevout_script, 101),
            ExpectedRequest(1, 1, tx(sequence=11), 1000, req.prevout_script, 100),
        ]:
            with self.assertRaises(ValueError):
                audit_words(original, expected_receipt(modified))

    def test_policy_values_canonical(self):
        req = self.csv()
        for invalid in [
            ExpectedRequest(1, True, req.raw_transaction, 1000, CSV_SCRIPT, 100),
            ExpectedRequest(1, 1, req.raw_transaction, -1, CSV_SCRIPT, 100),
            ExpectedRequest(1, 1, req.raw_transaction, MAX_MONEY+1, CSV_SCRIPT, 100),
            ExpectedRequest(1, 1, req.raw_transaction, 1000, CSV_SCRIPT, 100, network=2),
            ExpectedRequest(3, 1, req.raw_transaction, 1000, CSV_SCRIPT, 100),
            ExpectedRequest(1, 2**256, req.raw_transaction, 1000, CSV_SCRIPT, 100),
        ]:
            with self.assertRaises(ValueError):
                expected_receipt(invalid)

    def test_exact_bytearray_encoding(self):
        self.assertEqual(byte_array_words(b""), [0,0,0])
        self.assertEqual(byte_array_words(bytes(range(32))),
                         [1,int.from_bytes(bytes(range(31)),"big"),31,1])
        self.assertEqual(byte_array_words(bytes(range(31))),
                         [1,int.from_bytes(bytes(range(31)),"big"),0,0])

    def test_success_must_have_zero_error(self):
        with self.assertRaises(ValueError):
            expected_receipt(self.csv(), accepted=True, error=1)
        with self.assertRaises(TypeError):
            expected_receipt(self.csv(), accepted=1)


if __name__=="__main__":
    unittest.main()
