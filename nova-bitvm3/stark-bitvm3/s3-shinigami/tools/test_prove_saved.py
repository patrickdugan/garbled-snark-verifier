"""Input-integrity tests; these never invoke Scarb or a proof producer."""
import gzip
import hashlib
import tempfile
import unittest
from pathlib import Path
from prove_saved import restore_input


class RestoreTests(unittest.TestCase):
    def test_restores_with_exact_hash(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            original = b'hello'*30000
            with gzip.open(root/'input.gz','wb') as f:
                f.write(original)
            destination = root/'execution2/prover_input.json'
            receipt = restore_input(root/'input.gz', destination,
                expected_bytes=len(original),
                expected_sha256=hashlib.sha256(original).hexdigest())
            self.assertEqual(destination.read_bytes(),original)
            self.assertEqual(receipt['bytes'],len(original))
            with self.assertRaisesRegex(ValueError, 'already exists'):
                restore_input(root/'input.gz', destination,
                    expected_bytes=len(original), expected_sha256=receipt['sha256'])

    def test_rejects_wrong_hash_and_decompression_bomb(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            with gzip.open(root/'input.gz','wb') as f:
                f.write(b'A'*200_000)
            target = root/'execution2/prover_input.json'
            with self.assertRaisesRegex(ValueError,'beyond declared'):
                restore_input(root/'input.gz', target,
                    expected_bytes=100, expected_sha256='0'*64)
            self.assertFalse(target.exists())
            with self.assertRaisesRegex(ValueError,'SHA-256'):
                restore_input(root/'input.gz', target,
                    expected_bytes=200_000, expected_sha256='0'*64)
            self.assertFalse(target.exists())
            self.assertFalse(target.with_suffix('.partial').exists())


if __name__=='__main__':
    unittest.main()
