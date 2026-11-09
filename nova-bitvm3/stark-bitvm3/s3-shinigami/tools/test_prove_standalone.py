"""Standalone execution-id checks, without invoking Cairo or proving."""
import unittest
from prove_standalone import find_fresh_execution


class ExecutionDirectoryTests(unittest.TestCase):
    def test_exact_new_execution_id(self):
        self.assertEqual(find_fresh_execution(
            {'execution1'}, {'execution1','execution2'}),(2,'execution2'))

    def test_reject_ambiguous_or_unexpected_folder(self):
        cases=[(set(),set()),(set(),{'execution0'}),
               (set(),{'execution1','execution2'}),(set(),{'execution-1'})]
        for prior,after in cases:
            with self.subTest(prior=prior,after=after):
                with self.assertRaises(ValueError):
                    find_fresh_execution(prior,after)


if __name__=='__main__':
    unittest.main()
