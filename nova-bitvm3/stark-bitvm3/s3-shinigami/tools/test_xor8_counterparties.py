"""Proof-free checks for zero-tuple source attribution and strict native evidence."""
from __future__ import annotations
import unittest

from instrument_xor8_counterparties import (
    OLD_METHOD, NEW_METHOD, OLD_WRITER, NEW_WRITER, ROOT_COUNTERS,
    SOURCES, TABLE_SOURCE, instrument_table,
)
from summarize_xor8_counterparties import parse
from test_xor8_relations import native_log, native_report

EXAMPLE = {
    "triple_xor_32":(3072,256),
    "blake_g":(512,0),
    "blake_compress_opcode":(512,0),
    "bitwise_builtin":(0,16),
    "other":(0,0),
}


def synthetic(ledger=EXAMPLE, truncated=False):
    base = native_log(truncated=truncated).replace(
        "  [112558620, 20, 31, 11] -> 2147483646",
        "  [112558620] -> 2147479551",
    )
    lines = ["S3_XOR8_COUNTERPARTY_BEGIN"]
    for name in SOURCES:
        for index in range(2):
            lines.append(f"S3_XOR8_ZERO_USE source={name} relation={index} count={ledger[name][index]}")
    lines.append("S3_XOR8_COUNTERPARTY_END")
    return "\n".join(lines)+"\n"+base


class CounterpartyTests(unittest.TestCase):
    def test_original_multiplicity_increment_preserved(self):
        code = instrument_table(OLD_WRITER+OLD_METHOD)
        self.assertEqual(code.count("self.mults[relation_index].increase_at("),1)
        self.assertIn("S3_XOR8_COUNTERPARTY_BEGIN",code)
        self.assertIn("std::panic::Location::caller().file()",code)
        self.assertIn("#[cfg_attr(feature = \"relation-tracker\", track_caller)]",code)
        self.assertIn("input.iter().all(|value| value.0 == 0)",code)
        self.assertIn("S3_XOR8_ZERO_INPUT_COUNTS[source_slot].fetch_add(",code)
        for name in SOURCES[:-1]:
            self.assertIn(f"/{name}.rs",code)
        self.assertEqual(code.count("S3_XOR8_ZERO_USE source="),1)
        self.assertEqual(code.count("S3_XOR8_ZERO_INPUT_COUNTS"),3)

    def test_pinned_source_changes_rejected(self):
        with self.assertRaises(ValueError):
            instrument_table((OLD_WRITER+OLD_METHOD).replace("input_to_row","untrusted_map"))
        with self.assertRaises(ValueError):
            instrument_table(OLD_WRITER+OLD_METHOD+OLD_METHOD)
        with self.assertRaises(ValueError):
            instrument_table(OLD_WRITER+OLD_WRITER+OLD_METHOD)

    def test_all_counted_sources_balance_minus4096_input_supply(self):
        d=parse(synthetic(),native_report())
        self.assertEqual(d["caller_tag0_uses"],4096)
        self.assertEqual(d["table_signed_supply"],-4096)
        self.assertTrue(d["caller_tag0_matches_table_supply"])
        self.assertEqual(d["caller_zero_input_counts"]["triple_xor_32"]["0"],3072)
        self.assertEqual(d["caller_tag1_uses"],272)
        self.assertTrue(d["all_direct_caller_uses_attributed"])
        self.assertFalse(d["counterpart_air_tuple_balances_verified"])
        self.assertFalse(d["cross_component_lookup_argument_verified"])
        self.assertFalse(d["native_proof_verified"])
        self.assertFalse(d["bitcoin_settlement_authorized"])

    def test_incomplete_source_balance_remains_diagnostic(self):
        changed={k:v for k,v in EXAMPLE.items()}
        changed["triple_xor_32"]=(3069,256)
        d=parse(synthetic(changed),native_report())
        self.assertFalse(d["caller_tag0_matches_table_supply"])
        self.assertEqual(d["caller_tag0_uses"],4093)
        self.assertFalse(d["native_proof_verified"])

    def test_unknown_source_flagged_without_claim_of_complete_attribution(self):
        changed={k:v for k,v in EXAMPLE.items()}
        changed["triple_xor_32"]=(3071,256)
        changed["other"]=(1,0)
        d=parse(synthetic(changed),native_report())
        self.assertTrue(d["caller_tag0_matches_table_supply"])
        self.assertFalse(d["all_direct_caller_uses_attributed"])
        self.assertEqual(d["unknown_direct_caller_uses"],1)

    def test_invalid_or_missing_counters_rejected(self):
        for bad in [
            synthetic().replace("count=3072","count=-1"),
            synthetic().replace("count=3072","count=9999999999"),
            synthetic().replace("source=triple_xor_32","source=untrusted"),
            synthetic().replace("relation=1","relation=2"),
            synthetic().replace("S3_XOR8_COUNTERPARTY_BEGIN",""),
            synthetic().replace("S3_XOR8_COUNTERPARTY_END",""),
            synthetic().replace("S3_XOR8_ZERO_USE source=other relation=0 count=0",""),
            synthetic()+"S3_XOR8_ZERO_USE source=other relation=0 count=0\n",
        ]:
            with self.assertRaises(ValueError):
                parse(bad,native_report())

    def test_native_proof_or_local_qm31_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            parse(synthetic(),{**native_report(),"native_proof_verified":True})
        with self.assertRaises(ValueError):
            parse(synthetic().replace("1866027004","1866027003"),native_report())
        with self.assertRaises(ValueError):
            parse(synthetic().replace("matches=true","matches=false"),native_report())
        with self.assertRaises(ValueError):
            parse(synthetic(truncated=True),native_report())

    def test_local_trimmed_tuple_supply_is_checked(self):
        with self.assertRaises(ValueError):
            parse(synthetic().replace("[112558620] -> 2147479551","[112558620] -> 2147479550"),native_report())
        with self.assertRaises(ValueError):
            parse(synthetic().replace("[112558620] -> 2147479551","[112558620, 1] -> 2147479551"),native_report())


if __name__ == "__main__":
    unittest.main()
