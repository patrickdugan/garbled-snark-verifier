#!/usr/bin/env python3
"""Source-pinned XOR8 zero-input counterparty audit; native proof stays rejected.

Adds diagnostic-only atomic counters to the existing producer API
verify_bitwise_xor_8::ClaimGenerator::add_packed_inputs. #[track_caller]
assigns each supplied (0,0,0) tuple to the direct source component. The native
atomic multiplicity increase and source-row commitment are unchanged.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
from pathlib import Path
import subprocess

from instrument_local_relations import REV, SOURCE, TRACKER_SOURCE
from instrument_xor8_relations import (
    WITNESS_SOURCE, instrument_prover, instrument_tracker, instrument_witness,
)

TABLE_SOURCE = "stwo_cairo_prover/crates/prover/src/witness/components/verify_bitwise_xor_8.rs"
SOURCES = ("triple_xor_32", "blake_g", "blake_compress_opcode", "bitwise_builtin", "other")
OLD_METHOD = """    pub fn add_packed_inputs(&self, packed_inputs: &[PackedInputType], relation_index: usize) {
        packed_inputs.into_par_iter().for_each(|packed_input| {
            for input in packed_input.unpack() {
                self.mults[relation_index].increase_at(
                    (*self.input_to_row.get(&input).unwrap())
                        .try_into()
                        .unwrap(),
                );
            }
        });
    }
"""
NEW_METHOD = """    // Only this feature-gated diagnostic observes callsites. The original
    // atomic multiplicity updates below are identical to the pinned producer.
    #[cfg_attr(feature = "relation-tracker", track_caller)]
    pub fn add_packed_inputs(&self, packed_inputs: &[PackedInputType], relation_index: usize) {
        #[cfg(feature = "relation-tracker")]
        let source_slot = {
            assert!(relation_index < 2, "XOR8 relation index exceeds source shape");
            let file = std::panic::Location::caller().file();
            let group = if file.ends_with("/triple_xor_32.rs") {
                0usize
            } else if file.ends_with("/blake_g.rs") {
                1
            } else if file.ends_with("/blake_compress_opcode.rs") {
                2
            } else if file.ends_with("/bitwise_builtin.rs") {
                3
            } else {
                4
            };
            group * 2 + relation_index
        };
        packed_inputs.into_par_iter().for_each(|packed_input| {
            for input in packed_input.unpack() {
                #[cfg(feature = "relation-tracker")]
                if input.iter().all(|value| value.0 == 0) {
                    S3_XOR8_ZERO_INPUT_COUNTS[source_slot].fetch_add(
                        1, std::sync::atomic::Ordering::Relaxed,
                    );
                }
                self.mults[relation_index].increase_at(
                    (*self.input_to_row.get(&input).unwrap())
                        .try_into()
                        .unwrap(),
                );
            }
        });
    }
"""
ROOT_COUNTERS = """
/// Diagnostic-only per direct caller / relation index zero-input counters.
/// Index layout is source_index * 2 + relation_index. These atomics do not
/// influence the actual prover multiplicities or STARK verifier decisions.
#[cfg(feature = "relation-tracker")]
static S3_XOR8_ZERO_INPUT_COUNTS: [std::sync::atomic::AtomicU64; 10] =
    [const { std::sync::atomic::AtomicU64::new(0) }; 10];
"""
OLD_WRITER = """    pub fn write_trace(
        self,
    ) -> (
        ComponentTrace<N_TRACE_COLUMNS>,
        Claim,
        InteractionClaimGenerator,
    ) {
        let mults = self"""
NEW_WRITER = """    pub fn write_trace(
        self,
    ) -> (
        ComponentTrace<N_TRACE_COLUMNS>,
        Claim,
        InteractionClaimGenerator,
    ) {
        #[cfg(feature = "relation-tracker")]
        {
            use std::sync::atomic::Ordering;
            let labels = [
                "triple_xor_32", "blake_g", "blake_compress_opcode",
                "bitwise_builtin", "other",
            ];
            eprintln!("S3_XOR8_COUNTERPARTY_BEGIN");
            for (group, label) in labels.iter().enumerate() {
                for relation in 0..2 {
                    let count = S3_XOR8_ZERO_INPUT_COUNTS[group * 2 + relation]
                        .load(Ordering::Relaxed);
                    eprintln!(
                        "S3_XOR8_ZERO_USE source={} relation={} count={}",
                        label, relation, count
                    );
                }
            }
            eprintln!("S3_XOR8_COUNTERPARTY_END");
        }
        let mults = self"""


def instrument_table(original: str) -> str:
    if original.count(OLD_METHOD) != 1:
        raise ValueError("upstream XOR8 add_packed_inputs implementation changed")
    if original.count(OLD_WRITER) != 1:
        raise ValueError("upstream XOR8 write_trace entry changed")
    if "S3_XOR8_ZERO_INPUT_COUNTS" in original:
        raise ValueError("upstream already includes diagnostic counter")
    modified = original.replace(OLD_METHOD, NEW_METHOD).replace(OLD_WRITER, NEW_WRITER)
    if modified.count("self.mults[relation_index].increase_at(") != 1:
        raise ValueError("original table multiplicity update changed")
    if modified.count("S3_XOR8_ZERO_USE source=") != 1:
        raise ValueError("source inventory is incomplete")
    return modified + ROOT_COUNTERS


def prepare(root: Path, destination: Path) -> dict:
    root = root.resolve()
    actual = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    if actual != REV:
        raise ValueError(f"upstream revision changed: {actual}")
    patches = []
    updated = []
    for path, transform in (
        (SOURCE, instrument_prover),
        (TRACKER_SOURCE, instrument_tracker),
        (WITNESS_SOURCE, instrument_witness),
        (TABLE_SOURCE, instrument_table),
    ):
        original = subprocess.check_output(
            ["git", "-C", str(root), "show", f"HEAD:{path}"], text=True)
        if (root / path).read_text() != original:
            raise ValueError(f"upstream file was already modified: {path}")
        modified = transform(original)
        patches.append("".join(difflib.unified_diff(
            original.splitlines(keepends=True),
            modified.splitlines(keepends=True),
            fromfile="a/" + path, tofile="b/" + path,
        )))
        updated.append((path, original, modified))
    # Nothing changes until the complete four-file source pin has passed.
    for path, _, modified in updated:
        (root / path).write_text(modified)
    patch = "".join(patches)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(patch)
    return {
        "stage": "S3n pinned XOR8 zero-tuple cross-component attribution",
        "upstream_revision": REV,
        "selected_relation_tags": {"0": 112558620, "1": 521092554},
        "selected_tuple": [0, 0, 0],
        "expected_source_groups": list(SOURCES),
        "source_file_hashes": [{
            "path": path,
            "before_sha256": hashlib.sha256(original.encode()).hexdigest(),
            "diagnostic_sha256": hashlib.sha256(modified.encode()).hexdigest(),
        } for path, original, modified in updated],
        "patch_sha256": hashlib.sha256(patch.encode()).hexdigest(),
        "source_count_only": True,
        "original_multiplicity_increase_unchanged": True,
        "original_global_lookup_assertion_unchanged": True,
        "full_stark_proof_verified": False,
        "bitcoin_application_authorized": False,
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--upstream", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    print(json.dumps(prepare(args.upstream, args.output), indent=2))


if __name__ == "__main__":
    main()
