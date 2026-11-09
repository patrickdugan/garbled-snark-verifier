#!/usr/bin/env python3
"""Static checks for the exact source-pinned small Stwo-Cairo prover profile.

The 96-bit number is the upstream nominal FRI PoW + query-count accounting.
It does not certify the entire Cairo proof system or the BitVM3 settlement.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent
EXPECTED_STWO_CAIRO = "467d5c6d4d6d526c1db8ff69c14f2de6d57f4d73"
EXPECTED_PROFILE = HERE/"../params/canonical-small-96.json"
CANONICAL = 543_100_528
WITHOUT_PEDERSEN = 73_338_480
CANONICAL_SMALL = 10_161_776
LARGE_DEFAULT_LIFTING_LOG = 28
SMALL_LIFTING_LOG = 22
MAX_SMALL_PREPROC_LOG = 20


def check_profile(p: dict) -> dict:
    required = {"channel_hash","channel_salt","pcs_config","preprocessed_trace",
                "store_polynomials_coefficients","include_all_preprocessed_columns"}
    if set(p) != required or p['channel_hash'] != 'blake2s' or p['channel_salt'] != 0:
        raise ValueError("unexpected profile configuration or channel")
    if p['preprocessed_trace'] != 'canonical_small':
        raise ValueError("profile changes the pinned preprocessed trace")
    if p['store_polynomials_coefficients'] is not False or p['include_all_preprocessed_columns'] is not False:
        raise ValueError("unexpected prover memory or preprocessed-sampling mode")
    config=p['pcs_config']
    if set(config) != {'pow_bits','fri_config','lifting_log_size'}:
        raise ValueError("unexpected PCS config")
    fri=config['fri_config']
    if set(fri) != {'log_last_layer_degree_bound','log_blowup_factor','n_queries','fold_step'}:
        raise ValueError("unexpected FRI config")
    if (config['lifting_log_size'] != SMALL_LIFTING_LOG
        or fri['log_last_layer_degree_bound'] != 0 or fri['log_blowup_factor'] != 1
        or fri['n_queries'] != 70 or fri['fold_step'] != 1 or config['pow_bits'] != 26):
        raise ValueError("profile's selected FRI or lifting parameters changed")
    if any(type(v) is not int for v in list(fri.values())+[config['pow_bits'],config['lifting_log_size']]):
        raise ValueError("invalid parameter types")
    if SMALL_LIFTING_LOG < MAX_SMALL_PREPROC_LOG + fri['log_blowup_factor']:
        raise ValueError("preprocessed columns exceed chosen lifting capacity")
    nominal_security = config['pow_bits'] + fri['log_blowup_factor']*fri['n_queries']
    if nominal_security != 96:
        raise ValueError("nominal FRI security changed")
    return dict(
        upstream_stwo_cairo=EXPECTED_STWO_CAIRO,
        selected_preprocessing='canonical_small',
        canonical_cells=CANONICAL,
        canonical_small_cells=CANONICAL_SMALL,
        cells_ratio=round(CANONICAL/CANONICAL_SMALL,3),
        without_pedersen_cells=WITHOUT_PEDERSEN,
        raw_canonical_base_field_mib=round(CANONICAL*4/2**20,3),
        raw_small_base_field_mib=round(CANONICAL_SMALL*4/2**20,3),
        default_twiddle_log=LARGE_DEFAULT_LIFTING_LOG,
        selected_twiddle_log=SMALL_LIFTING_LOG,
        twiddle_domain_size_ratio=2**(LARGE_DEFAULT_LIFTING_LOG-SMALL_LIFTING_LOG),
        nominal_fri_security_bits=nominal_security,
        actually_proved=False,
        native_verification_complete=False,
    )


def verify_upstream_checkout(root: Path) -> str:
    root=root.resolve()
    checkout=subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip()
    if checkout!=EXPECTED_STWO_CAIRO:
        raise ValueError(f"expected upstream {EXPECTED_STWO_CAIRO}, found {checkout}")
    source=root/'stwo_cairo_prover/crates/common/src/preprocessed_columns/preprocessed_trace.rs'
    proving=root/'stwo_cairo_prover/crates/prover/src/prover.rs'
    for filename,term in [
      (source,'pub const CANONICAL_SIZE: u32 = 543100528;'),
      (source,'pub const CANONICAL_SMALL: u32 = 10161776;'),
      (source,'pub const SMALL_MAX_SEQUENCE_LOG_SIZE: u32 = 20;'),
      (proving,'preprocessed_trace: PreProcessedTraceVariant::Canonical,'),
      (proving,'pub store_polynomials_coefficients: bool,')
    ]:
        if term not in filename.read_text():
            raise ValueError('upstream preprocessed semantics differ from the pin: '+term)
    if not re.search(r'pub\(crate\) const LOG_MAX_ROWS: u32 = 27;',proving.read_text()):
        raise ValueError('default prover max-domain assumption changed')
    return checkout


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--profile',type=Path,default=EXPECTED_PROFILE)
    ap.add_argument('--upstream',type=Path)
    args=ap.parse_args()
    report=check_profile(json.loads(args.profile.read_text()))
    if args.upstream:
        report['checkout_verified']=verify_upstream_checkout(args.upstream)
    print(json.dumps(report,indent=2))


if __name__ == '__main__':
    main()
