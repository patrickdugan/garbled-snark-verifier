#!/usr/bin/env python3
"""Static fail-closed preflight for no-Pedersen fallback. No proving by default."""
from __future__ import annotations
import argparse
import gzip
import json
from pathlib import Path
from check_low_memory_profile import EXPECTED_STWO_CAIRO, verify_upstream_checkout

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "params/canonical-no-pedersen-96.json"
EXPECTED = {
    "channel_hash":"blake2s","channel_salt":0,
    "pcs_config":{
        "pow_bits":26,
        "fri_config":{
            "log_last_layer_degree_bound":0,
            "log_blowup_factor":1,
            "n_queries":70,
            "fold_step":1
        },
        "lifting_log_size":26
    },
    "preprocessed_trace":"canonical_without_pedersen",
    "store_polynomials_coefficients":False,
    "include_all_preprocessed_columns":False
}

def check(config: dict, builtin_segments: dict) -> dict:
    if (config != EXPECTED or type(config.get('channel_salt')) is not int
        or any(type(config['pcs_config'][k]) is not int
        for k in ['pow_bits','lifting_log_size']) or any(
        type(x) is not int for x in config['pcs_config']['fri_config'].values())):
        raise ValueError("fallback parameter set differs from the pinned profile")
    if not isinstance(builtin_segments,dict) or "pedersen_builtin" not in builtin_segments:
        raise ValueError("Pedersen builtin status is missing")
    if builtin_segments["pedersen_builtin"] is not None:
        raise ValueError("fallback requires an absent Pedersen builtin")
    if config["pcs_config"]["lifting_log_size"] < 25 + config["pcs_config"]["fri_config"]["log_blowup_factor"]:
        raise ValueError("lift smaller than full 25-log sequence with blowup")
    fri = config["pcs_config"]["fri_config"]
    nominal = config["pcs_config"]["pow_bits"] + fri["log_blowup_factor"] * fri["n_queries"]
    if nominal != 96:
        raise ValueError("unexpected nominal FRI security")
    return {
        "upstream":EXPECTED_STWO_CAIRO,
        "profile":"canonical_without_pedersen",
        "max_preprocessed_sequence_log":25,
        "lifting_log":26,
        "base_field_table_cells":73_338_480,
        "minimum_raw_base_field_bytes":73_338_480*4,
        "nominal_fri_security_bits":nominal,
        "pedersen_builtin_absent":True,
        "native_proof_verified":False,
        "production_security_reviewed":False,
    }

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--profile",type=Path,default=PROFILE)
    ap.add_argument("--input",type=Path,required=True,
                    help="exact standalone ProverInput JSON, optionally gzip-compressed")
    ap.add_argument("--upstream",type=Path,help="optional pinned upstream checkout to check")
    args=ap.parse_args()
    if args.input.suffix == ".gz":
        with gzip.open(args.input,"rt") as source:
            data=json.load(source)
    else:
        data=json.loads(args.input.read_text())
    result=check(json.loads(args.profile.read_text()),data["builtin_segments"])
    if args.upstream is not None:
        result["checkout_verified"]=verify_upstream_checkout(args.upstream)
    print(json.dumps(result,indent=2))

if __name__=="__main__":
    main()
