// SPDX-License-Identifier: LGPL-3.0-only

//! Staging check: every CKKS on-chain param set resolves all its required
//! proof artifacts from the integration node dir (fail-closed posture).
//!
//! Run after `scripts/stage-ckks-circuits.sh`:
//! `cargo test -p e3-zk-prover --release --test ckks_staged_artifacts -- --ignored --nocapture`

use std::path::PathBuf;

use e3_fhe_params::ckks_presets::ckks_params_for_on_chain_param_set;
use e3_fhe_params::BfvPreset;
use e3_zk_prover::ckks_artifacts::check_ckks_artifacts_for_e3;
use fhe_traits::Serialize as _;

#[test]
#[ignore = "needs the staged integration artifact dir"]
fn every_ckks_param_set_is_fully_staged() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/integration/.interfold/noir/circuits");
    for set in [0u8, 2, 3, 4, 5] {
        let params = ckks_params_for_on_chain_param_set(set).unwrap();
        let posture = check_ckks_artifacts_for_e3(
            Some(&dir),
            BfvPreset::InsecureThreshold512,
            &params.to_bytes(),
            1,
            3,
        )
        .unwrap_or_else(|e| panic!("param set {set}: {e:#}"));
        println!("ParamSet {set}: {}", posture.summary());
        assert!(!posture.is_proof_free_override());
    }
}
