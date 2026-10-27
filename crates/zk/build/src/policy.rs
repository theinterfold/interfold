// SPDX-License-Identifier: LGPL-3.0-only

use crate::artifacts::Circuit;
use e3_fhe_params::BfvPreset;

const LBFV: &[&str] = &[
    "lbfv_pk_generation",
    "lbfv_pk_aggregation",
    "rlk_generation",
    "rlk_aggregation",
    "lbfv_generation_fold",
    "lbfv_generation_fold_kernel",
    "node_fold_v2",
    "nodes_fold_v2",
    "nodes_fold_v2_kernel",
    "lbfv_aggregation_fold",
    "lbfv_aggregation_fold_kernel",
    "dkg_aggregator_v2",
    "sk_share_computation_chunk",
    "esm_share_computation_chunk",
    "share_encryption_chunked",
    "share_decryption_chunked",
    "decrypted_shares_aggregation_wide",
    "sk_c2_chunk_finalize",
    "esm_c2_chunk_finalize",
    "c2_chunk_batch",
    "c2ab_chunk_fold",
    "c3_fold_chunked",
    "c3_fold_kernel_chunked",
    "c3ab_fold_chunked",
    "node_fold_chunked",
];

const SHARED: &[&str] = &[
    "dkg/pk",
    "threshold/share_decryption",
    "recursive_aggregation/c6_fold",
    "recursive_aggregation/c6_fold_kernel",
    "recursive_aggregation/decryption_aggregator",
    "recursive_aggregation/c4ab_fold",
    "recursive_aggregation/nodes_fold_kernel",
    "recursive_aggregation/dkg_aggregator",
    "threshold/ct0_chunk_main",
    "threshold/ct0_pk_ct_commit",
    "threshold/ct0_eval_chunk_identity",
    "threshold/user_data_encryption_ct0_chunked",
    "threshold/ct1_chunk_main",
    "threshold/ct1_pk_ct_commit",
    "threshold/ct1_eval_chunk_identity",
    "threshold/user_data_encryption_ct1_chunked",
    "threshold/user_data_encryption_chunked",
];

pub fn enabled(circuit: &Circuit, preset: BfvPreset) -> bool {
    match preset {
        // The trBFV archives (insecure-64, secure-8192) hold no l-BFV circuits.
        BfvPreset::InsecureThreshold64 | BfvPreset::SecureThreshold8192 => {
            !LBFV.contains(&circuit.name.as_str())
        }
        // The insecure, SIMD and 16384-bit archives serve only the l-BFV path.
        BfvPreset::InsecureThresholdLbfv
        | BfvPreset::SecureThreshold16384
        | BfvPreset::SecureThreshold16384Simd
        | BfvPreset::SecureThreshold16384SimdD6
        | BfvPreset::InsecureThresholdSimd => {
            LBFV.contains(&circuit.name.as_str())
                || SHARED.contains(&format!("{}/{}", circuit.group, circuit.name).as_str())
        }
        _ => false,
    }
}

pub fn has_lbfv(preset: &str) -> bool {
    matches!(
        preset,
        "insecure"
            | "insecure-simd"
            | "secure-16384"
            | "secure-16384-simd"
            | "secure-16384-simd-d6"
    )
}

/// The l-BFV-only archives hold no trBFV circuits and anchor the VK tree at C6.
pub fn has_trbfv(preset: &str) -> bool {
    !has_lbfv(preset)
}

pub fn required_artifacts(preset: &str) -> Vec<String> {
    let mut files: Vec<String> =
        serde_json::from_str(include_str!("../../prover/required-artifacts.json"))
            .expect("valid common artifact manifest");
    if has_trbfv(preset) {
        files.extend(
            serde_json::from_str::<Vec<String>>(include_str!(
                "../../prover/required-artifacts-trbfv.json"
            ))
            .expect("valid trBFV artifact manifest"),
        );
    }
    if has_lbfv(preset) {
        files.extend(
            serde_json::from_str::<Vec<String>>(include_str!(
                "../../prover/required-artifacts-lbfv.json"
            ))
            .expect("valid l-BFV artifact manifest"),
        );
    }
    files
}
