// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{fs, path::Path};

use anyhow::Result;
use noirc_abi::InputMap;
use serde_json::Value;
use tempfile::TempDir;

use crate::error::ZkError;

pub use crate::circuits::vk::load_vk_artifacts;
// I5 PoC (wall-clock tests): reuse the fold-circuit witness surface + inner C3 transcript
// extraction so the batch wall test exercises the exact production code paths.
pub use crate::circuits::aggregation::helpers::{
    extract_single_field, field_keys,
};
pub use serde_json;

/// I5 PoC (wall-clock tests): prove the `c3_fold_kernel` genesis for one inner C3 proof —
/// the same call the sequential fold makes on its first step. Batch arms anchor at this proof.
pub fn c3_fold_kernel_genesis(
    prover: &crate::prover::ZkProver,
    inner: &e3_events::Proof,
    total_slots: usize,
    artifacts_dir: &str,
    e3_id: &str,
) -> Result<e3_events::Proof, ZkError> {
    crate::circuits::aggregation::c3_accumulator::generate_c3_fold_kernel_genesis_proof(
        prover, inner, total_slots, artifacts_dir, e3_id,
    )
}

/// Field strings for recursive aggregation witness I/O (integration tests only).
pub fn fold_witness_field_strings(bytes: &[u8]) -> Result<Vec<String>, ZkError> {
    crate::circuits::utils::bytes_to_field_strings(bytes)
}

/// JSON → Noir input map for fold witness generation (integration tests only).
pub fn fold_witness_input_map(json: &Value) -> Result<InputMap, ZkError> {
    crate::circuits::utils::inputs_json_to_input_map(json)
}

/// Get the tempdir within ./target/tmp. This is important since some virtual environments such as nix
/// won't necessarily have access to bb globaly. Not all tmp operations need to use this path only
/// operations that require tools to exist within a shell at that location.
pub fn get_tempdir() -> Result<TempDir> {
    let tmp = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("target")
        .join("tmp");
    fs::create_dir_all(tmp.clone())?;
    Ok(TempDir::new_in(tmp)?)
}
