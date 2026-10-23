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

/// Repository root for prover tests and their shared artifacts.
pub fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("prover crate must be inside crates/zk")
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
    let tmp = workspace_root().join("target/tmp");
    fs::create_dir_all(tmp.clone())?;
    Ok(TempDir::new_in(tmp)?)
}
