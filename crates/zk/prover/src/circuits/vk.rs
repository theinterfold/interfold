// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Loads verification key and hash for inner circuits (wrapper proof aggregation).
//! In the default variant directory, these are stored as `.vk` and `.vk_hash`.

use super::utils::bytes_to_field_strings;
use crate::error::ZkError;
use e3_zk_config::CircuitName;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::SystemTime;

/// Inner circuit VK artifacts for recursive verification.
#[derive(Clone, Debug)]
pub struct VkArtifacts {
    pub verification_key: Vec<String>,
    pub key_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct FileStamp {
    path: PathBuf,
    len: u64,
    modified: Option<SystemTime>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct VkCacheKey {
    vk: FileStamp,
    hash: FileStamp,
}

static VK_CACHE: OnceLock<RwLock<HashMap<VkCacheKey, Arc<VkArtifacts>>>> = OnceLock::new();
static VK_TREE_HASH_CACHE: OnceLock<RwLock<HashMap<FileStamp, String>>> = OnceLock::new();

fn stamp(path: &Path) -> Result<FileStamp, ZkError> {
    let meta = fs::metadata(path)
        .map_err(|e| ZkError::CircuitNotFound(format!("{}: {}", path.display(), e)))?;
    Ok(FileStamp {
        path: path.to_path_buf(),
        len: meta.len(),
        modified: meta.modified().ok(),
    })
}

fn load_vk_from_dir(circuit_dir: &Path, circuit_name: &str) -> Result<VkArtifacts, ZkError> {
    let vk_path = circuit_dir.join(format!("{}.vk", circuit_name));
    let vk_hash_path = circuit_dir.join(format!("{}.vk_hash", circuit_name));
    let key = VkCacheKey {
        vk: stamp(&vk_path)?,
        hash: stamp(&vk_hash_path)?,
    };

    let cache = VK_CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    if let Ok(guard) = cache.read() {
        if let Some(cached) = guard.get(&key) {
            return Ok((**cached).clone());
        }
    }

    let vk_bytes = fs::read(&vk_path)
        .map_err(|e| ZkError::CircuitNotFound(format!("{}: {}", vk_path.display(), e)))?;
    let verification_key = bytes_to_field_strings(&vk_bytes)?;
    let key_hash = load_hash(&vk_hash_path)?;

    let artifacts = Arc::new(VkArtifacts {
        verification_key,
        key_hash,
    });
    if let Ok(mut guard) = cache.write() {
        guard.retain(|existing, _| existing.vk.path != key.vk.path);
        guard.insert(key, Arc::clone(&artifacts));
    }
    Ok((*artifacts).clone())
}

fn load_hash(path: &Path) -> Result<String, ZkError> {
    let bytes = fs::read(path)
        .map_err(|e| ZkError::CircuitNotFound(format!("{}: {}", path.display(), e)))?;
    if bytes.len() != 32 {
        return Err(ZkError::InvalidInput(format!(
            "{}: expected 32 bytes, got {}",
            path.display(),
            bytes.len()
        )));
    }
    Ok(format!("0x{}", hex::encode(bytes)))
}

/// Load the complete recursive VK-tree anchor for a final aggregator witness.
pub fn load_vk_tree_hash(circuits_dir: &Path, circuit: CircuitName) -> Result<String, ZkError> {
    let path = circuits_dir
        .join(circuit.dir_path())
        .join(format!("{}.vk_tree_hash", circuit.as_str()));
    let key = stamp(&path)?;
    let cache = VK_TREE_HASH_CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    if let Ok(guard) = cache.read() {
        if let Some(cached) = guard.get(&key) {
            return Ok(cached.clone());
        }
    }
    let hash = load_hash(&path)?;
    if let Ok(mut guard) = cache.write() {
        guard.retain(|existing, _| existing.path != key.path);
        guard.insert(key, hash.clone());
    }
    Ok(hash)
}

/// Loads VK artifacts from `.vk` and `.vk_hash` in the variant-specific circuits directory.
/// The caller is responsible for passing the correct circuits_dir:
/// - `circuits_dir(CircuitVariant::Recursive)` for inner/base proofs embedded in a wrapper
/// - `circuits_dir(CircuitVariant::Default)` for wrapper/fold proofs
pub fn load_vk_artifacts(
    circuits_dir: &Path,
    circuit: CircuitName,
) -> Result<VkArtifacts, ZkError> {
    let circuit_dir = circuits_dir.join(circuit.dir_path());
    load_vk_from_dir(&circuit_dir, circuit.as_str())
}

/// Loads VK artifacts for a proof being combined into a recursive aggregation circuit.
#[allow(dead_code)]
pub fn load_vk_for_fold_input(
    circuits_dir: &Path,
    circuit: CircuitName,
) -> Result<VkArtifacts, ZkError> {
    load_vk_artifacts(circuits_dir, circuit)
}
