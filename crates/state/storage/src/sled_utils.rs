// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use sled::{Db, Tree};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tracing::info;

// Global static cache
pub static SLED_CACHE: Lazy<Arc<Mutex<HashMap<String, Db>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

// Returns a stable canonical string path used as a cache key.
// Canonicalizes the parent directory if the target path does not yet exist.
fn canonical_key(path: &Path) -> String {
    if path.exists() {
        return path
            .canonicalize()
            .unwrap_or_else(|_| path.to_path_buf())
            .to_string_lossy()
            .into_owned();
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let base: PathBuf = parent
        .canonicalize()
        .unwrap_or_else(|_| parent.to_path_buf());
    let tail = path.file_name().map(|s| s.to_owned()).unwrap_or_default();
    base.join(tail).to_string_lossy().into_owned()
}

// Opens or retrieves a cached sled database for the given path.
// Prevents conflicts by ensuring only a single connection was open to a db file at once per process.
// Ensures the directory exists and stabilizes the canonical key across OSes.
fn get_or_open_db(path: &PathBuf) -> Result<Db> {
    let _ = std::fs::create_dir_all(path);
    let key = canonical_key(path);
    let mut cache = SLED_CACHE.lock().unwrap();
    if let Some(db) = cache.get(&key) {
        return Ok(db.clone());
    }
    let db = sled::open(path).with_context(|| {
        format!(
            "Could not open database at path '{}'",
            path.to_string_lossy()
        )
    })?;
    cache.insert(key, db.clone());
    if !db.was_recovered() {
        info!("created db at: {:?}", &path);
    } else {
        info!("recovered db st: {:?}", &path);
    }

    Ok(db)
}

pub fn get_or_open_db_tree(path: &PathBuf, tree: &str) -> Result<Tree> {
    let db = get_or_open_db(path)?;
    Ok(db.open_tree(tree)?)
}

pub fn clear_all_caches() {
    let mut cache_lock = SLED_CACHE.lock().unwrap();
    cache_lock.clear();
}
