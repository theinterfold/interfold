// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The node's state on disk: its folder in the node's data directory, the layout the folder was
//! written in, and the E3s its journal still holds. The operator's keys are not in the folder:
//! they stay in the keystore, so deleting the folder keeps the node's identity.

use crate::keystore;
use anyhow::{Context, Result};
use e3_ciphernode_config::NodeConfig;
use e3_crypto::Cipher;
use e3_engine::Engine;
use e3_entrypoint::fence::{ProcessFence, LOCK_FILE_NAME};
use e3_journal::Journal;
use e3_protocol::{node::Node, E3Id};
use std::{
    collections::BTreeSet,
    io::ErrorKind,
    path::{Path, PathBuf},
};

pub fn folder(config: &NodeConfig) -> PathBuf {
    config.node_data_dir().join("v2")
}

/// The journal of the node whose data folder is `node_data_dir`.
pub fn journal_in(node_data_dir: &Path) -> PathBuf {
    node_data_dir.join("v2").join("journal.redb")
}

/// Whether the folder holds node data in a layout that this binary does not write, and so cannot
/// read: the node refuses to start on it.
pub fn layout_is_older(config: &NodeConfig) -> Result<bool> {
    match std::fs::read_to_string(folder(config).join("LAYOUT")) {
        Ok(found) => Ok(found.trim() != e3_node::launch::data_layout()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// The E3s the node's journal holds. The node keeps each E3, and the key share it dealt in it,
/// until the E3 ends. Replaying the journal needs the operator's address, from the keystore.
pub async fn held_e3s(config: &NodeConfig) -> Result<Vec<E3Id>> {
    let path = journal_in(&config.node_data_dir());
    if !path.exists() {
        return Ok(Vec::new());
    }
    let cipher = Cipher::from_file(config.key_file()).await?;
    let operator = keystore::read(&config.db_file(), &cipher)?
        .context("the node has a journal but no wallet: its E3s cannot be read")?
        .address();
    let journal = Journal::open(&path)?;
    let (engine, _) = Engine::open(journal, Node::new(operator), u64::MAX)?;
    Ok(engine.machine().held().copied().collect())
}

/// Fences every node whose lock is under `root` and returns the node folders under `root`, at any
/// depth, that `checked` does not name: whatever deletes `root` deletes their E3s unchecked. A
/// fence in `fences` already covers its lock.
pub fn guard(
    root: &Path,
    checked: &[PathBuf],
    fences: &mut Vec<ProcessFence>,
) -> Result<Vec<PathBuf>> {
    let mut contents = Contents::default();
    scan(root, &mut BTreeSet::new(), &mut contents)?;
    let canonical =
        |path: &Path| std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let held: BTreeSet<PathBuf> = fences.iter().map(|fence| canonical(fence.path())).collect();
    for lock in &contents.locks {
        if !held.contains(&canonical(lock)) {
            fences.push(ProcessFence::hold_existing(lock)?);
        }
    }
    let checked: BTreeSet<PathBuf> = checked.iter().map(|folder| canonical(folder)).collect();
    Ok(contents
        .nodes
        .into_iter()
        .filter(|folder| !checked.contains(&canonical(folder)))
        .collect())
}

/// What a folder holds at any depth: the node folders, each with its journal at
/// `v2/journal.redb`, and the lock files of the nodes that use them.
#[derive(Default)]
struct Contents {
    nodes: Vec<PathBuf>,
    locks: Vec<PathBuf>,
}

/// Every folder counts as a node folder when its journal exists, also inside another node's
/// folder. The walk follows links to folders, since a node's state may live elsewhere behind one,
/// and visits each folder once, since a link may point back up. The deletion follows no link.
fn scan(dir: &Path, visited: &mut BTreeSet<PathBuf>, contents: &mut Contents) -> Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !visited.insert(std::fs::canonicalize(dir)?) {
        return Ok(());
    }
    if journal_in(dir).exists() {
        contents.nodes.push(dir.to_path_buf());
    }
    for entry in entries {
        let entry = entry?;
        let (path, kind) = (entry.path(), entry.file_type()?);
        if entry.file_name() == LOCK_FILE_NAME {
            contents.locks.push(path);
        } else if kind.is_dir() {
            scan(&path, visited, contents)?;
        } else if kind.is_symlink() {
            match std::fs::metadata(&path) {
                Ok(target) if target.is_dir() => scan(&path, visited, contents)?,
                Ok(_) => {}
                // A link to nothing holds no node.
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| format!("reading {}", path.display()))
                }
            }
        }
    }
    Ok(())
}
