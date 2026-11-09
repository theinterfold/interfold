// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! What maintenance commands need to know about a node's state on disk, and the plan they work
//! out from it before they change anything. The operator's keys are not in the node's folder: they
//! stay in the keystore, so deleting the folder keeps the node's identity.

use alloy::primitives::Address;
use anyhow::{bail, Context, Result};
use e3_ciphernode_config::NodeConfig;
use e3_console::{log, Console};
use e3_engine::Engine;
use e3_entrypoint::fence::{ProcessFence, LOCK_FILE_NAME};
use e3_journal::Journal;
use e3_node::dir::{Inventory, NodeDir, State};
use e3_protocol::{node::Node, E3Id};
use std::{
    collections::BTreeSet,
    io::ErrorKind,
    path::{Path, PathBuf},
};

pub fn dir(config: &NodeConfig) -> NodeDir {
    NodeDir::new(config.node_data_dir().join("v2"))
}

pub fn inventory(config: &NodeConfig) -> Inventory {
    Inventory::beside(&config.key_file())
}

/// An E3 a node's journal holds, and what the node would give up for it.
pub struct Held {
    pub e3: E3Id,
    pub owes: Vec<&'static str>,
}

impl std::fmt::Display for Held {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "E3 {} ({})", self.e3, self.owes.join(", "))
    }
}

/// The E3s a current folder's journal holds. The node keeps each E3, and the key share it dealt in
/// it, until the E3 ends.
pub fn held_e3s(dir: &NodeDir, operator: Address) -> Result<Vec<Held>> {
    if !dir.journal().exists() {
        return Ok(Vec::new());
    }
    let journal = Journal::open(dir.journal())?;
    let (engine, _) = Engine::open(journal, Node::new(operator), u64::MAX)?;
    let machine = engine.machine();
    Ok(machine
        .held()
        .map(|e3| Held {
            e3: *e3,
            owes: machine.e3(e3).map(|state| state.owes()).unwrap_or_default(),
        })
        .collect())
}

/// What a maintenance command found. `blockers` stop it unless the operator overrides them;
/// `refusals` stop it whatever the operator says.
#[derive(Default)]
pub struct Plan {
    pub refusals: Vec<String>,
    pub blockers: Vec<String>,
}

impl Plan {
    /// Adds what `dir` holds, under the name `label`.
    pub fn check(&mut self, label: &str, dir: &NodeDir) {
        match dir.state(None) {
            State::Absent => {}
            State::Current(manifest) => match held_e3s(dir, manifest.identity.operator) {
                Ok(held) if held.is_empty() => {}
                Ok(held) => {
                    let held: Vec<String> = held.iter().map(ToString::to_string).collect();
                    self.blockers
                        .push(format!("{label} still holds {}", held.join("; ")));
                }
                Err(error) => self
                    .blockers
                    .push(format!("{label}'s E3s cannot be read: {error:#}")),
            },
            State::Older(_) if !dir.journal().exists() => {}
            State::Older(_) => self.blockers.push(format!(
                "{label} uses an older layout that this binary cannot read, so it cannot check \
                 for E3s that have not ended"
            )),
            State::Newer(_) => self.blockers.push(format!(
                "{label} was written by a later release, which this binary cannot read"
            )),
            State::Foreign(_) => self.blockers.push(format!(
                "{label} belongs to another chain, deployment or operator"
            )),
            State::Unreadable(why) => self.blockers.push(format!(
                "{} cannot be read ({why}), so its E3s cannot be checked",
                dir.path().display()
            )),
        }
    }

    /// Goes ahead or stops. An override goes ahead, and says what it skipped.
    pub fn settle(self, out: &Console, allow_active_e3s: bool) -> Result<()> {
        if !self.refusals.is_empty() {
            bail!("Deleted nothing: {}.", self.refusals.join("; "));
        }
        if self.blockers.is_empty() {
            return Ok(());
        }
        let blockers = self.blockers.join("; ");
        if !allow_active_e3s {
            bail!(
                "Deleted nothing: {blockers}. Wait for those E3s to end, or rerun with \
                 --allow-active-e3s after checking each on chain."
            );
        }
        log!(out, "--allow-active-e3s goes ahead despite: {blockers}");
        Ok(())
    }
}

/// Holds the lock of every node whose lock is under `root` and returns the node folders under
/// `root`, at any depth, that `checked` does not name: whatever deletes `root` deletes their E3s
/// unchecked. A fence in `fences` already covers its lock. Nothing is created.
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
    if dir.join("v2").join("journal.redb").exists() {
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
