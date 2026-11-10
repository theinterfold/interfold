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
use e3_engine::{restore, Store, Stored};
use e3_entrypoint::fence::{ProcessFence, LOCK_FILE_NAME};
use e3_journal::Journal;
use e3_node::dir::{NodeDir, State};
use e3_protocol::{node::Node, E3Id};
use std::{
    collections::BTreeSet,
    io::ErrorKind,
    path::{Path, PathBuf},
};

pub fn dir(config: &NodeConfig) -> NodeDir {
    NodeDir::new(config.node_data_dir().join("v2"))
}

/// Deletes the data of `nodes` and keeps their keys. It works out what stands in the way under
/// every node's lock before it deletes anything, so a refusal leaves every node as it was. The
/// command deletes `others` too, once this returns, so they must hold no key either.
pub fn clear(
    out: &Console,
    nodes: &[NodeConfig],
    others: &[PathBuf],
    allow_active_e3s: bool,
) -> Result<()> {
    let (mut fences, mut plan, mut folders) = (Vec::new(), Plan::default(), Vec::new());
    for node in nodes {
        let dir = dir(node);
        // Nothing to lose here, and a node that never ran gets no lock file.
        if dir.state(None) == State::Absent {
            continue;
        }
        fences.push(ProcessFence::acquire(&node.db_file(), &node.name())?);
        plan.check(&format!("node '{}'", node.name()), &dir);
        // Another node's `data_dir` may sit inside this folder: it is fenced, and stops this.
        let inside = guard(dir.path(), &mut fences)?;
        plan.blockers.extend(inside.iter().map(|other| {
            format!(
                "{} holds the journal of another node, whose E3s this command cannot check; move \
                 it out first",
                other.display()
            )
        }));
        folders.push(dir.path().to_path_buf());
    }
    // Every node's keys against everything that goes: one node's key can sit in another's folder.
    for (node, root) in nodes
        .iter()
        .flat_map(|node| folders.iter().chain(others).map(move |root| (node, root)))
    {
        for (name, credential) in [("key", node.key_file()), ("keystore", node.db_file())] {
            if credential.starts_with(root) || canonical(&credential).starts_with(canonical(root)) {
                plan.refusals.push(format!(
                    "the {name} of node '{}' at {} is inside the folder {}, which this deletes; \
                     move it out first",
                    node.name(),
                    credential.display(),
                    root.display()
                ));
            }
        }
    }
    plan.settle(out, allow_active_e3s)?;
    for folder in folders {
        match std::fs::remove_dir_all(&folder) {
            // It was inside a folder that went first.
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            result => result?,
        }
        log!(out, "Removed {}", folder.display());
    }
    Ok(())
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

/// The same path with its links resolved, or as given when it does not exist yet.
fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// The E3s a stopped node holds, read without changing its journal. A journal the node did not
/// close cleanly needs the recovery a start runs, so it is an error here.
pub fn inspect_held(dir: &NodeDir, operator: Address) -> Result<Vec<Held>> {
    if !dir.journal().exists() {
        return Ok(Vec::new());
    }
    let stored = Journal::read_existing(dir.journal()).context(
        "the journal cannot be read without changing it; if the node did not stop cleanly, start \
         it once to recover the journal",
    )?;
    held_in(stored, operator)
}

/// The E3s a folder's journal holds, for a command about to delete it. A journal the node did not
/// close cleanly is recovered first.
fn held_e3s(dir: &NodeDir, operator: Address) -> Result<Vec<Held>> {
    if !dir.journal().exists() {
        return Ok(Vec::new());
    }
    held_in(Journal::open(dir.journal())?.read()?, operator)
}

/// The node keeps each E3, and the key share it dealt in it, until the E3 ends.
fn held_in(stored: Stored, operator: Address) -> Result<Vec<Held>> {
    let machine = restore(stored, Node::new(operator))?;
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
struct Plan {
    refusals: Vec<String>,
    blockers: Vec<String>,
}

impl Plan {
    /// Adds what `dir` holds, under the name `label`.
    fn check(&mut self, label: &str, dir: &NodeDir) {
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
    fn settle(self, out: &Console, allow_active_e3s: bool) -> Result<()> {
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

/// Holds the lock of every node whose lock is under `root`, and lists the node folders under it,
/// at any depth. A fence in `fences` already covers its lock. Nothing is created.
fn guard(root: &Path, fences: &mut Vec<ProcessFence>) -> Result<Vec<PathBuf>> {
    let mut contents = Contents::default();
    scan(root, &mut BTreeSet::new(), &mut contents)?;
    let held: BTreeSet<PathBuf> = fences.iter().map(|fence| canonical(fence.path())).collect();
    for lock in &contents.locks {
        if !held.contains(&canonical(lock)) {
            fences.push(ProcessFence::hold_existing(lock)?);
        }
    }
    Ok(contents.nodes)
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
