// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Delete the `.interfold` data and configuration folders in a directory.
//!
//! `nodes purge` removes `.interfold/data` and `.interfold/config` in the current directory. That
//! also removes each node's operator key and libp2p key, and nothing can restore them.
//! `interfold node reset-data` clears a node's state and keeps its identity.
//!
//! The purge deletes nothing until it has checked each node whose store, event log, or key file it
//! would delete. It runs in three parts:
//! - [`facts`] reads what the targets and the node configurations hold. It changes nothing.
//! - [`plan`] decides which locks to hold, which stores to check, and which state the purge cannot
//!   check. It has no side effects.
//! - [`effects`] holds the locks, checks the stores, and deletes the targets.
//!
//! The checks:
//! - A node must not run. The purge holds the lock that `start` takes for the node's store. It
//!   must also be able to open the store, because sled refuses a store that another process has
//!   open. Nothing overrides this refusal.
//! - A node must hold no key share for an E3 that it has not seen complete.
//! - A store that the purge checks for a key file must hold an operator key. An empty store at the
//!   configured path is not the node's store.
//!
//! When the purge cannot check a node, it refuses. It reports every refusal at once, because
//! `--allow-active-e3s` overrides the key-share refusals and the cannot-check refusals together.
//!
//! Before it deletes, the purge writes a marker into each node folder that it empties. A later
//! purge treats a folder with the marker as the leftover of that purge and finishes the deletion.
//! An empty folder without the marker is not a leftover: it can be the mount point of a volume
//! that is not mounted. Another file or a link with the marker's name stops the purge before it
//! deletes anything.
//!
//! `interfold start` records the path of its store next to the key file (`store_record`), after
//! the stores of the node's earlier starts. For a key file with a record, the purge holds the lock
//! of each recorded store and checks it, also when the node ran with another `E3_DATA_DIR`,
//! `data_dir`, or working directory. The store of the last start must hold the operator key; the
//! other stores, and the store at the configured path, are checked for key shares. A key file that
//! no configured node uses, in a key folder or directly in the configuration folder, is checked
//! through its record. A recorded store that is not there is a refusal that the override covers,
//! unless its folder holds the marker of an earlier purge, which deleted it.
//!
//! Limits:
//! - A key file without a record, as of a node that has not started with this release, is checked
//!   through the store at the configured path, which a stale copy of the store can pass.
//! - The purge finds stores directly inside each node folder in the data folder, not deeper.

mod effects;
mod facts;
mod plan;

/// The file that the purge writes into each node folder before it empties the folder.
pub const MARKER_FILE_NAME: &str = "purge-in-progress";

/// The content of a complete marker. A later purge trusts only a marker with exactly this content,
/// so a marker that a failed write left part of the way is not a leftover.
pub const MARKER_TEXT: &str =
    "An interfold purge checked this node and started to empty this folder. Run the purge again \
     to finish it.\n";

use anyhow::{anyhow, bail, Result};
use e3_config::AppConfig;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// The folders that a purge removes.
#[derive(Debug, Clone)]
pub struct PurgeTargets {
    root: PathBuf,
    data: PathBuf,
    config: PathBuf,
}

impl PurgeTargets {
    /// The `.interfold` data and configuration folders in `dir`.
    pub fn in_dir(dir: &Path) -> Self {
        let root = dir.join(".interfold");
        Self {
            data: root.join("data"),
            config: root.join("config"),
            root,
        }
    }

    /// The targets with symbolic links resolved, so that node paths compare by location.
    ///
    /// The purge refuses when `.interfold` or a target is itself a symbolic link. It does not
    /// follow a link to the state that the link points to.
    fn resolved(&self) -> Result<Self> {
        for folder in [&self.root, &self.data, &self.config] {
            if is_link(folder) {
                bail!(
                    "{} is a symbolic link, and the purge does not follow links. The command \
                     deleted nothing. To clear a node that keeps its state there, stop the node. \
                     Then run `interfold node reset-data --name <node>`.",
                    folder.display()
                );
            }
        }
        Ok(Self {
            root: resolve(&self.root)?,
            data: resolve(&self.data)?,
            config: resolve(&self.config)?,
        })
    }

    fn contain(&self, path: &Path) -> bool {
        path.starts_with(&self.data) || path.starts_with(&self.config)
    }
}

/// Deletes the purge targets after it checks every node whose state they hold.
///
/// `nodes` are the configured nodes. The purge also checks each node folder in the data folder that
/// no profile names. It also checks each folder and file in the configuration folder.
pub async fn execute(
    targets: &PurgeTargets,
    nodes: &[AppConfig],
    allow_active_e3s: bool,
) -> Result<()> {
    let targets = targets.resolved()?;
    let facts = facts::gather(&targets, nodes).await?;
    let plan = plan::plan(&facts);
    let mut fences = effects::hold_existing(&plan)?;
    let warnings = effects::check(&plan, allow_active_e3s).await?;
    // The purge creates the missing node folders in the data folder only now, so that a refusal
    // creates nothing. Their locks keep those nodes from starting before the purge ends.
    fences.extend(effects::hold_created(&plan)?);
    for warning in warnings {
        warn!("{warning}");
    }
    effects::delete(&targets, &fences).await?;
    info!(
        "Removed {} and {}",
        targets.data.display(),
        targets.config.display()
    );
    Ok(())
}

fn is_link(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_symlink())
}

/// `path` as an absolute path with symbolic links resolved. A path that does not exist yet resolves
/// through its nearest existing ancestor.
fn resolve(path: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    let mut missing = Vec::new();
    let mut existing = absolute.as_path();
    loop {
        match existing.canonicalize() {
            Ok(resolved) => {
                return Ok(missing
                    .iter()
                    .rev()
                    .fold(resolved, |path: PathBuf, name| path.join(name)))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let (Some(parent), Some(name)) = (existing.parent(), existing.file_name()) else {
                    return Ok(absolute);
                };
                missing.push(name.to_os_string());
                existing = parent;
            }
            Err(error) => return Err(anyhow!("failed to resolve {}: {error}", existing.display())),
        }
    }
}

/// `path` with the links in its parent folders resolved, but not a link at `path` itself. The
/// purge removes a link at a target path, and keeps the state that the link points to.
fn locate(path: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    match (absolute.parent(), absolute.file_name()) {
        (Some(parent), Some(name)) => Ok(resolve(parent)?.join(name)),
        _ => Ok(absolute),
    }
}
