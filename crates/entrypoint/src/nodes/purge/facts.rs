// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! What the purge targets and the node configurations hold. Reading them changes nothing.

use anyhow::{anyhow, Result};
use e3_config::AppConfig;
use std::path::{Path, PathBuf};
use tokio::fs::{self, DirEntry};

use super::{locate, resolve, PurgeTargets};
use crate::fence::{lock_path_for, LOCK_FILE_NAME};
use crate::nodes::reset_data::event_log_paths;

/// Everything that the plan needs, read before the purge changes anything.
pub(super) struct Facts {
    pub(super) nodes: Vec<NodeFacts>,
    pub(super) data: Vec<DataEntry>,
    pub(super) config: Vec<ConfigEntry>,
}

/// One configured node.
pub(super) struct NodeFacts {
    pub(super) name: String,
    /// The store path that `start` uses: absolute, with links not resolved.
    pub(super) db_file: PathBuf,
    /// The store, when it exists.
    pub(super) store: Option<Location>,
    /// The lock that `start` takes for the store.
    pub(super) lock: Location,
    pub(super) lock_folder: FolderState,
    /// The lock's folder is in the data folder.
    pub(super) lock_folder_in_data: bool,
    /// The purge would delete the node's store, event log, or key file.
    pub(super) in_scope: bool,
    /// The key file exists and is in a target.
    pub(super) key_file_in_target: bool,
    /// The key file's path, with the links in its parent folders resolved.
    pub(super) key_file: PathBuf,
    /// An event log of the node exists and is in a target.
    pub(super) event_log_in_target: bool,
}

/// A path as the purge uses it, and two forms of it to compare locations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Location {
    pub(super) path: PathBuf,
    /// The links in the parent folders resolved, but not a link at the path itself.
    pub(super) located: PathBuf,
    /// Every link resolved.
    pub(super) resolved: PathBuf,
}

impl Location {
    fn of(path: PathBuf) -> Result<Self> {
        Ok(Self {
            located: locate(&path)?,
            resolved: resolve(&path)?,
            path,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FolderState {
    Missing,
    /// The folder holds nothing, or only the lock file. An earlier purge that stopped part of the
    /// way leaves this state.
    Empty,
    Holds,
}

/// An entry of the data folder.
pub(super) enum DataEntry {
    /// A node folder. Its name is the node's name.
    Folder {
        name: String,
        lock: Location,
        /// The sled stores directly inside the folder.
        stores: Vec<Location>,
        /// The symbolic links directly inside the folder.
        links: Vec<Link>,
    },
    Link(Link),
}

/// A symbolic link that the purge would remove.
pub(super) struct Link {
    /// The node folder that holds the link, or the link's own name in the data folder.
    pub(super) node: String,
    pub(super) path: PathBuf,
    /// The resolved target, or `None` when the link points to nothing.
    pub(super) target: Option<PathBuf>,
}

/// An entry of the configuration folder. A folder holds a node's key file.
pub(super) enum ConfigEntry {
    Folder { name: String, location: Location },
    File { name: String, location: Location },
}

pub(super) async fn gather(targets: &PurgeTargets, nodes: &[AppConfig]) -> Result<Facts> {
    let mut node_facts = Vec::with_capacity(nodes.len());
    for node in nodes {
        node_facts.push(node_facts_of(targets, node).await?);
    }
    Ok(Facts {
        nodes: node_facts,
        data: data_entries(&targets.data).await?,
        config: config_entries(&targets.config).await?,
    })
}

async fn node_facts_of(targets: &PurgeTargets, node: &AppConfig) -> Result<NodeFacts> {
    let db_file = std::path::absolute(node.db_file())?;
    let lock = lock_path_for(&db_file);
    let lock_folder = lock.parent().map(Path::to_path_buf).unwrap_or_default();
    let key_file = locate(&node.key_file())?;
    let in_scope = [&locate(&db_file)?, &locate(&node.log_file())?, &key_file]
        .into_iter()
        .any(|path| targets.contain(path));
    let key_file_in_target = targets.contain(&key_file) && fs::try_exists(&key_file).await?;
    let mut event_log_in_target = false;
    for log in event_log_paths(&node.log_file()).await? {
        event_log_in_target |= targets.contain(&locate(&log)?);
    }
    Ok(NodeFacts {
        name: node.name(),
        store: if fs::try_exists(&db_file).await? {
            Some(Location::of(db_file.clone())?)
        } else {
            None
        },
        lock: Location::of(lock)?,
        lock_folder: folder_state(&lock_folder).await?,
        lock_folder_in_data: locate(&lock_folder)?.starts_with(&targets.data),
        in_scope,
        key_file_in_target,
        key_file,
        event_log_in_target,
        db_file,
    })
}

async fn folder_state(folder: &Path) -> Result<FolderState> {
    if !fs::try_exists(folder).await? {
        return Ok(FolderState::Missing);
    }
    let holds = entries(folder)
        .await?
        .iter()
        .any(|entry| entry.file_name() != LOCK_FILE_NAME);
    Ok(if holds {
        FolderState::Holds
    } else {
        FolderState::Empty
    })
}

async fn data_entries(data: &Path) -> Result<Vec<DataEntry>> {
    let mut found = Vec::new();
    for entry in entries(data).await? {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let file_type = entry.file_type().await?;
        if file_type.is_symlink() {
            found.push(DataEntry::Link(link(&path, &name)?));
            continue;
        }
        if !file_type.is_dir() {
            continue;
        }
        let mut stores = Vec::new();
        let mut links = Vec::new();
        for inner in entries(&path).await? {
            let inner_path = inner.path();
            if inner.file_type().await?.is_symlink() {
                links.push(link(&inner_path, &name)?);
            } else if is_sled_store(&inner_path) {
                stores.push(Location::of(inner_path)?);
            }
        }
        found.push(DataEntry::Folder {
            name,
            lock: Location::of(path.join(LOCK_FILE_NAME))?,
            stores,
            links,
        });
    }
    Ok(found)
}

async fn config_entries(config: &Path) -> Result<Vec<ConfigEntry>> {
    let mut found = Vec::new();
    for entry in entries(config).await? {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        // `is_dir` and `is_file` follow a link. A link that points to nothing is neither.
        let location = Location::of(path.clone())?;
        if path.is_dir() {
            found.push(ConfigEntry::Folder { name, location });
        } else if path.is_file() {
            found.push(ConfigEntry::File { name, location });
        }
    }
    Ok(found)
}

fn link(path: &Path, node: &str) -> Result<Link> {
    // `exists` follows the link.
    let target = if path.exists() {
        Some(resolve(path)?)
    } else {
        None
    };
    Ok(Link {
        node: node.to_string(),
        path: path.to_path_buf(),
        target,
    })
}

/// A sled store is a folder with a `conf` file and a `db` file.
fn is_sled_store(folder: &Path) -> bool {
    folder.join("conf").is_file() && folder.join("db").is_file()
}

/// The entries of `folder`, or none when the folder does not exist.
pub(super) async fn entries(folder: &Path) -> Result<Vec<DirEntry>> {
    let mut reader = match fs::read_dir(folder).await {
        Ok(reader) => reader,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(anyhow!("failed to read {}: {error}", folder.display())),
    };
    let mut entries = Vec::new();
    while let Some(entry) = reader.next_entry().await? {
        entries.push(entry);
    }
    Ok(entries)
}
