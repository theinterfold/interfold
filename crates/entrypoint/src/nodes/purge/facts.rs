// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! What the purge targets and the node configurations hold. Reading them changes nothing.

use anyhow::{anyhow, Result};
use e3_config::AppConfig;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use tokio::fs::{self, DirEntry};

use super::{locate, resolve, PurgeTargets, MARKER_FILE_NAME, MARKER_TEXT};
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
    /// The lock's folder is in the data folder, with every link resolved.
    pub(super) lock_folder_in_data: bool,
    /// The purge would delete the node's store, event log, or key file.
    pub(super) in_scope: bool,
    /// The key file exists and is in a target.
    pub(super) key_file_in_target: bool,
    /// The key file's path, with the links in its parent folders resolved.
    pub(super) key_file: PathBuf,
    /// An event log of the node exists and is in a target.
    pub(super) event_log_in_target: bool,
    /// The stores that the record next to the key file names.
    pub(super) recorded: Recorded,
}

/// The stores that a key file's record names (`store_record`): every store that the node started
/// with, the store of its last start last.
#[derive(Debug)]
pub(super) enum Recorded {
    /// The key file has no record, as for a node that has not started with this release.
    Nothing,
    /// The record names these stores, the store of the last start last.
    Stores(Vec<RecordedStore>),
    /// The record exists, and the purge cannot read it.
    Unreadable(PathBuf),
}

impl Recorded {
    /// The store of the node's last start.
    pub(super) fn last(&self) -> Option<&Path> {
        match self {
            Recorded::Stores(stores) => stores.last().map(|store| store.db_file.as_path()),
            Recorded::Nothing | Recorded::Unreadable(_) => None,
        }
    }
}

/// A store that a record names.
#[derive(Debug)]
pub(super) struct RecordedStore {
    pub(super) db_file: PathBuf,
    /// The store, when it exists.
    pub(super) store: Option<Location>,
    /// The lock that `start` takes for the store.
    pub(super) lock: Location,
    /// The store is gone, and its folder in the data folder holds the marker of an earlier purge
    /// that checked it and stopped part of the way.
    pub(super) purged: bool,
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
    Exists,
    /// The folder holds the purge marker. An earlier purge passed its checks and started to empty
    /// the folder, then stopped part of the way.
    Purging,
}

/// An entry of the data folder.
pub(super) enum DataEntry {
    /// A node folder. Its name is the node's name.
    Folder {
        name: String,
        lock: Location,
        /// The folder holds a complete purge marker.
        marked: bool,
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
    Folder {
        name: String,
        location: Location,
        /// The store records in the folder, by the key file that each belongs to.
        records: Vec<(PathBuf, Recorded)>,
    },
    File {
        name: String,
        location: Location,
        recorded: Recorded,
    },
}

pub(super) async fn gather(targets: &PurgeTargets, nodes: &[AppConfig]) -> Result<Facts> {
    let mut node_facts = Vec::with_capacity(nodes.len());
    for node in nodes {
        node_facts.push(node_facts_of(targets, node).await?);
    }
    Ok(Facts {
        nodes: node_facts,
        data: data_entries(&targets.data).await?,
        config: config_entries(targets).await?,
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
        lock_folder_in_data: resolve(&lock_folder)?.starts_with(&targets.data),
        in_scope,
        key_file_in_target,
        recorded: recorded(targets, &key_file).await?,
        key_file,
        event_log_in_target,
        db_file,
    })
}

/// The stores that the record of `key_file` names. A record, or a store that it names, that the
/// purge cannot read or inspect is a refusal, not an error that ends the purge.
async fn recorded(targets: &PurgeTargets, key_file: &Path) -> Result<Recorded> {
    let record = crate::store_record::record_path(key_file);
    let db_files = match crate::store_record::read(key_file) {
        Ok(db_files) if db_files.is_empty() => return Ok(Recorded::Nothing),
        Ok(db_files) => db_files,
        Err(_) => return Ok(Recorded::Unreadable(record)),
    };
    let inspected = async {
        let mut stores = Vec::with_capacity(db_files.len());
        for db_file in db_files {
            let lock = lock_path_for(&db_file);
            let lock_folder = lock.parent().map(Path::to_path_buf).unwrap_or_default();
            let store = if fs::try_exists(&db_file).await? {
                Some(Location::of(db_file.clone())?)
            } else {
                None
            };
            let purged = store.is_none()
                && folder_state(&lock_folder).await? == FolderState::Purging
                && resolve(&lock_folder)?.starts_with(&targets.data);
            stores.push(RecordedStore {
                db_file,
                store,
                lock: Location::of(lock)?,
                purged,
            });
        }
        anyhow::Ok(stores)
    }
    .await;
    Ok(match inspected {
        Ok(stores) => Recorded::Stores(stores),
        Err(_) => Recorded::Unreadable(record),
    })
}

async fn folder_state(folder: &Path) -> Result<FolderState> {
    if !fs::try_exists(folder).await? {
        return Ok(FolderState::Missing);
    }
    // Only the marker shows an earlier purge. An empty folder, or one with only a lock file, can be
    // the mount point of a volume that is not mounted, or the folder of a store that an operator
    // removed.
    Ok(if marked(folder).await {
        FolderState::Purging
    } else {
        FolderState::Exists
    })
}

/// What is at the purge marker path of a folder.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Marker {
    Missing,
    /// A file that holds a start of the marker text, which a failed write left part of the way.
    Incomplete,
    Complete,
    /// Another file, a folder, or a link. The purge neither trusts it nor replaces it.
    Other,
}

/// Reads the marker path of `folder` without following a link there.
pub(super) async fn marker(folder: &Path) -> Result<Marker> {
    let path = folder.join(MARKER_FILE_NAME);
    let metadata = match fs::symlink_metadata(&path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Marker::Missing),
        Err(error) => return Err(anyhow!("failed to inspect {}: {error}", path.display())),
    };
    if !metadata.is_file() {
        return Ok(Marker::Other);
    }
    let content = fs::read(&path)
        .await
        .map_err(|error| anyhow!("failed to read {}: {error}", path.display()))?;
    Ok(if content == MARKER_TEXT.as_bytes() {
        Marker::Complete
    } else if MARKER_TEXT.as_bytes().starts_with(&content) {
        Marker::Incomplete
    } else {
        Marker::Other
    })
}

/// The folder holds a complete purge marker. A marker that a failed write left part of the way, or
/// one that cannot be read, does not count.
async fn marked(folder: &Path) -> bool {
    matches!(marker(folder).await, Ok(Marker::Complete))
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
            marked: marked(&path).await,
            stores,
            links,
        });
    }
    Ok(found)
}

async fn config_entries(targets: &PurgeTargets) -> Result<Vec<ConfigEntry>> {
    let mut found = Vec::new();
    for entry in entries(&targets.config).await? {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        // `is_dir` and `is_file` follow a link. A link that points to nothing is neither.
        let location = Location::of(path.clone())?;
        if path.is_dir() {
            let mut records = Vec::new();
            match entries(&path).await {
                Ok(inner_entries) => {
                    for inner in inner_entries {
                        let record = inner.path();
                        if !(record.is_file() && crate::store_record::is_record(&record)) {
                            continue;
                        }
                        // The key file's name is the record's without the suffix, byte for byte.
                        let name = record.file_name().unwrap_or_default().as_bytes();
                        let key_name = std::ffi::OsStr::from_bytes(
                            &name[..name.len() - crate::store_record::RECORD_SUFFIX.len()],
                        );
                        let key_file = record.with_file_name(key_name);
                        let recorded = recorded(targets, &key_file).await?;
                        records.push((key_file, recorded));
                    }
                }
                Err(_) => records.push((path.clone(), Recorded::Unreadable(path.clone()))),
            }
            found.push(ConfigEntry::Folder {
                name,
                location,
                records,
            });
        } else if path.is_file() && !is_store_record(&path) {
            found.push(ConfigEntry::File {
                name,
                recorded: recorded(targets, &path).await?,
                location,
            });
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
/// A store record, or the temporary file of one that a start writes.
fn is_store_record(path: &Path) -> bool {
    crate::store_record::is_record(path) || crate::store_record::is_record(&path.with_extension(""))
}

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
