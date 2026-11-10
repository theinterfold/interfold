// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! A node's folder on disk: what it holds, whose state it is, and whether this binary can use it.
//! `interfold start`, `validate`, `reset-data` and `purge` all read it through [`NodeDir`], so they
//! cannot disagree.

use alloy_primitives::Address;
use e3_protocol::ENCODING_VERSION;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
};

/// The version of the blob store's folders and the wallet's file.
const STORE_VERSION: u32 = 1;

const MANIFEST: &str = "manifest.json";

/// The files of a node in its folder; others, such as its configuration, may share it.
const NODE_FILES: [&str; 3] = ["journal.redb", "blobs", "unmined.json"];

/// The chain, deployment and operator a node's state belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub chain_id: u64,
    pub interfold: Address,
    pub operator: Address,
}

/// What a folder says about itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub encoding: u32,
    pub store: u32,
    #[serde(flatten)]
    pub identity: Identity,
}

impl Manifest {
    fn layout(&self) -> (u32, u32) {
        (self.encoding, self.store)
    }
}

fn current_layout() -> (u32, u32) {
    (ENCODING_VERSION, STORE_VERSION)
}

/// What a node's folder holds, as this binary sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// Nothing of a node is here.
    Absent,
    Current(Manifest),
    /// Written by an earlier release, in a layout this binary cannot read.
    Older(Manifest),
    /// Written by a later release: a rollback. This binary cannot read it and must not reset it.
    Newer(Manifest),
    /// In this binary's layout, but of another chain, deployment or operator.
    Foreign(Manifest),
    /// Node files that no readable manifest describes.
    Unreadable(String),
}

/// A node's folder.
#[derive(Clone, Debug)]
pub struct NodeDir {
    folder: PathBuf,
}

impl NodeDir {
    pub fn new(folder: impl Into<PathBuf>) -> Self {
        Self {
            folder: folder.into(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.folder
    }

    /// The journal of this folder's node.
    pub fn journal(&self) -> PathBuf {
        self.folder.join("journal.redb")
    }

    /// Where this folder's node keeps its notes for its operator.
    pub fn notes(&self) -> PathBuf {
        self.folder.join("notes")
    }

    /// What the folder holds. It changes nothing on disk. With `expected`, state of another
    /// chain, deployment or operator reads as [`State::Foreign`].
    pub fn state(&self, expected: Option<&Identity>) -> State {
        let bytes = match fs::read(self.folder.join(MANIFEST)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return self.without_manifest()
            }
            Err(error) => return State::Unreadable(format!("its manifest: {error}")),
        };
        let manifest: Manifest = match serde_json::from_slice(&bytes) {
            Ok(manifest) => manifest,
            Err(error) => return State::Unreadable(format!("its manifest: {error}")),
        };
        match manifest.layout().cmp(&current_layout()) {
            std::cmp::Ordering::Less => State::Older(manifest),
            std::cmp::Ordering::Greater => State::Newer(manifest),
            std::cmp::Ordering::Equal if expected.is_some_and(|id| *id != manifest.identity) => {
                State::Foreign(manifest)
            }
            std::cmp::Ordering::Equal => State::Current(manifest),
        }
    }

    fn without_manifest(&self) -> State {
        match NODE_FILES
            .iter()
            .any(|file| self.folder.join(file).exists())
        {
            true => State::Unreadable("node files without a manifest".into()),
            false => State::Absent,
        }
    }

    /// Makes the folder ready for `identity`'s node, or says why it cannot be used. The caller
    /// holds the node's process lock.
    pub fn open(&self, identity: &Identity) -> Result<(), DirError> {
        let folder = self.folder.clone();
        match self.state(Some(identity)) {
            State::Current(_) => Ok(()),
            State::Absent => {
                fs::create_dir_all(&folder)?;
                let manifest = Manifest {
                    encoding: ENCODING_VERSION,
                    store: STORE_VERSION,
                    identity: *identity,
                };
                write_durably(
                    &folder.join(MANIFEST),
                    &serde_json::to_vec_pretty(&manifest)?,
                )?;
                Ok(())
            }
            State::Older(found) => Err(DirError::Older { folder, found }),
            State::Newer(found) => Err(DirError::Newer { folder, found }),
            State::Foreign(found) => Err(DirError::Foreign {
                folder,
                found: Box::new(found),
                expected: *identity,
            }),
            State::Unreadable(why) => Err(DirError::Unreadable { folder, why }),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DirError {
    #[error(
        "{} holds data from an earlier release, which this binary cannot read: use `interfold node \
         reset-data`, or an empty directory",
        .folder.display()
    )]
    Older { folder: PathBuf, found: Manifest },
    #[error(
        "{} holds data from a later release (layout {}.{}): run that release, or use an empty \
         directory",
        .folder.display(), .found.encoding, .found.store
    )]
    Newer { folder: PathBuf, found: Manifest },
    #[error(
        "{} belongs to chain {}, Interfold {}, operator {}, not to chain {}, Interfold {}, operator \
         {}: use another directory",
        .folder.display(), .found.identity.chain_id, .found.identity.interfold,
        .found.identity.operator, .expected.chain_id, .expected.interfold, .expected.operator
    )]
    Foreign {
        folder: PathBuf,
        found: Box<Manifest>,
        expected: Identity,
    },
    #[error("{} cannot be read ({why}): use another directory", .folder.display())]
    Unreadable { folder: PathBuf, why: String },
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Encoding(#[from] serde_json::Error),
}

/// Writes `bytes` at `path` so that a crash leaves the old file or the whole new one.
fn write_durably(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let partial = path.with_extension("partial");
    let mut file = File::create(&partial)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&partial, path)?;
    match path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        Some(dir) => File::open(dir)?.sync_all(),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Identity {
        Identity {
            chain_id: 1,
            interfold: Address::repeat_byte(1),
            operator: Address::repeat_byte(2),
        }
    }

    fn write_manifest(dir: &Path, encoding: u32, store: u32, identity: Identity) {
        let manifest = Manifest {
            encoding,
            store,
            identity,
        };
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join(MANIFEST), serde_json::to_vec(&manifest).unwrap()).unwrap();
    }

    #[test]
    fn a_new_folder_becomes_current_for_its_node() {
        let dir = tempfile::tempdir().unwrap();
        let node = NodeDir::new(dir.path().join("v2"));
        assert_eq!(node.state(Some(&identity())), State::Absent);
        node.open(&identity()).unwrap();
        assert!(matches!(node.state(Some(&identity())), State::Current(_)));
        node.open(&identity()).unwrap();
    }

    /// A rollback must not treat newer data as older: that is how it would get reset.
    #[test]
    fn layouts_compare_by_number() {
        let dir = tempfile::tempdir().unwrap();
        let node = NodeDir::new(dir.path());
        let (encoding, store) = current_layout();

        write_manifest(dir.path(), encoding - 1, store, identity());
        assert!(matches!(node.state(None), State::Older(_)));
        write_manifest(dir.path(), encoding + 1, 0, identity());
        assert!(matches!(node.state(None), State::Newer(_)));
        write_manifest(dir.path(), encoding, store + 1, identity());
        assert!(matches!(node.state(None), State::Newer(_)));
        assert!(matches!(
            node.open(&identity()),
            Err(DirError::Newer { .. })
        ));
    }

    #[test]
    fn state_of_another_chain_deployment_or_operator_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let node = NodeDir::new(dir.path());
        node.open(&identity()).unwrap();
        for other in [
            Identity {
                chain_id: 5,
                ..identity()
            },
            Identity {
                interfold: Address::repeat_byte(9),
                ..identity()
            },
            Identity {
                operator: Address::repeat_byte(9),
                ..identity()
            },
        ] {
            assert!(matches!(node.state(Some(&other)), State::Foreign(_)));
            assert!(matches!(node.open(&other), Err(DirError::Foreign { .. })));
        }
    }

    #[test]
    fn node_files_without_a_manifest_are_unreadable_not_empty() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("journal.redb"), b"").unwrap();
        let node = NodeDir::new(dir.path());
        assert!(matches!(node.state(None), State::Unreadable(_)));
        assert!(matches!(
            node.open(&identity()),
            Err(DirError::Unreadable { .. })
        ));
    }

    #[test]
    fn a_damaged_manifest_is_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(MANIFEST), b"not json").unwrap();
        assert!(matches!(
            NodeDir::new(dir.path()).state(None),
            State::Unreadable(_)
        ));
    }
}
