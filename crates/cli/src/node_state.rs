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
use e3_journal::Journal;
use e3_protocol::{node::Node, E3Id};
use std::{io::ErrorKind, path::PathBuf};

pub fn folder(config: &NodeConfig) -> PathBuf {
    config.node_data_dir().join("v2")
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
    let path = folder(config).join("journal.redb");
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
