// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The v2 node's network: operator-signed peer messages, and the blobs they name, which a node
//! fetches from the message's publisher before it delivers the message.

mod memory;

pub use memory::{MemoryNetwork, MemoryPeer};

use e3_blobs::{BlobError, Blobs};
use e3_protocol::{wire::Envelope, BlobRef};
use std::{future::Future, sync::Arc};

/// What the node needs from the network. Inbound, an adapter delivers a peer message only if its
/// envelope opens, the message is for this node, and every blob the node needs from it is in the
/// node's store.
pub trait Network: Send + Sync + 'static {
    /// Sends `envelope` to the other nodes; its blobs are in this node's store.
    fn publish(&self, envelope: Envelope) -> impl Future<Output = Result<(), NetworkError>> + Send;
}

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error(transparent)]
    Blob(#[from] BlobError),
    #[error("blob {0:?} came back with other bytes")]
    WrongBlob(BlobRef),
}

pub type SharedBlobs = Arc<dyn Blobs + Send + Sync>;
