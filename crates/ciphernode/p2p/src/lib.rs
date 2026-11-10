// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The v2 node's network: operator-signed peer messages, and the blobs they name, which a node
//! fetches from the message's publisher once its machine admits the message.

mod behaviour;
mod driver;
mod fetcher;
mod inbound_ip_limits;
mod inbox;
mod peers;
mod protocols;
mod serving;
mod transport;

pub use driver::{P2p, P2pConfig, P2pError};
pub use inbox::{inbox, Inbox, InboxWriter};

use e3_protocol::{
    node::{Admission, PeerMessage},
    wire::Envelope,
};
use std::future::Future;

/// What the node needs from the network. Inbound, an adapter delivers each peer message whose
/// envelope opens and that is for this node, before it fetches any blob the message names.
pub trait Network: Send + Sync + 'static {
    /// Sends `envelope` to the other nodes; its blobs are in this node's store.
    fn publish(&self, envelope: Envelope) -> impl Future<Output = Result<(), NetworkError>> + Send;

    /// Brings the blobs `message` names into the node's store, from the peers that sent it.
    fn fetch(&self, message: PeerMessage) -> impl Future<Output = Result<(), NetworkError>> + Send;

    /// Deals only with those `admission` names from now on: another sender's message is neither
    /// delivered nor passed on, and a blob goes only to a member of its E3's committee.
    fn admit(&self, admission: Admission);

    /// How many peers are connected now.
    fn connected(&self) -> usize;

    /// Says goodbye to the peers, so they do not have to time out.
    fn close(&self) -> impl Future<Output = ()> + Send;
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("publishing: {0}")]
    Publish(String),
    /// The sender's re-send brings the message, and the peers to ask, again.
    #[error("no peer that sent the message gave its blobs")]
    Unavailable,
    #[error("the network has too much to do")]
    Busy,
    #[error("storing a blob: {0}")]
    Store(String),
    #[error("the network stopped")]
    Stopped,
}
