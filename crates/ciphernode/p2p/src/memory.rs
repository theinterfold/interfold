// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{Network, NetworkError, SharedBlobs};
use alloy_primitives::Address;
use e3_protocol::{node::PeerMessage, wire::Envelope, BlobRef};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Nodes in one process. A published envelope reaches every other node that uses its message once
/// the blobs that node needs are copied from the publisher's store, as a network adapter fetches
/// them from the publisher.
#[derive(Clone, Default)]
pub struct MemoryNetwork {
    nodes: Arc<Mutex<Vec<Member>>>,
}

#[derive(Clone)]
struct Member {
    address: Address,
    blobs: SharedBlobs,
    inbound: mpsc::Sender<PeerMessage>,
}

/// One node's place on a [`MemoryNetwork`].
pub struct MemoryPeer {
    network: MemoryNetwork,
    address: Address,
    blobs: SharedBlobs,
}

impl MemoryNetwork {
    /// Adds the node `address`, whose peer messages arrive on the returned receiver.
    pub fn join(
        &self,
        address: Address,
        blobs: SharedBlobs,
    ) -> (MemoryPeer, mpsc::Receiver<PeerMessage>) {
        let (inbound, receiver) = mpsc::channel(1_024);
        let member = Member {
            address,
            blobs: blobs.clone(),
            inbound,
        };
        self.nodes
            .lock()
            .expect("no holder of the lock panics")
            .push(member);
        let peer = MemoryPeer {
            network: self.clone(),
            address,
            blobs,
        };
        (peer, receiver)
    }
}

impl Network for MemoryPeer {
    async fn publish(&self, envelope: Envelope) -> Result<(), NetworkError> {
        let bytes = envelope.encode();
        let others: Vec<Member> = self
            .network
            .nodes
            .lock()
            .expect("no holder of the lock panics")
            .iter()
            .filter(|member| member.address != self.address)
            .cloned()
            .collect();
        for member in others {
            let Some(message) = Envelope::decode(&bytes).and_then(Envelope::open) else {
                continue;
            };
            if !message.is_for(member.address) {
                continue;
            }
            for blob in message.blobs() {
                if member.blobs.get(&blob).is_ok() {
                    continue;
                }
                let bytes = self.blobs.get(&blob)?;
                if BlobRef::of(&bytes) != blob {
                    return Err(NetworkError::WrongBlob(blob));
                }
                member.blobs.put(&bytes)?;
            }
            // A node that stopped has dropped its receiver; others still get the message.
            let _ = member.inbound.send(message).await;
        }
        Ok(())
    }
}
