// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use libp2p::{identity::ed25519, PeerId};

/// Wrapper around a libp2p ed25519 keypair used to identify this node on the network.
pub struct Libp2pKeypair {
    keypair: libp2p::identity::Keypair,
}

impl Libp2pKeypair {
    pub fn new(keypair: libp2p::identity::Keypair) -> Self {
        Self { keypair }
    }

    pub fn generate() -> Self {
        let id = libp2p::identity::Keypair::generate_ed25519();
        Self::new(id)
    }

    pub fn try_from_bytes(bytes: &mut [u8]) -> Result<Self> {
        let keypair: libp2p::identity::Keypair = ed25519::Keypair::try_from_bytes(bytes)?.into();
        Ok(Self { keypair })
    }

    pub fn into_keypair(self) -> libp2p::identity::Keypair {
        self.keypair
    }

    pub fn peer_id(&self) -> PeerId {
        self.keypair.public().to_peer_id()
    }
}
