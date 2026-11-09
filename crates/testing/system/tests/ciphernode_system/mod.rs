// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{Context, Result};
use e3_ciphernode_builder::CiphernodeHandle;
use e3_events::{Event, GetEvents, InterfoldEvent};
mod libp2p_mock;
use libp2p_mock::Libp2pMock;
use std::{future::Future, ops::Deref, pin::Pin};

// This type allows us to store various dynamic async callbacks
type SetupFn<'a> =
    Box<dyn Fn() -> Pin<Box<dyn Future<Output = Result<CiphernodeHandle>> + 'a>> + 'a>;

/// This builds a ciphernode system using the actor model only. This helps us simulate the network
/// in tests that we can run in the /crates/testing/system crate
/// ```ignore
/// let nodes = CiphernodeSystemBuilder::new()
///     .add_group(6, || async {
///         setup_local_ciphernode(bus, rng, true, rand_eth_addr(), None, cipher).await
///     })
///     .add_group(1, || async {
///         setup_aggregator_ciphernode(bus, rng, true, rand_eth_addr(), None, cipher).await
///     })
///     .build()
///     .await?;
/// ```
pub struct CiphernodeSystemBuilder<'a> {
    // Various groups with different setup functions
    groups: Vec<(u32, SetupFn<'a>)>,
    simulate: bool,
}

impl<'a> Default for CiphernodeSystemBuilder<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> CiphernodeSystemBuilder<'a> {
    pub fn new() -> Self {
        Self {
            groups: Vec::new(),
            simulate: false,
        }
    }

    /// Add a group of nodes with a specific configuration to the ciphernode system.
    /// We can add multiple groups of nodes each with a different configuration and count.
    pub fn add_group<F, Fut>(mut self, count: u32, setup_fn: F) -> Self
    where
        F: Fn() -> Fut + 'a,
        Fut: Future<Output = Result<CiphernodeHandle>> + 'a,
    {
        let wrapped_fn = Box::new(
            move || -> Pin<Box<dyn Future<Output = Result<CiphernodeHandle>> + 'a>> {
                Box::pin(setup_fn())
            },
        );
        self.groups.push((count, wrapped_fn));
        self
    }

    /// Add gossip simulation. This takes all event bus events on local ciphernode busses that have been set for
    /// broadcast and broadcasts them to all other nodes.
    pub fn simulate_libp2p(mut self) -> Self {
        self.simulate = true;
        self
    }

    /// Build the system returning a list of all nodes
    pub async fn build(self) -> Result<CiphernodeSystem> {
        let mut nodes = Vec::new();

        for (count, setup_fn) in self.groups {
            for _ in 0..count {
                nodes.push(setup_fn().await?);
            }
        }

        let network_mock = if self.simulate {
            Some(simulate_libp2p_net(&nodes).await)
        } else {
            None
        };

        Ok(CiphernodeSystem {
            nodes,
            network_mock,
        })
    }
}

/// Simulate libp2p by taking output net commands and converting them to net events sending them to
/// the other nodes
async fn simulate_libp2p_net(nodes: &[CiphernodeHandle]) -> Libp2pMock {
    let mock = Libp2pMock::new();
    for node in nodes.iter() {
        let interface = node.channel_bridge().unwrap();
        mock.add_node(node.peer_id, interface).await;
    }
    mock
}

pub struct CiphernodeSystem {
    nodes: Vec<CiphernodeHandle>,
    network_mock: Option<Libp2pMock>,
}

impl CiphernodeSystem {
    pub async fn disconnect_node(&self, index: usize) -> Result<()> {
        let node = self
            .nodes
            .get(index)
            .context("ciphernode index is out of range")?;
        let mock = self
            .network_mock
            .as_ref()
            .context("ciphernode system has no simulated network")?;
        mock.disconnect_node(node.peer_id).await;
        Ok(())
    }

    pub async fn get_history(&self, index: usize) -> Result<CiphernodeHistory> {
        let Some(node) = self.nodes.get(index) else {
            return Ok(CiphernodeHistory(vec![]));
        };

        let history = if let Some(history) = node.history() {
            history.send(GetEvents::new()).await?
        } else {
            vec![]
        };

        Ok(CiphernodeHistory(history))
    }
}

impl Deref for CiphernodeSystem {
    type Target = Vec<CiphernodeHandle>;

    fn deref(&self) -> &Self::Target {
        &self.nodes
    }
}

#[derive(Debug, Clone)]
pub struct CiphernodeHistory(Vec<InterfoldEvent>);

impl CiphernodeHistory {
    pub fn event_types(&self) -> Vec<String> {
        self.0.iter().map(|e| e.event_type()).collect()
    }
}

impl Deref for CiphernodeHistory {
    type Target = Vec<InterfoldEvent>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
