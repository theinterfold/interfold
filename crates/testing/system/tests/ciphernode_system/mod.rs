// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{bail, Context, Result};
use e3_ciphernode_builder::CiphernodeHandle;
use e3_events::{Event, GetEvents, InterfoldEvent};
mod libp2p_mock;
use libp2p_mock::Libp2pMock;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
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
            before_restart: HashMap::new(),
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
    /// What each restarted node logged before it stopped. A restarted node's history collector
    /// starts empty, so [`CiphernodeSystem::get_history`] joins the two.
    before_restart: HashMap<usize, Vec<InterfoldEvent>>,
}

impl CiphernodeSystem {
    /// Stops node `index` and replaces it with the node `rebuild` assembles from the stopped
    /// node's persisted state. The network holds gossip addressed to the node meanwhile and hands
    /// it to the replacement. Returns everything the stopped node logged.
    pub async fn restart_node<F>(&mut self, index: usize, rebuild: F) -> Result<CiphernodeHistory>
    where
        F: Future<Output = Result<CiphernodeHandle>>,
    {
        if index >= self.nodes.len() {
            bail!("ciphernode index is out of range");
        }
        let old = self.nodes.remove(index);
        let old_peer_id = old.peer_id;
        let old_history = old.history();
        if let Some(mock) = &self.network_mock {
            mock.disconnect_node_for_restart(old_peer_id).await;
        }
        old.shutdown(Duration::from_secs(30))
            .await
            .context("ciphernode shutdown before restart failed")?;
        // Read after the shutdown barrier, which is the last thing the stopped node logs.
        let logged = match old_history {
            Some(history) => history.send(GetEvents::new()).await?,
            None => vec![],
        };
        let replacement = rebuild
            .await
            .context("ciphernode rebuild after restart failed")?;
        if let Some(mock) = &self.network_mock {
            mock.add_replacement_node(
                old_peer_id,
                replacement.peer_id,
                replacement.channel_bridge()?,
            )
            .await;
        }
        self.nodes.insert(index, replacement);
        let earlier = self.before_restart.entry(index).or_default();
        let known: HashSet<_> = earlier.iter().map(Event::delivery_id).collect();
        let new: Vec<_> = logged
            .iter()
            .filter(|event| !known.contains(&event.delivery_id()))
            .cloned()
            .collect();
        earlier.extend(new);
        Ok(CiphernodeHistory(earlier.clone()))
    }

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

        let mut history = if let Some(history) = node.history() {
            history.send(GetEvents::new()).await?
        } else {
            vec![]
        };
        // An event delivered again after a restart has the same delivery ID; keep one copy, as
        // the bus does within one run.
        if let Some(earlier) = self.before_restart.get(&index) {
            let known: HashSet<_> = earlier.iter().map(Event::delivery_id).collect();
            history.retain(|event| !known.contains(&event.delivery_id()));
            history.splice(0..0, earlier.iter().cloned());
        }

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
