// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::simulate_libp2p_net;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use e3_ciphernode_builder::CiphernodeHandle;
use e3_events::Event;
use e3_events::{GetEvents, InterfoldEvent, ResetHistory, TakeEvents};
use std::time::Instant;
use std::{future::Future, ops::Deref, pin::Pin, time::Duration};
use tokio::time::timeout;
use tracing::info;

// This type allows us to store various dynamic async callbacks
type SetupFn<'a> =
    Box<dyn Fn() -> Pin<Box<dyn Future<Output = Result<CiphernodeHandle>> + 'a>> + 'a>;
type ThenFn<'a> =
    Box<dyn Fn(&CiphernodeHandle) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>> + 'a>;

/// This builds a ciphernode system using the actor model only. This helps us simulate the network
/// in tests that we can run in the /crates/tests crate
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
    thens: Vec<ThenFn<'a>>,
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
            thens: Vec::new(),
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

        if self.simulate {
            simulate_libp2p_net(&nodes).await;
        }

        for then_fn in self.thens {
            for node in nodes.iter() {
                then_fn(node).await?;
            }
        }

        Ok(CiphernodeSystem(nodes))
    }
}

pub struct CiphernodeSystem(Vec<CiphernodeHandle>);

impl CiphernodeSystem {
    pub async fn get_history(&self, index: usize) -> Result<CiphernodeHistory> {
        let Some(node) = self.0.get(index) else {
            return Ok(CiphernodeHistory(vec![]));
        };

        let history = if let Some(history) = node.history() {
            history.send(GetEvents::new()).await?
        } else {
            vec![]
        };

        Ok(CiphernodeHistory(history))
    }

    pub async fn take_history(&self, index: usize, count: usize) -> Result<CiphernodeHistory> {
        self.take_history_with_timeout(index, count, Duration::from_millis(4000))
            .await
    }

    /// expect events to fire with the default timeout 1000sec per event
    pub async fn expect_events(&self, expected: &[&str]) -> Result<CiphernodeHistory> {
        let h = self
            .take_history_with_timeouts(
                0,
                expected.len(),
                Some(Duration::from_secs(1000)),
                Some(Duration::from_secs(1000)),
            )
            .await
            .map_err(|e| anyhow::anyhow!("FAILURE: {expected:?} : {e}"))?;

        println!(">> {:?} == {:?}", h.event_types(), expected.to_vec());
        h.expect(expected.to_vec());
        Ok(h)
    }

    pub async fn expect_events_without_timeout(
        &self,
        expected: &[&str],
    ) -> Result<CiphernodeHistory> {
        let h = self
            .take_history_with_timeouts(0, expected.len(), None, None)
            .await
            .map_err(|e| anyhow::anyhow!("FAILURE: {expected:?} : {e}"))?;

        println!(">> {:?} == {:?}", h.event_types(), expected.to_vec());
        h.expect(expected.to_vec());
        Ok(h)
    }

    pub async fn expect_events_with_timeouts(
        &self,
        expected: &[&str],
        total_to: Duration,   // total
        per_evt_to: Duration, // per event
    ) -> Result<CiphernodeHistory> {
        let start = Instant::now();
        let h = self
            .take_history_with_timeouts(0, expected.len(), Some(total_to), Some(per_evt_to))
            .await
            .map_err(|e| anyhow::anyhow!("FAILURE: {expected:?} : {e}"))?;
        println!(">> {:?} == {:?}", h.event_types(), expected.to_vec());

        info!(
            "expectation take took {:?} for {:?} total_timeout={:?} per_evt_timeout={:?}",
            start.elapsed(),
            expected,
            total_to,
            per_evt_to
        );
        h.expect(expected.to_vec());
        Ok(h)
    }

    pub async fn take_history_with_timeout(
        &self,
        index: usize,
        count: usize,
        total_to: Duration,
    ) -> Result<CiphernodeHistory> {
        self.take_history_with_timeouts(
            index,
            count,
            Some(total_to),
            Some(Duration::from_millis(1000)),
        )
        .await
    }

    pub async fn take_history_with_timeouts(
        &self,
        index: usize,
        count: usize,
        total_to: Option<Duration>,
        event_to: Option<Duration>,
    ) -> Result<CiphernodeHistory> {
        let start = Instant::now();
        let Some(node) = self.0.get(index) else {
            bail!("No node found");
        };

        let Some(history) = node.history() else {
            return Ok(CiphernodeHistory(vec![]));
        };

        let history = timeout(
            total_to.unwrap_or(Duration::from_secs(u64::MAX)), // No timeout
            history.send(TakeEvents::with_per_evt_timeout(
                count,
                event_to.unwrap_or(Duration::from_secs(u64::MAX)),
            )),
        )
        .await
        .context(format!(
            "Could not take {} events from node {}",
            count, index
        ))??;

        if history.timed_out {
            bail!(
                "Take History timed out after {:?} was trying to take {} events. Returned {:?}",
                start.elapsed(),
                count,
                history
            );
        };
        info!(
            "take took {:?} for count={}, total_timeout={:?}, per_evt_timeout={:?}",
            start.elapsed(),
            count,
            total_to,
            event_to
        );
        Ok(CiphernodeHistory(history.events))
    }

    /// Collect events until one whose [`InterfoldEvent::event_type`] equals `last_event_type`
    /// (inclusive). Use when the pubkey flow ends with `PublicKeyAggregated` but a fixed
    /// `take_history` count can stop too early while gossip duplicates inflate the multiset.
    pub async fn take_history_until_last_event(
        &self,
        index: usize,
        last_event_type: &str,
        total_to: Option<Duration>,
        event_to: Option<Duration>,
    ) -> Result<CiphernodeHistory> {
        let start = Instant::now();
        let total_to = total_to.unwrap_or(Duration::from_secs(u64::MAX));
        let event_to = event_to.unwrap_or(Duration::from_secs(u64::MAX));
        let mut collected = Vec::new();

        loop {
            let remaining = total_to.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                bail!(
                    "take_history_until_last_event({last_event_type}) timed out after {:?}; got {} events: {:?}",
                    start.elapsed(),
                    collected.len(),
                    CiphernodeHistory(collected.clone()).event_types()
                );
            }
            let call_to = event_to.min(remaining);
            let batch = self
                .take_history_with_timeouts(index, 1, Some(call_to), Some(call_to))
                .await?;
            for event in batch.0 {
                let is_last = event.event_type() == last_event_type;
                collected.push(event);
                if is_last {
                    info!(
                        "take_history_until_last_event({last_event_type}) took {:?} ({} events)",
                        start.elapsed(),
                        collected.len()
                    );
                    return Ok(CiphernodeHistory(collected));
                }
            }
        }
    }

    pub async fn flush_all_history(&self, millis: u64) -> Result<()> {
        let nodes = &self.0;
        for node in nodes.iter() {
            let Some(history) = node.history() else {
                break;
            };
            loop {
                println!("IN FLUSH LOOP...");
                let nhs = history.send(TakeEvents::new(1));
                let tr = timeout(Duration::from_millis(millis), nhs).await;
                match tr {
                    Ok(Ok(result)) if result.timed_out => {
                        println!("PER-EVENT TIMEOUT, BREAKING LOOP...");
                        break;
                    }
                    Err(_) => {
                        println!("OUTER TIMEOUT, BREAKING LOOP...");
                        break;
                    }
                    _ => {
                        // Got events, keep draining
                    }
                }
            }
            history.send(ResetHistory).await?;
        }
        Ok(())
    }
}

impl Deref for CiphernodeSystem {
    type Target = Vec<CiphernodeHandle>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct CiphernodeHistory(Vec<InterfoldEvent>);

impl CiphernodeHistory {
    pub fn filter_by_event_type(&self, event_type: String) -> Vec<InterfoldEvent> {
        self.0
            .iter()
            .filter(|e| e.event_type() == event_type)
            .cloned()
            .collect()
    }

    pub fn event_types(&self) -> Vec<String> {
        self.0.iter().map(|e| e.event_type()).collect()
    }

    pub fn expect(&self, event_types: Vec<&str>) {
        assert_eq!(self.event_types(), event_types);
    }
}

impl Deref for CiphernodeHistory {
    type Target = Vec<InterfoldEvent>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::prelude::*;
    use e3_ciphernode_builder::{EventSystem, NetInterfaceKind};
    use e3_data::InMemStore;
    use e3_events::{EventBus, EventBusConfig};
    use libp2p::PeerId;

    async fn mock_setup_node(address: String) -> Result<CiphernodeHandle> {
        // Create mock actors for the test
        let store = InMemStore::new(true).start();
        let bus = EventBus::<InterfoldEvent>::new(EventBusConfig { deduplicate: true }).start();
        let history = EventBus::<InterfoldEvent>::history(&bus);
        let errors = EventBus::<InterfoldEvent>::error(&bus);

        let bus = EventSystem::new()
            .with_event_bus(bus)
            .handle()?
            .enable("test");

        Ok(CiphernodeHandle {
            address,
            store: (&store).into(),
            bus,
            history: Some(history),
            errors: Some(errors),
            peer_id: PeerId::random(),
            net_interface: NetInterfaceKind::Libp2p,
        })
    }

    #[actix::test]
    async fn test_builder_creates_multiple_groups() {
        let nodes = CiphernodeSystemBuilder::new()
            .add_group(2, || mock_setup_node("node_a".to_string()))
            .add_group(3, || mock_setup_node("node_b".to_string()))
            .build()
            .await
            .expect("Should create nodes successfully");

        // Should have created 5 total nodes (2 + 3)
        assert_eq!(nodes.len(), 5);

        // Verify node addresses
        assert_eq!(nodes[0].address, "node_a");
        assert_eq!(nodes[1].address, "node_a");
        assert_eq!(nodes[2].address, "node_b");
        assert_eq!(nodes[3].address, "node_b");
        assert_eq!(nodes[4].address, "node_b");
    }
}
