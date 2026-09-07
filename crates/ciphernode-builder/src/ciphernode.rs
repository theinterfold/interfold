// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::Addr;
use anyhow::{Context, Result};
use e3_data::{DataStore, InMemStore, StoreAddr};
use e3_events::{BusHandle, HistoryCollector, InterfoldEvent};
use e3_evm::GatewayFailureReceiver;
use e3_net::{NetChannelBridge, NetworkStatus};
use libp2p::PeerId;
use std::{future::Future, time::Duration};
use tracing::info;

use crate::global_eventstore_cache::EventStoreReader;

async fn enforce_shutdown_deadline<F>(deadline: Duration, shutdown: F) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    tokio::time::timeout(deadline, shutdown)
        .await
        .with_context(|| {
            format!(
                "ciphernode shutdown exceeded its {:.3}s deadline",
                deadline.as_secs_f64()
            )
        })?
}

/// The kind of network interface backing a ciphernode.
#[derive(Debug, Clone)]
pub enum NetInterfaceKind {
    /// Real libp2p networking (production).
    Libp2p,
    /// In-process channel bridge (tests / benchmarks).
    ChannelBridge(NetChannelBridge),
}

impl NetInterfaceKind {
    /// Extract the channel bridge, failing if this is a libp2p interface.
    pub fn into_channel_bridge(self) -> Result<NetChannelBridge> {
        match self {
            NetInterfaceKind::ChannelBridge(bridge) => Ok(bridge),
            NetInterfaceKind::Libp2p => Err(anyhow::anyhow!(
                "No channel bridge exists — node is using libp2p networking"
            )),
        }
    }
}

/// A sharable handle to a Ciphernode. Clones are available for use in the
/// CiphernodeSystem but they cannot await the task.
#[derive(Debug)]
pub struct CiphernodeHandle {
    pub address: String,
    pub store: DataStore,
    pub bus: BusHandle,
    /// Optional event history collector. Populated when the builder is configured
    /// with [`CiphernodeBuilder::with_history_collector`].
    pub history: Option<Addr<HistoryCollector<InterfoldEvent>>>,
    /// Optional error event collector. Populated when the builder is configured
    /// with [`CiphernodeBuilder::with_error_collector`].
    pub errors: Option<Addr<HistoryCollector<InterfoldEvent>>>,
    pub peer_id: PeerId,
    pub net_interface: NetInterfaceKind,
    pub network_status: NetworkStatus,
    pub eventstore: EventStoreReader,
    pub aggregate_ids: Vec<usize>,
    /// One receiver per chain gateway; yields a reason if that gateway fails closed after
    /// startup. Empty when the node runs without chains.
    pub gateway_failures: Vec<GatewayFailureReceiver>,
}

impl PartialEq for CiphernodeHandle {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address && self.peer_id == other.peer_id
    }
}

impl Eq for CiphernodeHandle {}

impl CiphernodeHandle {
    pub fn bus(&self) -> &BusHandle {
        &self.bus
    }

    pub fn history(&self) -> Option<Addr<HistoryCollector<InterfoldEvent>>> {
        self.history.clone()
    }

    pub fn errors(&self) -> Option<Addr<HistoryCollector<InterfoldEvent>>> {
        self.errors.clone()
    }

    pub fn address(&self) -> String {
        self.address.clone()
    }

    pub fn network_status(&self) -> NetworkStatus {
        self.network_status.clone()
    }

    pub fn eventstore(&self) -> EventStoreReader {
        self.eventstore.clone()
    }

    pub fn aggregate_ids(&self) -> &[usize] {
        &self.aggregate_ids
    }

    pub fn store(&self) -> &DataStore {
        &self.store
    }

    /// Extract the channel bridge for test network simulation.
    /// Returns an error if the node is using libp2p networking.
    pub fn channel_bridge(&self) -> Result<NetChannelBridge> {
        self.net_interface.clone().into_channel_bridge()
    }

    pub fn in_mem_store(&self) -> Option<&Addr<InMemStore>> {
        let addr = self.store.get_addr();
        if let StoreAddr::InMem(ref store) = addr {
            return Some(store);
        }
        None
    }

    /// Resolve with the reason as soon as any chain gateway fails closed.
    ///
    /// A gateway that fails closed stops ingesting chain events but leaves the rest of the
    /// node running: peers stay connected, the daemon and the DAppNode healthcheck both report
    /// it healthy, and the operator's only signal is one log line. The gateway's own message
    /// tells the operator to restart; the run loop uses this future to do that for them.
    /// Pends forever when the node has no chain gateways.
    pub fn gateway_failure(&self) -> impl Future<Output = String> + Send + 'static {
        let mut receivers = self.gateway_failures.clone();
        async move {
            if receivers.is_empty() {
                return std::future::pending().await;
            }
            let waits = receivers.iter_mut().map(|rx| {
                Box::pin(async move {
                    // `wait_for` yields immediately if a reason is already set, and resolves
                    // with an error if the gateway actor (the sender) is dropped.
                    match rx.wait_for(|reason| reason.is_some()).await {
                        Ok(reason) => reason
                            .clone()
                            .unwrap_or_else(|| "EVM chain gateway failed closed".to_owned()),
                        Err(_) => "EVM chain gateway stopped without reporting a reason".to_owned(),
                    }
                })
            });
            futures::future::select_all(waits).await.0
        }
    }

    /// Stop protocol actors and make persisted state durable within `deadline`.
    ///
    /// The ordering is deliberate: the persisted `Shutdown` event first stops
    /// producers and awaits subscriber final-state handlers; the event pipeline
    /// is then flushed; finally snapshot batches drain before the backing store
    /// is flushed and closed.
    pub async fn shutdown(self, deadline: Duration) -> Result<()> {
        enforce_shutdown_deadline(deadline, async move {
            info!(stage = "actor-drain", "Ciphernode shutdown barrier started");
            self.bus
                .publish_shutdown_and_wait()
                .await
                .context("failed to persist or acknowledge Shutdown")?;

            info!(
                stage = "event-flush",
                "Ciphernode shutdown barrier advanced"
            );
            self.bus
                .flush_event_pipeline()
                .await
                .context("failed to drain or flush the event pipeline")?;

            info!(
                stage = "store-flush",
                "Ciphernode shutdown barrier advanced"
            );
            self.store
                .shutdown()
                .await
                .context("failed to drain snapshots or flush the data store")?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_deadline_is_enforced() {
        let error = enforce_shutdown_deadline(
            Duration::from_millis(10),
            std::future::pending::<Result<()>>(),
        )
        .await
        .expect_err("pending shutdown must time out")
        .to_string();

        assert!(error.contains("shutdown exceeded its 0.010s deadline"));
    }
}
