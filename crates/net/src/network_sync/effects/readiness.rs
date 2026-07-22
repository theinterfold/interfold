// SPDX-License-Identifier: LGPL-3.0-only

//! Own network readiness, fallback timing, and ingress task setup.

use super::*;

impl NetSyncManager {
    /// Apply a readiness decision: publish `NetReady`, or schedule the fallback timeout.
    pub(in crate::actors::net_sync_manager) fn apply_readiness(
        &mut self,
        decision: ReadinessDecision,
        ctx: &mut actix::Context<Self>,
    ) {
        match decision {
            ReadinessDecision::PublishReady => {
                if let Err(e) = self.publish_net_ready() {
                    error!("Failed to publish NetReady: {e}");
                }
                self.net_ready = true;
                self.maybe_rebroadcast_own_artifacts(ctx);
            }
            ReadinessDecision::WaitForConnection => {
                info!(
                    "All peer dials failed, waiting for connections before publishing NetReady..."
                );
                ctx.run_later(NET_READY_CONNECT_TIMEOUT, move |this, ctx| {
                    if let ReadinessDecision::PublishReady = this.readiness.on_connect_timeout() {
                        warn!("No peer connections established within 60s timeout, publishing NetReady anyway");
                        if let Err(e) = this.publish_net_ready() {
                            error!("Failed to publish NetReady: {e}");
                        }
                        this.net_ready = true;
                        this.maybe_rebroadcast_own_artifacts(ctx);
                    }
                });
            }
            ReadinessDecision::Idle => {}
        }
    }

    pub fn setup(
        bus: &BusHandle,
        tx: &mpsc::Sender<NetCommand>,
        rx: &Arc<broadcast::Receiver<NetEvent>>,
        eventstore: Recipient<EventStoreQueryBy<TsAgg>>,
        topic: &str,
        protocol_signer: ProtocolSigner,
        protocol_authorization: NetworkAuthorizationState,
    ) -> Addr<Self> {
        let mut events = rx.resubscribe();
        let addr = Self::new(
            bus,
            tx,
            rx,
            eventstore,
            topic,
            protocol_signer,
            protocol_authorization,
        )
        .start();

        bus.subscribe(EventType::HistoricalNetSyncStart, addr.clone().recipient());

        // Forward from NetEvent
        tokio::spawn({
            debug!("Spawning event receive loop!");
            let addr = addr.clone();
            async move {
                while let Some(event) =
                    crate::event_subscription::recv_net_event(&mut events, "NetSyncManager").await
                {
                    debug!("Received event {:?}", event);
                    let delivery = match event {
                        // Someone is asking for our sync
                        NetEvent::IncomingRequest(value) => addr.send(value).await,
                        NetEvent::AllPeersDialed { connected, total } => {
                            addr.send(AllPeersDialed { connected, total }).await
                        }
                        NetEvent::ConnectionEstablished { .. } => addr.send(PeerConnected).await,
                        _ => continue,
                    };
                    if let Err(error) = delivery {
                        warn!(%error, "NetSyncManager stopped; ending sync ingress");
                        break;
                    }
                }
            }
        });

        addr
    }
}
