// SPDX-License-Identifier: LGPL-3.0-only

//! Re-gossip this node's forwardable in-flight artifacts after restart.

use super::*;

impl NetSyncManager {
    /// After a restart, proactively re-gossip this node's own already-produced forwardable DKG
    /// artifacts (H3/H11). Resume from a persisted phase is otherwise passive: the restored
    /// keyshare/aggregator actors wait for peer documents and never re-emit their own outputs, so
    /// peers that missed the original gossip (cache expiry, DHT miss, peer churn) can stall the
    /// node to its phase timeout.
    ///
    /// The artifacts are sent straight to libp2p as `GossipPublish`, bypassing both the EventBus
    /// dedup window (which already tracked them during replay) and the translator (which is only
    /// created on `EffectsEnabled`). Re-broadcasting the byte-identical original payload is
    /// equivocation-safe (peers dedup by event id) and idempotent. The query is bounded to the
    /// snapshot-cursor window so only the in-flight (un-delivered) artifacts are re-sent.
    pub(in crate::actors::net_sync_manager) fn maybe_rebroadcast_own_artifacts(
        &mut self,
        ctx: &mut actix::Context<Self>,
    ) {
        if self.rebroadcast_started || !self.net_ready {
            return;
        }
        let Some(since) = self.rebroadcast_since.clone() else {
            return;
        };
        self.rebroadcast_started = true;

        let id = CorrelationId::new();
        self.rebroadcast_query_ids.insert(id);
        info!("NetSyncManager: querying own forwardable artifacts for post-restart re-broadcast");
        if let Err(e) = self.eventstore.try_send(
            EventStoreQueryBy::<TsAgg>::new(id, since, ctx.address().recipient())
                .with_filter(EventStoreFilter::Source(EventSource::Local)),
        ) {
            error!("Failed to query EventStore for re-broadcast: {e}");
            self.rebroadcast_query_ids.remove(&id);
            self.rebroadcast_started = false;
        }
    }

    /// Re-gossip the node's own forwardable artifacts returned by the re-broadcast query.
    pub(in crate::actors::net_sync_manager) async fn rebroadcast_own_artifacts(
        tx: mpsc::Sender<NetCommand>,
        topic: String,
        signer: ProtocolSigner,
        authorization: NetworkAuthorizationState,
        events: Vec<InterfoldEvent>,
    ) -> Result<usize> {
        let mut count = 0usize;
        let admission = ProtocolAdmission::new(authorization);
        for event in events {
            if !EventTranslationService::is_forwardable_event(&event) {
                continue;
            }
            if let Err(error) = admission.authorize_local_event(signer.address(), &event) {
                warn!(%error, event_id=%event.id(), "Skipping stale or unauthorized own artifact during re-broadcast");
                continue;
            }
            let data = match signer.sign_event(event) {
                Ok(envelope) => GossipData::ProtocolEvent(envelope),
                Err(e) => {
                    warn!("Failed to convert own artifact to gossip data: {e}");
                    continue;
                }
            };
            tx.send(NetCommand::GossipPublish {
                topic: topic.clone(),
                data,
                correlation_id: CorrelationId::new(),
            })
            .await
            .context("network command channel closed while re-broadcasting an own artifact")?;
            count += 1;
        }
        info!("NetSyncManager: re-broadcast {count} own forwardable artifact(s) after restart");
        Ok(count)
    }
}
