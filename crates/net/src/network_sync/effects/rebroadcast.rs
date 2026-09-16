// SPDX-License-Identifier: LGPL-3.0-only

//! Re-gossip this node's forwardable in-flight artifacts after restart.

use super::*;
use e3_events::{DkgCoordination, E3id};

impl NetSyncManager {
    pub(in crate::actors::net_sync_manager) fn remember_dkg_coordination(
        &mut self,
        event: InterfoldEvent,
        message: &DkgCoordination,
    ) {
        if event.source() != EventSource::Local {
            return;
        }
        if let Err(error) = self.network.validate_event(&event) {
            warn!(%error, "Ignoring a local DKG coordination event for another network");
            return;
        }
        self.dkg_announcements.insert(
            (message.e3_id.clone(), message.party_id, message.kind),
            event,
        );
    }

    pub(in crate::actors::net_sync_manager) fn forget_dkg_coordination(&mut self, e3_id: &E3id) {
        self.dkg_announcements
            .retain(|(candidate, _, _), _| candidate != e3_id);
    }

    /// Re-send the latest locally signed DKG control messages without creating new durable
    /// events. Each transport delivery is distinct, but receivers deduplicate the embedded event.
    pub(in crate::actors::net_sync_manager) fn reannounce_dkg_coordination(&self) {
        if !self.net_ready || self.dkg_announcements.is_empty() {
            return;
        }
        let topic = self.topic.clone();
        let commands = self
            .dkg_announcements
            .values()
            .filter_map(|event| match event.clone().try_into() {
                Ok(data) => Some(NetCommand::gossip_republish(
                    topic.clone(),
                    data,
                    CorrelationId::new(),
                )),
                Err(error) => {
                    warn!(%error, "Could not encode a DKG coordination re-announcement");
                    None
                }
            })
            .collect::<Vec<_>>();
        let count = commands.len();
        let tx = self.tx.clone();
        actix::spawn(async move {
            for command in commands {
                if let Err(error) = tx.send(command).await {
                    warn!(%error, "Failed to queue a DKG coordination re-announcement");
                    break;
                }
            }
        });
        debug!(count, "Queued DKG coordination re-announcements");
    }

    /// After a restart, proactively re-gossip this node's own already-produced forwardable DKG
    /// artifacts (H3/H11). Resume from a persisted phase is otherwise passive: the restored
    /// keyshare/aggregator actors wait for peer documents and never re-emit their own outputs, so
    /// peers that missed the original gossip (cache expiry, DHT miss, peer churn) can stall the
    /// node to its phase timeout.
    ///
    /// The artifacts are sent straight to libp2p as `GossipPublish`, bypassing both the EventBus
    /// dedup window (which already tracked them during replay) and the translator (which is only
    /// created on `EffectsEnabled`). Re-broadcasting the original event in a fresh transport
    /// delivery is equivocation-safe because peers deduplicate the embedded event ID. The query is
    /// bounded to the snapshot-cursor window so only in-flight artifacts are re-sent.
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
                .with_filter(EventStoreFilter::Source(EventSource::Local))
                .with_limit(MAX_REBROADCAST_SCAN_EVENTS)
                .with_max_bytes(MAX_REBROADCAST_SCAN_BYTES),
        ) {
            error!("Failed to query EventStore for re-broadcast: {e}");
            self.rebroadcast_query_ids.remove(&id);
            self.rebroadcast_started = false;
        }
    }

    /// Re-gossip the node's own forwardable artifacts returned by the re-broadcast query.
    pub(in crate::actors::net_sync_manager) fn handle_rebroadcast_response(
        &mut self,
        events: Vec<InterfoldEvent>,
    ) {
        let mut commands = Vec::new();
        for event in events {
            if event.source() != EventSource::Local {
                continue;
            }
            if !EventTranslationService::is_forwardable_event(&event) {
                continue;
            }
            if let Err(error) = self.network.validate_event(&event) {
                warn!(%error, "Skipping own artifact that does not match the active network");
                continue;
            }
            let data: GossipData = match event.try_into() {
                Ok(data) => data,
                Err(e) => {
                    warn!("Failed to convert own artifact to gossip data: {e}");
                    continue;
                }
            };
            commands.push(NetCommand::gossip_republish(
                self.topic.clone(),
                data,
                CorrelationId::new(),
            ));
        }
        let count = commands.len();
        let tx = self.tx.clone();
        actix::spawn(async move {
            for command in commands {
                if let Err(error) = tx.send(command).await {
                    warn!(%error, "Failed to queue own artifact for re-broadcast");
                    break;
                }
            }
        });
        info!("NetSyncManager: queued {count} own forwardable artifact(s) after restart");
    }
}
