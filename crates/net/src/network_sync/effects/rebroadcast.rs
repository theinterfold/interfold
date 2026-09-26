// SPDX-License-Identifier: LGPL-3.0-only

//! Re-gossip this node's forwardable in-flight artifacts after restart.

use super::*;
use crate::backoff::backoff_delay;
use e3_events::{DecryptionshareCreated, DkgCoordination, E3id};

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
        self.schedule_reannouncement(
            AnnouncementKey::Dkg(message.e3_id.clone(), message.party_id, message.kind),
            event,
            DKG_REANNOUNCE_BASE,
            DKG_REANNOUNCE_CAP,
            Instant::now(),
        );
    }

    /// Keep re-sending this node's decryption share until the E3 ends. The aggregator ignores
    /// a party it already holds, so a repeat is harmless, and a lost share otherwise stays lost.
    pub(in crate::actors::net_sync_manager) fn remember_decryption_share(
        &mut self,
        event: InterfoldEvent,
        share: &DecryptionshareCreated,
    ) {
        if event.source() != EventSource::Local {
            return;
        }
        if let Err(error) = self.network.validate_event(&event) {
            warn!(%error, "Ignoring a local decryption share for another network");
            return;
        }
        self.schedule_reannouncement(
            AnnouncementKey::DecryptionShare(share.e3_id.clone(), share.party_id),
            event,
            SHARE_REANNOUNCE_BASE,
            SHARE_REANNOUNCE_CAP,
            Instant::now(),
        );
    }

    fn schedule_reannouncement(
        &mut self,
        key: AnnouncementKey,
        event: InterfoldEvent,
        base: Duration,
        cap: Duration,
        now: Instant,
    ) {
        if self
            .announcements
            .get(&key)
            .is_some_and(|existing| existing.event.event_id() == event.event_id())
        {
            return;
        }
        self.announcements.insert(
            key,
            Reannouncement {
                event,
                base,
                cap,
                sent: 0,
                next_due: now + base,
                expires: now + REANNOUNCE_LIFETIME,
            },
        );
    }

    pub(in crate::actors::net_sync_manager) fn forget_dkg_coordination(&mut self, e3_id: &E3id) {
        self.announcements
            .retain(|key, _| !(matches!(key, AnnouncementKey::Dkg(..)) && key.e3_id() == e3_id));
    }

    pub(in crate::actors::net_sync_manager) fn forget_e3_announcements(&mut self, e3_id: &E3id) {
        self.announcements.retain(|key, _| key.e3_id() != e3_id);
    }

    /// Re-send every message whose next send time has passed, with a new delivery ID, and back
    /// off its schedule. Messages past their lifetime are dropped.
    pub(in crate::actors::net_sync_manager) fn reannounce_due(&mut self, now: Instant) {
        self.announcements
            .retain(|_, announcement| announcement.expires > now);
        if !self.net_ready {
            return;
        }
        let topic = self.topic.clone();
        let mut commands = Vec::new();
        for announcement in self.announcements.values_mut() {
            if announcement.next_due > now {
                continue;
            }
            announcement.sent = announcement.sent.saturating_add(1);
            announcement.next_due = now
                + backoff_delay(
                    announcement.base,
                    announcement.sent.saturating_add(1),
                    announcement.cap,
                );
            match announcement.event.clone().try_into() {
                Ok(data) => commands.push(NetCommand::gossip_republish(
                    topic.clone(),
                    data,
                    CorrelationId::new(),
                )),
                Err(error) => warn!(%error, "Could not encode a re-announcement"),
            }
        }
        if commands.is_empty() {
            return;
        }
        let count = commands.len();
        let tx = self.tx.clone();
        actix::spawn(async move {
            for command in commands {
                if let Err(error) = tx.send(command).await {
                    warn!(%error, "Failed to queue a re-announcement");
                    break;
                }
            }
        });
        debug!(count, "Queued re-announcements");
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
            if let InterfoldEventData::DecryptionshareCreated(share) = event.get_data() {
                let share = share.clone();
                self.remember_decryption_share(event.clone(), &share);
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
