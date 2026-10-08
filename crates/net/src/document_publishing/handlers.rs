// SPDX-License-Identifier: LGPL-3.0-only

//! Actix routing for document lifecycle and network notifications.

use super::*;
use futures::future::Abortable;

impl Actor for DocumentPublisher {
    type Context = actix::Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
        ctx.run_interval(FETCH_QUEUE_POLL, |actor, ctx| actor.start_due_fetches(ctx));
    }
}

impl Handler<InterfoldEvent> for DocumentPublisher {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let source = msg.source();
        let (msg, ec) = msg.into_components();
        match msg {
            // Startup publishes chain history between `EffectsEnabled` and `SyncEnded`. A
            // publication that starts earlier can announce or upload a document of an E3 whose
            // closing stage is still in that history.
            InterfoldEventData::SyncEnded(_) if !self.publishing_enabled => {
                self.publishing_enabled = true;
                let ids: Vec<_> = self.publications.keys().cloned().collect();
                for id in &ids {
                    self.start_publication(id, ctx);
                }
                self.restore_next_received_document(ctx);
            }
            InterfoldEventData::PublishDocumentRequested(data) => {
                ctx.notify(TypedEvent::new(data, ec))
            }
            InterfoldEventData::CiphernodeSelected(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::DocumentReceived(data) => {
                let id = (
                    data.meta.e3_id.clone(),
                    ContentHash::from_content(&data.value),
                );
                if self.received.len() < MAX_RECEIVED_DOCUMENTS || self.received.contains(&id) {
                    // Recovery reads only the receipts of the E3s in the committee snapshot, which
                    // can predate a selection that replay restores. A receipt that replay delivers
                    // before `SyncEnded` and that recovery did not read is restored too.
                    if self.received.insert(id)
                        && !self.publishing_enabled
                        && !self.closed_e3s.contains(&data.meta.e3_id)
                    {
                        self.restorable.push(data, chrono::Utc::now());
                    }
                } else {
                    self.bus.err(
                        EType::DocumentPublishing,
                        anyhow::anyhow!("received-document cache is full"),
                    );
                }
            }
            InterfoldEventData::E3StageChanged(data)
                if source == EventSource::Evm
                    && matches!(
                        data.new_stage,
                        E3Stage::KeyPublished
                            | E3Stage::CiphertextReady
                            | E3Stage::Complete
                            | E3Stage::Failed
                    ) =>
            {
                if let Err(error) = self.handle_canonical_dkg_end(&data.e3_id, ctx) {
                    self.bus.err(EType::DocumentPublishing, error);
                }
            }
            _ => (),
        }
    }
}

impl Handler<TypedEvent<PublishDocumentRequested>> for DocumentPublisher {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<PublishDocumentRequested>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let id = (
            msg.meta.e3_id.clone(),
            ContentHash::from_content(&msg.value),
        );
        // Publications wait for `SyncEnded`, and replay brings back requests that may have
        // expired, so an expired publication must not take the outbox or this document's place.
        self.remove_expired_publications(ctx);
        if self.closed_e3s.contains(&msg.meta.e3_id) || self.publications.contains_key(&id) {
            return;
        }
        let size = msg.value.size();
        if self.publications.len() >= MAX_PENDING_PUBLICATIONS
            || self.publication_bytes.saturating_add(size) > MAX_PENDING_PUBLICATION_BYTES
        {
            self.bus.err(
                EType::DocumentPublishing,
                anyhow::anyhow!("document publication outbox is full"),
            );
            return;
        }
        self.service.track_published_key(&id.0, &msg.value);
        self.publication_bytes += size;
        self.publications
            .insert(id.clone(), Publication::new(msg.into_inner()));
        if self.publishing_enabled {
            self.start_publication(&id, ctx);
        }
    }
}

impl Handler<TypedEvent<CiphernodeSelected>> for DocumentPublisher {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<CiphernodeSelected>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        trap(EType::DocumentPublishing, &self.bus.with_ec(&ec), || {
            self.handle_ciphernode_selected(msg, _ctx)
        })
    }
}

impl Handler<AnnounceDocument> for DocumentPublisher {
    type Result = ();

    fn handle(&mut self, AnnounceDocument(id): AnnounceDocument, ctx: &mut Self::Context) {
        let Some(event) = self.ready_publication(&id, ctx) else {
            return;
        };
        let Some(publication) = self.publications.get_mut(&id) else {
            return;
        };
        if publication.announcing.is_some() {
            return;
        }
        let (abort, registration) = AbortHandle::new_pair();
        publication.announcing = Some(abort);
        let announcement = announce_stored_document(
            self.tx.clone(),
            self.rx.clone(),
            event,
            self.topic.clone(),
            self.bus.clone(),
        );
        ctx.spawn(
            Abortable::new(announcement, registration)
                .into_actor(self)
                .map(move |result, actor, ctx| {
                    // An aborted announcement belongs to a publication that was removed.
                    let Ok(outcome) = result else {
                        return;
                    };
                    let Some(publication) = actor.publications.get_mut(&id) else {
                        return;
                    };
                    publication.announcing = None;
                    if publication.is_expired() {
                        actor.remove_publication(&id, ctx);
                        return;
                    }
                    let delay = match outcome {
                        Ok(()) => publication.schedule.record_announced(),
                        Err(error) => {
                            let delay = publication.schedule.record_announcement_failed();
                            actor.bus.err(EType::IO, error);
                            delay
                        }
                    };
                    actor.schedule_announcement(id, delay, ctx);
                }),
        );
    }
}

impl Handler<ReplicateDocument> for DocumentPublisher {
    type Result = ();

    fn handle(&mut self, ReplicateDocument(id): ReplicateDocument, ctx: &mut Self::Context) {
        let Some(event) = self.ready_publication(&id, ctx) else {
            return;
        };
        let uploads_in_flight = self
            .publications
            .values()
            .filter(|publication| publication.replicating.is_some())
            .count();
        let Some(publication) = self.publications.get_mut(&id) else {
            return;
        };
        if publication.replicating.is_some() {
            return;
        }
        let now = Instant::now();
        if !publication.schedule.needs_replication(now) {
            let due_in = publication.schedule.replication_due_in(now);
            self.schedule_replication(id, due_in, ctx);
            return;
        }
        if uploads_in_flight >= MAX_INFLIGHT_REPLICATIONS {
            self.schedule_replication(id, REPLICATION_QUEUE_POLL, ctx);
            return;
        }
        let (abort, registration) = AbortHandle::new_pair();
        publication.replicating = Some(abort);
        let (tx, rx) = (self.tx.clone(), self.rx.clone());
        let upload = async move { replicate_document(tx, rx, &event).await };
        ctx.spawn(Abortable::new(upload, registration).into_actor(self).map(
            move |result, actor, ctx| {
                // An aborted upload belongs to a publication that was removed.
                let Ok(outcome) = result else {
                    return;
                };
                let Some(publication) = actor.publications.get_mut(&id) else {
                    return;
                };
                publication.replicating = None;
                if publication.is_expired() {
                    actor.remove_publication(&id, ctx);
                    return;
                }
                let delay = match outcome {
                    Ok(()) => {
                        info!(e3_id = %id.0, key = ?id.1, "Uploaded a document to the DHT");
                        publication.schedule.record_replicated(Instant::now())
                    }
                    Err(error) => {
                        let delay = publication.schedule.record_replication_failed();
                        actor.bus.err(EType::IO, error);
                        delay
                    }
                };
                actor.schedule_replication(id, delay, ctx);
            },
        ));
    }
}

/// Receiving DocumentPublishedNotification from libp2p. The fetch runs in the actor context, so
/// the network receive loop does not wait for it.
impl Handler<DocumentPublishedNotification> for DocumentPublisher {
    type Result = ();
    fn handle(&mut self, msg: DocumentPublishedNotification, ctx: &mut Self::Context) {
        self.handle(
            DocumentIngress {
                propagation_source: None,
                notification: msg,
            },
            ctx,
        );
    }
}

impl Handler<DocumentIngress> for DocumentPublisher {
    type Result = ();
    fn handle(&mut self, ingress: DocumentIngress, ctx: &mut Self::Context) {
        let peer = ingress.propagation_source;
        let msg = ingress.notification;
        let now = chrono::Utc::now();
        if !notification_is_valid(&msg, now) {
            debug!("Ignored an invalid or expired document notification");
            return;
        }
        // The document is published at the notification's time, which the clock refuses beyond its
        // drift allowance. Such a notification cannot deliver the document, and it must not take
        // the place of one that can.
        match self.bus.latest_admissible_ts() {
            Ok(latest) if msg.ts <= latest => {}
            Ok(_) => {
                debug!("Ignored a document notification stamped beyond the clock-drift allowance");
                return;
            }
            Err(error) => {
                self.bus.err(EType::DocumentPublishing, error);
                return;
            }
        }
        let id = (msg.meta.e3_id.clone(), msg.key.clone());
        if self.closed_e3s.contains(&msg.meta.e3_id) {
            return;
        }
        let ids = self.service.interest_snapshot();
        if !ids.contains_key(&msg.meta.e3_id) {
            self.early_notifications
                .retain(|item| item.notification.meta.expires_at > now);
            // Keep one notification per peer, document and party filter, with the latest expiry. Only
            // the filter decides whether a notification can match the payload, so a forged copy
            // that arrives first must not hide a correct one with another filter or outlive it.
            if let Some(item) = self.early_notifications.iter_mut().find(|item| {
                item.notification.meta.e3_id == msg.meta.e3_id
                    && item.notification.key == msg.key
                    && item.notification.meta.filter == msg.meta.filter
                    && item.propagation_source == peer
            }) {
                if msg.meta.expires_at > item.notification.meta.expires_at {
                    item.notification = msg;
                }
            } else {
                if self.early_notifications.len() >= MAX_BUFFERED_NOTIFICATIONS {
                    let mut counts = HashMap::new();
                    for item in &self.early_notifications {
                        *counts.entry(item.propagation_source).or_insert(0usize) += 1;
                    }
                    let owner = crate::ingress_limits::eviction_owner(
                        peer,
                        counts.into_iter(),
                        MAX_BUFFERED_NOTIFICATIONS,
                    );
                    if owner == peer {
                        return;
                    }
                    if let Some(index) = self
                        .early_notifications
                        .iter()
                        .position(|item| item.propagation_source == owner)
                    {
                        self.early_notifications.remove(index);
                    }
                }
                self.early_notifications.push_back(DocumentIngress {
                    propagation_source: peer,
                    notification: msg,
                });
            }
            return;
        }
        if DocumentPublishingService::interest_in(&ids, &msg).is_none()
            || self.received.contains(&id)
        {
            return;
        }
        if let Some(fetching) = self.fetching.get_mut(&id) {
            fetching.add(peer, msg);
            return;
        }
        if self.received.len() >= MAX_RECEIVED_DOCUMENTS {
            self.bus.err(
                EType::DocumentPublishing,
                anyhow::anyhow!("received-document cache is full"),
            );
            return;
        }
        if !self.fetch_queue.push(id, peer, msg, Instant::now()) {
            debug!("Dropped a document notification because the fetch queue is full");
            return;
        }
        self.start_due_fetches(ctx);
    }
}

impl DocumentPublisher {
    /// Publish a fetched document that is bound to a matching notification.
    fn accept_document(
        &mut self,
        id: DocumentId,
        document: DocumentReceived,
        notification: DocumentPublishedNotification,
    ) {
        if self.closed_e3s.contains(&document.meta.e3_id) {
            return;
        }
        if let Err(error) =
            self.bus
                .publish_from_remote(document, notification.ts, None, EventSource::Net)
        {
            self.bus.err(EType::IO, error);
        } else {
            self.received.insert(id);
        }
    }

    /// Start waiting fetches whose retry time has passed, up to the concurrency limit.
    fn start_due_fetches(&mut self, ctx: &mut actix::Context<Self>) {
        let now = Instant::now();
        while self.fetching.len() < MAX_INFLIGHT_TRANSFERS {
            let mut in_flight = HashMap::new();
            for fetching in self.fetching.values() {
                *in_flight.entry(fetching.peer).or_insert(0) += 1;
            }
            let Some((id, waiting)) = self.fetch_queue.pop_due(now, &in_flight) else {
                break;
            };
            if self.closed_e3s.contains(&id.0) || self.received.contains(&id) {
                continue;
            }
            self.start_fetch(id, waiting, ctx);
        }
    }

    fn start_fetch(
        &mut self,
        id: DocumentId,
        waiting: WaitingFetch,
        ctx: &mut actix::Context<Self>,
    ) {
        let ids = self.service.interest_snapshot();
        let tx = self.tx.clone();
        let rx = self.rx.clone();
        let (abort, registration) = AbortHandle::new_pair();
        let notifications = waiting.notifications.clone();
        self.fetching.insert(id.clone(), waiting);
        self.fetch_aborts.insert(id.clone(), abort);
        ctx.spawn(
            Abortable::new(
                handle_document_published_notification(tx, rx, ids, notifications),
                registration,
            )
            .into_actor(self)
            .map(move |result, actor, ctx| {
                actor.fetch_aborts.remove(&id);
                let Some(mut waiting) = actor.fetching.remove(&id) else {
                    return;
                };
                let now = chrono::Utc::now();
                waiting
                    .notifications
                    .retain(|notification| notification.meta.expires_at > now);
                match result {
                    Ok(Ok(Some((document, notification)))) => {
                        actor.accept_document(id, document, notification);
                    }
                    Ok(Ok(None)) => {}
                    Ok(Err(error)) => {
                        let fetched = error
                            .downcast_ref::<DocumentMetadataMismatch>()
                            .map(|mismatch| mismatch.value().clone());
                        actor.bus.err(EType::IO, error);
                        match fetched {
                            // The document arrived, but its metadata matched none of these
                            // notifications. Check the notifications that arrived during the fetch
                            // against the same bytes, and do not fetch it again for them.
                            Some(value) => {
                                let ids = actor.service.interest_snapshot();
                                if let Ok(Some((document, notification))) =
                                    bind_to_candidate(&ids, waiting.notifications, value)
                                {
                                    actor.accept_document(id, document, notification);
                                } else {
                                    debug!(
                                        "Dropped a document whose metadata matched no notification"
                                    );
                                }
                            }
                            None => {
                                waiting.failures = waiting.failures.saturating_add(1);
                                if !actor.fetch_queue.retry(id, waiting, Instant::now()) {
                                    debug!(
                                        "Stopped fetching a document until it is announced again"
                                    );
                                }
                            }
                        }
                    }
                    Err(_) => return,
                }
                actor.start_due_fetches(ctx);
            }),
        );
    }
}
