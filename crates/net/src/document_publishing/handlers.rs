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
        if !notification_is_well_formed(&msg) {
            debug!("Ignored a malformed document notification");
            return;
        }
        // An expired notification cannot lead to the document. This also drops the early
        // notifications that expired while the node waited for selection.
        if msg.meta.expires_at <= chrono::Utc::now() {
            return;
        }
        let id = (msg.meta.e3_id.clone(), msg.key.clone());
        if self.closed_e3s.contains(&msg.meta.e3_id) {
            return;
        }
        let ids = self.service.interest_snapshot();
        if !ids.contains_key(&msg.meta.e3_id) {
            // Keep one notification per document and party filter, with the latest expiry. Only
            // the filter decides whether a notification can match the payload, so a forged copy
            // that arrives first must not hide a correct one with another filter or outlive it.
            if let Some(item) = self.early_notifications.iter_mut().find(|item| {
                item.meta.e3_id == msg.meta.e3_id
                    && item.key == msg.key
                    && item.meta.filter == msg.meta.filter
            }) {
                if msg.meta.expires_at > item.meta.expires_at {
                    *item = msg;
                }
            } else {
                if self.early_notifications.len() == MAX_BUFFERED_NOTIFICATIONS {
                    self.early_notifications.pop_front();
                }
                self.early_notifications.push_back(msg);
            }
            return;
        }
        if DocumentPublishingService::interest_in(&ids, &msg).is_none()
            || self.received.contains(&id)
        {
            return;
        }
        if self.fetching.contains_key(&id) {
            add_candidate(self.late_notifications.entry(id).or_default(), msg);
            return;
        }
        if self.received.len() >= MAX_RECEIVED_DOCUMENTS {
            self.bus.err(
                EType::DocumentPublishing,
                anyhow::anyhow!("received-document cache is full"),
            );
            return;
        }
        if !self.fetch_queue.push(id, msg, Instant::now()) {
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
            let Some((id, waiting)) = self.fetch_queue.pop_due(now) else {
                break;
            };
            if self.closed_e3s.contains(&id.0) || self.received.contains(&id) {
                continue;
            }
            self.start_fetch(id, waiting.notifications, waiting.failures, ctx);
        }
    }

    fn start_fetch(
        &mut self,
        id: DocumentId,
        notifications: Vec<DocumentPublishedNotification>,
        failures: u32,
        ctx: &mut actix::Context<Self>,
    ) {
        let ids = self.service.interest_snapshot();
        let tx = self.tx.clone();
        let rx = self.rx.clone();
        let (abort, registration) = AbortHandle::new_pair();
        self.fetching.insert(id.clone(), failures);
        self.fetch_aborts.insert(id.clone(), abort);
        ctx.spawn(
            Abortable::new(
                handle_document_published_notification(tx, rx, ids, notifications.clone()),
                registration,
            )
            .into_actor(self)
            .map(move |result, actor, ctx| {
                actor.fetching.remove(&id);
                actor.fetch_aborts.remove(&id);
                let now = chrono::Utc::now();
                let late: Vec<_> = actor
                    .late_notifications
                    .remove(&id)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|notification| notification.meta.expires_at > now)
                    .collect();
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
                                    bind_to_candidate(&ids, late, value)
                                {
                                    actor.accept_document(id, document, notification);
                                } else {
                                    debug!(
                                        "Dropped a document whose metadata matched no notification"
                                    );
                                }
                            }
                            None => {
                                let mut candidates = notifications;
                                for notification in late {
                                    add_candidate(&mut candidates, notification);
                                }
                                candidates
                                    .retain(|notification| notification.meta.expires_at > now);
                                if !actor.fetch_queue.retry(
                                    id,
                                    candidates,
                                    failures + 1,
                                    Instant::now(),
                                ) {
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
