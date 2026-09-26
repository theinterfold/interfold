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
            InterfoldEventData::EffectsEnabled(_) => {
                self.effects_enabled = true;
                for id in self.publications.keys().cloned() {
                    ctx.notify(AnnounceDocument(id));
                }
            }
            InterfoldEventData::PublishDocumentRequested(data) => {
                ctx.notify(TypedEvent::new(data, ec))
            }
            InterfoldEventData::CiphernodeSelected(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::DocumentReceived(data) => {
                let id = (data.meta.e3_id, ContentHash::from_content(&data.value));
                if self.received.len() < MAX_RECEIVED_DOCUMENTS || self.received.contains(&id) {
                    self.received.insert(id);
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
                if let Err(error) = self.handle_canonical_dkg_end(&data.e3_id) {
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
        self.publications.insert(id.clone(), msg.into_inner());
        if self.effects_enabled {
            ctx.notify(AnnounceDocument(id));
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
        let Some(event) = self.publications.get(&id).cloned() else {
            return;
        };
        if event.meta.expires_at <= chrono::Utc::now() {
            self.remove_publication(&id);
            return;
        }
        if !self.effects_enabled || self.publishing.contains(&id) {
            return;
        }
        let replicate = self
            .schedules
            .entry(id.clone())
            .or_default()
            .needs_replication(Instant::now());
        if replicate && self.replicating.len() >= MAX_INFLIGHT_REPLICATIONS {
            ctx.notify_later(AnnounceDocument(id), REPLICATION_QUEUE_POLL);
            return;
        }
        self.publishing.insert(id.clone());
        if replicate {
            self.replicating.insert(id.clone());
        }
        let (abort, registration) = AbortHandle::new_pair();
        self.publish_aborts.insert(id.clone(), abort);
        let tx = self.tx.clone();
        let rx = self.rx.clone();
        let bus = self.bus.clone();
        let topic = self.topic.clone();
        let operation = async move {
            if replicate {
                if let Err(error) = replicate_document(tx.clone(), rx.clone(), &event).await {
                    return (false, Err(error));
                }
            }
            (
                replicate,
                announce_document(tx, rx, event, topic, bus).await,
            )
        };
        ctx.spawn(
            Abortable::new(operation, registration)
                .into_actor(self)
                .map(move |result, actor, ctx| {
                    actor.publishing.remove(&id);
                    actor.replicating.remove(&id);
                    actor.publish_aborts.remove(&id);
                    let Ok((replicated, outcome)) = result else {
                        return;
                    };
                    if actor
                        .publications
                        .get(&id)
                        .is_some_and(|event| event.meta.expires_at <= chrono::Utc::now())
                    {
                        actor.remove_publication(&id);
                        return;
                    }
                    let Some(schedule) = actor.schedules.get_mut(&id) else {
                        return;
                    };
                    if replicated {
                        schedule.record_replicated(Instant::now());
                    }
                    let delay = match outcome {
                        Ok(()) => schedule.record_announced(),
                        Err(error) => {
                            actor.bus.err(EType::IO, error);
                            schedule.record_failed()
                        }
                    };
                    if actor.publications.contains_key(&id) {
                        ctx.notify_later(AnnounceDocument(id), delay);
                    }
                }),
        );
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
        let id = (msg.meta.e3_id.clone(), msg.key.clone());
        if self.closed_e3s.contains(&msg.meta.e3_id) {
            return;
        }
        let ids = self.service.interest_snapshot();
        if !ids.contains_key(&msg.meta.e3_id) {
            if msg.meta.expires_at > chrono::Utc::now()
                && !self
                    .early_notifications
                    .iter()
                    .any(|item| item.meta.e3_id == msg.meta.e3_id && item.key == msg.key)
            {
                if self.early_notifications.len() == MAX_BUFFERED_NOTIFICATIONS {
                    self.early_notifications.pop_front();
                }
                self.early_notifications.push_back(msg);
            }
            return;
        }
        if DocumentPublishingService::interest_in(&ids, &msg).is_none()
            || self.received.contains(&id)
            || self.fetching.contains_key(&id)
        {
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
            self.start_fetch(id, waiting.notification, waiting.failures, ctx);
        }
    }

    fn start_fetch(
        &mut self,
        id: DocumentId,
        msg: DocumentPublishedNotification,
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
                handle_document_published_notification(tx, rx, ids, msg.clone()),
                registration,
            )
            .into_actor(self)
            .map(move |result, actor, ctx| {
                actor.fetching.remove(&id);
                actor.fetch_aborts.remove(&id);
                match result {
                    Ok(Ok(Some(document))) => {
                        if actor.closed_e3s.contains(&document.meta.e3_id) {
                            return;
                        }
                        if let Err(error) =
                            actor
                                .bus
                                .publish_from_remote(document, msg.ts, None, EventSource::Net)
                        {
                            actor.bus.err(EType::IO, error);
                        } else {
                            actor.received.insert(id);
                        }
                    }
                    Ok(Ok(None)) => {}
                    Ok(Err(error)) => {
                        let final_error = error.is::<DocumentMetadataMismatch>();
                        actor.bus.err(EType::IO, error);
                        if !final_error
                            && msg.meta.expires_at > chrono::Utc::now()
                            && !actor
                                .fetch_queue
                                .retry(id, msg, failures + 1, Instant::now())
                        {
                            debug!("Stopped retrying a document fetch until it is announced again");
                        }
                    }
                    Err(_) => return,
                }
                actor.start_due_fetches(ctx);
            }),
        );
    }
}
