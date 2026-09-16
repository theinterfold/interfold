// SPDX-License-Identifier: LGPL-3.0-only

//! Actix routing for document lifecycle and network notifications.

use super::*;
use futures::future::Abortable;

impl Actor for DocumentPublisher {
    type Context = actix::Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT)
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
    type Result = ResponseActFuture<Self, ()>;

    fn handle(
        &mut self,
        AnnounceDocument(id): AnnounceDocument,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let Some(event) = self.publications.get(&id).cloned() else {
            return Box::pin(async {}.into_actor(self));
        };
        if event.meta.expires_at <= chrono::Utc::now() {
            self.publications.remove(&id);
            self.publication_bytes = self.publication_bytes.saturating_sub(event.value.size());
            return Box::pin(async {}.into_actor(self));
        }
        if !self.effects_enabled || self.publishing.contains(&id) {
            return Box::pin(async {}.into_actor(self));
        }
        if self.publishing.len() >= MAX_INFLIGHT_TRANSFERS {
            ctx.notify_later(AnnounceDocument(id), RETRY_INTERVAL);
            return Box::pin(async {}.into_actor(self));
        }
        self.publishing.insert(id.clone());
        let (abort, registration) = AbortHandle::new_pair();
        self.publish_aborts.insert(id.clone(), abort);
        let tx = self.tx.clone();
        let rx = self.rx.clone();
        let bus = self.bus.clone();
        let topic = self.topic.clone();
        Box::pin(
            Abortable::new(
                handle_publish_document_requested(tx, rx, event, topic, bus),
                registration,
            )
            .into_actor(self)
            .map(move |result, actor, ctx| {
                actor.publishing.remove(&id);
                actor.publish_aborts.remove(&id);
                if actor
                    .publications
                    .get(&id)
                    .is_some_and(|event| event.meta.expires_at <= chrono::Utc::now())
                {
                    if let Some(event) = actor.publications.remove(&id) {
                        actor.publication_bytes =
                            actor.publication_bytes.saturating_sub(event.value.size());
                    }
                    return;
                }
                let delay = match result {
                    Ok(Ok(())) => ANNOUNCE_INTERVAL,
                    Ok(Err(error)) => {
                        actor.bus.err(EType::IO, error);
                        RETRY_INTERVAL
                    }
                    Err(_) => return,
                };
                if actor.publications.contains_key(&id) {
                    ctx.notify_later(AnnounceDocument(id), delay);
                }
            }),
        )
    }
}

/// Receiving DocumentPublishedNotification from libp2p
impl Handler<DocumentPublishedNotification> for DocumentPublisher {
    type Result = ResponseActFuture<Self, ()>;
    fn handle(
        &mut self,
        msg: DocumentPublishedNotification,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let id = (msg.meta.e3_id.clone(), msg.key.clone());
        if self.closed_e3s.contains(&msg.meta.e3_id) {
            return Box::pin(async {}.into_actor(self));
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
            return Box::pin(async {}.into_actor(self));
        }
        if DocumentPublishingService::interest_in(&ids, &msg).is_none()
            || self.received.contains(&id)
            || !self.fetching.insert(id.clone())
        {
            return Box::pin(async {}.into_actor(self));
        }
        if self.received.len() >= MAX_RECEIVED_DOCUMENTS {
            self.fetching.remove(&id);
            self.bus.err(
                EType::DocumentPublishing,
                anyhow::anyhow!("received-document cache is full"),
            );
            return Box::pin(async {}.into_actor(self));
        }
        if self.fetching.len() > MAX_INFLIGHT_TRANSFERS {
            self.fetching.remove(&id);
            ctx.notify_later(msg, RETRY_INTERVAL);
            return Box::pin(async {}.into_actor(self));
        }
        let tx = self.tx.clone();
        let rx = self.rx.clone();
        let (abort, registration) = AbortHandle::new_pair();
        self.fetch_aborts.insert(id.clone(), abort);
        Box::pin(
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
                        actor.bus.err(EType::IO, error);
                        if msg.meta.expires_at > chrono::Utc::now() {
                            ctx.notify_later(msg, RETRY_INTERVAL);
                        }
                    }
                    Err(_) => {}
                }
            }),
        )
    }
}
