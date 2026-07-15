// SPDX-License-Identifier: LGPL-3.0-only

//! Actix routing for document lifecycle and network notifications.

use super::*;

impl Actor for DocumentPublisher {
    type Context = actix::Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT)
    }
}

impl Handler<InterfoldEvent> for DocumentPublisher {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        let msg = match msg {
            InterfoldEventData::EffectRetry(retry) => retry.into_effect(),
            msg => msg,
        };
        match msg {
            InterfoldEventData::PublishDocumentRequested(data) => {
                ctx.notify(TypedEvent::new(data, ec))
            }
            InterfoldEventData::CiphernodeSelected(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::E3RequestComplete(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            _ => (),
        }
    }
}

impl Handler<TypedEvent<PublishDocumentRequested>> for DocumentPublisher {
    type Result = ResponseFuture<()>;
    fn handle(
        &mut self,
        msg: TypedEvent<PublishDocumentRequested>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let tx = self.tx.clone();
        let (msg, ec) = msg.into_components();

        self.service
            .track_published_key(&msg.meta.e3_id, &msg.value);

        let rx = self.rx.clone();
        let bus = self.bus.clone();
        let topic = self.topic.clone();
        trap_fut(
            EType::IO,
            &bus.with_ec(&ec),
            handle_publish_document_requested(tx, rx, msg, topic, bus),
        )
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
            self.handle_ciphernode_selected(msg)
        })
    }
}

impl Handler<TypedEvent<E3RequestComplete>> for DocumentPublisher {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<E3RequestComplete>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        trap(EType::DocumentPublishing, &self.bus.with_ec(&ec), || {
            self.handle_e3_request_complete(msg)
        })
    }
}

/// Receiving DocumentPublishedNotification from libp2p
impl Handler<DocumentPublishedNotification> for DocumentPublisher {
    type Result = ResponseFuture<()>;
    fn handle(
        &mut self,
        msg: DocumentPublishedNotification,
        _: &mut Self::Context,
    ) -> Self::Result {
        let ids = self.service.interest_snapshot();
        let bus = self.bus.clone();
        let tx = self.tx.clone();
        let rx = self.rx.clone();
        trap_fut(
            EType::IO,
            &bus,
            handle_document_published_notification(tx, rx, bus.clone(), ids, msg),
        )
    }
}
