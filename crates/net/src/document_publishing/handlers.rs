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
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let tx = self.tx.clone();
        let (msg, ec) = msg.into_components();

        self.service
            .track_published_key(&msg.meta.e3_id, &msg.value);

        let rx = self.rx.clone();
        let bus = self.bus.clone();
        let topic = self.topic.clone();
        let addr = ctx.address();
        trap_fut(EType::IO, &bus.with_ec(&ec), async move {
            let notification = handle_publish_document_requested(tx, rx, msg, topic, bus).await?;
            // Hand the gossiped pointer back to the actor so a late peer can be re-told.
            addr.do_send(Announced(notification));
            Ok(())
        })
    }
}

/// A notification that has been gossiped once; kept so it can be re-announced.
#[derive(Message)]
#[rtype(result = "()")]
pub(super) struct Announced(pub DocumentPublishedNotification);

impl Handler<Announced> for DocumentPublisher {
    type Result = ();
    fn handle(&mut self, msg: Announced, _: &mut Self::Context) -> Self::Result {
        self.service.track_announced(msg.0);
    }
}

/// A peer joined the gossip topic. Re-announce every in-flight document pointer so a peer
/// that restarted or connected after the original broadcast can fetch the DHT record.
#[derive(Message)]
#[rtype(result = "()")]
pub(super) struct PeerSubscribed;

impl Handler<PeerSubscribed> for DocumentPublisher {
    type Result = ResponseFuture<()>;
    fn handle(&mut self, _: PeerSubscribed, _: &mut Self::Context) -> Self::Result {
        let notifications = self.service.announcements_to_repeat();
        if notifications.is_empty() {
            return Box::pin(async {});
        }
        info!(
            count = notifications.len(),
            "Peer subscribed; re-announcing in-flight document pointers"
        );
        let tx = self.tx.clone();
        let rx = self.rx.clone();
        let topic = self.topic.clone();
        let bus = self.bus.clone();
        let stamp_bus = bus.clone();
        trap_fut(EType::IO, &bus, async move {
            for notification in notifications {
                repeat_document_published_notification(
                    tx.clone(),
                    rx.clone(),
                    notification,
                    topic.clone(),
                    &stamp_bus,
                )
                .await?;
            }
            Ok(())
        })
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
