// SPDX-License-Identifier: LGPL-3.0-only
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::domain::EventTranslationService;
use crate::events::{NetCommand, NetEvent};
use crate::{NetworkAuthorizationState, ProtocolSigner};
use actix::prelude::*;
use e3_events::{
    prelude::*, BusHandle, CorrelationId, EType, EventContextAccessors, EventSource, EventType,
    InterfoldEvent, InterfoldEventData, Unsequenced,
};
use e3_utils::MAILBOX_LIMIT;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// NetEventTranslator Actor converts between EventBus events and Libp2p events forwarding them to a
/// Libp2pNetInterface for propagation over the p2p network. All translation/dedup decisions live
/// in [`EventTranslationService`].
pub struct NetEventTranslator {
    bus: BusHandle,
    tx: mpsc::Sender<NetCommand>,
    service: EventTranslationService,
    signer: ProtocolSigner,
    effects_enabled: bool,
}

impl Actor for NetEventTranslator {
    type Context = Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

/// Libp2pEvent is used to send data to the Libp2pNetInterface from the NetEventTranslator
#[derive(Message, Clone, Debug, PartialEq, Eq)]
#[rtype(result = "()")]
struct LibP2pEvent(InterfoldEvent<Unsequenced>);

impl NetEventTranslator {
    /// Create a new NetEventTranslator actor
    pub fn new(
        bus: &BusHandle,
        tx: &mpsc::Sender<NetCommand>,
        topic: &str,
        signer: ProtocolSigner,
        authorization: NetworkAuthorizationState,
    ) -> Self {
        Self {
            bus: bus.clone(),
            tx: tx.clone(),
            service: EventTranslationService::new(topic, authorization),
            signer,
            effects_enabled: true,
        }
    }

    pub fn setup(
        bus: &BusHandle,
        tx: &mpsc::Sender<NetCommand>,
        rx: &Arc<broadcast::Receiver<NetEvent>>,
        topic: &str,
        signer: ProtocolSigner,
        authorization: NetworkAuthorizationState,
    ) -> Addr<Self> {
        let mut rx = rx.resubscribe();
        let mut actor = NetEventTranslator::new(bus, tx, topic, signer, authorization);
        actor.effects_enabled = false;
        let addr = actor.start();

        // Listen on all events
        bus.subscribe(EventType::All, addr.clone().recipient());
        info!("NetEventTranslator is running");
        tokio::spawn({
            let addr = addr.clone();
            async move {
                while let Some(event) =
                    crate::event_subscription::recv_net_event(&mut rx, "NetEventTranslator").await
                {
                    if let NetEvent::AuthorizedGossip(event) = event {
                        if let Err(error) = addr.send(LibP2pEvent(*event)).await {
                            warn!(%error, "NetEventTranslator stopped; ending gossip ingress");
                            break;
                        }
                    }
                }
            }
        });

        addr
    }

    /// Function to determine which events are allowed to be automatically broadcast to the
    /// network. Kept here so the rule can be referenced via `NetEventTranslator` while the
    /// implementation lives in the pure service.
    pub fn is_forwardable_event(event: &InterfoldEvent) -> bool {
        EventTranslationService::is_forwardable_event(event)
    }
}

impl Handler<LibP2pEvent> for NetEventTranslator {
    type Result = AtomicResponse<Self, ()>;
    fn handle(&mut self, msg: LibP2pEvent, _: &mut Self::Context) -> Self::Result {
        let event = msg.0;
        if !EventTranslationService::is_forwardable_event(&event) {
            return AtomicResponse::new(Box::pin(actix::fut::ready(())));
        }
        let id = event.id();
        let (data, ec) = event.into_components();
        let bus = self.bus.clone();
        AtomicResponse::new(Box::pin(
            async move {
                bus.publish_from_remote_and_wait(data, ec.ts(), None, None, EventSource::Net)
                    .await
            }
            .into_actor(self)
            .map(move |result, actor, _| match result {
                Ok(()) => actor.service.mark_accepted(id),
                Err(error) => actor.bus.err(EType::Net, error),
            }),
        ))
    }
}

impl Handler<InterfoldEvent> for NetEventTranslator {
    type Result = AtomicResponse<Self, ()>;
    fn handle(&mut self, msg: InterfoldEvent, _: &mut Self::Context) -> Self::Result {
        self.service.observe(&msg);
        if matches!(msg.get_data(), InterfoldEventData::EffectsEnabled(_)) {
            self.effects_enabled = true;
        }
        if !self.effects_enabled {
            return AtomicResponse::new(Box::pin(actix::fut::ready(())));
        }
        let bus = self.bus.with_ec(msg.get_ctx());
        let prepared = match self.service.prepare_outbound(msg, &self.signer) {
            Ok(prepared) => prepared,
            Err(error) => {
                bus.err(EType::Net, error);
                return AtomicResponse::new(Box::pin(actix::fut::ready(())));
            }
        };
        let Some((id, data)) = prepared else {
            return AtomicResponse::new(Box::pin(actix::fut::ready(())));
        };

        let command = NetCommand::GossipPublish {
            topic: self.service.topic().to_owned(),
            data,
            correlation_id: CorrelationId::new(),
        };
        let tx = self.tx.clone();
        AtomicResponse::new(Box::pin(
            async move { tx.send(command).await }
                .into_actor(self)
                .map(move |result, actor, _| match result {
                    Ok(()) => actor.service.mark_accepted(id),
                    Err(error) => bus.err(
                        EType::Net,
                        anyhow::anyhow!(
                            "network command channel closed before gossip acceptance: {error}"
                        ),
                    ),
                }),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::local::PrivateKeySigner;
    use e3_ciphernode_builder::EventSystem;
    use e3_events::{
        Committee, E3id, EventConstructorWithTimestamp, EventSource, PlaintextAggregated,
        Unsequenced,
    };
    use e3_utils::ArcBytes;
    use libp2p::PeerId;
    use std::{collections::HashMap, time::Duration};

    fn forwardable_event() -> InterfoldEvent {
        let event: InterfoldEvent<Unsequenced> = InterfoldEvent::new_with_timestamp(
            PlaintextAggregated {
                e3_id: E3id::new("1", 1),
                decrypted_output: vec![ArcBytes::from_bytes(&[1, 2, 3])],
                decryption_aggregator_proofs: vec![],
            }
            .into(),
            None,
            42,
            None,
            EventSource::Local,
        );
        event.into_sequenced(1)
    }

    #[actix::test]
    async fn full_command_channel_applies_backpressure_without_losing_or_deduping() {
        let system = EventSystem::new().with_fresh_bus();
        let bus = system.handle().unwrap().enable("test");
        let (tx, mut rx) = mpsc::channel(1);
        tx.send(NetCommand::Shutdown).await.unwrap();
        let event = forwardable_event();
        let signer = PrivateKeySigner::random();
        let protocol_signer = ProtocolSigner::new(signer.clone(), PeerId::random());
        let authorization = NetworkAuthorizationState::new(
            HashMap::from([(
                event.get_e3_id().unwrap(),
                Committee::new(vec![signer.address().to_string()]),
            )]),
            HashMap::new(),
        );
        let addr =
            NetEventTranslator::new(&bus, &tx, "topic", protocol_signer, authorization).start();

        let pending = tokio::spawn({
            let addr = addr.clone();
            let event = event.clone();
            async move { addr.send(event).await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !pending.is_finished(),
            "full channel must backpressure the actor"
        );

        assert!(matches!(rx.recv().await, Some(NetCommand::Shutdown)));
        pending.await.unwrap().unwrap();
        assert!(matches!(
            rx.recv().await,
            Some(NetCommand::GossipPublish { .. })
        ));

        addr.send(event).await.unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(20), rx.recv())
            .await
            .is_err());
    }
}
