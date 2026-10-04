// SPDX-License-Identifier: LGPL-3.0-only
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::domain::EventTranslationService;
use crate::events::{
    call_and_await_response, GossipData, GossipPublishFailure, NetCommand, NetEvent,
};
use crate::net_interface_handle::NetEventSubscriber;
use crate::NetworkPolicy;
use actix::prelude::*;
use anyhow::Result;
use e3_events::{
    prelude::*, trap, BusHandle, CorrelationId, EType, EventContextAccessors, EventId, EventSource,
    EventType, InterfoldEvent,
};
use e3_utils::MAILBOX_LIMIT;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tracing::{info, warn};

/// NetEventTranslator Actor converts between EventBus events and Libp2p events forwarding them to a
/// Libp2pNetInterface for propagation over the p2p network. All translation/dedup decisions live
/// in [`EventTranslationService`].
pub struct NetEventTranslator {
    bus: BusHandle,
    tx: mpsc::Sender<NetCommand>,
    /// Registers each publication for its result, so broadcast lag cannot drop the result.
    events: NetEventSubscriber,
    service: EventTranslationService,
    pending: HashMap<CorrelationId, PendingPublish>,
}

const MAX_GOSSIP_PUBLISH_ATTEMPTS: u8 = 3;
const GOSSIP_RETRY_DELAY: Duration = Duration::from_secs(2);
const MAX_NO_PEER_PUBLISH_ATTEMPTS: u8 = 20;
const NO_PEER_RETRY_DELAY: Duration = Duration::from_secs(30);
const GOSSIP_PUBLISH_RESULT_TIMEOUT: Duration = Duration::from_secs(30);

struct PendingPublish {
    event_id: EventId,
    data: GossipData,
    attempt: u8,
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
struct LibP2pEvent(pub GossipData);

impl NetEventTranslator {
    /// Create a new NetEventTranslator actor
    pub fn new(
        bus: &BusHandle,
        tx: &mpsc::Sender<NetCommand>,
        events: &NetEventSubscriber,
        topic: &str,
        network: NetworkPolicy,
    ) -> Self {
        Self {
            bus: bus.clone(),
            tx: tx.clone(),
            events: events.clone(),
            service: EventTranslationService::with_network(topic, network),
            pending: HashMap::new(),
        }
    }

    pub fn setup(
        bus: &BusHandle,
        tx: &mpsc::Sender<NetCommand>,
        rx: &NetEventSubscriber,
        topic: &str,
        network: NetworkPolicy,
    ) -> Addr<Self> {
        let addr = NetEventTranslator::new(bus, tx, rx, topic, network).start();
        let mut rx = rx.subscribe();

        // Listen on all events
        bus.subscribe(EventType::All, addr.clone().recipient());
        info!("NetEventTranslator is running");
        tokio::spawn({
            let addr = addr.clone();
            async move {
                while let Some(event) =
                    crate::event_subscription::recv_net_event(&mut rx, "NetEventTranslator").await
                {
                    let NetEvent::GossipData(data @ GossipData::GossipBytes(_)) = event else {
                        continue;
                    };
                    if let Err(error) = addr.send(LibP2pEvent(data)).await {
                        warn!(%error, "NetEventTranslator stopped; ending gossip ingress");
                        break;
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

    fn handle_interfold_event(
        &mut self,
        msg: InterfoldEvent,
        ctx: &mut Context<Self>,
    ) -> Result<()> {
        self.service.record_stored_event(&msg, Instant::now());
        if let Some((event_id, data)) = self.service.prepare_outbound(msg)? {
            self.queue_publish(event_id, data, 1, ctx);
        }
        Ok(())
    }

    fn queue_publish(
        &mut self,
        event_id: EventId,
        data: GossipData,
        attempt: u8,
        ctx: &mut Context<Self>,
    ) {
        let correlation_id = CorrelationId::new();
        let command = if attempt == 1 {
            NetCommand::gossip_publish(
                self.service.topic().to_owned(),
                data.clone(),
                correlation_id,
            )
        } else {
            NetCommand::gossip_republish(
                self.service.topic().to_owned(),
                data.clone(),
                correlation_id,
            )
        };
        self.pending.insert(
            correlation_id,
            PendingPublish {
                event_id,
                data,
                attempt,
            },
        );
        let publish = call_and_await_response(
            self.tx.clone(),
            self.events.clone(),
            command,
            publish_result,
            GOSSIP_PUBLISH_RESULT_TIMEOUT,
        );
        ctx.spawn(
            publish
                .into_actor(self)
                .map(move |result, actor, ctx| match result {
                    Ok(Ok(())) => {
                        if let Some(pending) = actor.pending.remove(&correlation_id) {
                            actor.service.mark_published(pending.event_id);
                        }
                    }
                    Ok(Err(failure)) => actor.handle_publish_failed(correlation_id, failure, ctx),
                    Err(error) => {
                        actor.handle_publish_failed(correlation_id, wait_failure(&error), ctx)
                    }
                }),
        );
    }

    fn handle_publish_failed(
        &mut self,
        correlation_id: CorrelationId,
        failure: GossipPublishFailure,
        ctx: &mut Context<Self>,
    ) {
        let Some(pending) = self.pending.remove(&correlation_id) else {
            return;
        };
        let retry = retry_policy(&failure);
        if let Some((_, delay)) = retry.filter(|(max, _)| pending.attempt < *max) {
            warn!(
                attempt = pending.attempt,
                %failure,
                "Gossip publish failed; scheduling retry"
            );
            ctx.run_later(delay, move |actor, ctx| {
                actor.queue_publish(pending.event_id, pending.data, pending.attempt + 1, ctx);
            });
        } else {
            self.service.mark_failed(pending.event_id);
            if retry.is_some() {
                warn!(attempts = pending.attempt, %failure, "Gossip publish retries exhausted");
            } else {
                warn!(attempts = pending.attempt, %failure, "Gossip publish failed permanently");
            }
        }
    }

    fn handle_remote_event(&mut self, msg: LibP2pEvent) -> Result<()> {
        let event = self.service.prepare_inbound(msg.0)?;
        let (data, ec) = event.into_components();
        // The peer supplies the context ID; the event store derives the ID from the payload.
        let id = EventId::hash(&data);
        let now = Instant::now();
        if !self.service.admit_remote_event(&id, now) {
            return Ok(());
        }
        if let Err(error) = self
            .bus
            .publish_from_remote(data, ec.ts(), None, EventSource::Net)
        {
            self.service.reject_remote_event(&id);
            return Err(error);
        }
        Ok(())
    }
}

impl Handler<LibP2pEvent> for NetEventTranslator {
    type Result = ();
    fn handle(&mut self, msg: LibP2pEvent, _: &mut Self::Context) -> Self::Result {
        trap(EType::Net, &self.bus.clone(), || {
            self.handle_remote_event(msg)
        });
    }
}

/// Reads the network's result of a gossip publication.
fn publish_result(event: &NetEvent) -> Option<Result<Result<(), GossipPublishFailure>>> {
    match event {
        NetEvent::GossipPublished { .. } => Some(Ok(Ok(()))),
        NetEvent::GossipPublishError { error, .. } => Some(Ok(Err(error.as_ref().clone()))),
        _ => None,
    }
}

/// A closed command queue means that the network interface stopped, so a retry cannot succeed.
/// Other waits that end without a result, such as a timeout, can succeed on a retry.
fn wait_failure(error: &anyhow::Error) -> GossipPublishFailure {
    if error.is::<mpsc::error::SendError<NetCommand>>() {
        GossipPublishFailure::permanent(format!("network command queue closed: {error}"))
    } else {
        GossipPublishFailure::transient(format!("{error:#}"))
    }
}

fn retry_policy(failure: &GossipPublishFailure) -> Option<(u8, Duration)> {
    match failure {
        GossipPublishFailure::NoPeersSubscribed => {
            Some((MAX_NO_PEER_PUBLISH_ATTEMPTS, NO_PEER_RETRY_DELAY))
        }
        GossipPublishFailure::Transient(_) => {
            Some((MAX_GOSSIP_PUBLISH_ATTEMPTS, GOSSIP_RETRY_DELAY))
        }
        GossipPublishFailure::Permanent(_) => None,
    }
}

impl Handler<InterfoldEvent> for NetEventTranslator {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        trap(EType::Net, &self.bus.with_ec(msg.get_ctx()), || {
            self.handle_interfold_event(msg, ctx)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net_interface_handle::NetEventChannel;
    use e3_ciphernode_builder::EventSystem;
    use e3_events::{E3id, EventConstructorWithTimestamp, KeyshareCreated, Unsequenced};
    use e3_utils::ArcBytes;
    use libp2p::gossipsub::MessageId;

    fn local_forwardable_event() -> InterfoldEvent {
        let event: InterfoldEvent<Unsequenced> = InterfoldEvent::new_with_timestamp(
            KeyshareCreated {
                pubkey: ArcBytes::from_bytes(&[1, 2, 3]),
                e3_id: E3id::new("1", 1),
                node: "node-1".to_string(),
                party_id: 1,
                signed_pk_generation_proof: None,
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
    async fn churn_is_throttled_before_a_stored_event_can_return() -> Result<()> {
        use crate::seen_messages::{INGRESS_BURST, INGRESS_RATE};
        use e3_events::{AggregateConfig, AggregateId, EventBus, EventBusConfig, TakeEvents};
        let system = EventSystem::new()
            .with_event_bus(EventBus::new(EventBusConfig { deduplicate: false }).start())
            .with_aggregate_config(AggregateConfig::new(HashMap::from([(
                AggregateId::new(1),
                Duration::ZERO,
            )])));
        let bus = system.handle()?.enable("test");
        let history = bus.history();
        let (tx, _commands) = mpsc::channel(8);
        let events = NetEventChannel::new(8);
        let translator = NetEventTranslator::new(
            &bus,
            &tx,
            &NetEventSubscriber::from(&events),
            "topic",
            NetworkPolicy::local_unrestricted(),
        )
        .start();
        let gossip = |party_id| -> Result<GossipData> {
            Ok(GossipData::GossipBytes(
                bus.event_from(
                    KeyshareCreated {
                        e3_id: E3id::new("1", 1),
                        pubkey: ArcBytes::from_bytes(b"key"),
                        node: format!("node-{party_id}"),
                        party_id,
                        signed_pk_generation_proof: None,
                    },
                    None,
                )?
                .to_bytes()?,
            ))
        };
        let original = gossip(0)?;
        let start = Instant::now();
        const ANNOUNCEMENTS: u64 = 20_002;
        for index in 0..ANNOUNCEMENTS {
            translator.send(LibP2pEvent(gossip(index)?)).await?;
        }
        translator.send(LibP2pEvent(original)).await?;
        let limit =
            INGRESS_BURST + (start.elapsed().as_secs_f64() * INGRESS_RATE as f64).ceil() as u64;
        let sentinel = KeyshareCreated {
            party_id: u64::MAX,
            e3_id: E3id::new("1", 1),
            node: "sentinel".into(),
            pubkey: ArcBytes::from_bytes(b"key"),
            signed_pk_generation_proof: None,
        };
        bus.publish_without_context(sentinel)?;
        let (stored, originals) = tokio::time::timeout(Duration::from_secs(5), async {
            let (mut stored, mut originals) = (0, 0);
            loop {
                let batch = history.send(TakeEvents::<InterfoldEvent>::new(1)).await?;
                for event in batch.events {
                    if let e3_events::InterfoldEventData::KeyshareCreated(key) = event.get_data() {
                        if key.party_id == u64::MAX {
                            return anyhow::Ok((stored, originals));
                        }
                        stored += 1;
                        originals += u64::from(key.party_id == 0);
                    }
                }
            }
        })
        .await??;
        assert_eq!(originals, 1, "the first event must be stored only once");
        assert!(
            stored <= limit && stored < ANNOUNCEMENTS,
            "new events must be throttled before storage: {stored} > {limit}"
        );
        Ok(())
    }

    #[actix::test]
    async fn rejected_timestamp_does_not_mark_an_event_as_stored() -> Result<()> {
        use e3_events::{AggregateConfig, AggregateId, GetEvents};
        let system =
            EventSystem::new()
                .with_fresh_bus()
                .with_aggregate_config(AggregateConfig::new(HashMap::from([(
                    AggregateId::new(1),
                    Duration::ZERO,
                )])));
        let bus = system.handle()?.enable("test");
        let history = bus.history();
        let (tx, _commands) = mpsc::channel(8);
        let events = NetEventChannel::new(8);
        let mut translator = NetEventTranslator::new(
            &bus,
            &tx,
            &NetEventSubscriber::from(&events),
            "topic",
            NetworkPolicy::local_unrestricted(),
        );
        let data = local_forwardable_event().get_data().clone();
        let rejected: InterfoldEvent<Unsequenced> = InterfoldEvent::new_with_timestamp(
            data.clone(),
            None,
            u128::MAX,
            None,
            EventSource::Net,
        );
        assert!(translator
            .handle_remote_event(LibP2pEvent(GossipData::GossipBytes(rejected.to_bytes()?)))
            .is_err());
        let accepted = bus.event_from(data.clone(), None)?;
        translator
            .handle_remote_event(LibP2pEvent(GossipData::GossipBytes(accepted.to_bytes()?)))?;
        bus.flush_event_pipeline().await?;
        let stored = history.send(GetEvents::<InterfoldEvent>::new()).await?;
        assert_eq!(
            stored
                .iter()
                .filter(|event| event.get_data() == &data)
                .count(),
            1,
            "a rejected timestamp must not suppress a later valid delivery"
        );
        Ok(())
    }

    /// The network reports the result of a publication once, on a bounded broadcast channel. A
    /// burst of other events can replace it there before the translator reads the channel. The
    /// translator still gets the result, so it does not time out and publish the event again.
    #[actix::test]
    async fn publish_result_survives_a_lagging_event_channel() -> Result<()> {
        tokio::time::pause();
        let system = EventSystem::new().with_fresh_bus();
        let bus = system.handle()?.enable("test");
        let (command_tx, mut commands) = mpsc::channel(8);
        let events = NetEventChannel::new(1);
        let translator = NetEventTranslator::setup(
            &bus,
            &command_tx,
            &NetEventSubscriber::from(&events),
            "topic",
            NetworkPolicy::local_unrestricted(),
        );
        translator.send(local_forwardable_event()).await?;
        let Some(NetCommand::GossipPublish { correlation_id, .. }) = commands.recv().await else {
            anyhow::bail!("the translator did not publish the event");
        };

        // The second event replaces the result in the one-slot broadcast.
        let published = |correlation_id| NetEvent::GossipPublished {
            correlation_id,
            message_id: MessageId::new(b"message"),
        };
        events.send(published(correlation_id))?;
        events.send(published(CorrelationId::new()))?;

        let republished =
            tokio::time::timeout(GOSSIP_PUBLISH_RESULT_TIMEOUT * 3, commands.recv()).await;
        assert!(
            republished.is_err(),
            "the translator published a delivered event again: {republished:?}"
        );
        Ok(())
    }

    #[test]
    fn no_peer_failures_use_the_long_join_window() {
        assert_eq!(
            retry_policy(&GossipPublishFailure::NoPeersSubscribed),
            Some((MAX_NO_PEER_PUBLISH_ATTEMPTS, NO_PEER_RETRY_DELAY))
        );
    }

    #[test]
    fn permanent_publish_failures_are_not_retried() {
        assert_eq!(
            retry_policy(&GossipPublishFailure::permanent("invalid payload")),
            None
        );
    }
}
