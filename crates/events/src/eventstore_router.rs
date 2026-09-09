// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
use crate::eventstore::EventStore;
use crate::{
    events::{EventStoreQueryResponse, FlushEventStores, StoreEventRequested},
    AggregateId, EventContextAccessors, EventLog, SequenceIndex,
};
use crate::{CorrelationId, Die, EventStoreQueryBy, InterfoldEvent, Seq, SeqAgg, Ts, TsAgg};
use actix::{
    Actor, ActorContext, ActorFutureExt, Addr, AsyncContext, Context, Handler, Recipient,
    ResponseFuture, WrapFuture,
};
use anyhow::{Context as _, Result};
use e3_utils::MAILBOX_LIMIT_LARGE;
use std::collections::HashMap;
use tracing::{debug, error, trace, warn};

/// QueryAggregator - handles a single query's lifecycle
struct QueryAggregator {
    parent_id: CorrelationId,
    sender: Recipient<EventStoreQueryResponse>,
    pending: HashMap<CorrelationId, AggregateId>,
    collected_events: Vec<InterfoldEvent>,
}

fn quarantine_misrouted_events(
    events: Vec<InterfoldEvent>,
    aggregate_id: AggregateId,
) -> (Vec<InterfoldEvent>, usize) {
    let before = events.len();
    let events: Vec<_> = events
        .into_iter()
        .filter(|event| event.aggregate_id() == aggregate_id)
        .collect();
    let quarantined = before.saturating_sub(events.len());
    (events, quarantined)
}

impl QueryAggregator {
    fn new(parent_id: CorrelationId, sender: Recipient<EventStoreQueryResponse>) -> Self {
        Self {
            parent_id,
            sender,
            pending: HashMap::new(),
            collected_events: Vec::new(),
        }
    }

    fn add_pending(&mut self, sub_query_id: CorrelationId, aggregate_id: AggregateId) {
        self.pending.insert(sub_query_id, aggregate_id);
    }

    #[allow(dead_code)]
    fn pending_aggregates(&self) -> Vec<&AggregateId> {
        self.pending.values().collect()
    }
}

impl Actor for QueryAggregator {
    type Context = Context<Self>;
}

impl Handler<EventStoreQueryResponse> for QueryAggregator {
    type Result = ();

    fn handle(&mut self, msg: EventStoreQueryResponse, ctx: &mut Self::Context) -> Self::Result {
        let sub_query_id = msg.id();

        if let Some(aggregate_id) = self.pending.remove(&sub_query_id) {
            debug!(
                "Received response for aggregate {:?}, {} pending",
                aggregate_id,
                self.pending.len()
            );
            let events = match msg.into_events() {
                Ok(events) => events,
                Err(error) => {
                    error!(
                        %error,
                        ?aggregate_id,
                        "Aggregate EventStore query failed; forwarding the failure"
                    );
                    self.sender.do_send(EventStoreQueryResponse::from_result(
                        self.parent_id,
                        Err(error),
                    ));
                    ctx.notify(Die);
                    return;
                }
            };
            let (events, quarantined) = quarantine_misrouted_events(events, aggregate_id);
            self.collected_events.extend(events);
            if quarantined > 0 {
                warn!(
                    %aggregate_id,
                    quarantined,
                    "Ignoring legacy events that were written to the wrong aggregate store"
                );
            }

            if self.pending.is_empty() {
                debug!("All aggregates fulfilled, sending response");
                let response = EventStoreQueryResponse::new(
                    self.parent_id,
                    std::mem::take(&mut self.collected_events),
                );
                self.sender.do_send(response);
                ctx.notify(Die)
            }
        } else {
            warn!("Received response for unknown sub-query: {}", sub_query_id);
        }
    }
}

impl Handler<Die> for QueryAggregator {
    type Result = ();

    fn handle(&mut self, _msg: Die, ctx: &mut Self::Context) -> Self::Result {
        ctx.stop()
    }
}

/// EventStoreRouter - routes events and spawns query aggregators to handle eventstore queries
pub struct EventStoreRouter<I: SequenceIndex, L: EventLog> {
    stores: HashMap<AggregateId, Addr<EventStore<I, L>>>,
}

impl<I: SequenceIndex, L: EventLog> EventStoreRouter<I, L> {
    pub fn new(stores: HashMap<usize, Addr<EventStore<I, L>>>) -> Self {
        debug!("Making eventstore router...");
        let stores = stores
            .into_iter()
            .map(|(index, addr)| (AggregateId::new(index), addr))
            .collect();
        Self { stores }
    }

    pub fn handle_store_event_requested(&mut self, msg: StoreEventRequested) {
        let aggregate_id = msg.event.aggregate_id();
        trace!(
            aggregate = %aggregate_id,
            event_type = ?msg.event.event_type_enum(),
            "Routing event to its aggregate store"
        );
        let store_addr = self.stores.get(&aggregate_id).unwrap_or_else(|| {
            panic!(
                "No EventStore is configured for aggregate {aggregate_id}; refusing to write it to another aggregate"
            )
        });
        let event = msg.event;
        let sender = msg.sender;
        store_addr.do_send(StoreEventRequested::new(event, sender));
    }

    pub fn handle_event_store_query_ts(
        &mut self,
        msg: EventStoreQueryBy<TsAgg>,
        ctx: &mut Context<Self>,
    ) -> Result<()> {
        debug!("Received request for timestamp query.");
        let parent_id = msg.id();
        let query = msg.query().clone();
        let limit = msg.limit();
        let filter = msg.filter().cloned();
        let sender = msg.sender();

        let missing: Vec<_> = query
            .keys()
            .filter(|aggregate_id| !self.stores.contains_key(aggregate_id))
            .copied()
            .collect();
        if !missing.is_empty() {
            let response = EventStoreQueryResponse::from_result(
                parent_id,
                Err(anyhow::anyhow!(
                    "No EventStore is configured for aggregates {missing:?}"
                )),
            );
            ctx.spawn(
                async move { sender.send(response).await }
                    .into_actor(self)
                    .map(|result, _, _| {
                        if let Err(error) = result {
                            error!(%error, "Failed to return the missing aggregate error");
                        }
                    }),
            );
            return Ok(());
        }

        let sub_queries: Vec<_> = query
            .into_iter()
            .filter_map(|(aggregate_id, ts)| {
                self.stores
                    .get(&aggregate_id)
                    .map(|store_addr| (aggregate_id, ts, CorrelationId::new(), store_addr.clone()))
            })
            .collect();

        if sub_queries.is_empty() {
            debug!("No valid stores to query, sending empty response immediately");
            let response = EventStoreQueryResponse::new(parent_id, Vec::new());
            sender.do_send(response);
            return Ok(());
        }

        let mut aggregator = QueryAggregator::new(parent_id, sender);
        for (aggregate_id, _, sub_query_id, _) in &sub_queries {
            aggregator.add_pending(*sub_query_id, *aggregate_id);
        }
        let aggregator_addr = aggregator.start();

        for (aggregate_id, ts, sub_query_id, store_addr) in sub_queries {
            let get_events_msg =
                EventStoreQueryBy::<Ts>::new(sub_query_id, ts, aggregator_addr.clone().recipient())
                    .with_options(limit, filter.clone());
            debug!("Sending query for aggregate {:?}", aggregate_id);
            store_addr.do_send(get_events_msg);
        }

        Ok(())
    }

    pub fn handle_event_store_query_seq(
        &mut self,
        msg: EventStoreQueryBy<SeqAgg>,
        ctx: &mut Context<Self>,
    ) -> Result<()> {
        debug!("Received request for sequence query.");
        let parent_id = msg.id();
        let query = msg.query().clone();
        let limit = msg.limit();
        let filter = msg.filter().cloned();
        let sender = msg.sender();

        let missing: Vec<_> = query
            .keys()
            .filter(|aggregate_id| !self.stores.contains_key(aggregate_id))
            .copied()
            .collect();
        if !missing.is_empty() {
            let response = EventStoreQueryResponse::from_result(
                parent_id,
                Err(anyhow::anyhow!(
                    "No EventStore is configured for aggregates {missing:?}"
                )),
            );
            ctx.spawn(
                async move { sender.send(response).await }
                    .into_actor(self)
                    .map(|result, _, _| {
                        if let Err(error) = result {
                            error!(%error, "Failed to return the missing aggregate error");
                        }
                    }),
            );
            return Ok(());
        }

        let sub_queries: Vec<_> = query
            .into_iter()
            .filter_map(|(aggregate_id, seq)| {
                self.stores
                    .get(&aggregate_id)
                    .map(|store_addr| (aggregate_id, seq, CorrelationId::new(), store_addr.clone()))
            })
            .collect();

        if sub_queries.is_empty() {
            debug!("No valid stores to query, sending empty response immediately");
            let response = EventStoreQueryResponse::new(parent_id, Vec::new());
            sender.do_send(response);
            return Ok(());
        }

        let mut aggregator = QueryAggregator::new(parent_id, sender);
        for (aggregate_id, _, sub_query_id, _) in &sub_queries {
            aggregator.add_pending(*sub_query_id, *aggregate_id);
        }
        let aggregator_addr = aggregator.start();

        for (aggregate_id, seq, sub_query_id, store_addr) in sub_queries {
            let get_events_msg = EventStoreQueryBy::<Seq>::new(
                sub_query_id,
                seq,
                aggregator_addr.clone().recipient(),
            )
            .with_options(limit, filter.clone());
            debug!("Sending query for aggregate {:?}", aggregate_id);
            store_addr.do_send(get_events_msg);
        }

        Ok(())
    }
}

impl<I: SequenceIndex, L: EventLog> Actor for EventStoreRouter<I, L> {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT_LARGE);
    }
}

impl<I: SequenceIndex, L: EventLog> Handler<StoreEventRequested> for EventStoreRouter<I, L> {
    type Result = ();

    fn handle(&mut self, msg: StoreEventRequested, _: &mut Self::Context) -> Self::Result {
        self.handle_store_event_requested(msg);
    }
}

impl<I: SequenceIndex, L: EventLog> Handler<FlushEventStores> for EventStoreRouter<I, L> {
    type Result = ResponseFuture<Result<()>>;

    fn handle(&mut self, _: FlushEventStores, _: &mut Self::Context) -> Self::Result {
        let stores: Vec<_> = self.stores.values().cloned().collect();
        Box::pin(async move {
            for store in stores {
                store
                    .send(FlushEventStores)
                    .await
                    .context("event store stopped before its shutdown flush")??;
            }
            Ok(())
        })
    }
}

impl<I: SequenceIndex, L: EventLog> Handler<EventStoreQueryBy<TsAgg>> for EventStoreRouter<I, L> {
    type Result = ();

    fn handle(&mut self, msg: EventStoreQueryBy<TsAgg>, ctx: &mut Self::Context) -> Self::Result {
        if let Err(e) = self.handle_event_store_query_ts(msg, ctx) {
            error!("Failed to route get events after request: {}", e);
        }
    }
}

impl<I: SequenceIndex, L: EventLog> Handler<EventStoreQueryBy<SeqAgg>> for EventStoreRouter<I, L> {
    type Result = ();

    fn handle(&mut self, msg: EventStoreQueryBy<SeqAgg>, ctx: &mut Self::Context) -> Self::Result {
        if let Err(e) = self.handle_event_store_query_seq(msg, ctx) {
            error!("Failed to route get events after request: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{E3id, EventConstructorWithTimestamp, EventSource, TestEvent, Unsequenced};

    fn event(chain_id: Option<u64>, sequence: u64) -> InterfoldEvent {
        let mut data = TestEvent::new("router", sequence);
        if let Some(chain_id) = chain_id {
            data = data.with_e3_id(E3id::new(sequence.to_string(), chain_id));
        }
        InterfoldEvent::<Unsequenced>::new_with_timestamp(
            data.into(),
            None,
            u128::from(sequence),
            None,
            EventSource::Local,
        )
        .into_sequenced(sequence)
    }

    #[test]
    fn legacy_events_in_the_wrong_store_are_quarantined() {
        let expected = event(Some(1), 1);
        let (events, quarantined) = quarantine_misrouted_events(
            vec![expected.clone(), event(Some(11_155_111), 2), event(None, 3)],
            AggregateId::new(1),
        );

        assert_eq!(events, vec![expected]);
        assert_eq!(quarantined, 2);
    }
}
