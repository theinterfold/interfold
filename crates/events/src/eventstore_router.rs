// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
use crate::eventstore::EventStore;
use crate::{
    events::{EventStoreQueryResponse, StoreEventRequested},
    AggregateId, EventContextAccessors, EventLog, SequenceIndex,
};
use crate::{CorrelationId, Die, EventStoreQueryBy, InterfoldEvent, Seq, SeqAgg, Ts, TsAgg};
use actix::{Actor, ActorContext, Addr, AsyncContext, Context, Handler, Recipient};
use anyhow::Result;
use e3_utils::MAILBOX_LIMIT_LARGE;
use std::collections::HashMap;
use tracing::{debug, error, info, warn};

/// QueryAggregator - handles a single query's lifecycle
struct QueryAggregator {
    parent_id: CorrelationId,
    sender: Recipient<EventStoreQueryResponse>,
    pending: HashMap<CorrelationId, AggregateId>,
    collected_events: Vec<InterfoldEvent>,
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
            info!(
                "Received response for aggregate {:?}, {} pending",
                aggregate_id,
                self.pending.len()
            );
            self.collected_events.extend(msg.into_events());

            if self.pending.is_empty() {
                info!("All aggregates fulfilled, sending response");
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
        debug!("Handling store event requested....");
        let aggregate_id = msg.event.aggregate_id();
        let store_addr = self.stores.get(&aggregate_id).unwrap_or_else(|| {
            self.stores
                .get(&AggregateId::new(0))
                .expect("Default EventStore for AggregateId(0) not found")
        });
        let event = msg.event;
        let sender = msg.sender;
        store_addr.do_send(StoreEventRequested::new(event, sender));
    }

    pub fn handle_event_store_query_ts(
        &mut self,
        msg: EventStoreQueryBy<TsAgg>,
        _ctx: &mut Context<Self>,
    ) -> Result<()> {
        debug!("Received request for timestamp query.");
        let parent_id = msg.id();
        let query = msg.query().clone();
        let limit = msg.limit();
        let filter = msg.filter().cloned();
        let sender = msg.sender();

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
        _ctx: &mut Context<Self>,
    ) -> Result<()> {
        debug!("Received request for sequence query.");
        let parent_id = msg.id();
        let query = msg.query().clone();
        let limit = msg.limit();
        let filter = msg.filter().cloned();
        let sender = msg.sender();

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
