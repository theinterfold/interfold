// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use actix::{Actor, Handler, ResponseFuture};
use e3_ciphernode_builder::EventSystem;
use e3_events::{
    AggregateConfig, EventConstructorWithTimestamp, StoreEventRequested, StoreEventResponse,
    TestEvent, Unsequenced,
};

struct GapReader {
    inner: Recipient<EventStoreQueryBy<SeqAgg>>,
    missing_record: bool,
}

impl Actor for GapReader {
    type Context = actix::Context<Self>;
}

impl Handler<EventStoreQueryBy<SeqAgg>> for GapReader {
    type Result = ResponseFuture<()>;

    fn handle(&mut self, query: EventStoreQueryBy<SeqAgg>, _: &mut Self::Context) -> Self::Result {
        let inner = self.inner.clone();
        let missing_record = self.missing_record;
        Box::pin(async move {
            let mut cursors = query.query().clone();
            if missing_record {
                for cursor in cursors.values_mut() {
                    if *cursor == 2 {
                        *cursor = 3;
                    }
                }
            }
            let (recipient, response) = channel::oneshot::<EventStoreQueryResponse>();
            let forwarded = EventStoreQueryBy::<SeqAgg>::new(query.id(), cursors, recipient)
                .with_options(query.limit(), None, query.max_bytes());
            let page = query.limit() != Some(1);
            inner.send(forwarded).await.unwrap();
            let response = response.await.unwrap();
            let head = response.log_head();
            let events = response.into_events().map(|mut events| {
                if page {
                    events.retain(|event| event.seq() != 2);
                }
                events
            });
            let id = query.id();
            query
                .sender()
                .try_send(EventStoreQueryResponse::from_result(id, events).with_log_head(head))
                .unwrap();
        })
    }
}

#[actix::test]
async fn c0_recovery_rejects_non_quarantined_sequence_gaps() -> Result<()> {
    let aggregate = AggregateId::new(1);
    let e3_id = E3id::new("8", 1);
    let system = EventSystem::new()
        .with_fresh_bus()
        .with_aggregate_config(AggregateConfig::new(HashMap::from([(
            aggregate,
            Duration::ZERO,
        )])));
    for seq in 1..=3 {
        let event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
            TestEvent::new("record", seq)
                .with_e3_id(e3_id.clone())
                .into(),
            None,
            u128::from(seq),
            None,
            EventSource::Local,
        );
        let (recipient, response) = channel::oneshot::<StoreEventResponse>();
        system
            .eventstore_router()?
            .send(StoreEventRequested::new(event, recipient))
            .await?;
        response.await?;
    }

    // Neither a record omitted from a page nor a missing record is a quarantined entry.
    for missing_record in [false, true] {
        let reader = GapReader {
            inner: system.eventstore_reader()?.seq(),
            missing_record,
        }
        .start()
        .recipient();
        let error = recover_pending_verifications(
            &reader,
            &[aggregate],
            &HashSet::from([e3_id.clone()]),
            &HashMap::new(),
            &HashMap::new(),
        )
        .await
        .expect_err("C0 recovery must reject a non-quarantined sequence gap");
        assert!(error.to_string().contains("sequence gap"), "{error:#}");
    }
    Ok(())
}
