// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use crate::{E3ContextSnapshot, EventBufferLimits};
use actix::{Message, Recipient};
use e3_data::InMemStore;
use e3_events::{DecryptionshareCreated, E3Requested, InterfoldEventData, Sequenced};
use e3_utils::utility_types::ArcBytes;

#[derive(Default)]
struct Recorder(Vec<(E3id, u64)>);

impl Actor for Recorder {
    type Context = Context<Self>;
}

impl Handler<InterfoldEvent> for Recorder {
    type Result = ();

    fn handle(&mut self, event: InterfoldEvent, _: &mut Self::Context) {
        self.0
            .push((event.get_e3_id().unwrap(), event.get_ctx().seq()));
    }
}

#[derive(Message)]
#[rtype(result = "Vec<u64>")]
struct Recorded(E3id);

impl Handler<Recorded> for Recorder {
    type Result = Vec<u64>;

    fn handle(&mut self, message: Recorded, _: &mut Self::Context) -> Self::Result {
        self.0
            .iter()
            .filter_map(|(id, seq)| (id == &message.0).then_some(*seq))
            .collect()
    }
}

struct LateRecipient {
    key: &'static str,
    recipient: Recipient<InterfoldEvent>,
}

#[async_trait]
impl E3Extension for LateRecipient {
    fn on_event(&self, context: &mut E3Context, event: &InterfoldEvent) {
        if matches!(event.get_data(), InterfoldEventData::TestEvent(data) if data.msg == "attach") {
            context.set_event_recipient(self.key, Some(self.recipient.clone()));
        }
    }

    async fn hydrate(&self, context: &mut E3Context, snapshot: &E3ContextSnapshot) -> Result<()> {
        if snapshot.contains(self.key) {
            context.set_event_recipient(self.key, Some(self.recipient.clone()));
        }
        Ok(())
    }
}

fn router_builder(store: &DataStore, recorders: &[Addr<Recorder>]) -> E3RouterBuilder {
    let mut builder = E3Router::builder(&super::test_bus(), store.clone());
    for (key, recorder) in [
        "plaintext",
        "threshold_keyshare",
        "publickey",
        "accusation_manager",
        "commitment_consistency_checker",
    ]
    .into_iter()
    .zip(recorders)
    {
        builder = builder.with_recipient(
            key,
            Box::new(LateRecipient {
                key,
                recipient: recorder.clone().recipient(),
            }),
        );
    }
    builder
}

fn router_params(store: &DataStore, recorders: &[Addr<Recorder>]) -> E3RouterParams {
    let builder = router_builder(store, recorders);
    E3RouterParams {
        extensions: builder.extensions.into(),
        bus: builder.bus,
        store: builder.store,
        replay_cursors: HashMap::new(),
        recovery_store: builder.recovery_store,
        recovered_selections: Vec::new(),
        teardown_grace: Duration::ZERO,
        complete_on_restart: HashSet::new(),
    }
}

fn admission(id: &E3id) -> InterfoldEvent {
    InterfoldEvent::<Sequenced>::test_event("admit")
        .data(E3Requested {
            e3_id: id.clone(),
            threshold_m: 9,
            threshold_n: 19,
            params_preset: e3_fhe_params::BfvPreset::SecureThreshold8192,
            ..Default::default()
        })
        .seq(1)
        .build()
}

fn share(id: &E3id, sequence: u64) -> InterfoldEvent {
    InterfoldEvent::<Sequenced>::test_event("share")
        .data(DecryptionshareCreated {
            e3_id: id.clone(),
            party_id: sequence,
            node: "member".into(),
            decryption_share: vec![ArcBytes::from_bytes(&[0; 512])],
            signed_decryption_proofs: Vec::new(),
        })
        .seq(sequence)
        .build()
}

fn attach(id: &E3id, sequence: u64) -> InterfoldEvent {
    InterfoldEvent::<Sequenced>::test_event("attach")
        .e3_id(id.clone())
        .seq(sequence)
        .build()
}

async fn route(router: &Addr<E3Router>, event: InterfoldEvent) {
    router
        .send(event)
        .timeout(Duration::from_secs(5))
        .await
        .expect("the router must keep accepting events");
}

#[derive(Message)]
#[rtype(result = "usize")]
struct ExpectedRecipients(E3id);

impl Handler<ExpectedRecipients> for E3Router {
    type Result = usize;

    fn handle(&mut self, message: ExpectedRecipients, _: &mut Self::Context) -> Self::Result {
        self.contexts[&message.0].recipients.len()
    }
}

fn charged_bytes(event: &InterfoldEvent) -> usize {
    bincode::serialize(event).unwrap().len() + std::mem::size_of::<InterfoldEvent>()
}

async fn check_deferred_limit(limit: &str) -> Result<()> {
    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    let recorders = [Recorder::default().start(), Recorder::default().start()];
    let mut router = E3Router::from_params(router_params(&store, &recorders));
    let a = E3id::new("31", 1);
    let b = E3id::new("32", 1);
    let history_bytes = charged_bytes(&admission(&a)) + 2 * charged_bytes(&share(&a, 2));
    let mut limits = EventBufferLimits::default();
    match limit {
        "per-E3 items" => limits.per_e3_items = 6,
        "per-E3 bytes" => limits.per_e3_bytes = 2 * history_bytes,
        "global items" => limits.global_items = 10,
        "global bytes" => {
            limits.global_bytes =
                2 * (history_bytes + charged_bytes(&admission(&b)) + charged_bytes(&share(&b, 2)));
        }
        _ => unreachable!(),
    }
    router.buffer = EventBuffer::with_limits(limits);
    let router = router.start();
    route(&router, admission(&a)).await;
    route(&router, share(&a, 2)).await;
    route(&router, share(&a, 3)).await;

    let (overflowed, healthy, next) = if limit.starts_with("global") {
        route(&router, admission(&b)).await;
        route(&router, share(&b, 2)).await;
        (&b, &a, 3)
    } else {
        (&a, &b, 4)
    };
    route(&router, share(overflowed, next)).await;
    route(
        &router,
        InterfoldEvent::<Sequenced>::test_event("waiting")
            .e3_id(overflowed.clone())
            .seq(next + 1)
            .build(),
    )
    .await;
    route(&router, attach(overflowed, next + 2)).await;
    // A failed deferred queue stays empty, but its recipient still gets live events.
    route(&router, share(overflowed, next + 3)).await;
    let mut delivered = Vec::new();
    for recorder in &recorders {
        delivered.push(recorder.send(Recorded(overflowed.clone())).await?);
    }
    delivered.sort_by_key(Vec::len);
    assert_eq!(delivered[0], [next + 2, next + 3], "{limit}");
    assert_eq!(delivered[1], (1..=next + 3).collect::<Vec<_>>(), "{limit}");

    if healthy == &b {
        route(&router, admission(healthy)).await;
        route(&router, share(healthy, 2)).await;
        route(&router, share(healthy, 3)).await;
    }
    route(&router, attach(healthy, 4)).await;
    for recorder in &recorders {
        assert_eq!(
            recorder.send(Recorded(healthy.clone())).await?,
            [1, 2, 3, 4],
            "{limit}"
        );
    }

    // Draining and terminal cleanup must return both reservations to the shared budget.
    for id in [E3id::new("33", 1), E3id::new("34", 1)] {
        route(&router, admission(&id)).await;
        route(&router, share(&id, 2)).await;
        route(&router, share(&id, 3)).await;
        if id == E3id::new("33", 1) {
            route(
                &router,
                InterfoldEvent::<Sequenced>::test_event("complete")
                    .data(E3RequestComplete { e3_id: id })
                    .seq(4)
                    .build(),
            )
            .await;
        } else {
            route(&router, attach(&id, 4)).await;
            for recorder in &recorders {
                assert_eq!(
                    recorder.send(Recorded(id.clone())).await?,
                    [1, 2, 3, 4],
                    "{limit}"
                );
            }
        }
    }
    Ok(())
}

// Exercise the documented count and byte allowances without generating proofs.
async fn check_largest_committee_capacity() -> Result<()> {
    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    let recorders: Vec<_> = (0..5).map(|_| Recorder::default().start()).collect();
    let router = E3Router::from_params(router_params(&store, &recorders)).start();
    let large = ArcBytes::from_bytes(&vec![0; 160 * 1024 * 1024]);
    let medium = ArcBytes::from_bytes(&vec![0; 16 * 1024 * 1024]);
    let ids: Vec<_> = (51..55).map(|id| E3id::new(id.to_string(), 1)).collect();
    for id in &ids {
        route(&router, admission(id)).await;
        for sequence in 2..=1_536 {
            let bytes = match sequence {
                2 => large.clone(),
                3..=24 => medium.clone(),
                _ => ArcBytes::default(),
            };
            route(
                &router,
                InterfoldEvent::<Sequenced>::test_event("early")
                    .data(DecryptionshareCreated {
                        e3_id: id.clone(),
                        party_id: 0,
                        node: "member".into(),
                        decryption_share: vec![bytes],
                        signed_decryption_proofs: Vec::new(),
                    })
                    .seq(sequence)
                    .build(),
            )
            .await;
        }
    }
    for id in ids {
        route(&router, attach(&id, 1_537)).await;
        for recorder in &recorders {
            assert_eq!(
                recorder.send(Recorded(id.clone())).await?,
                (1..=1_537).collect::<Vec<_>>()
            );
        }
    }
    Ok(())
}

#[actix::test]
async fn per_e3_item_limit_preserves_capacity_and_isolates_overflow() -> Result<()> {
    check_largest_committee_capacity().await?;
    check_deferred_limit("per-E3 items").await
}

#[actix::test]
async fn per_e3_byte_limit_isolates_deferred_overflow() -> Result<()> {
    check_deferred_limit("per-E3 bytes").await
}

#[actix::test]
async fn global_item_limit_isolates_deferred_overflow() -> Result<()> {
    check_deferred_limit("global items").await
}

#[actix::test]
async fn global_byte_limit_isolates_deferred_overflow() -> Result<()> {
    check_deferred_limit("global bytes").await
}

#[actix::test]
async fn restart_rebuilds_expectations_without_restoring_deferred_events() -> Result<()> {
    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    let recorder = Recorder::default().start();
    let recorders = [recorder.clone()];
    let mut router = E3Router::from_params(router_params(&store, &recorders));
    router.buffer = EventBuffer::with_limits(EventBufferLimits {
        per_e3_items: 2,
        ..EventBufferLimits::default()
    });
    let router = router.start();
    let pending = E3id::new("41", 1);
    let overflowed = E3id::new("42", 1);
    for id in [&pending, &overflowed] {
        route(&router, admission(id)).await;
        route(&router, share(id, 2)).await;
    }
    route(&router, share(&overflowed, 3)).await;
    drop(router);
    let recovered = router_builder(&store, &recorders).build().await?;
    for id in [&pending, &overflowed] {
        assert_eq!(recovered.send(ExpectedRecipients(id.clone())).await?, 1);
        route(&recovered, share(id, 4)).await;
        route(&recovered, attach(id, 5)).await;
        assert_eq!(recorder.send(Recorded(id.clone())).await?, [4, 5]);
    }
    Ok(())
}
