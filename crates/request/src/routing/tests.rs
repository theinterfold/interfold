// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::{
    ContextRepositoryFactory, DkgFoldAttestationContextRepositoryFactory, E3ContextSnapshot,
    E3MetaExtension, DKG_FOLD_ATTESTATION_CONTEXT_KEY,
};
use actix::{Actor, Handler};
use async_trait::async_trait;
use e3_data::{InMemStore, RepositoriesFactory};
use e3_events::{
    hlc_factory::HlcFactory, BusHandle, CiphernodeSelected, DkgFoldAttestationContext,
    DkgFoldAttestationContextEstablished, E3Failed, E3Requested, E3Stage, EventBus, EventType,
    FailureReason, InterfoldEventData, RequestRouterCheckpoint, Sequencer, StoreEventRequested,
    StoreEventResponse, SyncEffect, Unsequenced, DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

struct StoreSink;

impl Actor for StoreSink {
    type Context = Context<Self>;
}

impl Handler<StoreEventRequested> for StoreSink {
    type Result = ();

    fn handle(&mut self, _: StoreEventRequested, _: &mut Self::Context) {}
}

/// A store that sequences events so published events actually reach bus subscribers.
struct SequencingStore {
    next_seq: u64,
}

impl Actor for SequencingStore {
    type Context = Context<Self>;
}

impl Handler<StoreEventRequested> for SequencingStore {
    type Result = ();

    fn handle(&mut self, msg: StoreEventRequested, _: &mut Self::Context) {
        let StoreEventRequested { event, sender } = msg;
        let seq = self.next_seq;
        self.next_seq += 1;
        sender.do_send(StoreEventResponse(event.into_sequenced(seq)));
    }
}

fn sequencing_bus() -> BusHandle {
    let event_bus = EventBus::<InterfoldEvent>::default().start();
    let store = SequencingStore { next_seq: 1 }.start();
    let sequencer = Sequencer::new(&event_bus, store.recipient()).start();
    BusHandle::new(event_bus, sequencer, HlcFactory::new()).enable("router-teardown-test")
}

struct RecoveryExtension {
    hydrations: Arc<AtomicUsize>,
}

#[async_trait]
impl E3Extension for RecoveryExtension {
    fn on_event(&self, _: &mut E3Context, _: &InterfoldEvent) {}

    async fn hydrate(&self, _: &mut E3Context, _: &E3ContextSnapshot) -> Result<()> {
        self.hydrations.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct SelectionRecoveryExtension {
    selections: Arc<AtomicUsize>,
}

#[async_trait]
impl E3Extension for SelectionRecoveryExtension {
    fn on_event(&self, _: &mut E3Context, event: &InterfoldEvent) {
        if matches!(event.get_data(), InterfoldEventData::CiphernodeSelected(_)) {
            self.selections.fetch_add(1, Ordering::SeqCst);
        }
    }

    async fn hydrate(&self, _: &mut E3Context, _: &E3ContextSnapshot) -> Result<()> {
        Ok(())
    }
}

fn test_bus() -> BusHandle {
    let event_bus = EventBus::<InterfoldEvent>::default().start();
    let store = StoreSink.start();
    let sequencer = Sequencer::new(&event_bus, store.recipient()).start();
    BusHandle::new(event_bus, sequencer, HlcFactory::new()).enable("router-recovery-test")
}

#[actix::test]
async fn mid_e3_context_and_completed_set_survive_hydration() -> Result<()> {
    let active = E3id::new("7", 31337);
    let complete = E3id::new("6", 31337);
    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    let repositories = store.repositories();
    let router_store = repositories.router();
    router_store
        .repositories()
        .context(&active)
        .write_sync(&E3ContextSnapshot {
            e3_id: active.clone(),
            recipients: vec!["threshold_keyshare".into()],
            dependencies: vec!["meta".into()],
        })
        .await?;

    let hydrations = Arc::new(AtomicUsize::new(0));
    let recovery_store = repositories.request_router_checkpoint();
    let params = E3RouterParams {
        extensions: Arc::new(vec![Box::new(RecoveryExtension {
            hydrations: hydrations.clone(),
        })]),
        bus: test_bus(),
        store: router_store,
        replay_cursors: HashMap::new(),
        recovery_store,
        recovered_selections: Vec::new(),
        teardown_deadlines: HashMap::new(),
        teardown_grace: SLASHABLE_FAILURE_TEARDOWN_GRACE,
    };
    let recovered = E3Router::from_snapshot(
        params,
        E3RouterSnapshot {
            contexts: vec![active.clone()],
            completed: HashSet::from([complete.clone()]),
        },
    )
    .await?;

    assert!(recovered.contexts.contains_key(&active));
    assert!(recovered.completed.contains(&complete));
    assert_eq!(hydrations.load(Ordering::SeqCst), 1);

    let roundtrip = recovered.snapshot()?;
    assert_eq!(roundtrip.contexts, vec![active]);
    assert_eq!(roundtrip.completed, HashSet::from([complete]));
    Ok(())
}

#[actix::test]
async fn hydration_fails_when_an_active_context_snapshot_is_missing() -> Result<()> {
    let missing = E3id::new("8", 31337);
    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    let repositories = store.repositories();
    let router_store = repositories.router();
    let recovery_store = repositories.request_router_checkpoint();
    let params = E3RouterParams {
        extensions: Arc::new(vec![E3MetaExtension::create()]),
        bus: test_bus(),
        store: router_store,
        replay_cursors: HashMap::new(),
        recovery_store,
        recovered_selections: Vec::new(),
        teardown_deadlines: HashMap::new(),
        teardown_grace: SLASHABLE_FAILURE_TEARDOWN_GRACE,
    };

    let error = match E3Router::from_snapshot(
        params,
        E3RouterSnapshot {
            contexts: vec![missing.clone()],
            completed: HashSet::new(),
        },
    )
    .await
    {
        std::result::Result::Ok(_) => panic!("missing active context must fail startup"),
        Err(error) => error,
    };

    assert!(error.to_string().contains(&format!("E3 {missing}")));
    Ok(())
}

#[actix::test]
async fn recovery_is_direct_and_uses_one_checkpoint() -> Result<()> {
    let recovered_e3 = E3id::new("9", 31337);
    let live_e3 = E3id::new("10", 31337);
    let aggregate_id = AggregateId::from_chain_id(Some(31337));
    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    let repositories = store.repositories();
    repositories
        .router()
        .repositories()
        .context(&recovered_e3)
        .write_sync(&E3ContextSnapshot {
            e3_id: recovered_e3.clone(),
            recipients: Vec::new(),
            dependencies: Vec::new(),
        })
        .await?;
    let recovery_store = repositories.request_router_checkpoint();
    recovery_store
        .write_sync(&RequestRouterCheckpoint {
            contexts: vec![recovered_e3.clone()],
            completed: HashSet::new(),
            replay_cursors: HashMap::from([(aggregate_id, 12)]),
            teardown_deadlines: HashMap::new(),
        })
        .await?;

    let selections = Arc::new(AtomicUsize::new(0));
    let router = E3RouterBuilder {
        bus: test_bus(),
        extensions: vec![Box::new(SelectionRecoveryExtension {
            selections: selections.clone(),
        })],
        recovered_selections: vec![CiphernodeSelected {
            e3_id: recovered_e3.clone(),
            ..Default::default()
        }],
        recovery_store: recovery_store.clone(),
        store: repositories.router(),
        teardown_grace: SLASHABLE_FAILURE_TEARDOWN_GRACE,
    }
    .build()
    .await?;

    assert_eq!(selections.load(Ordering::SeqCst), 0);
    router
        .send(
            InterfoldEvent::<Unsequenced>::test_event("sync-effect")
                .data(SyncEffect::new())
                .seq(13)
                .build(),
        )
        .await?;
    assert_eq!(selections.load(Ordering::SeqCst), 1);

    router
        .send(
            InterfoldEvent::<Unsequenced>::test_event("request")
                .data(E3Requested {
                    e3_id: live_e3.clone(),
                    ..Default::default()
                })
                .seq(14)
                .build(),
        )
        .await?;

    let checkpoint = recovery_store
        .read()
        .await?
        .expect("canonical checkpoint must exist");
    assert_eq!(checkpoint.replay_cursors.get(&aggregate_id), Some(&14));
    assert_eq!(
        checkpoint.contexts.into_iter().collect::<HashSet<_>>(),
        HashSet::from([recovered_e3, live_e3])
    );
    assert_eq!(selections.load(Ordering::SeqCst), 1);
    Ok(())
}

#[actix::test]
async fn slashable_failure_tears_the_context_down_after_the_grace_window() -> Result<()> {
    let e3_id = E3id::new("21", 31337);
    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    let repositories = store.repositories();
    let recovery_store = repositories.request_router_checkpoint();
    let bus = sequencing_bus();
    let completions = Arc::new(AtomicUsize::new(0));
    bus.subscribe(
        EventType::E3RequestComplete,
        CompletionCounter {
            completions: completions.clone(),
        }
        .start()
        .recipient(),
    );

    let router = E3RouterBuilder {
        bus: bus.clone(),
        extensions: vec![E3MetaExtension::create()],
        recovered_selections: Vec::new(),
        recovery_store: recovery_store.clone(),
        store: repositories.router(),
        teardown_grace: std::time::Duration::from_secs(1),
    }
    .build()
    .await?;

    router
        .send(
            InterfoldEvent::<Unsequenced>::test_event("request")
                .data(E3Requested {
                    e3_id: e3_id.clone(),
                    ..Default::default()
                })
                .seq(1)
                .build(),
        )
        .await?;
    router
        .send(
            InterfoldEvent::<Unsequenced>::test_event("failed")
                .data(E3Failed {
                    e3_id: e3_id.clone(),
                    failed_at_stage: E3Stage::CommitteeFinalized,
                    reason: FailureReason::DKGInvalidShares,
                })
                .seq(2)
                .build(),
        )
        .await?;

    // During the grace window the context is alive (the accusation manager needs it) and
    // the deadline is durable.
    let checkpoint = recovery_store.read().await?.expect("checkpoint");
    assert!(checkpoint.contexts.contains(&e3_id));
    assert!(checkpoint.teardown_deadlines.contains_key(&e3_id));
    assert_eq!(completions.load(Ordering::SeqCst), 0);

    actix::clock::sleep(std::time::Duration::from_millis(1500)).await;
    // Let the E3RequestComplete round-trip through the bus back into the router.
    router
        .send(
            InterfoldEvent::<Unsequenced>::test_event("sync-effect")
                .data(SyncEffect::new())
                .seq(3)
                .build(),
        )
        .await?;

    assert_eq!(completions.load(Ordering::SeqCst), 1);
    let checkpoint = recovery_store.read().await?.expect("checkpoint");
    assert!(
        !checkpoint.contexts.contains(&e3_id),
        "the failed E3's context must be torn down once the slashing window closes"
    );
    assert!(checkpoint.completed.contains(&e3_id));
    assert!(checkpoint.teardown_deadlines.is_empty());
    Ok(())
}

#[actix::test]
async fn a_persisted_teardown_deadline_is_rearmed_after_restart() -> Result<()> {
    let e3_id = E3id::new("22", 31337);
    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    let repositories = store.repositories();
    repositories
        .router()
        .repositories()
        .context(&e3_id)
        .write_sync(&E3ContextSnapshot {
            e3_id: e3_id.clone(),
            recipients: Vec::new(),
            dependencies: Vec::new(),
        })
        .await?;
    let recovery_store = repositories.request_router_checkpoint();
    // A deadline that already passed while the node was down.
    recovery_store
        .write_sync(&RequestRouterCheckpoint {
            contexts: vec![e3_id.clone()],
            completed: HashSet::new(),
            replay_cursors: HashMap::new(),
            teardown_deadlines: HashMap::from([(e3_id.clone(), 1)]),
        })
        .await?;

    let bus = sequencing_bus();
    let completions = Arc::new(AtomicUsize::new(0));
    bus.subscribe(
        EventType::E3RequestComplete,
        CompletionCounter {
            completions: completions.clone(),
        }
        .start()
        .recipient(),
    );
    let router = E3RouterBuilder {
        bus: bus.clone(),
        extensions: vec![E3MetaExtension::create()],
        recovered_selections: Vec::new(),
        recovery_store: recovery_store.clone(),
        store: repositories.router(),
        teardown_grace: SLASHABLE_FAILURE_TEARDOWN_GRACE,
    }
    .build()
    .await?;

    actix::clock::sleep(std::time::Duration::from_millis(200)).await;
    router
        .send(
            InterfoldEvent::<Unsequenced>::test_event("sync-effect")
                .data(SyncEffect::new())
                .seq(1)
                .build(),
        )
        .await?;

    assert_eq!(completions.load(Ordering::SeqCst), 1);
    let checkpoint = recovery_store.read().await?.expect("checkpoint");
    assert!(!checkpoint.contexts.contains(&e3_id));
    assert!(checkpoint.completed.contains(&e3_id));
    Ok(())
}

struct CompletionCounter {
    completions: Arc<AtomicUsize>,
}

impl Actor for CompletionCounter {
    type Context = Context<Self>;
}

impl Handler<InterfoldEvent> for CompletionCounter {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, _: &mut Self::Context) {
        if matches!(msg.get_data(), InterfoldEventData::E3RequestComplete(_)) {
            self.completions.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// `completed` is serialized into the checkpoint on every event; unbounded, its size grows
/// with the node's whole E3 history. The oldest ids must go first so late events for the
/// most recent completions are still rejected.
#[test]
fn completed_set_is_bounded_and_prunes_the_oldest_ids_first() {
    let mut completed: HashSet<E3id> = (0..(MAX_REMEMBERED_COMPLETIONS as u64 + 10))
        .map(|n| E3id::new(n.to_string(), 31337))
        .collect();
    prune_completed(&mut completed);
    assert_eq!(completed.len(), MAX_REMEMBERED_COMPLETIONS);
    for oldest in 0..10u64 {
        assert!(
            !completed.contains(&E3id::new(oldest.to_string(), 31337)),
            "E3 {oldest} is the oldest and must have been pruned"
        );
    }
    let newest = MAX_REMEMBERED_COMPLETIONS as u64 + 9;
    assert!(completed.contains(&E3id::new(newest.to_string(), 31337)));
    assert!(completed.contains(&E3id::new("10", 31337)));

    // Under the bound nothing is touched.
    let mut small: HashSet<E3id> = HashSet::from([E3id::new("1", 1), E3id::new("2", 1)]);
    prune_completed(&mut small);
    assert_eq!(small.len(), 2);
}

#[actix::test]
async fn request_time_attestation_contexts_survive_router_snapshots() -> Result<()> {
    let old_e3 = E3id::new("41", 1);
    let new_e3 = E3id::new("42", 1);
    let missing_context_e3 = E3id::new("40", 1);
    let old_context = DkgFoldAttestationContext {
        registry: "0x1111111111111111111111111111111111111111".parse()?,
        verifying_contract: "0x1212121212121212121212121212121212121212".parse()?,
    };
    let new_context = DkgFoldAttestationContext {
        registry: "0x2121212121212121212121212121212121212121".parse()?,
        verifying_contract: "0x2222222222222222222222222222222222222222".parse()?,
    };
    let repositories = DataStore::from_in_mem(&InMemStore::new(false).start()).repositories();
    let router_store = repositories.router();
    let context_repositories = router_store.repositories();

    for (e3_id, context) in [(old_e3.clone(), old_context), (new_e3.clone(), new_context)] {
        context_repositories
            .context(&e3_id)
            .repositories()
            .dkg_fold_attestation_context(&e3_id)
            .write_sync(&DkgFoldAttestationContextEstablished {
                schema_version: DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION,
                e3_id,
                context,
            })
            .await?;
    }
    context_repositories
        .context(&old_e3)
        .write_sync(&E3ContextSnapshot {
            e3_id: old_e3.clone(),
            recipients: Vec::new(),
            dependencies: vec!["dkg_fold_attestation_context".into()],
        })
        .await?;
    router_store
        .write_sync(&E3RouterSnapshot {
            contexts: vec![missing_context_e3.clone()],
            completed: HashSet::new(),
        })
        .await?;
    repositories
        .request_router_checkpoint()
        .write_sync(&RequestRouterCheckpoint {
            contexts: vec![old_e3.clone(), new_e3.clone()],
            completed: HashSet::new(),
            replay_cursors: HashMap::new(),
            teardown_deadlines: HashMap::new(),
        })
        .await?;

    let restored = load_dkg_fold_attestation_contexts(&repositories).await?;
    assert_eq!(restored.get(&old_e3), Some(&old_context));
    assert_eq!(restored.get(&new_e3), Some(&new_context));
    assert!(!restored.contains_key(&missing_context_e3));

    let extensions: Arc<Vec<Box<dyn E3Extension>>> = Arc::new(vec![E3MetaExtension::create()]);
    let recovery_store = repositories.request_router_checkpoint();
    let recovered = E3Router::from_snapshot(
        E3RouterParams {
            extensions,
            bus: test_bus(),
            store: router_store,
            replay_cursors: HashMap::new(),
            recovery_store,
            recovered_selections: Vec::new(),
            teardown_deadlines: HashMap::new(),
            teardown_grace: SLASHABLE_FAILURE_TEARDOWN_GRACE,
        },
        E3RouterSnapshot {
            contexts: vec![old_e3.clone()],
            completed: HashSet::new(),
        },
    )
    .await?;
    assert!(recovered.contexts.contains_key(&old_e3));
    assert_eq!(
        recovered
            .contexts
            .get(&old_e3)
            .and_then(|context| context.get_dependency(DKG_FOLD_ATTESTATION_CONTEXT_KEY)),
        Some(&old_context)
    );
    Ok(())
}
