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
use actix::Actor;
use async_trait::async_trait;
use e3_data::{InMemEventLog, InMemSequenceIndex, InMemStore, RepositoriesFactory};
use e3_events::{
    hlc_factory::HlcFactory, BusHandle, CiphernodeSelected, DkgFoldAttestationContext,
    DkgFoldAttestationContextEstablished, E3Failed, E3Requested, E3Stage, EffectsEnabled, EventBus,
    EventStore, FailureReason, InterfoldEventData, RequestRouterCheckpoint, Sequencer, SyncEffect,
    Unsequenced, DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

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
    let store = EventStore::new(InMemSequenceIndex::new(), InMemEventLog::new())
        .expect("in-memory EventStore")
        .start();
    let sequencer =
        Sequencer::new_with_flush(&event_bus, store.clone().recipient(), store.recipient()).start();
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
        teardown_grace: Duration::ZERO,
        complete_on_restart: HashSet::new(),
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
        teardown_grace: Duration::ZERO,
        complete_on_restart: HashSet::new(),
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
        teardown_grace: Duration::ZERO,
        complete_on_restart: HashSet::new(),
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
async fn failed_contexts_are_torn_down_after_the_grace() -> Result<()> {
    let (live, restored) = (E3id::new("21", 31337), E3id::new("22", 31337));
    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    let checkpoints = store.repositories().request_router_checkpoint();
    let bus = test_bus();
    let router = E3Router::builder(&bus, store)
        .with_teardown_grace(Duration::from_millis(300))
        .with_complete_on_restart(HashSet::from([restored.clone()]))
        .build()
        .await?;
    let request = |e3_id: &E3id| E3Requested {
        e3_id: e3_id.clone(),
        ..Default::default()
    };
    let failed = E3Failed {
        e3_id: live.clone(),
        failed_at_stage: E3Stage::CommitteeFinalized,
        reason: FailureReason::DKGInvalidShares,
    };
    let events: [InterfoldEventData; 4] = [
        request(&live).into(),
        request(&restored).into(),
        failed.into(),
        EffectsEnabled::new().into(),
    ];
    for (seq, data) in (1u64..).zip(events) {
        let event = InterfoldEvent::<Unsequenced>::test_event("event")
            .data(data)
            .seq(seq);
        router.send(event.build()).await?;
    }
    // A slashable failure keeps its context for the grace.
    assert!(checkpoints
        .read()
        .await?
        .expect("checkpoint")
        .contexts
        .contains(&live));

    actix::clock::sleep(Duration::from_millis(600)).await;
    bus.flush_event_pipeline().await?;
    let checkpoint = checkpoints.read().await?.expect("checkpoint");
    assert!(checkpoint.contexts.is_empty());
    assert!(checkpoint.completed.contains(&live) && checkpoint.completed.contains(&restored));
    Ok(())
}

/// Records which E3 contexts received `EffectsEnabled`.
struct EffectsProbe {
    e3_id: E3id,
    enabled: Arc<std::sync::Mutex<Vec<E3id>>>,
}

impl Actor for EffectsProbe {
    type Context = actix::Context<Self>;
}

impl Handler<InterfoldEvent> for EffectsProbe {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, _: &mut Self::Context) {
        if matches!(msg.get_data(), InterfoldEventData::EffectsEnabled(_)) {
            self.enabled.lock().unwrap().push(self.e3_id.clone());
        }
    }
}

struct EffectsProbeExtension {
    enabled: Arc<std::sync::Mutex<Vec<E3id>>>,
}

#[async_trait]
impl E3Extension for EffectsProbeExtension {
    fn on_event(&self, ctx: &mut E3Context, event: &InterfoldEvent) {
        if let InterfoldEventData::E3Requested(data) = event.get_data() {
            let probe = EffectsProbe {
                e3_id: data.e3_id.clone(),
                enabled: self.enabled.clone(),
            };
            ctx.set_event_recipient("effects_probe", Some(probe.start().recipient()));
        }
    }

    async fn hydrate(&self, _: &mut E3Context, _: &E3ContextSnapshot) -> Result<()> {
        Ok(())
    }
}

#[actix::test]
async fn finished_contexts_complete_without_resuming_work() -> Result<()> {
    let (active, finished) = (E3id::new("23", 31337), E3id::new("24", 31337));
    let enabled = Arc::new(std::sync::Mutex::new(Vec::new()));
    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    let checkpoints = store.repositories().request_router_checkpoint();
    let bus = test_bus();
    let router = E3Router::builder(&bus, store)
        .with(Box::new(EffectsProbeExtension {
            enabled: enabled.clone(),
        }))
        .with_complete_on_restart(HashSet::from([finished.clone()]))
        .build()
        .await?;
    let events: [InterfoldEventData; 3] = [
        E3Requested {
            e3_id: active.clone(),
            ..Default::default()
        }
        .into(),
        E3Requested {
            e3_id: finished.clone(),
            ..Default::default()
        }
        .into(),
        EffectsEnabled::new().into(),
    ];
    for (seq, data) in (1u64..).zip(events) {
        let event = InterfoldEvent::<Unsequenced>::test_event("event")
            .data(data)
            .seq(seq);
        router.send(event.build()).await?;
    }
    bus.flush_event_pipeline().await?;
    actix::clock::sleep(Duration::from_millis(100)).await;

    assert_eq!(*enabled.lock().unwrap(), vec![active.clone()]);
    let checkpoint = checkpoints.read().await?.expect("checkpoint");
    assert_eq!(checkpoint.contexts, vec![active]);
    assert!(checkpoint.completed.contains(&finished));
    Ok(())
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
            teardown_grace: Duration::ZERO,
            complete_on_restart: HashSet::new(),
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

#[path = "buffer_tests.rs"]
mod buffer_tests;
