// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sortition and ciphernode selection, restored from their snapshots.

use super::restart::terminal_e3s;
use crate::recovery::reconcile_committee_snapshots;
use actix::Addr;
use anyhow::Result;
use e3_events::BusHandle;
use e3_request::E3LifecycleRepositoryFactory;
use e3_sortition::CommitteeFinalizerRepositoryFactory;
use e3_sortition::{
    AggregatorFailoverRepositoryFactory, CiphernodeSelector, CiphernodeSelectorFactory,
    CiphernodeSelectorState, FinalizedCommitteesRepositoryFactory, GetCiphernodeSelectorState,
    NodeStateRepositoryFactory, Sortition, SortitionAttachParams, SortitionBackend,
    SortitionRecoveryRepositoryFactory, SortitionRepositoryFactory,
};

/// Reconcile the selector and finalized-committee snapshots, then attach the ciphernode selector
/// and score sortition.
pub(super) async fn setup_sortition(
    bus: &BusHandle,
    repositories: &e3_data::Repositories,
    addr: &str,
) -> Result<(Addr<Sortition>, CiphernodeSelectorState)> {
    let lifecycle = repositories
        .e3_lifecycle()
        .read()
        .await?
        .unwrap_or_default();
    let selector_store = repositories.ciphernode_selector();
    let mut selector_snapshot = selector_store.read().await?.unwrap_or_default();
    let committees_repo = repositories.finalized_committees();
    let mut committees = committees_repo.read().await?.unwrap_or_default();
    let (selector_changed, committees_changed) =
        reconcile_committee_snapshots(&mut selector_snapshot, &mut committees, &lifecycle)?;
    let finished_e3s = terminal_e3s(&lifecycle);
    if selector_changed {
        selector_store.write_sync(&selector_snapshot).await?;
    }
    if committees_changed {
        committees_repo.write_sync(&committees).await?;
    }
    let ciphernode_selector = CiphernodeSelector::attach(
        bus,
        selector_store,
        repositories.aggregator_failover(),
        lifecycle,
        addr,
    )
    .await?;
    let selector_state = ciphernode_selector
        .send(GetCiphernodeSelectorState)
        .await??;
    let sortition = Sortition::attach(SortitionAttachParams {
        bus,
        backends_store: repositories.sortition(),
        node_state_store: repositories.node_state(),
        bond_owners_store: repositories.sortition_bond_owners(),
        admission_store: repositories.sortition_admission(),
        recovery_store: repositories.sortition_recovery(),
        committees_store: committees_repo,
        default_backend: SortitionBackend::score(),
        ciphernode_selector,
        address: addr,
        submitted_e3s: repositories
            .committee_finalizer_recovery()
            .read()
            .await?
            .unwrap_or_default()
            .tickets
            .into_iter()
            .filter_map(|(e3_id, ticket)| ticket.node.eq_ignore_ascii_case(addr).then_some(e3_id))
            .collect(),
        finished_e3s,
    })
    .await?;
    Ok((sortition, selector_state))
}

#[cfg(test)]
mod tests {
    use super::setup_sortition;
    use alloy::primitives::Address;
    use e3_events::{E3Stage, E3id, Seed};
    use std::collections::HashMap;
    use std::time::Duration;

    #[actix::test]
    async fn startup_keeps_existing_ticket_intents_without_reranking() -> anyhow::Result<()> {
        use e3_events::{
            E3Requested, EffectsEnabled, EventConstructorWithTimestamp, EventSource, GetEvents,
            InterfoldEvent, TicketGenerated, TicketId, TypedEvent, Unsequenced,
        };
        use e3_sortition::{CommitteeFinalizerRecoveryState, CommitteeFinalizerRepositoryFactory};
        use e3_sortition::{SortitionRecoveryRepositoryFactory, SortitionRecoveryState};

        let system = e3_event_system::EventSystem::new().with_fresh_bus();
        let bus = system.handle()?.enable("sortition-upgrade");
        let errors = bus.errors();
        let repos = e3_data::Repositories::from(system.store()?);
        let local = Address::from([0xab; 20]).to_string();
        let e3_id = E3id::new("7", 1);
        let event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
            E3Requested {
                e3_id: e3_id.clone(),
                ..Default::default()
            }
            .into(),
            None,
            1u128,
            None,
            EventSource::Local,
        )
        .into_sequenced(1);
        let ticket = TicketGenerated {
            e3_id: e3_id.clone(),
            ticket_id: TicketId::Score(9),
            node: local.to_lowercase(),
            party_index: Some(27),
        };
        repos
            .committee_finalizer_recovery()
            .write_sync(&CommitteeFinalizerRecoveryState {
                tickets: HashMap::from([(e3_id.clone(), ticket.clone())]),
                ..Default::default()
            })
            .await?;
        repos
            .sortition_recovery()
            .write_sync(&SortitionRecoveryState {
                seeds: HashMap::from([(e3_id.clone(), Seed([1; 32]))]),
                pending_requests: HashMap::from([(
                    e3_id.clone(),
                    TypedEvent::new(
                        E3Requested {
                            e3_id: e3_id.clone(),
                            ..Default::default()
                        },
                        event.get_ctx().clone(),
                    ),
                )]),
                ..Default::default()
            })
            .await?;
        let (sortition, _) = setup_sortition(&bus, &repos, &local).await?;
        sortition.send(EffectsEnabled::new()).await?;
        bus.flush_event_pipeline().await?;
        // Without the recovered intent, sortition would try to rank this request and fail
        // because this fixture deliberately has no ranking snapshot.
        assert!(errors.send(GetEvents::new()).await?.is_empty());
        let recovered = repos.committee_finalizer_recovery().read().await?.unwrap();
        assert_eq!(recovered.tickets[&e3_id], ticket);
        Ok(())
    }

    #[actix::test]
    async fn non_aggregator_restart_keeps_ticket_before_or_after_snapshot() -> anyhow::Result<()> {
        use e3_events::{
            AggregateConfig, AggregateId, E3Requested, EffectsEnabled,
            EventConstructorWithTimestamp, EventPublisher, EventSource, GetEvents, InterfoldEvent,
            TicketGenerated, TicketId, TypedEvent, Unsequenced,
        };
        use e3_request::E3LifecycleRepositoryFactory;
        use e3_sortition::{CommitteeFinalizerRecoveryState, CommitteeFinalizerRepositoryFactory};
        use e3_sortition::{SortitionRecoveryRepositoryFactory, SortitionRecoveryState};
        use e3_sync::SyncRepositoryFactory;

        for before_snapshot in [true, false] {
            let aggregate = AggregateId::from_chain_id(Some(1));
            let system = e3_event_system::EventSystem::new()
                .with_fresh_bus()
                .with_aggregate_config(AggregateConfig::new(HashMap::from([(
                    aggregate,
                    Duration::ZERO,
                )])));
            let bus = system.handle()?.enable("non-aggregator-ticket-restart");
            let errors = bus.errors();
            let repos = e3_data::Repositories::from(system.store()?);
            let local = Address::from([0xab; 20]).to_string();
            let e3_id = E3id::new("7", 1);
            let request = E3Requested {
                e3_id: e3_id.clone(),
                ..Default::default()
            };
            let context = InterfoldEvent::<Unsequenced>::new_with_timestamp(
                request.clone().into(),
                None,
                1,
                None,
                EventSource::Local,
            )
            .into_sequenced(1)
            .get_ctx()
            .clone();
            repos
                .sortition_recovery()
                .write_sync(&SortitionRecoveryState {
                    seeds: HashMap::from([(e3_id.clone(), Seed([1; 32]))]),
                    pending_requests: HashMap::from([(
                        e3_id.clone(),
                        TypedEvent::new(request, context),
                    )]),
                    ..Default::default()
                })
                .await?;
            repos
                .e3_lifecycle()
                .write_sync(&HashMap::from([(e3_id.clone(), E3Stage::Requested)]))
                .await?;
            // This repository exists after an earlier boot, but no finalizer actor populated it.
            repos
                .committee_finalizer_recovery()
                .write_sync(&CommitteeFinalizerRecoveryState::default())
                .await?;
            let ticket = TicketGenerated {
                e3_id: e3_id.clone(),
                ticket_id: TicketId::Score(9),
                node: local.to_lowercase(),
                party_index: Some(27),
            };
            bus.publish_without_context(ticket.clone())?;
            bus.flush_event_pipeline().await?;
            repos
                .aggregate_seq(aggregate)
                .write_sync(&u64::from(before_snapshot))
                .await?;
            crate::recovery::backfill_restart_state(
                &repos,
                &system.eventstore_reader()?.seq(),
                &[1],
                false,
            )
            .await?;
            let (sortition, _) = setup_sortition(&bus, &repos, &local).await?;
            if !before_snapshot {
                // Startup replays the log suffix before it enables effects.
                sortition
                    .send(
                        InterfoldEvent::<Unsequenced>::new_with_timestamp(
                            ticket.clone().into(),
                            None,
                            2,
                            None,
                            EventSource::Local,
                        )
                        .into_sequenced(1),
                    )
                    .await?;
            }
            sortition.send(EffectsEnabled::new()).await?;
            bus.flush_event_pipeline().await?;
            assert!(
                errors.send(GetEvents::new()).await?.is_empty(),
                "before_snapshot={before_snapshot}"
            );
            if before_snapshot {
                assert_eq!(
                    repos
                        .committee_finalizer_recovery()
                        .read()
                        .await?
                        .unwrap()
                        .tickets[&e3_id],
                    ticket
                );
            }
        }
        Ok(())
    }

    #[actix::test]
    async fn legacy_admission_logs_recover_before_and_after_snapshot() -> anyhow::Result<()> {
        use alloy::{
            primitives::{keccak256, B256, U256},
            sol_types::SolValue,
        };
        use e3_events::{
            AggregateConfig, AggregateId, EventBusFanout, EventConstructorWithTimestamp,
            EventSource, EvmLogObserved, FlushPendingSnapshots, GetEvents, InterfoldEvent,
            Unsequenced,
        };
        use e3_sortition::{
            AdmissionState, NodeState, NodeStateStore, SortitionRecoveryRepositoryFactory,
        };
        use e3_sync::SyncRepositoryFactory;

        for before_snapshot in [true, false] {
            let aggregate = AggregateId::from_chain_id(Some(1));
            let system = e3_event_system::EventSystem::new()
                .with_fresh_bus()
                .with_aggregate_config(AggregateConfig::new(HashMap::from([
                    (aggregate, Duration::ZERO),
                    (AggregateId::from_chain_id(None), Duration::ZERO),
                ])));
            let bus = system.handle()?.enable("legacy-admission-restart");
            let errors = bus.errors();
            let repos = e3_data::Repositories::from(system.store()?);
            let operator = Address::repeat_byte(1);
            let raw = |topics: Vec<B256>, data: Vec<u8>| EvmLogObserved {
                contract: "BondingRegistry".into(),
                chain_id: 1,
                e3_id: None,
                event_name: "UnknownEvmLog".into(),
                signature: None,
                known: false,
                topics: topics.into_iter().map(|topic| topic.to_string()).collect(),
                data: e3_utils::ArcBytes::from_bytes(&data),
            };
            let started = |timepoint| {
                raw(
                    vec![
                        keccak256("AdmissionStarted(address,uint48)"),
                        operator.into_word(),
                    ],
                    U256::from(timepoint).abi_encode(),
                )
            };
            let policy = raw(
                vec![keccak256(
                    "AdmissionPolicyUpdated(uint48,(bool,bool,uint48,uint48,bool,uint48))",
                )],
                (
                    U256::from(20),
                    (true, false, U256::from(100), U256::ZERO, false, U256::ZERO),
                )
                    .abi_encode(),
            );
            let mut events = Vec::new();
            for (index, (log, source)) in [
                (started(10u64), EventSource::Evm),
                (policy, EventSource::Evm),
                (started(200u64), EventSource::Local),
            ]
            .into_iter()
            .enumerate()
            {
                let event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
                    log.into(),
                    None,
                    (index + 1) as u128,
                    Some(1),
                    source,
                );
                if before_snapshot {
                    bus.naked_dispatch_async(event.clone()).await?;
                }
                events.push(event.into_sequenced(index as u64 + 1));
            }
            bus.flush_event_pipeline().await?;
            repos
                .aggregate_seq(aggregate)
                .write_sync(&if before_snapshot { 3 } else { 0 })
                .await?;

            // The old decoder could persist an empty chain projection. Keep its bytes intact.
            let legacy_store =
                e3_data::Repository::new(repos.store.scope("//sortition/admission/v1"));
            let mut legacy = AdmissionState {
                schema_version: 1,
                ..Default::default()
            };
            legacy.chains.entry(1).or_default();
            legacy_store.write_sync(&legacy).await?;
            let legacy_bytes = bincode::serialize(&legacy)?;
            crate::recovery::backfill_restart_state(
                &repos,
                &system.eventstore_reader()?.seq(),
                &[1],
                false,
            )
            .await?;
            let (_sortition, _) = setup_sortition(&bus, &repos, &operator.to_string()).await?;
            if !before_snapshot {
                // Replay delivers stored envelopes on a fresh bus without appending them again.
                for event in events {
                    system.eventbus().send(EventBusFanout(event)).await??;
                }
                bus.flush_event_pipeline().await?;
                system.buffer()?.send(FlushPendingSnapshots).await??;
            }
            let nodes = NodeStateStore {
                nodes: HashMap::from([(operator.to_string(), NodeState::default())]),
                ..Default::default()
            };
            let state = repos.sortition_admission().read().await?.unwrap();
            state.validate()?;
            assert_eq!(state.filter(1, 19, &nodes).nodes.len(), 1);
            assert_eq!(
                state.filter(1, 109, &nodes).nodes.len(),
                0,
                "before_snapshot={before_snapshot}, state={state:?}"
            );
            assert_eq!(state.filter(1, 110, &nodes).nodes.len(), 1);
            assert_eq!(
                state.filter(1, 250, &nodes).nodes.len(),
                1,
                "local raw log must be ignored"
            );
            assert!(errors.send(GetEvents::new()).await?.is_empty());
            crate::recovery::backfill_restart_state(
                &repos,
                &system.eventstore_reader()?.seq(),
                &[1],
                false,
            )
            .await?;
            assert_eq!(
                bincode::serialize(&state)?,
                bincode::serialize(&repos.sortition_admission().read().await?.unwrap())?
            );
            assert_eq!(
                legacy_bytes,
                bincode::serialize(&legacy_store.read().await?.unwrap())?
            );
        }
        Ok(())
    }

    /// The startup chain sync can deliver an E3's failure before its committee finalization, and
    /// the failure can also be in the saved lifecycle while only the finalization is replayed. The
    /// late finalization must not reserve slots, because no later event releases them.
    #[actix::test]
    async fn a_finalization_after_the_e3_failure_reserves_no_capacity() -> anyhow::Result<()> {
        use e3_events::{
            AggregateConfig, AggregateId, CommitteeFinalized, E3Failed,
            EventConstructorWithTimestamp, EventSource, FailureReason, FlushPendingSnapshots,
            InterfoldEvent, InterfoldEventData, Unsequenced,
        };
        use e3_request::E3LifecycleRepositoryFactory;
        use e3_sortition::{NodeRegistry, NodeStateRepositoryFactory};

        for failure_in_lifecycle in [false, true] {
            let aggregate = AggregateId::from_chain_id(Some(1));
            let system = e3_event_system::EventSystem::new()
                .with_fresh_bus()
                .with_aggregate_config(AggregateConfig::new(HashMap::from([(
                    aggregate,
                    Duration::ZERO,
                )])));
            let bus = system.handle()?.enable("sortition-late-finalization");
            let repos = e3_data::Repositories::from(system.store()?);
            let local = Address::from([0xab; 20]).to_string();
            let e3_id = E3id::new("1", 1);
            let mut events: Vec<InterfoldEventData> = Vec::new();
            if failure_in_lifecycle {
                repos
                    .e3_lifecycle()
                    .write_sync(&HashMap::from([(e3_id.clone(), E3Stage::Failed)]))
                    .await?;
            } else {
                events.push(
                    E3Failed {
                        e3_id: e3_id.clone(),
                        failed_at_stage: E3Stage::CommitteeFinalized,
                        reason: FailureReason::DKGTimeout,
                    }
                    .into(),
                );
            }
            events.push(
                CommitteeFinalized {
                    e3_id: e3_id.clone(),
                    committee: vec![local.clone(), Address::from([0xcd; 20]).to_string()],
                    scores: vec!["1".into(), "2".into()],
                    chain_id: 1,
                }
                .into(),
            );
            let (_sortition, _) = setup_sortition(&bus, &repos, &local).await?;

            for (index, data) in events.into_iter().enumerate() {
                let event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
                    data,
                    None,
                    index as u128 + 1,
                    Some(1),
                    EventSource::Evm,
                )
                .into_sequenced(index as u64 + 1);
                system
                    .eventbus()
                    .send(e3_events::EventBusFanout(event))
                    .await??;
            }
            bus.flush_event_pipeline().await?;
            system.buffer()?.send(FlushPendingSnapshots).await??;

            let state = repos.node_state().read().await?.unwrap_or_default();
            assert!(
                NodeRegistry::open_committees(&state).is_empty(),
                "failure_in_lifecycle={failure_in_lifecycle}: a finished E3 holds capacity: {state:?}"
            );
        }
        Ok(())
    }

    /// A node whose saved state already holds a finished E3's slots gets them back at startup.
    #[actix::test]
    async fn startup_releases_the_capacity_of_finished_e3s() -> anyhow::Result<()> {
        use e3_request::E3LifecycleRepositoryFactory;
        use e3_sortition::{committee_key, NodeRegistry, NodeStateRepositoryFactory};

        let system = e3_event_system::EventSystem::new().with_fresh_bus();
        let bus = system.handle()?.enable("sortition-startup-release");
        let repos = e3_data::Repositories::from(system.store()?);
        let local = Address::from([0xab; 20]).to_string();
        let failed = E3id::new("1", 1);
        let active = E3id::new("2", 1);
        let mut state = HashMap::new();
        for e3_id in [&failed, &active] {
            NodeRegistry::reconcile_committee_jobs(
                &mut state,
                e3_id,
                std::slice::from_ref(&local),
                "test",
            );
        }
        repos.node_state().write_sync(&state).await?;
        repos
            .e3_lifecycle()
            .write_sync(&HashMap::from([
                (failed.clone(), E3Stage::Failed),
                (active.clone(), E3Stage::KeyPublished),
            ]))
            .await?;

        let (_sortition, _) = setup_sortition(&bus, &repos, &local).await?;
        system
            .buffer()?
            .send(e3_events::FlushPendingSnapshots)
            .await??;

        let state = repos.node_state().read().await?.unwrap_or_default();
        let open = NodeRegistry::open_committees(&state)
            .into_iter()
            .map(|committee| committee.committee_key)
            .collect::<Vec<_>>();
        assert_eq!(open, vec![committee_key(&active)]);
        assert_eq!(state[&1].nodes[&local].active_jobs, 1);
        Ok(())
    }
}
