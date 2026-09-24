// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Restart-state migration and reconciliation.

use anyhow::{ensure, Result};
use e3_aggregator::{
    CommitteeFinalizerRecoveryState, CommitteeFinalizerRepositoryFactory,
    RecoveredCommitteeRequest as FinalizerRecoveredCommitteeRequest,
    COMMITTEE_FINALIZER_RECOVERY_SCHEMA_VERSION,
};
use e3_events::{AggregateId, CiphernodeSelected, Committee, E3Stage, E3id};
use e3_evm::{SlashingWriterRepositoryFactory, SLASHING_WRITER_RECOVERY_SCHEMA_VERSION};
use e3_request::E3LifecycleRepositoryFactory;
use e3_sortition::{
    CiphernodeSelectorFactory, CiphernodeSelectorState, FinalizedCommitteesRepositoryFactory,
    SortitionRecoveryRepositoryFactory, SORTITION_RECOVERY_SCHEMA_VERSION,
};
use e3_sync::{project_restart_state_backfill, SyncRepositoryFactory};
use std::collections::{HashMap, HashSet};
use tracing::{info, warn};

fn backfill_missing_seeds(
    current: &mut HashMap<E3id, e3_events::Seed>,
    recovered: HashMap<E3id, e3_events::Seed>,
) {
    for (e3_id, seed) in recovered {
        current.entry(e3_id).or_insert(seed);
    }
}

pub(crate) async fn backfill_restart_state(
    repositories: &e3_data::Repositories,
    eventstore: &actix::Recipient<e3_events::EventStoreQueryBy<e3_events::SeqAgg>>,
    chain_ids: &[u64],
    slashing_manager_enabled: bool,
) -> Result<CommitteeFinalizerRecoveryState> {
    let mut selector = repositories
        .ciphernode_selector()
        .read()
        .await?
        .unwrap_or_default();
    let lifecycle = repositories
        .e3_lifecycle()
        .read()
        .await?
        .unwrap_or_default();
    let mut finalized_committees = repositories
        .finalized_committees()
        .read()
        .await?
        .unwrap_or_default();
    // Validate the two committee views before any backfill repository is changed. The later
    // startup reconciliation persists missing copies, but contradictory data must fail closed
    // without pruning restart inputs first.
    reconcile_committee_snapshots(&mut selector, &mut finalized_committees, &lifecycle)?;
    let sortition_store = repositories.sortition_recovery();
    let owners_store = repositories.sortition_bond_owners();
    let admission_store = repositories.sortition_admission();
    let mut admission = admission_store.read().await?.unwrap_or_default();
    admission.validate()?;
    let admission_target_chains = chain_ids
        .iter()
        .copied()
        .filter(|chain_id| !admission.chains.contains_key(chain_id))
        .collect::<HashSet<_>>();
    let mut owners = owners_store.read().await?.unwrap_or_default();
    owners.validate()?;
    let owner_target_chains = chain_ids
        .iter()
        .copied()
        .filter(|chain_id| !owners.chains.contains_key(chain_id))
        .collect::<HashSet<_>>();
    let persisted_sortition = sortition_store.read().await?;
    let sortition_was_missing = persisted_sortition.is_none();
    let mut sortition = persisted_sortition.unwrap_or_default();
    ensure!(
        sortition.schema_version == SORTITION_RECOVERY_SCHEMA_VERSION,
        "unsupported sortition recovery schema {}",
        sortition.schema_version
    );
    let finalizer_store = repositories.committee_finalizer_recovery();
    let persisted_finalizer = finalizer_store.read().await?;
    let finalizer_was_missing = persisted_finalizer.is_none();
    let mut finalizer = persisted_finalizer.unwrap_or_default();
    ensure!(
        finalizer.schema_version == COMMITTEE_FINALIZER_RECOVERY_SCHEMA_VERSION,
        "unsupported committee-finalizer recovery schema {}",
        finalizer.schema_version
    );
    let mut slashing_recovery = HashMap::new();
    if slashing_manager_enabled {
        for chain_id in chain_ids.iter().copied().collect::<HashSet<_>>() {
            let store = repositories.slashing_writer_recovery(chain_id);
            let persisted = store.read().await?;
            let was_missing = persisted.is_none();
            let state = persisted.unwrap_or_default();
            ensure!(
                state.schema_version == SLASHING_WRITER_RECOVERY_SCHEMA_VERSION,
                "unsupported slashing-writer recovery schema {} for chain {}",
                state.schema_version,
                chain_id
            );
            slashing_recovery.insert(chain_id, (store, state, was_missing));
        }
    }
    let slash_target_chains = slashing_recovery
        .iter()
        .filter_map(|(chain_id, (_, _, was_missing))| was_missing.then_some(*chain_id))
        .collect::<HashSet<_>>();
    let terminal_sortition_e3s = sortition
        .seeds
        .keys()
        .chain(sortition.pending_requests.keys())
        .chain(sortition.pending_expulsions.keys())
        .chain(sortition.pending_exclusions.keys())
        .filter(|e3_id| {
            matches!(
                lifecycle.get(*e3_id),
                Some(E3Stage::Complete | E3Stage::Failed)
            )
        })
        .cloned()
        .collect::<HashSet<_>>();
    let mut sortition_pruned = !terminal_sortition_e3s.is_empty();
    for e3_id in terminal_sortition_e3s {
        sortition.remove(&e3_id);
    }
    for e3_id in finalized_committees
        .keys()
        .chain(selector.committees.keys())
    {
        sortition_pruned |=
            sortition.seeds.contains_key(e3_id) || sortition.pending_requests.contains_key(e3_id);
        sortition.complete_sortition(e3_id);
    }
    let stale_finalizer_e3s: HashSet<E3id> = finalizer
        .pending_requests
        .keys()
        .chain(finalizer.tickets.keys())
        .filter(|e3_id| {
            selector.committees.contains_key(*e3_id)
                || finalized_committees.contains_key(*e3_id)
                || matches!(
                    lifecycle.get(*e3_id),
                    Some(E3Stage::Complete | E3Stage::Failed)
                )
        })
        .cloned()
        .collect();
    let finalizer_pruned = !stale_finalizer_e3s.is_empty();
    for e3_id in stale_finalizer_e3s {
        finalizer.remove(&e3_id);
    }
    let active_e3s: HashSet<E3id> = selector
        .e3_cache
        .keys()
        .chain(lifecycle.keys())
        .chain(selector.committees.keys())
        .chain(finalized_committees.keys())
        .filter(|e3_id| {
            !matches!(
                lifecycle.get(*e3_id),
                Some(e3_events::E3Stage::Complete | e3_events::E3Stage::Failed)
            )
        })
        .cloned()
        .collect();
    let active_unfinalized = active_e3s
        .iter()
        .filter(|e3_id| {
            !selector.committees.contains_key(*e3_id) && !finalized_committees.contains_key(*e3_id)
        })
        .cloned()
        .collect::<HashSet<_>>();
    let checked_store = repositories.restart_input_cursors();
    let mut checked = checked_store.read().await?.unwrap_or_default();
    checked.retain(|e3_id, _| active_unfinalized.contains(e3_id));
    if sortition_was_missing || finalizer_was_missing {
        checked.clear();
    }
    let mut targets: HashSet<E3id> = active_unfinalized
        .iter()
        .filter(|e3_id| {
            !sortition.seeds.contains_key(*e3_id)
                || (sortition_was_missing && !sortition.pending_requests.contains_key(*e3_id))
                || (finalizer_was_missing && !finalizer.pending_requests.contains_key(*e3_id))
                || !finalizer.tickets.contains_key(*e3_id)
        })
        .cloned()
        .collect();
    if sortition_was_missing {
        targets.extend(active_e3s);
    }
    let projection_target_chains = owner_target_chains
        .union(&admission_target_chains)
        .copied()
        .collect::<HashSet<_>>();
    let mut cursors = HashMap::new();
    for aggregate_id in targets
        .iter()
        .map(|e3_id| AggregateId::from_chain_id(Some(e3_id.chain_id())))
        .chain(
            slash_target_chains
                .iter()
                .chain(&admission_target_chains)
                .map(|chain_id| AggregateId::from_chain_id(Some(*chain_id))),
        )
        // Typed owner/admission events use aggregate zero. Legacy raw logs use their chain aggregate.
        .chain((!projection_target_chains.is_empty()).then(|| AggregateId::from_chain_id(None)))
    {
        if cursors.contains_key(&aggregate_id) {
            continue;
        }
        let cursor = repositories
            .aggregate_seq(aggregate_id)
            .read()
            .await?
            .unwrap_or(0);
        if cursor > 0 {
            cursors.insert(aggregate_id, cursor);
        }
    }

    let mut start_cursors: HashMap<AggregateId, u64> = HashMap::new();
    for e3_id in &targets {
        let aggregate = AggregateId::from_chain_id(Some(e3_id.chain_id()));
        let start = checked.get(e3_id).copied().unwrap_or(0);
        let end = cursors.get(&aggregate).copied().unwrap_or(0);
        ensure!(
            start <= end,
            "restart input cursor exceeds the snapshot for E3 {e3_id}"
        );
        start_cursors
            .entry(aggregate)
            .and_modify(|value| *value = (*value).min(start))
            .or_insert(start);
    }
    targets.retain(|e3_id| {
        let aggregate = AggregateId::from_chain_id(Some(e3_id.chain_id()));
        checked.get(e3_id).copied().unwrap_or(0) < cursors.get(&aggregate).copied().unwrap_or(0)
    });
    for chain_id in slash_target_chains.iter().chain(&admission_target_chains) {
        start_cursors.insert(AggregateId::from_chain_id(Some(*chain_id)), 0);
    }
    if !projection_target_chains.is_empty() {
        start_cursors.insert(AggregateId::from_chain_id(None), 0);
    }
    if targets.is_empty() && slash_target_chains.is_empty() && projection_target_chains.is_empty() {
        if sortition_was_missing || sortition_pruned {
            sortition_store.write_sync(&sortition).await?;
        }
        if finalizer_was_missing || finalizer_pruned {
            finalizer_store.write_sync(&finalizer).await?;
        }
        checked_store.write_sync(&checked).await?;
        return Ok(finalizer);
    }

    let recovered = project_restart_state_backfill(
        eventstore,
        start_cursors,
        cursors.clone(),
        &targets,
        &slash_target_chains,
        &projection_target_chains,
    )
    .await?;
    // Only absent chain projections are backfilled. Existing snapshots remain authoritative.
    for event in recovered.bond_owner_updates {
        if owner_target_chains.contains(&event.owner.chain_id) {
            owners.record(&event.owner, event.timepoint)?;
        }
    }
    for event in recovered.admission_updates {
        if admission_target_chains.contains(&event.chain_id) {
            admission.record(&event)?;
        }
    }
    for chain_id in &admission_target_chains {
        admission.chains.entry(*chain_id).or_default();
    }
    if !admission_target_chains.is_empty() {
        admission_store.write_sync(&admission).await?;
    }
    for chain_id in &owner_target_chains {
        owners.chains.entry(*chain_id).or_default();
    }
    if !owner_target_chains.is_empty() {
        owners_store.write_sync(&owners).await?;
    }
    let recovered_seed_count = recovered.sortition_seeds.len();
    let recovered_slash_count = recovered.slash_intents.len();
    backfill_missing_seeds(&mut sortition.seeds, recovered.sortition_seeds);
    if sortition_was_missing {
        sortition
            .pending_requests
            .extend(recovered.pending_sortition_requests);
        sortition
            .pending_expulsions
            .extend(recovered.pending_expulsions);
        sortition
            .pending_exclusions
            .extend(recovered.pending_exclusions);
    }
    if finalizer_was_missing {
        finalizer
            .pending_requests
            .extend(
                recovered
                    .committee_requests
                    .into_iter()
                    .map(|(e3_id, recovered)| {
                        (
                            e3_id,
                            FinalizerRecoveredCommitteeRequest {
                                request: recovered.request,
                                context: recovered.context,
                            },
                        )
                    }),
            );
    }
    // TicketGenerated is durable even when aggregation is disabled. Recover missing intents
    // from the log prefix, without replacing an intent already saved by the finalizer.
    for (e3_id, ticket) in recovered.tickets {
        finalizer.tickets.entry(e3_id).or_insert(ticket);
    }
    for intent in recovered.slash_intents {
        let chain_id = intent.e3_id.chain_id();
        let Some((_, state, was_missing)) = slashing_recovery.get_mut(&chain_id) else {
            continue;
        };
        if *was_missing {
            if let Err(error) = state.record(intent) {
                warn!(chain_id, %error, "Ignored malformed slash intent during restart backfill");
            }
        }
    }
    // The projection may span history that predates a finalized-committee snapshot. Keep later
    // unresolved membership changes, but never reintroduce seed, request, ticket, or finalization
    // work for a committee that the authoritative snapshots already finalized.
    for e3_id in finalized_committees.keys() {
        sortition.complete_sortition(e3_id);
        finalizer.remove(e3_id);
    }
    sortition_store.write_sync(&sortition).await?;
    finalizer_store.write_sync(&finalizer).await?;
    for (store, state, was_missing) in slashing_recovery.values() {
        if *was_missing {
            store.write_sync(state).await?;
        }
    }
    // Advance only after the recovered inputs are durable. An empty scan is also a checked prefix.
    for e3_id in targets {
        let aggregate = AggregateId::from_chain_id(Some(e3_id.chain_id()));
        if let Some(cursor) = cursors.get(&aggregate) {
            checked.insert(e3_id, *cursor);
        }
    }
    checked_store.write_sync(&checked).await?;
    info!(
        recovered_seed_count,
        recovered_finalizer_requests = finalizer.pending_requests.len(),
        recovered_tickets = finalizer.tickets.len(),
        recovered_slash_count,
        "Backfilled missing restart state from EventStore"
    );
    Ok(finalizer)
}

pub(crate) fn recovered_ciphernode_selections(
    selector: &CiphernodeSelectorState,
    address: &str,
) -> Result<Vec<CiphernodeSelected>> {
    let mut selections = Vec::new();
    for (e3_id, committee) in &selector.committees {
        let Some(party_id) = committee.party_id_for(address) else {
            continue;
        };
        let meta = selector
            .e3_cache
            .get(e3_id)
            .ok_or_else(|| anyhow::anyhow!("persisted committee {e3_id} has no E3 metadata"))?;
        selections.push(CiphernodeSelected {
            e3_id: e3_id.clone(),
            threshold_m: meta.threshold_m,
            threshold_n: meta.threshold_n,
            seed: meta.seed,
            error_size: meta.error_size.clone(),
            params_preset: meta.params_preset,
            params: meta.params.clone(),
            party_id,
            committee: committee.members().to_vec(),
        });
    }
    selections.sort_by(|left, right| {
        (left.e3_id.chain_id(), left.e3_id.e3_id())
            .cmp(&(right.e3_id.chain_id(), right.e3_id.e3_id()))
    });
    Ok(selections)
}

pub(crate) fn reconcile_committee_snapshots(
    selector: &mut CiphernodeSelectorState,
    finalized: &mut HashMap<E3id, Committee>,
    lifecycle: &HashMap<E3id, E3Stage>,
) -> Result<(bool, bool)> {
    let terminal = lifecycle
        .iter()
        .filter(|(_, stage)| matches!(stage, E3Stage::Complete | E3Stage::Failed))
        .map(|(e3_id, _)| e3_id.clone())
        .collect::<HashSet<_>>();
    let selector_lengths = (
        selector.e3_cache.len(),
        selector.committees.len(),
        selector.expelled.len(),
        selector.is_aggregator.len(),
    );
    selector
        .e3_cache
        .retain(|e3_id, _| !terminal.contains(e3_id));
    selector
        .committees
        .retain(|e3_id, _| !terminal.contains(e3_id));
    selector
        .expelled
        .retain(|e3_id, _| !terminal.contains(e3_id));
    selector
        .is_aggregator
        .retain(|e3_id, _| !terminal.contains(e3_id));
    let mut selector_changed = selector_lengths
        != (
            selector.e3_cache.len(),
            selector.committees.len(),
            selector.expelled.len(),
            selector.is_aggregator.len(),
        );

    let finalized_before = finalized.len();
    finalized.retain(|e3_id, _| !terminal.contains(e3_id));
    let mut finalized_changed = finalized.len() != finalized_before;

    for (e3_id, committee) in selector.committees.clone() {
        ensure!(
            selector.e3_cache.contains_key(&e3_id),
            "persisted committee {e3_id} has no E3 metadata"
        );
        match finalized.get(&e3_id) {
            Some(persisted) => ensure!(
                committees_match(persisted, &committee),
                "persisted committee snapshots disagree for E3 {e3_id}"
            ),
            None => {
                finalized.insert(e3_id, committee);
                finalized_changed = true;
            }
        }
    }

    for (e3_id, committee) in finalized.iter() {
        ensure!(
            selector.e3_cache.contains_key(e3_id),
            "persisted committee {e3_id} has no E3 metadata"
        );
        if !selector.committees.contains_key(e3_id) {
            selector.committees.insert(e3_id.clone(), committee.clone());
            selector_changed = true;
        }
        if !selector.expelled.contains_key(e3_id) {
            selector.expelled.insert(e3_id.clone(), Vec::new());
            selector_changed = true;
        }
    }

    Ok((selector_changed, finalized_changed))
}

fn committees_match(left: &Committee, right: &Committee) -> bool {
    left.members().len() == right.members().len()
        && left
            .members()
            .iter()
            .zip(right.members())
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::{Actor, Context, Handler, Recipient, ResponseFuture};
    use e3_events::Seed;
    use e3_events::{EventStoreQueryBy, SeqAgg};
    use std::sync::{Arc, Mutex};

    struct TrackedQueries {
        inner: Recipient<EventStoreQueryBy<SeqAgg>>,
        queries: Arc<Mutex<Vec<HashMap<AggregateId, u64>>>>,
    }

    impl Actor for TrackedQueries {
        type Context = Context<Self>;
    }

    impl Handler<EventStoreQueryBy<SeqAgg>> for TrackedQueries {
        type Result = ResponseFuture<()>;

        fn handle(
            &mut self,
            query: EventStoreQueryBy<SeqAgg>,
            _: &mut Context<Self>,
        ) -> Self::Result {
            self.queries.lock().unwrap().push(query.query().clone());
            let inner = self.inner.clone();
            Box::pin(async move {
                inner.send(query).await.unwrap();
            })
        }
    }

    #[actix::test]
    async fn ticket_backfill_skips_checked_prefixes_and_retries_incomplete_reads() -> Result<()> {
        use e3_events::{E3Requested, EventPublisher, TicketGenerated, TicketId};
        use e3_sortition::SortitionRecoveryState;
        let aggregate = AggregateId::from_chain_id(Some(1));
        let system = crate::EventSystem::new()
            .with_fresh_bus()
            .with_aggregate_config(e3_events::AggregateConfig::new(HashMap::from([(
                aggregate,
                std::time::Duration::ZERO,
            )])));
        let bus = system.handle()?.enable("checked-ticket-prefix");
        let repos = e3_data::Repositories::from(system.store()?);
        let e3_id = E3id::new("1", 1);
        repos
            .e3_lifecycle()
            .write_sync(&HashMap::from([(e3_id.clone(), E3Stage::Requested)]))
            .await?;
        repos
            .sortition_recovery()
            .write_sync(&SortitionRecoveryState {
                seeds: HashMap::from([(e3_id.clone(), Seed([1; 32]))]),
                ..Default::default()
            })
            .await?;
        repos
            .committee_finalizer_recovery()
            .write_sync(&CommitteeFinalizerRecoveryState::default())
            .await?;
        bus.publish_without_context(E3Requested {
            e3_id: e3_id.clone(),
            ..Default::default()
        })?;
        bus.flush_event_pipeline().await?;
        repos.aggregate_seq(aggregate).write_sync(&1).await?;
        let queries = Arc::new(Mutex::new(Vec::new()));
        let reader = TrackedQueries {
            inner: system.eventstore_reader()?.seq(),
            queries: queries.clone(),
        }
        .start()
        .recipient();
        let recovered = backfill_restart_state(&repos, &reader, &[1], false).await?;
        assert!(!recovered.tickets.contains_key(&e3_id));
        assert_eq!(queries.lock().unwrap()[0][&aggregate], 1);
        assert_eq!(
            repos.restart_input_cursors().read().await?.unwrap()[&e3_id],
            1
        );

        queries.lock().unwrap().clear();
        backfill_restart_state(&repos, &reader, &[1], false).await?;
        assert!(
            queries.lock().unwrap().is_empty(),
            "unchanged restart must not scan again"
        );

        repos.aggregate_seq(aggregate).write_sync(&2).await?;
        assert!(backfill_restart_state(&repos, &reader, &[1], false)
            .await
            .is_err());
        assert_eq!(queries.lock().unwrap()[0][&aggregate], 2);
        assert_eq!(
            repos.restart_input_cursors().read().await?.unwrap()[&e3_id],
            1,
            "failed reads must not advance the checkpoint"
        );
        let ticket = TicketGenerated {
            e3_id: e3_id.clone(),
            ticket_id: TicketId::Score(9),
            node: alloy::primitives::Address::repeat_byte(1).to_string(),
            party_index: Some(0),
        };
        bus.publish_without_context(ticket.clone())?;
        bus.flush_event_pipeline().await?;
        let recovered = backfill_restart_state(&repos, &reader, &[1], false).await?;
        assert_eq!(recovered.tickets[&e3_id], ticket);
        assert_eq!(
            repos.restart_input_cursors().read().await?.unwrap()[&e3_id],
            2
        );

        let next_e3 = E3id::new("2", 1);
        repos
            .e3_lifecycle()
            .write_sync(&HashMap::from([
                (e3_id.clone(), E3Stage::Complete),
                (next_e3.clone(), E3Stage::Requested),
            ]))
            .await?;
        queries.lock().unwrap().clear();
        backfill_restart_state(&repos, &reader, &[1], false).await?;
        assert_eq!(
            queries.lock().unwrap()[0][&aggregate],
            1,
            "a new E3 must not inherit another E3's checked prefix"
        );
        let checked = repos.restart_input_cursors().read().await?.unwrap();
        assert!(
            !checked.contains_key(&e3_id),
            "terminal checkpoints must be pruned"
        );
        assert_eq!(checked[&next_e3], 2);
        Ok(())
    }

    #[test]
    fn existing_seed_is_authoritative() {
        let e3_id = E3id::new("1", 1);
        let existing = Seed([1; 32]);
        let mut seeds = HashMap::from([(e3_id.clone(), existing)]);

        backfill_missing_seeds(&mut seeds, HashMap::from([(e3_id.clone(), Seed([2; 32]))]));

        assert_eq!(seeds.get(&e3_id), Some(&existing));
    }

    #[actix::test]
    async fn admission_backfill_preserves_existing_owner_state_and_restart_history() -> Result<()> {
        use alloy::primitives::Address;
        use e3_events::{AdmissionChange, AdmissionPolicy, AdmissionUpdated, EventPublisher};
        use e3_sortition::{BondOwnerState, NodeState, NodeStateStore};
        let aggregate = AggregateId::from_chain_id(None);
        let system = crate::EventSystem::new()
            .with_fresh_bus()
            .with_aggregate_config(e3_events::AggregateConfig::new(HashMap::from([(
                aggregate,
                std::time::Duration::ZERO,
            )])));
        let bus = system.handle()?.enable("admission-backfill");
        let repositories = e3_data::Repositories::from(system.store()?);
        let operator = Address::repeat_byte(1);
        let start = AdmissionUpdated {
            chain_id: 1,
            timepoint: 10,
            change: AdmissionChange::Started {
                operator: operator.to_string(),
            },
        };
        bus.publish_without_context(start.clone())?;
        bus.publish_without_context(AdmissionUpdated {
            chain_id: 1,
            timepoint: 20,
            change: AdmissionChange::Policy(AdmissionPolicy {
                cooldown_enabled: true,
                cooldown_duration: 100,
                ..Default::default()
            }),
        })?;
        bus.flush_event_pipeline().await?;
        repositories.aggregate_seq(aggregate).write_sync(&2).await?;
        let mut owners = BondOwnerState::default();
        owners.chains.entry(1).or_default();
        repositories
            .sortition_bond_owners()
            .write_sync(&owners)
            .await?;
        let owner_bytes = bincode::serialize(&owners)?;
        let reader = system.eventstore_reader()?.seq();
        backfill_restart_state(&repositories, &reader, &[1], false).await?;
        let store = repositories.sortition_admission();
        let mut state = store.read().await?.unwrap();
        state.validate()?;
        let nodes = NodeStateStore {
            nodes: HashMap::from([(operator.to_string(), NodeState::default())]),
            ..Default::default()
        };
        assert_eq!(state.filter(1, 19, &nodes).nodes.len(), 1);
        assert_eq!(state.filter(1, 109, &nodes).nodes.len(), 0);
        assert_eq!(state.filter(1, 110, &nodes).nodes.len(), 1);
        assert_eq!(
            owner_bytes,
            bincode::serialize(&repositories.sortition_bond_owners().read().await?.unwrap())?
        );
        state.record(&AdmissionUpdated {
            timepoint: 200,
            ..start
        })?;
        store.write_sync(&state).await?;
        backfill_restart_state(&repositories, &reader, &[1], false).await?;
        let state = store.read().await?.unwrap();
        assert_eq!(state.filter(1, 250, &nodes).nodes.len(), 0);
        assert_eq!(state.filter(1, 150, &nodes).nodes.len(), 1);
        Ok(())
    }

    #[test]
    fn committee_address_casing_is_equivalent() {
        let lower = Committee::new(vec!["0xabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_owned()]);
        let upper = Committee::new(vec!["0xABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD".to_owned()]);

        assert!(committees_match(&lower, &upper));
    }

    #[actix::test]
    async fn owner_backfill_preserves_legacy_snapshots_and_restarts() -> Result<()> {
        use alloy::primitives::Address;
        use e3_events::{BondOwnerSet, BondOwnerSetAt, EventPublisher};
        use e3_sortition::NodeStateRepositoryFactory;

        let chain = AggregateId::from_chain_id(None);
        let system = crate::EventSystem::new()
            .with_fresh_bus()
            .with_aggregate_config(e3_events::AggregateConfig::new(HashMap::from([(
                chain,
                std::time::Duration::ZERO,
            )])));
        let bus = system.handle()?.enable("owner-backfill");
        let repositories = e3_data::Repositories::from(system.store()?);
        let node = Address::from([1; 20]);
        let original = Address::from([2; 20]);
        let replacement = Address::from([3; 20]);
        let event = BondOwnerSet {
            operator: node.to_string(),
            bond_owner: original.to_string(),
            chain_id: 1,
        };
        bus.publish_without_context(BondOwnerSetAt {
            owner: event.clone(),
            timepoint: 10,
        })?;
        bus.flush_event_pipeline().await?;
        repositories.aggregate_seq(chain).write_sync(&1).await?;
        let mut legacy = e3_sortition::NodeStateStore::default();
        legacy.nodes.insert(
            node.to_string(),
            e3_sortition::NodeState {
                active_jobs: 1,
                ..Default::default()
            },
        );
        repositories
            .node_state()
            .write_sync(&HashMap::from([(1, legacy)]))
            .await?;
        let before = bincode::serialize(&repositories.node_state().read().await?.unwrap())?;

        let reader = system.eventstore_reader()?.seq();
        backfill_restart_state(&repositories, &reader, &[1], false).await?;
        let owners_store = repositories.sortition_bond_owners();
        let mut owners = owners_store.read().await?.unwrap();
        owners.validate()?;
        assert_eq!(owners.owner_at(1, node, u64::MAX), Some(original));
        assert_eq!(owners.owner_at(1, node, 9), None);
        assert_eq!(owners.owner_at(1, node, 10), Some(original));
        assert_eq!(
            before,
            bincode::serialize(&repositories.node_state().read().await?.unwrap())?
        );

        // Simulate a later live update committed with its aggregate snapshot. Backfill must
        // preserve it instead of rebuilding an existing projection from an older prefix.
        let later = owners.chains[&1][&node].last().unwrap().timepoint + 1;
        owners.record(
            &BondOwnerSet {
                bond_owner: replacement.to_string(),
                ..event
            },
            later,
        )?;
        owners_store.write_sync(&owners).await?;
        backfill_restart_state(&repositories, &reader, &[1], false).await?;
        assert_eq!(
            owners_store
                .read()
                .await?
                .unwrap()
                .owner_at(1, node, u64::MAX),
            Some(replacement)
        );

        owners.schema_version += 1;
        owners_store.write_sync(&owners).await?;
        let error = backfill_restart_state(&repositories, &reader, &[1], false)
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported bond-owner snapshot schema"));
        Ok(())
    }

    #[actix::test]
    async fn legacy_owner_events_do_not_become_chain_time_checkpoints() -> Result<()> {
        use alloy::primitives::Address;
        use e3_events::{BondOwnerSet, EventPublisher};

        let aggregate = AggregateId::from_chain_id(None);
        let system = crate::EventSystem::new()
            .with_fresh_bus()
            .with_aggregate_config(e3_events::AggregateConfig::new(HashMap::from([(
                aggregate,
                std::time::Duration::ZERO,
            )])));
        let bus = system.handle()?.enable("legacy-owner-time");
        let repositories = e3_data::Repositories::from(system.store()?);
        let operator = Address::from([1; 20]);
        bus.publish_without_context(BondOwnerSet {
            operator: operator.to_string(),
            bond_owner: Address::from([2; 20]).to_string(),
            chain_id: 1,
        })?;
        bus.flush_event_pipeline().await?;
        repositories.aggregate_seq(aggregate).write_sync(&1).await?;
        backfill_restart_state(
            &repositories,
            &system.eventstore_reader()?.seq(),
            &[1],
            false,
        )
        .await?;
        let owners = repositories.sortition_bond_owners().read().await?.unwrap();
        assert_eq!(owners.owner_at(1, operator, u64::MAX), None);
        Ok(())
    }
}
