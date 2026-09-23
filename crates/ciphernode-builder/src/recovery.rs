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
use e3_events::{
    hlc::HlcTimestamp, AggregateId, CiphernodeSelected, Committee, E3Stage, E3id,
    EventContextAccessors,
};
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
    let mut targets: HashSet<E3id> = active_unfinalized
        .iter()
        .filter(|e3_id| {
            !sortition.seeds.contains_key(*e3_id)
                || (sortition_was_missing && !sortition.pending_requests.contains_key(*e3_id))
                || (finalizer_was_missing && !finalizer.pending_requests.contains_key(*e3_id))
        })
        .cloned()
        .collect();
    if sortition_was_missing {
        targets.extend(active_e3s);
    }
    if targets.is_empty() && slash_target_chains.is_empty() && owner_target_chains.is_empty() {
        if sortition_was_missing || sortition_pruned {
            sortition_store.write_sync(&sortition).await?;
        }
        if finalizer_was_missing || finalizer_pruned {
            finalizer_store.write_sync(&finalizer).await?;
        }
        for (store, state, was_missing) in slashing_recovery.values() {
            if *was_missing {
                store.write_sync(state).await?;
            }
        }
        return Ok(finalizer);
    }

    let mut cursors = HashMap::new();
    for aggregate_id in targets
        .iter()
        .map(|e3_id| AggregateId::from_chain_id(Some(e3_id.chain_id())))
        .chain(
            slash_target_chains
                .iter()
                .map(|chain_id| AggregateId::from_chain_id(Some(*chain_id))),
        )
        // BondOwnerSet has no E3 ID, so its durable events belong to aggregate zero.
        .chain((!owner_target_chains.is_empty()).then(|| AggregateId::from_chain_id(None)))
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

    let recovered = project_restart_state_backfill(
        eventstore,
        cursors,
        &targets,
        &slash_target_chains,
        &owner_target_chains,
    )
    .await?;
    // Only absent chain projections are backfilled. Existing snapshots remain authoritative.
    for event in recovered.bond_owner_updates {
        owners.record(&event, HlcTimestamp::wall_time(event.ts()) / 1_000_000_000)?;
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
        finalizer.tickets.extend(recovered.tickets);
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
    use e3_events::Seed;

    #[test]
    fn existing_seed_is_authoritative() {
        let e3_id = E3id::new("1", 1);
        let existing = Seed([1; 32]);
        let mut seeds = HashMap::from([(e3_id.clone(), existing)]);

        backfill_missing_seeds(&mut seeds, HashMap::from([(e3_id.clone(), Seed([2; 32]))]));

        assert_eq!(seeds.get(&e3_id), Some(&existing));
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
        use e3_events::{BondOwnerSet, EventPublisher};
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
        bus.publish_without_context(event.clone())?;
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
}
