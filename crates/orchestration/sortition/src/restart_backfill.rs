// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Restart-state migration and committee snapshot reconciliation for sortition.

use crate::{
    AdmissionState, BondOwnerState, CiphernodeSelectorFactory, CiphernodeSelectorState,
    CommitteeFinalizerRecoveryState, CommitteeFinalizerRepositoryFactory,
    FinalizedCommitteesRepositoryFactory, IdentityPolicyState,
    RecoveredCommitteeRequest as FinalizerRecoveredCommitteeRequest,
    SortitionRecoveryRepositoryFactory, SortitionRecoveryState,
    COMMITTEE_FINALIZER_RECOVERY_SCHEMA_VERSION, SORTITION_RECOVERY_SCHEMA_VERSION,
};
use actix::Recipient;
use anyhow::{ensure, Result};
use e3_committee::Committee;
use e3_data::Repositories;
use e3_events::{
    AccusationQuorumReached, AggregateId, CiphernodeSelected, E3Stage, E3id, EventStoreQueryBy,
    Seed, SeqAgg,
};
use e3_request::E3LifecycleRepositoryFactory;
use e3_sync::{project_restart_state_backfill, SyncRepositoryFactory};
use std::collections::{HashMap, HashSet};
use tracing::{info, warn};

fn backfill_missing_seeds(current: &mut HashMap<E3id, Seed>, recovered: HashMap<E3id, Seed>) {
    for (e3_id, seed) in recovered {
        current.entry(e3_id).or_insert(seed);
    }
}

/// Appends the identity policy changes in the raw logs that the journal took in after the position
/// that each existing projection replayed through, then records the new position. A binary without
/// the identity projection (an older release run in between, which the schema allows) ingests policy
/// logs without projecting them. Chains without a projection are left to the full backfill.
async fn catch_up_identity_policy(
    repositories: &Repositories,
    eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
    chain_ids: &[u64],
    missing: &HashSet<u64>,
    identity: &mut IdentityPolicyState,
) -> Result<()> {
    let mut start_cursors = HashMap::new();
    let mut end_cursors = HashMap::new();
    let mut chains = HashSet::new();
    for chain_id in chain_ids
        .iter()
        .filter(|chain_id| !missing.contains(chain_id))
    {
        let aggregate = AggregateId::from_chain_id(Some(*chain_id));
        let end = repositories
            .aggregate_seq(aggregate)
            .read()
            .await?
            .unwrap_or(0);
        let start = identity.replayed.get(chain_id).copied().unwrap_or(0);
        if end > start {
            start_cursors.insert(aggregate, start);
            end_cursors.insert(aggregate, end);
            chains.insert(*chain_id);
        }
    }
    if chains.is_empty() {
        return Ok(());
    }
    let recovered = match project_restart_state_backfill(
        eventstore,
        start_cursors,
        end_cursors.clone(),
        &HashSet::new(),
        &HashSet::new(),
        &chains,
    )
    .await
    {
        Ok(recovered) => recovered,
        Err(error) => {
            // The log cannot serve the range (for example, a snapshot ahead of it). The history can
            // miss a change, so the policy reads as required until the next startup replays it.
            warn!(
                "Could not replay the event log for the identity policy; it counts as required \
                 until a replay succeeds: {error:#}"
            );
            identity.unknown.extend(&chains);
            repositories
                .sortition_identity_policy()
                .write_sync(identity)
                .await?;
            return Ok(());
        }
    };
    let mut appended = 0;
    for change in recovered.identity_policy_updates {
        if chains.contains(&change.chain_id) && identity.catch_up(&change)? {
            appended += 1;
        }
    }
    for chain_id in &chains {
        let aggregate = AggregateId::from_chain_id(Some(*chain_id));
        identity.replayed.insert(*chain_id, end_cursors[&aggregate]);
        identity.unknown.remove(chain_id);
    }
    repositories
        .sortition_identity_policy()
        .write_sync(identity)
        .await?;
    if appended > 0 {
        warn!(
            appended,
            "Caught up on identity policy logs that this node took in without projecting them"
        );
    }
    Ok(())
}

/// Sortition restart inputs, validated and loaded before any missing store is backfilled.
///
/// Stores that predate a recovery repository kept its inputs only in the event log. Restart fills
/// each missing store from the log, and existing snapshots remain authoritative. Pending slash
/// intents come from the same scan, so the caller passes the chains whose slashing-writer store is
/// missing and writes the returned intents before it commits the checkpoint.
pub struct SortitionRestartBackfill {
    repositories: Repositories,
    selector: CiphernodeSelectorState,
    lifecycle: HashMap<E3id, E3Stage>,
    finalized_committees: HashMap<E3id, Committee>,
    admission: AdmissionState,
    admission_target_chains: HashSet<u64>,
    identity: IdentityPolicyState,
    identity_target_chains: HashSet<u64>,
    owners: BondOwnerState,
    owner_target_chains: HashSet<u64>,
    sortition: SortitionRecoveryState,
    sortition_was_missing: bool,
    finalizer: CommitteeFinalizerRecoveryState,
    finalizer_was_missing: bool,
}

/// The checked event-log prefixes, which advance only after every recovered input is durable.
#[must_use = "the checked prefixes are recorded only by `commit`"]
pub struct RestartInputCheckpoint {
    repositories: Repositories,
    checked: HashMap<E3id, u64>,
    targets: HashSet<E3id>,
    cursors: HashMap<AggregateId, u64>,
    finalizer: CommitteeFinalizerRecoveryState,
}

impl SortitionRestartBackfill {
    /// Validates the sortition snapshots and catches up existing identity-policy projections.
    pub async fn load(
        repositories: &Repositories,
        eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
        chain_ids: &[u64],
    ) -> Result<Self> {
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
        let admission = repositories
            .sortition_admission()
            .read()
            .await?
            .unwrap_or_default();
        admission.validate()?;
        let admission_target_chains = chain_ids
            .iter()
            .copied()
            .filter(|chain_id| !admission.chains.contains_key(chain_id))
            .collect::<HashSet<_>>();
        let mut identity = repositories
            .sortition_identity_policy()
            .read()
            .await?
            .unwrap_or_default();
        identity.validate()?;
        let identity_target_chains = chain_ids
            .iter()
            .copied()
            .filter(|chain_id| !identity.chains.contains_key(chain_id))
            .collect::<HashSet<_>>();
        catch_up_identity_policy(
            repositories,
            eventstore,
            chain_ids,
            &identity_target_chains,
            &mut identity,
        )
        .await?;
        let owners = repositories
            .sortition_bond_owners()
            .read()
            .await?
            .unwrap_or_default();
        owners.validate()?;
        let owner_target_chains = chain_ids
            .iter()
            .copied()
            .filter(|chain_id| !owners.chains.contains_key(chain_id))
            .collect::<HashSet<_>>();
        let persisted_sortition = repositories.sortition_recovery().read().await?;
        let sortition_was_missing = persisted_sortition.is_none();
        let sortition = persisted_sortition.unwrap_or_default();
        ensure!(
            sortition.schema_version == SORTITION_RECOVERY_SCHEMA_VERSION,
            "unsupported sortition recovery schema {}",
            sortition.schema_version
        );
        let persisted_finalizer = repositories.committee_finalizer_recovery().read().await?;
        let finalizer_was_missing = persisted_finalizer.is_none();
        let finalizer = persisted_finalizer.unwrap_or_default();
        ensure!(
            finalizer.schema_version == COMMITTEE_FINALIZER_RECOVERY_SCHEMA_VERSION,
            "unsupported committee-finalizer recovery schema {}",
            finalizer.schema_version
        );
        Ok(Self {
            repositories: repositories.clone(),
            selector,
            lifecycle,
            finalized_committees,
            admission,
            admission_target_chains,
            identity,
            identity_target_chains,
            owners,
            owner_target_chains,
            sortition,
            sortition_was_missing,
            finalizer,
            finalizer_was_missing,
        })
    }

    /// Prunes finished work, scans the unchecked log range, and writes the missing sortition
    /// stores. Returns the pending slash intents for `slash_target_chains`.
    pub async fn backfill(
        self,
        eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
        slash_target_chains: &HashSet<u64>,
    ) -> Result<(Vec<AccusationQuorumReached>, RestartInputCheckpoint)> {
        let Self {
            repositories,
            selector,
            lifecycle,
            finalized_committees,
            mut admission,
            admission_target_chains,
            mut identity,
            identity_target_chains,
            mut owners,
            owner_target_chains,
            mut sortition,
            sortition_was_missing,
            mut finalizer,
            finalizer_was_missing,
        } = self;
        let sortition_store = repositories.sortition_recovery();
        let finalizer_store = repositories.committee_finalizer_recovery();
        let terminal_sortition_e3s = sortition
            .seeds
            .keys()
            .chain(sortition.pending_requests.keys())
            .chain(sortition.pending_expulsions.keys())
            .chain(sortition.pending_exclusions.keys())
            .filter(|e3_id| lifecycle.get(*e3_id).is_some_and(E3Stage::is_terminal))
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
            sortition_pruned |= sortition.seeds.contains_key(e3_id)
                || sortition.pending_requests.contains_key(e3_id);
            sortition.complete_sortition(e3_id);
        }
        let stale_finalizer_e3s: HashSet<E3id> = finalizer
            .pending_requests
            .keys()
            .chain(finalizer.tickets.keys())
            .filter(|e3_id| {
                selector.committees.contains_key(*e3_id)
                    || finalized_committees.contains_key(*e3_id)
                    || lifecycle.get(*e3_id).is_some_and(E3Stage::is_terminal)
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
                    Some(E3Stage::Complete | E3Stage::Failed)
                )
            })
            .cloned()
            .collect();
        let active_unfinalized = active_e3s
            .iter()
            .filter(|e3_id| {
                !selector.committees.contains_key(*e3_id)
                    && !finalized_committees.contains_key(*e3_id)
            })
            .cloned()
            .collect::<HashSet<_>>();
        let mut checked = repositories
            .restart_input_cursors()
            .read()
            .await?
            .unwrap_or_default();
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
            .iter()
            .chain(&admission_target_chains)
            .chain(&identity_target_chains)
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
                    .chain(&identity_target_chains)
                    .map(|chain_id| AggregateId::from_chain_id(Some(*chain_id))),
            )
            // Typed owner/admission events use aggregate zero. Legacy raw logs use their chain
            // aggregate.
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
        for chain_id in slash_target_chains
            .iter()
            .chain(&admission_target_chains)
            .chain(&identity_target_chains)
        {
            start_cursors.insert(AggregateId::from_chain_id(Some(*chain_id)), 0);
        }
        if !projection_target_chains.is_empty() {
            start_cursors.insert(AggregateId::from_chain_id(None), 0);
        }
        if targets.is_empty()
            && slash_target_chains.is_empty()
            && projection_target_chains.is_empty()
        {
            if sortition_was_missing || sortition_pruned {
                sortition_store.write_sync(&sortition).await?;
            }
            if finalizer_was_missing || finalizer_pruned {
                finalizer_store.write_sync(&finalizer).await?;
            }
            let checkpoint = RestartInputCheckpoint {
                repositories,
                checked,
                targets,
                cursors,
                finalizer,
            };
            return Ok((Vec::new(), checkpoint));
        }

        let recovered = project_restart_state_backfill(
            eventstore,
            start_cursors,
            cursors.clone(),
            &targets,
            slash_target_chains,
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
            repositories
                .sortition_admission()
                .write_sync(&admission)
                .await?;
        }
        for change in recovered.identity_policy_updates {
            if identity_target_chains.contains(&change.chain_id) {
                identity.record(&change)?;
            }
        }
        for chain_id in &identity_target_chains {
            identity.chains.entry(*chain_id).or_default();
            let aggregate = AggregateId::from_chain_id(Some(*chain_id));
            identity
                .replayed
                .insert(*chain_id, cursors.get(&aggregate).copied().unwrap_or(0));
        }
        if !identity_target_chains.is_empty() {
            repositories
                .sortition_identity_policy()
                .write_sync(&identity)
                .await?;
        }
        for chain_id in &owner_target_chains {
            owners.chains.entry(*chain_id).or_default();
        }
        if !owner_target_chains.is_empty() {
            repositories
                .sortition_bond_owners()
                .write_sync(&owners)
                .await?;
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
        // The projection may span history that predates a finalized-committee snapshot. Keep later
        // unresolved membership changes, but never reintroduce seed, request, ticket, or
        // finalization work for a committee that the authoritative snapshots already finalized.
        for e3_id in finalized_committees.keys() {
            sortition.complete_sortition(e3_id);
            finalizer.remove(e3_id);
        }
        sortition_store.write_sync(&sortition).await?;
        finalizer_store.write_sync(&finalizer).await?;
        info!(
            recovered_seed_count,
            recovered_finalizer_requests = finalizer.pending_requests.len(),
            recovered_tickets = finalizer.tickets.len(),
            recovered_slash_count,
            "Backfilled missing restart state from EventStore"
        );
        let checkpoint = RestartInputCheckpoint {
            repositories,
            checked,
            targets,
            cursors,
            finalizer,
        };
        Ok((recovered.slash_intents, checkpoint))
    }
}

impl RestartInputCheckpoint {
    /// Records the scanned prefixes and returns the committee-finalizer state to start from. Call
    /// it only after the caller's recovered inputs are durable.
    pub async fn commit(self) -> Result<CommitteeFinalizerRecoveryState> {
        let Self {
            repositories,
            mut checked,
            targets,
            cursors,
            finalizer,
        } = self;
        // An empty scan is also a checked prefix.
        for e3_id in targets {
            let aggregate = AggregateId::from_chain_id(Some(e3_id.chain_id()));
            if let Some(cursor) = cursors.get(&aggregate) {
                checked.insert(e3_id, *cursor);
            }
        }
        repositories
            .restart_input_cursors()
            .write_sync(&checked)
            .await?;
        Ok(finalizer)
    }
}

pub fn recovered_ciphernode_selections(
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

pub fn reconcile_committee_snapshots(
    selector: &mut CiphernodeSelectorState,
    finalized: &mut HashMap<E3id, Committee>,
    lifecycle: &HashMap<E3id, E3Stage>,
) -> Result<(bool, bool)> {
    let terminal = lifecycle
        .iter()
        .filter(|(_, stage)| stage.is_terminal())
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
#[path = "restart_backfill_tests.rs"]
mod tests;
