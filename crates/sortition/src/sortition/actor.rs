// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::domain::backends::{SortitionBackend, SortitionList};
use crate::domain::node_registry::{NodeRegistry, NodeStateStore, SortitionSnapshot};
use crate::messages::{
    CommitteeMembersResponse, E3CommitteeContainsRequest, E3CommitteeContainsResponse,
    GetCommitteeMembersRequest, WithSortitionTicket,
};
use crate::CiphernodeSelector;
use crate::{AdmissionState, BondOwnerState, FinalizedCommitteeRetention};
use actix::prelude::*;
use anyhow::{anyhow, ensure, Result};
use e3_data::{AutoPersist, Persistable, Repository};
use e3_events::hlc::HlcTimestamp;
use e3_events::{
    prelude::*, trap, BondOwnerSetAt, CiphernodeAdded, CiphernodeRemoved, Committee,
    CommitteeFinalized, CommitteeMemberExcluded, CommitteeMemberExpelled, CommitteeRequested,
    ConfigurationUpdated, E3Failed, E3RequestComplete, E3Requested, E3Stage, E3StageChanged, EType,
    EffectsEnabled, EventContext, EventType, InterfoldEvent, OperatorActivationChanged,
    PlaintextOutputPublished, Seed, Sequenced, TicketBalanceUpdated, TicketGenerated, TypedEvent,
};
use e3_events::{BusHandle, E3id, InterfoldEventData};
use e3_utils::{NotifySync, MAILBOX_LIMIT};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::{info, instrument, warn};

/// Sortition actor that manages the sortition algorithm and the node state.
pub struct Sortition {
    /// Persistent map of `chain_id -> SortitionBackend`.
    backends: Persistable<HashMap<u64, SortitionBackend>>,
    /// Persistent map of `chain_id -> NodeStateStore`.
    node_state: Persistable<HashMap<u64, NodeStateStore>>,
    /// Owner history is derived from chain events and persisted separately from node state.
    bond_owners: Persistable<BondOwnerState>,
    admission: Persistable<AdmissionState>,
    /// Event bus for error reporting and interfold event subscription.
    bus: BusHandle,
    /// Persistent map of finalized committees per E3
    finalized_committees: Persistable<HashMap<e3_events::E3id, Committee>>,
    /// Address for the CiphernodeSelector
    ciphernode_selector: Addr<CiphernodeSelector>,
    /// Address for the current node
    address: String,
    /// Restart-critical delayed inputs and pre-finalization membership changes.
    recovery: Persistable<SortitionRecoveryState>,
    /// Requests already dispatched during this process.
    processed_requests: HashSet<E3id>,
    effects_enabled: bool,
}

pub const SORTITION_RECOVERY_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SortitionRecoveryState {
    pub schema_version: u32,
    pub seeds: HashMap<E3id, Seed>,
    pub pending_requests: HashMap<E3id, TypedEvent<E3Requested>>,
    pub pending_expulsions: HashMap<E3id, Vec<(CommitteeMemberExpelled, EventContext<Sequenced>)>>,
    pub pending_exclusions: HashMap<E3id, Vec<(CommitteeMemberExcluded, EventContext<Sequenced>)>>,
}

impl Default for SortitionRecoveryState {
    fn default() -> Self {
        Self {
            schema_version: SORTITION_RECOVERY_SCHEMA_VERSION,
            seeds: HashMap::new(),
            pending_requests: HashMap::new(),
            pending_expulsions: HashMap::new(),
            pending_exclusions: HashMap::new(),
        }
    }
}

impl SortitionRecoveryState {
    pub fn complete_sortition(&mut self, e3_id: &E3id) {
        self.seeds.remove(e3_id);
        self.pending_requests.remove(e3_id);
    }

    pub fn remove(&mut self, e3_id: &E3id) {
        self.complete_sortition(e3_id);
        self.pending_expulsions.remove(e3_id);
        self.pending_exclusions.remove(e3_id);
    }

    pub fn buffer_expulsion(
        &mut self,
        data: CommitteeMemberExpelled,
        context: EventContext<Sequenced>,
    ) {
        let pending = self
            .pending_expulsions
            .entry(data.e3_id.clone())
            .or_default();
        if !pending.iter().any(|(existing, _)| existing == &data) {
            pending.push((data, context));
        }
    }

    pub fn acknowledge_expulsion(&mut self, data: &CommitteeMemberExpelled) {
        let Some(pending) = self.pending_expulsions.get_mut(&data.e3_id) else {
            return;
        };
        pending.retain(|(existing, _)| {
            existing.node != data.node
                || existing.reason != data.reason
                || existing.active_count_after != data.active_count_after
        });
        if pending.is_empty() {
            self.pending_expulsions.remove(&data.e3_id);
        }
    }

    pub fn buffer_exclusion(
        &mut self,
        data: CommitteeMemberExcluded,
        context: EventContext<Sequenced>,
    ) {
        let pending = self
            .pending_exclusions
            .entry(data.e3_id.clone())
            .or_default();
        if !pending.iter().any(|(existing, _)| existing == &data) {
            pending.push((data, context));
        }
    }

    pub fn acknowledge_exclusion(&mut self, data: &CommitteeMemberExcluded) {
        let Some(pending) = self.pending_exclusions.get_mut(&data.e3_id) else {
            return;
        };
        pending.retain(|(existing, _)| {
            existing.node != data.node || existing.proof_type != data.proof_type
        });
        if pending.is_empty() {
            self.pending_exclusions.remove(&data.e3_id);
        }
    }
}

/// Parameters for constructing a `Sortition` actor.
#[derive(Debug)]
pub struct SortitionParams {
    /// Event bus address.
    pub bus: BusHandle,
    /// Persisted per-chain backend map.
    pub backends: Persistable<HashMap<u64, SortitionBackend>>,
    /// Node state store per chain
    pub node_state: Persistable<HashMap<u64, NodeStateStore>>,
    pub bond_owners: Persistable<BondOwnerState>,
    pub admission: Persistable<AdmissionState>,
    /// Persistent map of finalized committees per E3
    pub finalized_committees: Persistable<HashMap<e3_events::E3id, Committee>>,
    /// Persisted delayed and pre-finalization inputs.
    pub recovery: Persistable<SortitionRecoveryState>,
    /// Address for the CiphernodeSelector
    pub ciphernode_selector: Addr<CiphernodeSelector>,
    /// Address for the current node
    pub address: String,
    /// Existing ticket intents retain their ticket number and finalization rank after upgrade.
    pub submitted_e3s: HashSet<E3id>,
}

/// Startup dependencies for the global sortition actor.
pub struct SortitionAttachParams<'a> {
    pub bus: &'a BusHandle,
    pub backends_store: Repository<HashMap<u64, SortitionBackend>>,
    pub node_state_store: Repository<HashMap<u64, NodeStateStore>>,
    pub bond_owners_store: Repository<BondOwnerState>,
    pub admission_store: Repository<AdmissionState>,
    pub recovery_store: Repository<SortitionRecoveryState>,
    pub committees_store: Repository<HashMap<e3_events::E3id, Committee>>,
    pub default_backend: SortitionBackend,
    pub ciphernode_selector: Addr<CiphernodeSelector>,
    pub address: &'a str,
    pub submitted_e3s: HashSet<E3id>,
}

impl Sortition {
    pub fn new(params: SortitionParams) -> Self {
        Self {
            backends: params.backends,
            node_state: params.node_state,
            bond_owners: params.bond_owners,
            admission: params.admission,
            bus: params.bus,
            finalized_committees: params.finalized_committees,
            ciphernode_selector: params.ciphernode_selector,
            address: params.address,
            recovery: params.recovery,
            processed_requests: params.submitted_e3s,
            effects_enabled: false,
        }
    }

    #[instrument(name = "sortition_attach", skip_all)]
    pub async fn attach(params: SortitionAttachParams<'_>) -> Result<Addr<Self>> {
        let SortitionAttachParams {
            bus,
            backends_store,
            node_state_store,
            bond_owners_store,
            admission_store,
            recovery_store,
            committees_store,
            default_backend,
            ciphernode_selector,
            address,
            submitted_e3s,
        } = params;
        let mut backends = backends_store.load_or_default(HashMap::new()).await?;
        let node_state = node_state_store.load_or_default(HashMap::new()).await?;
        let bond_owners = bond_owners_store
            .load_or_default(BondOwnerState::default())
            .await?;
        bond_owners.try_get()?.validate()?;
        let admission = admission_store
            .load_or_default(AdmissionState::default())
            .await?;
        admission.try_get()?.validate()?;
        let recovery = recovery_store
            .load_or_default(SortitionRecoveryState::default())
            .await?;
        ensure!(
            recovery.try_get()?.schema_version == SORTITION_RECOVERY_SCHEMA_VERSION,
            "unsupported sortition recovery schema"
        );
        let finalized_committees = committees_store.load_or_default(HashMap::new()).await?;

        backends.try_mutate_without_context(|mut list| {
            list.insert(u64::MAX, default_backend);
            Ok(list)
        })?;

        let addr = Sortition::new(SortitionParams {
            bus: bus.clone(),
            backends,
            node_state,
            bond_owners,
            admission,
            recovery,
            finalized_committees,
            ciphernode_selector,
            address: address.to_owned(),
            submitted_e3s,
        })
        .start();

        // Subscribe to state-building events immediately (needed during EventStore replay)
        bus.subscribe_all(
            &[
                EventType::CiphernodeAdded,
                EventType::CiphernodeRemoved,
                EventType::BondOwnerSetAt,
                EventType::AdmissionUpdated,
                EventType::TicketBalanceUpdated,
                EventType::TicketGenerated,
                EventType::OperatorActivationChanged,
                EventType::ConfigurationUpdated,
                EventType::CommitteeRequested,
                EventType::PlaintextOutputPublished,
                EventType::CommitteeFinalized,
                EventType::CommitteeMemberExpelled,
                EventType::CommitteeMemberExcluded,
                EventType::E3Failed,
                EventType::E3StageChanged,
                EventType::E3RequestComplete,
                EventType::EffectsEnabled,
            ],
            addr.clone().into(),
        );

        // Gate E3Requested behind EffectsEnabled — sortition should not trigger
        // ticket generation during historical event replay.
        bus.subscribe(
            EventType::EffectsEnabled,
            e3_events::run_once::<e3_events::EffectsEnabled>({
                let bus = bus.clone();
                let addr = addr.clone();
                move |_| {
                    bus.subscribe(EventType::E3Requested, addr.into());
                    Ok(())
                }
            })
            .recipient(),
        );

        info!("Sortition actor started");
        Ok(addr)
    }

    pub fn get_nodes(&self, chain_id: u64) -> Result<Vec<String>> {
        let map = self
            .backends
            .get()
            .ok_or_else(|| anyhow!("Could not get backends cache"))?;
        let backend = map
            .get(&chain_id)
            .ok_or_else(|| anyhow!("No backend for chain_id {}", chain_id))?;
        Ok(backend.nodes())
    }

    fn redrive_membership_changes(&self, e3_id: &E3id) {
        let Some(recovery) = self.recovery.get() else {
            return;
        };

        for (data, context) in recovery
            .pending_expulsions
            .get(e3_id)
            .cloned()
            .unwrap_or_default()
        {
            if let Err(error) = self.try_resolve_and_publish_expulsion(data, context) {
                warn!(%e3_id, %error, "Failed to redrive a pending committee expulsion");
            }
        }
        for (data, context) in recovery
            .pending_exclusions
            .get(e3_id)
            .cloned()
            .unwrap_or_default()
        {
            if let Err(error) = self.try_resolve_and_publish_exclusion(data, context) {
                warn!(%e3_id, %error, "Failed to redrive a pending committee exclusion");
            }
        }
    }

    pub fn get_node_index(
        &self,
        e3_id: E3id,
        seed: Seed,
        chain_id: u64,
        snapshot: SortitionSnapshot,
        candidate_owners: usize,
    ) -> Option<(u64, Option<u64>)> {
        let bus = self.bus.clone();
        let map = self.backends.get()?;
        let state_map = self.node_state.get()?;
        let backend = map.get(&chain_id)?;
        let state = state_map.get(&chain_id)?;
        let owners = self.bond_owners.get()?;
        let admission = self.admission.get()?;
        let state = admission.filter(chain_id, snapshot.request_block.checked_sub(1)?, state);

        backend
            .get_submission_index(
                e3_id,
                seed,
                self.address.clone(),
                chain_id,
                &state,
                snapshot,
                candidate_owners,
                &owners,
            )
            .unwrap_or_else(|err| {
                bus.err(EType::Sortition, err);
                None
            })
    }

    fn evm_timepoint(ec: &EventContext<Sequenced>) -> u64 {
        HlcTimestamp::wall_time(ec.ts()) / 1_000_000_000
    }

    fn get_committee(&self, e3_id: &E3id) -> Option<Committee> {
        self.finalized_committees
            .get()
            .and_then(|committees| committees.get(e3_id).cloned())
    }

    /// Resolve an expelled node's `party_id` against the finalized committee and re-publish the
    /// enriched [`CommitteeMemberExpelled`] event for downstream actors.
    ///
    /// Returns `Ok(true)` when the committee is known (the expulsion was handled, whether or not
    /// the node was a member) and `Ok(false)` when the committee has not been finalized yet, in
    /// which case the caller should buffer the event and retry after finalization (C18).
    fn try_resolve_and_publish_expulsion(
        &self,
        data: CommitteeMemberExpelled,
        ec: EventContext<Sequenced>,
    ) -> Result<bool> {
        let node_addr = data.node.to_string();

        let Some(committee) = self.get_committee(&data.e3_id) else {
            return Ok(false);
        };

        let Some(party_id) = committee.party_id_for(&node_addr) else {
            warn!(
                "Expelled node {} not found in committee for e3_id={}",
                node_addr, data.e3_id
            );
            return Ok(true);
        };

        info!(
            "Sortition: resolved expelled node {} to party_id={} for e3_id={}, re-publishing enriched event",
            node_addr, party_id, data.e3_id
        );

        self.bus.publish(
            CommitteeMemberExpelled {
                party_id: Some(party_id),
                ..data
            },
            ec,
        )?;

        Ok(true)
    }

    /// Resolve a locally excluded node against the immutable finalized committee roster.
    fn try_resolve_and_publish_exclusion(
        &self,
        data: CommitteeMemberExcluded,
        ec: EventContext<Sequenced>,
    ) -> Result<bool> {
        let node_addr = data.node.to_string();

        let Some(committee) = self.get_committee(&data.e3_id) else {
            return Ok(false);
        };

        let Some(party_id) = committee.party_id_for(&node_addr) else {
            warn!(
                "Locally excluded node {} not found in committee for e3_id={}",
                node_addr, data.e3_id
            );
            return Ok(true);
        };

        info!(
            node = %node_addr,
            party_id,
            e3_id = %data.e3_id,
            "Resolved local E3 exclusion to a stable party ID"
        );
        self.bus.publish(
            CommitteeMemberExcluded {
                party_id: Some(party_id),
                ..data
            },
            ec,
        )?;

        Ok(true)
    }

    fn committee_contains(&mut self, e3_id: E3id, node: String) -> bool {
        let Some(committee) = self.get_committee(&e3_id) else {
            // Non blocking error
            self.bus.err(
                EType::Sortition,
                anyhow!("No finalized committee found for E3 {}", e3_id),
            );
            return false;
        };

        committee.contains(&node)
    }
    /// Helper method to release active jobs for an E3's committee.
    fn decrement_jobs_for_e3(
        &mut self,
        e3_id: &E3id,
        reason: &str,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        self.node_state.try_mutate(&ec, |mut state_map| {
            NodeRegistry::release_committee_jobs(&mut state_map, e3_id, reason);
            Ok(state_map)
        })
    }
}

#[path = "handlers/mod.rs"]
mod handlers;
