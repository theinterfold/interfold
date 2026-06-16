// SPDX-License-Identifier: LGPL-4.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::domain::backends::{SortitionBackend, SortitionList};
use crate::domain::node_registry::{NodeRegistry, NodeStateStore};
use crate::domain::ticket_sortition;
use crate::messages::{
    CommitteeMembersResponse, E3CommitteeContainsRequest, E3CommitteeContainsResponse,
    GetCommitteeMembersRequest, WithSortitionTicket,
};
use crate::CiphernodeSelector;
use actix::prelude::*;
use anyhow::{anyhow, Result};
use e3_data::{AutoPersist, Persistable, Repository};
use e3_events::{
    prelude::*, trap, CiphernodeAdded, CiphernodeRemoved, Committee, CommitteeFinalized,
    CommitteeMemberExpelled, CommitteePublished, ConfigurationUpdated, E3Failed, E3Requested,
    E3Stage, E3StageChanged, EType, EventContext, EventType, InterfoldEvent,
    OperatorActivationChanged, PlaintextOutputPublished, Seed, Sequenced, TicketBalanceUpdated,
    TypedEvent,
};
use e3_events::{BusHandle, E3id, InterfoldEventData};
use e3_utils::{NotifySync, MAILBOX_LIMIT};
use std::collections::HashMap;
use tracing::{info, instrument, warn};

/// Sortition actor that manages the sortition algorithm and the node state.
pub struct Sortition {
    /// Persistent map of `chain_id -> SortitionBackend`.
    backends: Persistable<HashMap<u64, SortitionBackend>>,
    /// Persistent map of `chain_id -> NodeStateStore`.
    node_state: Persistable<HashMap<u64, NodeStateStore>>,
    /// Event bus for error reporting and interfold event subscription.
    bus: BusHandle,
    /// Persistent map of finalized committees per E3
    finalized_committees: Persistable<HashMap<e3_events::E3id, Committee>>,
    /// Address for the CiphernodeSelector
    ciphernode_selector: Addr<CiphernodeSelector>,
    /// Address for the current node
    address: String,
    /// Ephemeral buffer of raw `CommitteeMemberExpelled` events that arrived before the matching
    /// committee was finalized (e.g. out-of-order live delivery or a reorg). Drained when the
    /// `CommitteeFinalized` event for the same E3 is processed so early expulsions are not lost.
    pending_expulsions: HashMap<E3id, Vec<(CommitteeMemberExpelled, EventContext<Sequenced>)>>,
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
    /// Persistent map of finalized committees per E3
    pub finalized_committees: Persistable<HashMap<e3_events::E3id, Committee>>,
    /// Address for the CiphernodeSelector
    pub ciphernode_selector: Addr<CiphernodeSelector>,
    /// Address for the current node
    pub address: String,
}

impl Sortition {
    pub fn new(params: SortitionParams) -> Self {
        Self {
            backends: params.backends,
            node_state: params.node_state,
            bus: params.bus,
            finalized_committees: params.finalized_committees,
            ciphernode_selector: params.ciphernode_selector,
            address: params.address,
            pending_expulsions: HashMap::new(),
        }
    }

    #[instrument(name = "sortition_attach", skip_all)]
    pub async fn attach(
        bus: &BusHandle,
        backends_store: Repository<HashMap<u64, SortitionBackend>>,
        node_state_store: Repository<HashMap<u64, NodeStateStore>>,
        committees_store: Repository<HashMap<e3_events::E3id, Committee>>,
        default_backend: SortitionBackend,
        ciphernode_selector: Addr<CiphernodeSelector>,
        address: &str,
    ) -> Result<Addr<Self>> {
        let mut backends = backends_store.load_or_default(HashMap::new()).await?;
        let node_state = node_state_store.load_or_default(HashMap::new()).await?;
        let finalized_committees = committees_store.load_or_default(HashMap::new()).await?;

        backends.try_mutate_without_context(|mut list| {
            list.insert(u64::MAX, default_backend);
            Ok(list)
        })?;

        let addr = Sortition::new(SortitionParams {
            bus: bus.clone(),
            backends,
            node_state,
            finalized_committees,
            ciphernode_selector,
            address: address.to_owned(),
        })
        .start();

        // Subscribe to state-building events immediately (needed during EventStore replay)
        bus.subscribe_all(
            &[
                EventType::CiphernodeAdded,
                EventType::CiphernodeRemoved,
                EventType::TicketBalanceUpdated,
                EventType::OperatorActivationChanged,
                EventType::ConfigurationUpdated,
                EventType::CommitteePublished,
                EventType::PlaintextOutputPublished,
                EventType::CommitteeFinalized,
                EventType::CommitteeMemberExpelled,
                EventType::E3Failed,
                EventType::E3StageChanged,
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

    pub fn get_node_index(
        &self,
        e3_id: E3id,
        seed: Seed,
        size: usize,
        chain_id: u64,
    ) -> Option<(u64, Option<u64>)> {
        let bus = self.bus.clone();
        let map = self.backends.get()?;
        let state_map = self.node_state.get()?;
        let backend = map.get(&chain_id)?;
        let state = state_map.get(&chain_id)?;

        backend
            .get_index(e3_id, seed, size, self.address.clone(), chain_id, state)
            .unwrap_or_else(|err| {
                bus.err(EType::Sortition, err);
                None
            })
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

impl Actor for Sortition {
    type Context = actix::Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

impl Handler<InterfoldEvent> for Sortition {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        match msg {
            InterfoldEventData::E3Requested(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CiphernodeAdded(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CiphernodeRemoved(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::TicketBalanceUpdated(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::OperatorActivationChanged(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ConfigurationUpdated(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CommitteePublished(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::PlaintextOutputPublished(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CommitteeFinalized(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CommitteeMemberExpelled(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::E3Failed(data) => self.notify_sync(ctx, TypedEvent::new(data, ec)),
            InterfoldEventData::E3StageChanged(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            _ => (),
        }
    }
}

impl Handler<TypedEvent<E3Requested>> for Sortition {
    type Result = ();
    fn handle(&mut self, msg: TypedEvent<E3Requested>, _: &mut Self::Context) -> Self::Result {
        let e3_id = msg.e3_id.clone();
        let chain_id = msg.e3_id.chain_id();
        let seed = msg.seed;
        let threshold_m = msg.threshold_m;
        let threshold_n = msg.threshold_n;
        let buffer = ticket_sortition::calculate_buffer_size(threshold_m, threshold_n);
        let total_selection_size = threshold_n + buffer;

        info!(
            e3_id = %e3_id,
            threshold_m = threshold_m,
            threshold_n = threshold_n,
            buffer = buffer,
            total_selection_size = total_selection_size,
            "Performing Sortition with buffer"
        );

        let node_index = self.get_node_index(e3_id.clone(), seed, total_selection_size, chain_id);

        match &node_index {
            Some((index, ticket_id)) => {
                info!(
                    e3_id = %e3_id,
                    node = %self.address,
                    index = index,
                    ticket_id = ?ticket_id,
                    "This node was SELECTED for sortition"
                );
            }
            None => {
                info!(
                    e3_id = %e3_id,
                    node = %self.address,
                    "This node was NOT selected for sortition"
                );
            }
        }

        self.ciphernode_selector
            .do_send(WithSortitionTicket::new(msg, node_index, &self.address))
    }
}

impl Handler<TypedEvent<CiphernodeAdded>> for Sortition {
    type Result = ();

    fn handle(&mut self, msg: TypedEvent<CiphernodeAdded>, _: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            let chain_id = msg.chain_id;
            let addr = msg.address.clone();

            self.node_state.try_mutate(&ec, |mut state_map| {
                NodeRegistry::add_node(&mut state_map, chain_id, addr.clone());
                Ok(state_map)
            })?;
            self.backends.try_mutate(&ec, move |mut list_map| {
                let default_backend = list_map
                    .get(&u64::MAX)
                    .cloned()
                    .unwrap_or_else(SortitionBackend::score);

                list_map
                    .entry(chain_id)
                    .or_insert_with(|| default_backend)
                    .add(addr);
                Ok(list_map)
            })?;
            Ok(())
        })
    }
}

impl Handler<TypedEvent<CiphernodeRemoved>> for Sortition {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<CiphernodeRemoved>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            let chain_id = msg.chain_id;
            let addr = msg.address.clone();

            self.node_state.try_mutate(&ec, |mut state_map| {
                NodeRegistry::remove_node(&mut state_map, chain_id, &addr);
                Ok(state_map)
            })?;
            self.backends.try_mutate(&ec, move |mut list_map| {
                if let Some(backend) = list_map.get_mut(&chain_id) {
                    backend.remove(addr);
                }
                Ok(list_map)
            })?;
            Ok(())
        })
    }
}

impl Handler<TypedEvent<TicketBalanceUpdated>> for Sortition {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<TicketBalanceUpdated>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            self.node_state.try_mutate(&ec, |mut state_map| {
                NodeRegistry::set_ticket_balance(
                    &mut state_map,
                    msg.chain_id,
                    msg.operator.clone(),
                    msg.new_balance,
                );
                Ok(state_map)
            })
        })
    }
}

impl Handler<TypedEvent<OperatorActivationChanged>> for Sortition {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<OperatorActivationChanged>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            self.node_state.try_mutate(&ec, |mut state_map| {
                NodeRegistry::set_operator_active(&mut state_map, msg.operator.clone(), msg.active);
                Ok(state_map)
            })
        })
    }
}

impl Handler<TypedEvent<ConfigurationUpdated>> for Sortition {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ConfigurationUpdated>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            if msg.parameter == "ticketPrice" {
                self.node_state.try_mutate(&ec, |mut state_map| {
                    NodeRegistry::set_ticket_price(&mut state_map, msg.chain_id, msg.new_value);
                    Ok(state_map)
                })?;
            }
            Ok(())
        })
    }
}

impl Handler<TypedEvent<CommitteePublished>> for Sortition {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<CommitteePublished>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            self.node_state.try_mutate(&ec, |mut state_map| {
                NodeRegistry::record_committee_published(&mut state_map, &msg.e3_id, &msg.nodes);
                Ok(state_map)
            })
        })
    }
}

impl Handler<GetCommitteeMembersRequest> for Sortition {
    type Result = ();

    fn handle(&mut self, msg: GetCommitteeMembersRequest, _: &mut Self::Context) -> Self::Result {
        trap(EType::Sortition, &self.bus.clone(), || {
            let members = self.get_committee(&msg.e3_id).map(|c| c.members().to_vec());
            let reply = msg.reply;
            // `try_send` can drop the reply when the aggregator mailbox is busy (e.g. mid
            // `AggregationProofSigned`), leaving decryption stuck after C7 with no ZK job.
            actix::spawn(async move {
                if reply
                    .send(CommitteeMembersResponse { members })
                    .await
                    .is_err()
                {
                    tracing::error!("committee members reply failed: aggregator recipient closed");
                }
            });
            Ok(())
        })
    }
}

impl<T> Handler<E3CommitteeContainsRequest<T>> for Sortition
where
    T: Clone + Send + Sync + 'static,
{
    type Result = ();
    fn handle(
        &mut self,
        msg: E3CommitteeContainsRequest<T>,
        _: &mut Self::Context,
    ) -> Self::Result {
        trap(EType::Sortition, &self.bus.clone(), || {
            let response = E3CommitteeContainsResponse::new(
                msg.inner,
                self.committee_contains(msg.e3_id, msg.node),
            );
            msg.sender.try_send(response)?;
            Ok(())
        })
    }
}

impl Handler<TypedEvent<PlaintextOutputPublished>> for Sortition {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<PlaintextOutputPublished>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            self.decrement_jobs_for_e3(&msg.e3_id, "PlaintextOutputPublished", ec)
        })
    }
}

impl Handler<TypedEvent<E3Failed>> for Sortition {
    type Result = ();

    fn handle(&mut self, msg: TypedEvent<E3Failed>, _ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            let reason = format!("E3Failed: {:?}", msg.reason);
            self.decrement_jobs_for_e3(&msg.e3_id, &reason, ec)
        })
    }
}

impl Handler<TypedEvent<E3StageChanged>> for Sortition {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<E3StageChanged>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            match msg.new_stage {
                E3Stage::Complete | E3Stage::Failed => {
                    let reason = format!("E3StageChanged to {:?}", msg.new_stage);
                    self.decrement_jobs_for_e3(&msg.e3_id, &reason, ec)?;
                }
                _ => {
                    // Non-terminal stages, no action needed
                }
            }
            Ok(())
        })
    }
}

impl Handler<TypedEvent<CommitteeFinalized>> for Sortition {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<CommitteeFinalized>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let (mut msg, ec) = msg.into_components();
        msg.sort_by_score();
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            info!(
                e3_id = %msg.e3_id,
                committee_size = msg.committee.len(),
                "Storing finalized committee"
            );

            self.finalized_committees
                .try_mutate(&ec, |mut committees| {
                    committees.insert(msg.e3_id.clone(), Committee::new(msg.committee.clone()));
                    Ok(committees)
                })?;

            // Drain any expulsions that arrived before the committee was finalized (C18).
            if let Some(buffered) = self.pending_expulsions.remove(&msg.e3_id) {
                info!(
                    e3_id = %msg.e3_id,
                    count = buffered.len(),
                    "Sortition: draining buffered pre-finalization expulsion(s)"
                );
                for (data, buffered_ec) in buffered {
                    if let Err(e) = self.try_resolve_and_publish_expulsion(data, buffered_ec) {
                        warn!(
                            e3_id = %msg.e3_id,
                            error = %e,
                            "Sortition: failed to process buffered expulsion after finalization"
                        );
                    }
                }
            }

            Ok(())
        })
    }
}

impl Handler<TypedEvent<CommitteeMemberExpelled>> for Sortition {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<CommitteeMemberExpelled>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let (data, ec) = msg.into_components();

        // Only process raw events from chain (party_id not yet resolved).
        // Events we re-publish with party_id set will also arrive here; ignore them.
        if data.party_id.is_some() {
            return;
        }

        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            if self.try_resolve_and_publish_expulsion(data.clone(), ec.clone())? {
                return Ok(());
            }

            // Committee not finalized yet — buffer until CommitteeFinalized arrives (C18) instead
            // of dropping the expulsion, which would otherwise leave a known-bad member in the
            // committee until the round times out.
            warn!(
                node = %data.node,
                e3_id = %data.e3_id,
                "CommitteeMemberExpelled arrived before committee finalized; buffering until finalization"
            );
            self.pending_expulsions
                .entry(data.e3_id.clone())
                .or_default()
                .push((data, ec));
            Ok(())
        })
    }
}
