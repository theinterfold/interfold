// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::WithSortitionTicket;
use actix::prelude::*;
use anyhow::bail;
use anyhow::Result;
use e3_data::{AutoPersist, Persistable, Repository};
use e3_events::E3RequestComplete;
use e3_events::EventContext;
use e3_events::Sequenced;
use e3_events::TypedEvent;
use e3_events::{
    prelude::*, trap, AggregatorChanged, BusHandle, CiphernodeSelected, Committee,
    CommitteeFinalized, CommitteeMemberExpelled, E3Requested, E3id, EType, EventType,
    InterfoldEvent, InterfoldEventData, Shutdown, TicketGenerated, TicketId,
};
use e3_request::E3Meta;
use e3_utils::NotifySync;
use e3_utils::MAILBOX_LIMIT;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

/// Build an `E3Meta` from an `E3Requested` event's fields.
fn e3_meta_from(req: &E3Requested) -> E3Meta {
    E3Meta {
        seed: req.seed,
        threshold_n: req.threshold_n,
        threshold_m: req.threshold_m,
        params_preset: req.params_preset,
        params: req.params.clone(),
        error_size: req.error_size.clone(),
        proof_aggregation_enabled: req.proof_aggregation_enabled,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CiphernodeSelectorState {
    pub e3_cache: HashMap<E3id, E3Meta>,
    pub committees: HashMap<E3id, Committee>,
    pub expelled: HashMap<E3id, Vec<u64>>,
    /// Party ids the local node presumes unresponsive for failover purposes.
    /// Treated identically to `expelled` when computing the active aggregator,
    /// but populated by local liveness signals rather than on-chain expulsion.
    /// Empty by default, so behaviour is unchanged unless a standby is promoted.
    pub unresponsive: HashMap<E3id, Vec<u64>>,
    pub is_aggregator: HashMap<E3id, bool>,
}

#[derive(Message, Debug, Clone, Copy)]
#[rtype(result = "()")]
pub struct EmitPersistedAggregatorState;

/// CiphernodeSelector is an actor that determines if a ciphernode is part of a committee and if so
/// emits a TicketGenerated event (score sortition) to the event bus
pub struct CiphernodeSelector {
    bus: BusHandle,
    address: String,
    state: Persistable<CiphernodeSelectorState>,
}

impl Actor for CiphernodeSelector {
    type Context = Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

impl CiphernodeSelector {
    pub fn new(
        bus: &BusHandle,
        state: Persistable<CiphernodeSelectorState>,
        address: &str,
    ) -> Self {
        Self {
            bus: bus.clone(),
            state,
            address: address.to_owned(),
        }
    }

    pub async fn attach(
        bus: &BusHandle,
        selector_store: Repository<CiphernodeSelectorState>,
        address: &str,
    ) -> Result<Addr<Self>> {
        let state = selector_store
            .load_or_default(CiphernodeSelectorState::default())
            .await?;
        let addr = CiphernodeSelector::new(bus, state, address).start();

        bus.subscribe(EventType::E3Requested, addr.clone().recipient());
        bus.subscribe(EventType::E3RequestComplete, addr.clone().recipient());
        bus.subscribe(EventType::CommitteeFinalized, addr.clone().recipient());
        bus.subscribe(EventType::CommitteeMemberExpelled, addr.clone().recipient());
        bus.subscribe(EventType::Shutdown, addr.clone().recipient());

        info!("CiphernodeSelector listening!");
        Ok(addr)
    }

    fn update_aggregator_status(
        &mut self,
        e3_id: &E3id,
        ec: &EventContext<Sequenced>,
        force_emit: bool,
    ) -> Result<()> {
        let Some(state) = self.state.get() else {
            bail!("Could not get selector state");
        };

        let committee = state
            .committees
            .get(e3_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Missing finalized committee for {}", e3_id))?;
        let expelled = state.expelled.get(e3_id).cloned().unwrap_or_default();
        let unresponsive = state.unresponsive.get(e3_id).cloned().unwrap_or_default();
        let is_aggregator = committee.effective_aggregator(&self.address, &expelled, &unresponsive);
        let previous = state.is_aggregator.get(e3_id).copied();

        self.state.try_mutate(ec, |mut selector_state| {
            selector_state
                .is_aggregator
                .insert(e3_id.clone(), is_aggregator);
            Ok(selector_state)
        })?;

        if force_emit || previous != Some(is_aggregator) {
            self.bus.publish(
                AggregatorChanged {
                    e3_id: e3_id.clone(),
                    is_aggregator,
                },
                ec.clone(),
            )?;
        }

        Ok(())
    }
}

impl Handler<InterfoldEvent> for CiphernodeSelector {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        match msg {
            InterfoldEventData::E3Requested(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::E3RequestComplete(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CommitteeFinalized(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CommitteeMemberExpelled(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::Shutdown(data) => self.notify_sync(ctx, data),
            _ => (),
        }
    }
}

/// Handles `E3Requested` events received directly from the EventBus.
///
/// This handler populates `e3_cache` during sync replay, when `Sortition` gates its
/// `E3Requested` subscription behind `EffectsEnabled` and therefore does NOT forward
/// `WithSortitionTicket` messages to us. Without this handler the cache would be empty
/// when `CommitteeFinalized` arrives during replay, causing a missing-meta error.
///
/// During live operation both this handler AND the `WithSortitionTicket` handler fire for
/// the same E3. `or_insert` ensures the first write wins; the `WithSortitionTicket`
/// handler then overwrites with identical data via `insert`.
impl Handler<TypedEvent<E3Requested>> for CiphernodeSelector {
    type Result = ();

    fn handle(&mut self, msg: TypedEvent<E3Requested>, _: &mut Self::Context) -> Self::Result {
        trap(EType::Sortition, &self.bus.with_ec(msg.get_ctx()), || {
            self.state.try_mutate(msg.get_ctx(), |mut state| {
                state
                    .e3_cache
                    .entry(msg.e3_id.clone())
                    .or_insert_with(|| e3_meta_from(&msg));
                Ok(state)
            })
        })
    }
}

impl Handler<WithSortitionTicket<TypedEvent<E3Requested>>> for CiphernodeSelector {
    type Result = ();

    fn handle(
        &mut self,
        data: WithSortitionTicket<TypedEvent<E3Requested>>,
        _: &mut Self::Context,
    ) -> Self::Result {
        trap(EType::Sortition, &self.bus.with_ec(data.get_ctx()), || {
            self.state.try_mutate(data.get_ctx(), |mut state| {
                info!(
                    "Mutating selector state: appending data: {:?}",
                    data.e3_id.clone()
                );
                state
                    .e3_cache
                    .insert(data.e3_id.clone(), e3_meta_from(&data));
                Ok(state)
            })?;

            if !data.is_selected() {
                info!(node = &data.address(), "Ciphernode was not selected");
                return Ok(());
            }
            if let Some(tid) = data.ticket_id() {
                info!(
                    node = &data.address(),
                    ticket_id = tid,
                    "Ticket generated for score sortition"
                );
                self.bus.publish(
                    TicketGenerated {
                        e3_id: data.e3_id.clone(),
                        ticket_id: TicketId::Score(tid),
                        node: data.address().to_owned(),
                        party_index: data.party_id(),
                    },
                    data.get_ctx().to_owned(),
                )?;
            }

            Ok(())
        })
    }
}

impl Handler<TypedEvent<E3RequestComplete>> for CiphernodeSelector {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<E3RequestComplete>,
        _: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::Sortition,
            &self.bus.with_ec(msg.get_ctx()),
            move || {
                self.state.try_mutate(msg.get_ctx(), |mut state| {
                    state.e3_cache.remove(&msg.e3_id);
                    state.committees.remove(&msg.e3_id);
                    state.expelled.remove(&msg.e3_id);
                    state.unresponsive.remove(&msg.e3_id);
                    state.is_aggregator.remove(&msg.e3_id);
                    Ok(state)
                })
            },
        )
    }
}

impl Handler<TypedEvent<CommitteeFinalized>> for CiphernodeSelector {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<CommitteeFinalized>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::Sortition,
            &self.bus.with_ec(msg.get_ctx()),
            move || {
                let (mut msg, ec) = msg.into_components();
                msg.sort_by_score();
                info!("CiphernodeSelector received CommitteeFinalized.");
                let bus = self.bus.clone();
                info!("Getting selector state...");
                let Some(state) = self.state.get() else {
                    bail!("Could not get selector state");
                };

                info!("Getting e3_meta...");
                let Some(e3_meta) = state.e3_cache.get(&msg.e3_id) else {
                    bail!(
                        "Could not find E3Meta on CiphernodeSelector for {}",
                        msg.e3_id
                    );
                };

                self.state.try_mutate(&ec, |mut selector_state| {
                    selector_state
                        .committees
                        .insert(msg.e3_id.clone(), Committee::new(msg.committee.clone()));
                    selector_state
                        .expelled
                        .entry(msg.e3_id.clone())
                        .or_default();
                    Ok(selector_state)
                })?;

                // Check if this node is in the finalized committee
                if let Some(party_id) = msg.committee.iter().position(|addr| addr == &self.address)
                {
                    info!(
                        node = self.address,
                        party_id = party_id,
                        "Node is in finalized committee, emitting CiphernodeSelected"
                    );

                    bus.publish(
                        CiphernodeSelected {
                            party_id: party_id as u64,
                            e3_id: msg.e3_id.clone(),
                            threshold_m: e3_meta.threshold_m,
                            threshold_n: e3_meta.threshold_n,
                            error_size: e3_meta.error_size.clone(),
                            params_preset: e3_meta.params_preset,
                            params: e3_meta.params.clone(),
                            seed: e3_meta.seed,
                        },
                        ec.clone(),
                    )?;
                } else {
                    info!(node = self.address, "Node not in finalized committee");
                }

                self.update_aggregator_status(&msg.e3_id, &ec, true)?;

                Ok(())
            },
        )
    }
}

impl Handler<TypedEvent<CommitteeMemberExpelled>> for CiphernodeSelector {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<CommitteeMemberExpelled>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(EType::Sortition, &self.bus.with_ec(msg.get_ctx()), || {
            let (msg, ec) = msg.into_components();
            let Some(party_id) = msg.party_id else {
                return Ok(());
            };

            self.state.try_mutate(&ec, |mut state| {
                let expelled = state.expelled.entry(msg.e3_id.clone()).or_default();
                if !expelled.contains(&party_id) {
                    expelled.push(party_id);
                    expelled.sort_unstable();
                }
                Ok(state)
            })?;

            self.update_aggregator_status(&msg.e3_id, &ec, false)
        })
    }
}

impl Handler<EmitPersistedAggregatorState> for CiphernodeSelector {
    type Result = ();

    fn handle(
        &mut self,
        _: EmitPersistedAggregatorState,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let Some(state) = self.state.get() else {
            return;
        };

        for (e3_id, is_aggregator) in state.is_aggregator {
            if let Err(err) = self.bus.publish_without_context(AggregatorChanged {
                e3_id,
                is_aggregator,
            }) {
                self.bus.err(EType::Sortition, err);
            }
        }
    }
}

impl Handler<Shutdown> for CiphernodeSelector {
    type Result = ();
    fn handle(&mut self, _msg: Shutdown, ctx: &mut Self::Context) -> Self::Result {
        info!("Killing CiphernodeSelector");
        ctx.stop();
    }
}
