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
    prelude::*, trap, AggregatorChanged, AggregatorFailoverExhausted, AggregatorLeaseUpdated,
    BusHandle, CiphernodeSelected, Committee, CommitteeFinalized, CommitteeMemberExpelled,
    CommitteePublished, E3Failed, E3Requested, E3id, EType, EventType, InterfoldEvent,
    InterfoldEventData, PlaintextOutputPublished, Shutdown, TicketGenerated, TicketId,
};
use e3_request::E3Meta;
use e3_utils::NotifySync;
use e3_utils::MAILBOX_LIMIT;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::info;

#[path = "failover.rs"]
mod failover;
#[path = "handlers.rs"]
mod handlers;

pub use failover::AggregatorFailoverState;
use failover::{
    arm_lease, decide_failover, next_attempt_deadline, EligibleAggregators, FailoverDecision,
};

/// Build an `E3Meta` from an `E3Requested` event's fields.
fn e3_meta_from(req: &E3Requested) -> E3Meta {
    E3Meta {
        seed: req.seed,
        threshold_n: req.threshold_n,
        threshold_m: req.threshold_m,
        params_preset: req.params_preset,
        params: req.params.clone(),
        error_size: req.error_size.clone(),
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
    failover: Persistable<AggregatorFailoverState>,
}

impl Actor for CiphernodeSelector {
    type Context = Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
        ctx.run_interval(Duration::from_secs(1), |actor, ctx| {
            actor.evaluate_failover(ctx);
        });
    }
}

impl CiphernodeSelector {
    pub fn new(
        bus: &BusHandle,
        state: Persistable<CiphernodeSelectorState>,
        failover: Persistable<AggregatorFailoverState>,
        address: &str,
    ) -> Self {
        Self {
            bus: bus.clone(),
            state,
            failover,
            address: address.to_owned(),
        }
    }

    pub async fn attach(
        bus: &BusHandle,
        selector_store: Repository<CiphernodeSelectorState>,
        failover_store: Repository<AggregatorFailoverState>,
        address: &str,
    ) -> Result<Addr<Self>> {
        let state = selector_store
            .load_or_default(CiphernodeSelectorState::default())
            .await?;
        let failover = failover_store
            .load_or_default(AggregatorFailoverState::default())
            .await?;
        let addr = CiphernodeSelector::new(bus, state, failover, address).start();

        bus.subscribe(EventType::E3Requested, addr.clone().recipient());
        bus.subscribe(EventType::E3RequestComplete, addr.clone().recipient());
        bus.subscribe(EventType::CommitteeFinalized, addr.clone().recipient());
        bus.subscribe(EventType::CommitteeMemberExpelled, addr.clone().recipient());
        bus.subscribe(EventType::AggregatorLeaseUpdated, addr.clone().recipient());
        bus.subscribe(EventType::CommitteePublished, addr.clone().recipient());
        bus.subscribe(
            EventType::PlaintextOutputPublished,
            addr.clone().recipient(),
        );
        bus.subscribe(EventType::E3Failed, addr.clone().recipient());
        bus.subscribe(EventType::Shutdown, addr.clone().recipient());

        info!("CiphernodeSelector listening!");
        Ok(addr)
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
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
