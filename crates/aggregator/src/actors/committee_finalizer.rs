// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::prelude::*;
use e3_events::{
    prelude::*, trap, BusHandle, CommitteeFinalizeRequested, CommitteeRequested, E3Failed,
    E3RequestComplete, E3Stage, E3StageChanged, EType, EffectsEnabled, EventType, InterfoldEvent,
    InterfoldEventData, Shutdown, TicketGenerated, TypedEvent,
};
use e3_events::{E3id, EventContext, Sequenced};
use e3_utils::{NotifySync, MAILBOX_LIMIT};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{error, info};

const FINALIZATION_BUFFER_SECONDS: u64 = 1;
const FINALIZE_INTERVAL_SECONDS: u64 = 5;

#[derive(Clone)]
struct PendingCommitteeRequest {
    e3_id: E3id,
    committee_deadline: u64,
    ec: EventContext<Sequenced>,
}

/// CommitteeFinalizer is an actor that listens to CommitteeRequested events and dispatches
/// CommitteeFinalizeRequested events after the submission deadline has passed.
pub struct CommitteeFinalizer {
    bus: BusHandle,
    pending_committees: HashMap<String, SpawnHandle>,
    pending_requests: HashMap<String, PendingCommitteeRequest>,
    party_indexes: HashMap<String, u64>,
    effects_enabled: bool,
}

impl CommitteeFinalizer {
    pub fn new(bus: &BusHandle) -> Self {
        Self {
            bus: bus.clone(),
            pending_committees: HashMap::new(),
            pending_requests: HashMap::new(),
            party_indexes: HashMap::new(),
            effects_enabled: false,
        }
    }

    pub fn attach(bus: &BusHandle) -> Addr<Self> {
        let addr = CommitteeFinalizer::new(bus).start();

        // Subscribe to state-building / cleanup events immediately
        bus.subscribe_all(
            &[
                EventType::Shutdown,
                EventType::E3Failed,
                EventType::E3StageChanged,
                EventType::E3RequestComplete,
                EventType::TicketGenerated,
                EventType::CommitteeRequested,
                EventType::EffectsEnabled,
            ],
            addr.clone().recipient(),
        );

        addr
    }

    fn schedule_committee(
        &mut self,
        e3_id: String,
        request: PendingCommitteeRequest,
        party_index: u64,
        ctx: &mut Context<Self>,
    ) {
        if self.pending_committees.contains_key(&e3_id) {
            return;
        }

        let committee_deadline = request.committee_deadline;
        let request_e3_id = request.e3_id.clone();
        let ec = request.ec.clone();
        let e3_id_for_async = e3_id.clone();

        let fut = async move {
            match e3_evm::helpers::get_current_timestamp().await {
                Ok(timestamp) => Some(timestamp),
                Err(e) => {
                    error!(
                        e3_id = %e3_id_for_async,
                        error = %e,
                        "Failed to get current timestamp from RPC"
                    );
                    None
                }
            }
        };

        ctx.spawn(
            fut.into_actor(self)
                .then(move |current_timestamp, act, ctx| {
                    if let Some(current_timestamp) = current_timestamp {
                        let seconds_until_deadline = committee_deadline.saturating_sub(current_timestamp) + FINALIZATION_BUFFER_SECONDS
                            + (party_index * FINALIZE_INTERVAL_SECONDS);

                        info!(
                            e3_id = %e3_id,
                            party_index,
                            committee_deadline,
                            current_timestamp,
                            seconds_to_wait = seconds_until_deadline,
                            "Scheduling committee finalization"
                        );

                        let bus = act.bus.clone();
                        let e3_id_clone = e3_id.clone();
                        let ec_clone = ec.clone();

                        let handle = ctx.run_later(
                            Duration::from_secs(seconds_until_deadline),
                            move |act, _ctx| {
                                info!(e3_id = %e3_id_clone, party_index, "Dispatching CommitteeFinalizeRequested event");

                                trap(EType::Sortition, &act.bus.with_ec(&ec_clone), || {
                                    bus.publish(
                                        CommitteeFinalizeRequested {
                                            e3_id: request_e3_id.clone(),
                                        },
                                        ec_clone.clone(),
                                    )?;
                                    Ok(())
                                });

                                act.pending_committees.remove(&e3_id_clone);
                            },
                        );

                        act.pending_committees.insert(e3_id.clone(), handle);
                    }

                    async {}.into_actor(act)
                }),
        );
    }

    fn schedule_if_ready(&mut self, e3_id: &str, ctx: &mut Context<Self>) {
        if !self.effects_enabled {
            return;
        }

        let Some(request) = self.pending_requests.get(e3_id).cloned() else {
            return;
        };
        let Some(party_index) = self.party_indexes.get(e3_id).copied() else {
            return;
        };

        self.schedule_committee(e3_id.to_owned(), request, party_index, ctx);
    }
}

impl Actor for CommitteeFinalizer {
    type Context = Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

impl Handler<InterfoldEvent> for CommitteeFinalizer {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        match msg {
            InterfoldEventData::CommitteeRequested(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::EffectsEnabled(data) => self.notify_sync(ctx, data),
            InterfoldEventData::TicketGenerated(data) => self.notify_sync(ctx, data),
            InterfoldEventData::Shutdown(data) => self.notify_sync(ctx, data),
            InterfoldEventData::E3Failed(data) => self.notify_sync(ctx, TypedEvent::new(data, ec)),
            InterfoldEventData::E3RequestComplete(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::E3StageChanged(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            _ => (),
        }
    }
}

impl Handler<TypedEvent<CommitteeRequested>> for CommitteeFinalizer {
    type Result = ();

    // TODO: Remove all async from this function. Remove reliance on e3_evm package. Add unit test.
    fn handle(
        &mut self,
        msg: TypedEvent<CommitteeRequested>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let e3_id = msg.e3_id.to_string();
        self.pending_requests.insert(
            e3_id.clone(),
            PendingCommitteeRequest {
                e3_id: msg.e3_id.clone(),
                committee_deadline: msg.committee_deadline,
                ec: msg.get_ctx().clone(),
            },
        );
        self.schedule_if_ready(&e3_id, ctx);
    }
}

impl Handler<TicketGenerated> for CommitteeFinalizer {
    type Result = ();

    fn handle(&mut self, msg: TicketGenerated, ctx: &mut Self::Context) -> Self::Result {
        let Some(party_index) = msg.party_index else {
            return;
        };

        let e3_id = msg.e3_id.to_string();
        self.party_indexes.insert(e3_id.clone(), party_index);
        self.schedule_if_ready(&e3_id, ctx);
    }
}

impl Handler<EffectsEnabled> for CommitteeFinalizer {
    type Result = ();

    fn handle(&mut self, _msg: EffectsEnabled, ctx: &mut Self::Context) -> Self::Result {
        self.effects_enabled = true;
        let e3_ids: Vec<String> = self.pending_requests.keys().cloned().collect();
        for e3_id in e3_ids {
            self.schedule_if_ready(&e3_id, ctx);
        }
    }
}

impl Handler<Shutdown> for CommitteeFinalizer {
    type Result = ();
    fn handle(&mut self, _msg: Shutdown, ctx: &mut Self::Context) -> Self::Result {
        info!("Killing CommitteeFinalizer");
        // Cancel all pending finalization tasks
        for (_, handle) in self.pending_committees.drain() {
            ctx.cancel_future(handle);
        }
        ctx.stop();
    }
}

impl Handler<TypedEvent<E3Failed>> for CommitteeFinalizer {
    type Result = ();
    fn handle(&mut self, msg: TypedEvent<E3Failed>, ctx: &mut Self::Context) -> Self::Result {
        let e3_id_str = msg.e3_id.to_string();
        if let Some(handle) = self.pending_committees.remove(&e3_id_str) {
            info!(
                e3_id = %msg.e3_id,
                reason = ?msg.reason,
                "E3 failed — cancelling pending committee finalization timer"
            );
            ctx.cancel_future(handle);
        }
        self.pending_requests.remove(&e3_id_str);
        self.party_indexes.remove(&e3_id_str);
    }
}

impl Handler<TypedEvent<E3StageChanged>> for CommitteeFinalizer {
    type Result = ();
    fn handle(&mut self, msg: TypedEvent<E3StageChanged>, ctx: &mut Self::Context) -> Self::Result {
        match &msg.new_stage {
            E3Stage::Complete | E3Stage::Failed => {
                let e3_id_str = msg.e3_id.to_string();
                if let Some(handle) = self.pending_committees.remove(&e3_id_str) {
                    info!(
                        e3_id = %msg.e3_id,
                        stage = ?msg.new_stage,
                        "E3 reached terminal stage — cancelling pending committee finalization timer"
                    );
                    ctx.cancel_future(handle);
                }
                self.pending_requests.remove(&e3_id_str);
                self.party_indexes.remove(&e3_id_str);
            }
            _ => {}
        }
    }
}

impl Handler<TypedEvent<E3RequestComplete>> for CommitteeFinalizer {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<E3RequestComplete>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let e3_id_str = msg.e3_id.to_string();
        if let Some(handle) = self.pending_committees.remove(&e3_id_str) {
            ctx.cancel_future(handle);
        }
        self.pending_requests.remove(&e3_id_str);
        self.party_indexes.remove(&e3_id_str);
    }
}
