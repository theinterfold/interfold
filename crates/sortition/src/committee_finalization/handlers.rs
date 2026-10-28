// SPDX-License-Identifier: LGPL-3.0-only

//! Committee deadline, cleanup, and lifecycle handlers.

use super::*;

impl Handler<InterfoldEvent> for CommitteeFinalizer {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        match msg {
            InterfoldEventData::CommitteeRequested(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::EffectsEnabled(data) => self.notify_sync(ctx, data),
            InterfoldEventData::TicketGenerated(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CommitteeFinalized(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
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

    fn handle(
        &mut self,
        msg: TypedEvent<CommitteeRequested>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let e3_id = msg.e3_id.clone();
        let request = RecoveredCommitteeRequest {
            request: (*msg).clone(),
            context: msg.get_ctx().clone(),
        };
        if let Err(error) = self.recovery.try_mutate(msg.get_ctx(), |mut recovery| {
            recovery.pending_requests.insert(e3_id, request);
            Ok(recovery)
        }) {
            self.bus.with_ec(msg.get_ctx()).err(EType::Sortition, error);
            return;
        }
        self.schedule_if_ready(&msg.e3_id, ctx);
    }
}

impl Handler<TypedEvent<TicketGenerated>> for CommitteeFinalizer {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<TicketGenerated>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        if msg.party_index.is_none() {
            return;
        }

        let e3_id = msg.e3_id.clone();
        if let Err(error) = self.recovery.try_mutate(msg.get_ctx(), |mut recovery| {
            recovery.tickets.insert(e3_id, (*msg).clone());
            Ok(recovery)
        }) {
            self.bus.with_ec(msg.get_ctx()).err(EType::Sortition, error);
            return;
        }
        self.schedule_if_ready(&msg.e3_id, ctx);
    }
}

impl Handler<EffectsEnabled> for CommitteeFinalizer {
    type Result = ();

    fn handle(&mut self, _msg: EffectsEnabled, ctx: &mut Self::Context) -> Self::Result {
        self.effects_enabled = true;
        let e3_ids: Vec<E3id> = self
            .recovery
            .get()
            .map(|recovery| recovery.pending_requests.keys().cloned().collect())
            .unwrap_or_default();
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
        if let Some(handle) = self.pending_committees.remove(&msg.e3_id) {
            info!(
                e3_id = %msg.e3_id,
                reason = ?msg.reason,
                "E3 failed — cancelling pending committee finalization timer"
            );
            ctx.cancel_future(handle);
        }
        if let Err(error) = self.recovery.try_mutate(msg.get_ctx(), |mut recovery| {
            recovery.remove(&msg.e3_id);
            Ok(recovery)
        }) {
            self.bus.with_ec(msg.get_ctx()).err(EType::Sortition, error);
        }
    }
}

impl Handler<TypedEvent<E3StageChanged>> for CommitteeFinalizer {
    type Result = ();
    fn handle(&mut self, msg: TypedEvent<E3StageChanged>, ctx: &mut Self::Context) -> Self::Result {
        match &msg.new_stage {
            E3Stage::Complete | E3Stage::Failed => {
                if let Some(handle) = self.pending_committees.remove(&msg.e3_id) {
                    info!(
                        e3_id = %msg.e3_id,
                        stage = ?msg.new_stage,
                        "E3 reached terminal stage — cancelling pending committee finalization timer"
                    );
                    ctx.cancel_future(handle);
                }
                if let Err(error) = self.recovery.try_mutate(msg.get_ctx(), |mut recovery| {
                    recovery.remove(&msg.e3_id);
                    Ok(recovery)
                }) {
                    self.bus.with_ec(msg.get_ctx()).err(EType::Sortition, error);
                }
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
        if let Some(handle) = self.pending_committees.remove(&msg.e3_id) {
            ctx.cancel_future(handle);
        }
        if let Err(error) = self.recovery.try_mutate(msg.get_ctx(), |mut recovery| {
            recovery.remove(&msg.e3_id);
            Ok(recovery)
        }) {
            self.bus.with_ec(msg.get_ctx()).err(EType::Sortition, error);
        }
    }
}

impl Handler<TypedEvent<CommitteeFinalized>> for CommitteeFinalizer {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<CommitteeFinalized>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        if let Some(handle) = self.pending_committees.remove(&msg.e3_id) {
            ctx.cancel_future(handle);
        }
        if let Err(error) = self.recovery.try_mutate(msg.get_ctx(), |mut recovery| {
            recovery.remove(&msg.e3_id);
            Ok(recovery)
        }) {
            self.bus.with_ec(msg.get_ctx()).err(EType::Sortition, error);
        }
    }
}
