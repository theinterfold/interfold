// SPDX-License-Identifier: LGPL-3.0-only

//! Actix envelope routing into the accusation workflow.

use super::*;

impl Actor for AccusationManager {
    type Context = Context<Self>;
}

impl Handler<InterfoldEvent> for AccusationManager {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        // Only an event of this E3 is a position of its chain aggregate; `EffectsEnabled` and
        // `Shutdown` are the node's.
        if msg.get_e3_id().as_ref() == Some(self.voting.e3_id()) {
            self.last_ec = Some(ec.clone());
        }
        match msg {
            InterfoldEventData::ProofVerificationFailed(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ProofVerificationPassed(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ProofFailureAccusation(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::AccusationVote(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ComputeResponse(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ComputeRequestError(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CommitteeMemberExpelled(data) => {
                self.voting.on_member_expelled(&data);
            }
            InterfoldEventData::EffectsEnabled(_) => {
                let actions = self.voting.on_effects_enabled();
                self.apply_actions(actions, ctx);
            }
            InterfoldEventData::CommitmentConsistencyViolation(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            // A vote timeout publishes this; it changed the state before.
            InterfoldEventData::AccusationQuorumReached(_) => {}
            InterfoldEventData::E3RequestComplete(data) => {
                if data.e3_id == *self.voting.e3_id() {
                    self.end_e3(&ec, ctx);
                }
                return;
            }
            _ => return,
        }
        // Each handler above runs synchronously, so the state is complete here.
        self.save_votes();
    }
}

impl Handler<TypedEvent<ProofVerificationFailed>> for AccusationManager {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ProofVerificationFailed>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let (data, ec) = msg.into_components();
        let actions = self.voting.on_local_proof_failure(data, &ec);
        self.apply_actions(actions, ctx);
    }
}

impl Handler<TypedEvent<ProofVerificationPassed>> for AccusationManager {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ProofVerificationPassed>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let (data, _ec) = msg.into_components();
        self.voting.on_proof_verification_passed(data);
    }
}

impl Handler<TypedEvent<ProofFailureAccusation>> for AccusationManager {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ProofFailureAccusation>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let (data, ec) = msg.into_components();
        let actions = self.voting.on_accusation_received(data, &ec);
        self.apply_actions(actions, ctx);
    }
}

impl Handler<TypedEvent<AccusationVote>> for AccusationManager {
    type Result = ();

    fn handle(&mut self, msg: TypedEvent<AccusationVote>, ctx: &mut Self::Context) -> Self::Result {
        let (data, ec) = msg.into_components();
        let actions = self.voting.on_vote_received(data, &ec);
        self.apply_actions(actions, ctx);
    }
}

impl Handler<TypedEvent<ComputeResponse>> for AccusationManager {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let actions = self.voting.handle_reverification_response(msg);
        self.apply_actions(actions, ctx);
    }
}

impl Handler<TypedEvent<ComputeRequestError>> for AccusationManager {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ComputeRequestError>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.voting.handle_reverification_error(msg);
    }
}

impl Handler<TypedEvent<CommitmentConsistencyViolation>> for AccusationManager {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<CommitmentConsistencyViolation>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let (data, ec) = msg.into_components();
        let actions = self.voting.on_consistency_violation(data, &ec);
        self.apply_actions(actions, ctx);
    }
}
