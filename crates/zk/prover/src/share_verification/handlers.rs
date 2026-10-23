// SPDX-License-Identifier: LGPL-3.0-only

//! Actix envelope routing for proof verification.

use super::*;

impl Actor for ShareVerificationActor {
    type Context = Context<Self>;
}

impl Handler<InterfoldEvent> for ShareVerificationActor {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        match msg {
            InterfoldEventData::CommitteeFinalized(mut data) => {
                // Mirror the C0 verifier's canonical ordering at this trust boundary. Replayed and
                // test-produced events are not assumed to have passed through the EVM decoder.
                data.sort_by_address();
                self.store_committee(data.e3_id, &data.committee);
            }
            InterfoldEventData::ShareVerificationDispatched(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ComputeResponse(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ComputeRequestError(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CommitmentConsistencyCheckComplete(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::E3RequestComplete(data) => {
                let e3_id = data.e3_id;
                self.committees.remove(&e3_id);
                self.pending.retain(|_, pending| pending.e3_id != e3_id);
                self.pending_consistency
                    .retain(|_, pending| pending.e3_id != e3_id);
            }
            _ => (),
        }
    }
}

impl Handler<TypedEvent<ShareVerificationDispatched>> for ShareVerificationActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ShareVerificationDispatched>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_share_verification_dispatched(msg)
    }
}

impl Handler<TypedEvent<ComputeResponse>> for ShareVerificationActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_compute_response(msg)
    }
}

impl Handler<TypedEvent<ComputeRequestError>> for ShareVerificationActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ComputeRequestError>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_compute_request_error(msg)
    }
}

impl Handler<TypedEvent<CommitmentConsistencyCheckComplete>> for ShareVerificationActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<CommitmentConsistencyCheckComplete>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_consistency_check_complete(msg)
    }
}
