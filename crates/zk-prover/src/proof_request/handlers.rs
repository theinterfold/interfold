// SPDX-License-Identifier: LGPL-3.0-only

//! Actix envelope routing for proof-generation workflows.

use super::*;

impl Actor for ProofRequestActor {
    type Context = Context<Self>;
}

impl Handler<InterfoldEvent> for ProofRequestActor {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();

        match msg {
            InterfoldEventData::EncryptionKeyPending(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ThresholdSharePending(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ComputeResponse(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ComputeRequestError(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::DecryptionShareProofsPending(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ShareDecryptionProofPending(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::PkAggregationProofPending(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::AggregationProofPending(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::PkGenerationCkksProofPending(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::RelinRound1ProofPending(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            _ => (),
        }
    }
}

impl Handler<TypedEvent<EncryptionKeyPending>> for ProofRequestActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<EncryptionKeyPending>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_encryption_key_pending(msg)
    }
}

impl Handler<TypedEvent<ThresholdSharePending>> for ProofRequestActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ThresholdSharePending>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_threshold_share_pending(msg);
    }
}

impl Handler<TypedEvent<ComputeResponse>> for ProofRequestActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_compute_response(msg)
    }
}

impl Handler<TypedEvent<ComputeRequestError>> for ProofRequestActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ComputeRequestError>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_compute_request_error(msg)
    }
}

impl Handler<TypedEvent<DecryptionShareProofsPending>> for ProofRequestActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<DecryptionShareProofsPending>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_decryption_share_proofs_pending(msg)
    }
}

impl Handler<TypedEvent<ShareDecryptionProofPending>> for ProofRequestActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ShareDecryptionProofPending>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_share_decryption_proof_pending(msg)
    }
}

impl Handler<TypedEvent<PkAggregationProofPending>> for ProofRequestActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<PkAggregationProofPending>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_pk_aggregation_proof_pending(msg)
    }
}

impl Handler<TypedEvent<AggregationProofPending>> for ProofRequestActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<AggregationProofPending>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_aggregation_proof_pending(msg)
    }
}

impl Handler<TypedEvent<PkGenerationCkksProofPending>> for ProofRequestActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<PkGenerationCkksProofPending>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_pk_generation_ckks_proof_pending(msg)
    }
}

impl Handler<TypedEvent<RelinRound1ProofPending>> for ProofRequestActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<RelinRound1ProofPending>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_relin_round1_proof_pending(msg)
    }
}
