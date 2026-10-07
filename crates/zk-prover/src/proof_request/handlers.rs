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

        let finished = match &msg {
            InterfoldEventData::E3RequestComplete(data) => Some(&data.e3_id),
            InterfoldEventData::E3Failed(data) => Some(&data.e3_id),
            InterfoldEventData::E3StageChanged(data) if data.new_stage.is_terminal() => {
                Some(&data.e3_id)
            }
            _ => None,
        };
        if let Some(id) = finished {
            self.finished_e3s.insert(id.clone());
            self.held_share_decryption.remove(id);
            self.pending_share_decryption.remove(id);
            self.share_decryption_correlation
                .retain(|_, e3_id| e3_id != id);
            return;
        }

        match msg {
            InterfoldEventData::EvmLogObserved(_)
            | InterfoldEventData::CommitteePublished(_)
            | InterfoldEventData::CommitteePublicKeyChunkPublished(_)
            | InterfoldEventData::PublicKeyAggregated(_)
            | InterfoldEventData::EffectsEnabled(_) => {
                let pending = std::mem::take(&mut self.held_share_decryption);
                for (_, request) in pending {
                    self.handle_share_decryption_proof_pending(request);
                }
            }
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
