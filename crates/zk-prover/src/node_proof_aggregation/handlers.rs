// SPDX-License-Identifier: LGPL-3.0-only

//! Event routing and compute-result handling.

use super::*;

impl Actor for NodeProofAggregator {
    type Context = Context<Self>;
}

impl Handler<InterfoldEvent> for NodeProofAggregator {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, _ctx: &mut Self::Context) -> Self::Result {
        let (data, ec) = msg.into_components();
        match data {
            InterfoldEventData::DkgFoldAttestationContextEstablished(data) => {
                self.handle_dkg_fold_attestation_context(TypedEvent::new(data, ec));
            }
            InterfoldEventData::ThresholdSharePending(data) => {
                self.handle_threshold_share_pending(TypedEvent::new(data, ec));
            }
            InterfoldEventData::DKGInnerProofReady(data) => {
                self.handle_inner_proof_ready(TypedEvent::new(data, ec));
            }
            InterfoldEventData::ComputeResponse(data) => {
                self.handle_compute_response(TypedEvent::new(data, ec));
            }
            InterfoldEventData::ComputeRequestError(data) => {
                self.handle_compute_request_error(TypedEvent::new(data, ec));
            }
            _ => {}
        }
    }
}

impl Handler<TypedEvent<DkgFoldAttestationContextEstablished>> for NodeProofAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<DkgFoldAttestationContextEstablished>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_dkg_fold_attestation_context(msg);
    }
}

impl Handler<TypedEvent<ThresholdSharePending>> for NodeProofAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ThresholdSharePending>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_threshold_share_pending(msg);
    }
}

impl Handler<TypedEvent<DKGInnerProofReady>> for NodeProofAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<DKGInnerProofReady>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_inner_proof_ready(msg);
    }
}

impl Handler<TypedEvent<ComputeResponse>> for NodeProofAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_compute_response(msg);
    }
}

impl Handler<TypedEvent<ComputeRequestError>> for NodeProofAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ComputeRequestError>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_compute_request_error(msg);
    }
}

impl NodeProofAggregator {
    pub(super) fn handle_dkg_fold_attestation_context(
        &mut self,
        msg: TypedEvent<DkgFoldAttestationContextEstablished>,
    ) {
        let (msg, _) = msg.into_components();
        if msg.schema_version == DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION {
            self.dkg_fold_attestation_contexts_by_e3
                .insert(msg.e3_id, msg.context);
        }
    }

    pub(super) fn dkg_fold_attestation_context_for(
        &self,
        e3_id: &E3id,
    ) -> Option<DkgFoldAttestationContext> {
        if let Some(context) = self.dkg_fold_attestation_contexts_by_e3.get(e3_id) {
            return Some(*context);
        }

        let chain_id = e3_id.chain_id();
        match self.dkg_fold_attestation_contexts_by_chain.get(&chain_id) {
            Some(Some(context)) => Some(*context),
            Some(None) => None,
            None => {
                warn!(chain_id, "no DKG fold-attestation context available for E3");
                None
            }
        }
    }

    pub(super) fn handle_compute_response(&mut self, msg: TypedEvent<ComputeResponse>) {
        let (msg, _ec) = msg.into_components();
        if let ComputeResponseKind::Zk(ZkResponse::NodeDkgFold(resp)) = msg.response {
            self.handle_node_dkg_response(&msg.correlation_id, resp.proof);
        }
    }

    pub(super) fn handle_compute_request_error(&mut self, msg: TypedEvent<ComputeRequestError>) {
        let (msg, ec) = msg.into_components();
        let Some(e3_id) = self.fold_correlation.remove(msg.correlation_id()) else {
            // Every compute-dispatching actor receives every error, so an unowned correlation
            // is another actor's failure, not a fault here.
            debug!(
                "NodeProofAggregator: ignored compute error for correlation {:?} held by another actor: {msg}",
                msg.correlation_id()
            );
            return;
        };

        error!(
            "NodeProofAggregator: NodeDkgFold failed for E3 {}: {msg} — aggregation aborted",
            e3_id
        );
        let state = self.states.remove(&e3_id);
        warn!(
            "NodeProofAggregator: E3 {} NodeDkgFold failed — publishing E3Failed",
            e3_id
        );

        if let Some(_state) = state {
            if let Err(err) = self.bus.publish(
                E3Failed {
                    e3_id: e3_id.clone(),
                    failed_at_stage: E3Stage::CommitteeFinalized,
                    reason: FailureReason::DKGInvalidShares,
                },
                ec,
            ) {
                error!(
                    "NodeProofAggregator: failed to publish E3Failed for E3 {}: {err}",
                    e3_id
                );
            }
        }
    }
}
