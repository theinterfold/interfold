// SPDX-License-Identifier: LGPL-3.0-only

//! Generate and publish aggregator C5 and C7 proofs.

use super::*;

impl ProofRequestActor {
    /// Handle PkAggregationProofPending: dispatch C5 proof generation.
    pub(in crate::actors::proof_request) fn handle_pk_aggregation_proof_pending(
        &mut self,
        msg: TypedEvent<PkAggregationProofPending>,
    ) {
        let (msg, ec) = msg.into_components();
        let e3_id = msg.e3_id.clone();

        if self.pending_pk_aggregation.contains_key(&e3_id) {
            warn!(
                "Duplicate PkAggregationProofPending for E3 {} — ignoring",
                e3_id
            );
            return;
        }

        self.pending_pk_aggregation.insert(
            e3_id.clone(),
            PendingPkAggregationProof {
                ec: ec.clone(),
                request: msg.proof_request.clone(),
            },
        );

        let correlation_id = CorrelationId::new();
        self.pk_aggregation_correlation
            .insert(correlation_id, e3_id.clone());

        info!("Requesting C5 PkAggregation proof for E3 {}", e3_id);
        if let Err(err) = self.bus.publish(
            ComputeRequest::zk(
                ZkRequest::PkAggregation(msg.proof_request),
                correlation_id,
                e3_id.clone(),
            ),
            ec,
        ) {
            error!("Failed to publish C5 proof request: {err}");
            self.pk_aggregation_correlation.remove(&correlation_id);
            self.pending_pk_aggregation.remove(&e3_id);
        }
    }

    /// Handle C5 proof response — sign proof and publish PkAggregationProofSigned.
    pub(in crate::actors::proof_request) fn handle_pk_aggregation_proof_response(
        &mut self,
        correlation_id: &CorrelationId,
        proof: Proof,
    ) {
        let Some(e3_id) = self.pk_aggregation_correlation.get(correlation_id).cloned() else {
            return;
        };

        let Some(pending) = self.pending_pk_aggregation.get(&e3_id).cloned() else {
            error!(
                "No pending pk aggregation proof for E3 {} — orphan correlation",
                e3_id
            );
            return;
        };

        let Some(signed) = self.sign_proof(&e3_id, ProofType::C5PkAggregation, proof) else {
            error!("Failed to sign the local C5 proof; pending work is preserved");
            return;
        };

        self.pk_aggregation_correlation.remove(correlation_id);
        self.pending_pk_aggregation.remove(&e3_id);

        info!(
            "C5 proof signed for E3 {} (signer: {})",
            e3_id,
            self.signer.address()
        );

        if let Err(err) = self.bus.publish(
            PkAggregationProofSigned {
                e3_id: e3_id.clone(),
                signed_proof: signed,
            },
            pending.ec,
        ) {
            error!("Failed to publish PkAggregationProofSigned: {err}");
        }
    }

    /// Handle AggregationProofPending: dispatch C7 proof generation.
    pub(in crate::actors::proof_request) fn handle_aggregation_proof_pending(
        &mut self,
        msg: TypedEvent<AggregationProofPending>,
    ) {
        let (msg, ec) = msg.into_components();
        let e3_id = msg.e3_id.clone();

        if self.pending_aggregation.contains_key(&e3_id) {
            warn!(
                "Duplicate AggregationProofPending for E3 {} — ignoring",
                e3_id
            );
            return;
        }

        self.pending_aggregation
            .insert(e3_id.clone(), PendingAggregationProof { ec: ec.clone() });

        let correlation_id = CorrelationId::new();
        self.aggregation_correlation
            .insert(correlation_id, e3_id.clone());

        info!(
            "Requesting C7 DecryptedSharesAggregation proof for E3 {}",
            e3_id
        );
        if let Err(err) = self.bus.publish(
            ComputeRequest::zk(
                ZkRequest::DecryptedSharesAggregation(msg.proof_request),
                correlation_id,
                e3_id.clone(),
            ),
            ec,
        ) {
            error!("Failed to publish C7 proof request: {err}");
            self.aggregation_correlation.remove(&correlation_id);
            self.pending_aggregation.remove(&e3_id);
        }
    }

    /// Handle C7 proof response — sign proofs and publish AggregationProofSigned.
    pub(in crate::actors::proof_request) fn handle_aggregation_proof_response(
        &mut self,
        correlation_id: &CorrelationId,
        proofs: Vec<Proof>,
    ) {
        let Some(e3_id) = self.aggregation_correlation.get(correlation_id).cloned() else {
            return;
        };

        let Some(pending) = self.pending_aggregation.get(&e3_id).cloned() else {
            error!(
                "No pending aggregation proof for E3 {} — orphan correlation",
                e3_id
            );
            return;
        };

        // Sign each C7 proof
        let mut signed_proofs = Vec::with_capacity(proofs.len());
        for proof in proofs {
            let Some(signed) =
                self.sign_proof(&e3_id, ProofType::C7DecryptedSharesAggregation, proof)
            else {
                error!("Failed to sign the local C7 proof; pending work is preserved");
                return;
            };
            signed_proofs.push(signed);
        }

        self.aggregation_correlation.remove(correlation_id);
        self.pending_aggregation.remove(&e3_id);

        info!(
            "All C7 proofs signed for E3 {} (signer: {})",
            e3_id,
            self.signer.address()
        );

        if let Err(err) = self.bus.publish(
            AggregationProofSigned {
                e3_id: e3_id.clone(),
                signed_proofs,
            },
            pending.ec,
        ) {
            error!("Failed to publish AggregationProofSigned: {err}");
        }
    }
}
