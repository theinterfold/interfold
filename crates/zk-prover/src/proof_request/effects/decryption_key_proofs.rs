// SPDX-License-Identifier: LGPL-3.0-only

//! Generate, correlate, sign, and publish C4 proof bundles.

use super::*;

impl ProofRequestActor {
    /// Handle DecryptionShareProofsPending: dispatch C4 proof generation.
    pub(in crate::actors::proof_request) fn handle_decryption_share_proofs_pending(
        &mut self,
        msg: TypedEvent<DecryptionShareProofsPending>,
    ) {
        let (msg, ec) = msg.into_components();
        let e3_id = msg.e3_id.clone();

        if self.pending_decryption.contains_key(&e3_id) {
            warn!(
                "Duplicate DecryptionShareProofsPending for E3 {} — ignoring",
                e3_id
            );
            return;
        }

        self.pending_decryption.insert(
            e3_id.clone(),
            PendingDecryptionProofs {
                party_id: msg.party_id,
                node: msg.node,
                ec: ec.clone(),
                sk_proof: None,
            },
        );

        // Dispatch the C4a share-decryption proof. The planner owns the sequence
        // number. This actor allocates the correlation id and publishes the request.
        let c4_base_seq = self
            .node_agg_meta
            .get(&e3_id)
            .map(NodeAggregationMeta::c4_base_seq)
            .unwrap_or(0);
        for item in plan_decryption_dispatch(msg.sk_request, c4_base_seq) {
            let corr = CorrelationId::new();
            self.decryption_correlation
                .insert(corr, (e3_id.clone(), item.kind, item.seq));
            if let Err(err) = self.bus.publish(
                ComputeRequest::zk(item.request, corr, e3_id.clone()),
                ec.clone(),
            ) {
                error!("Failed to publish C4 proof request: {err}");
                self.decryption_correlation
                    .retain(|_, (eid, _, _)| *eid != e3_id);
                self.pending_decryption.remove(&e3_id);
                return;
            }
        }
    }

    /// Handle a C4 proof response — store and check completeness.
    pub(in crate::actors::proof_request) fn handle_decryption_proof_response(
        &mut self,
        correlation_id: &CorrelationId,
        proof: Proof,
        ec: &EventContext<Sequenced>,
    ) {
        let Some((e3_id, kind, seq)) = self.decryption_correlation.remove(correlation_id) else {
            return;
        };

        let Some(pending) = self.pending_decryption.get_mut(&e3_id) else {
            error!(
                "No pending decryption proofs for E3 {} — orphan correlation",
                e3_id
            );
            return;
        };

        let proof_for_agg = proof.clone();
        match kind {
            DecryptionProofKind::SecretKey => {
                info!("Received C4a SK decryption proof for E3 {}", e3_id);
                pending.sk_proof = Some(proof);
            }
        }

        if let Some(meta) = self.node_agg_meta.get(&e3_id) {
            if self.proof_aggregation_enabled {
                if let Err(err) = self.bus.publish(
                    DKGInnerProofReady {
                        e3_id: e3_id.clone(),
                        party_id: meta.party_id,
                        proof: proof_for_agg,
                        seq,
                    },
                    ec.clone(),
                ) {
                    error!(
                        "Failed to publish DKGInnerProofReady for C4 seq={}: {err}",
                        seq
                    );
                }
            }
        }

        if pending.is_complete() {
            info!(
                "All C4 proofs complete for E3 {} — signing and publishing DecryptionKeyShared",
                e3_id
            );
            let pending = self.pending_decryption[&e3_id].clone();
            if self.sign_and_publish_decryption_key_shared(&e3_id, pending) {
                self.pending_decryption.remove(&e3_id);
            }
        }
    }

    /// Sign all C4 proofs and publish DecryptionKeyShared (Exchange #3).
    pub(in crate::actors::proof_request) fn sign_and_publish_decryption_key_shared(
        &mut self,
        e3_id: &E3id,
        pending: PendingDecryptionProofs,
    ) -> bool {
        // Sign C4a (SK decryption proof)
        let Some(signed_sk) = self.sign_proof(
            e3_id,
            ProofType::C4aSkShareDecryption,
            pending.sk_proof.expect("checked in is_complete"),
        ) else {
            error!("Failed to sign the local C4a proof; pending work is preserved");
            return false;
        };

        info!(
            "All C4 proofs signed for E3 {} party {} (signer: {})",
            e3_id,
            pending.party_id,
            self.signer.address()
        );

        if let Err(err) = self.bus.publish(
            DecryptionKeyShared {
                e3_id: e3_id.clone(),
                party_id: pending.party_id,
                node: pending.node,
                signed_sk_decryption_proof: signed_sk,
                external: false,
            },
            pending.ec,
        ) {
            error!("Failed to publish DecryptionKeyShared: {err}");
        }

        true
    }
}
