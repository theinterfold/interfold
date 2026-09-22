// SPDX-License-Identifier: LGPL-3.0-only

//! Generate and publish per-party C6 decryption-share proofs.

use super::*;

impl ProofRequestActor {
    /// Handle ShareDecryptionProofPending: dispatch C6 proof generation.
    pub(in crate::actors::proof_request) fn handle_share_decryption_proof_pending(
        &mut self,
        msg: TypedEvent<ShareDecryptionProofPending>,
    ) {
        let (msg, ec) = msg.into_components();
        let e3_id = msg.e3_id.clone();

        if self.pending_share_decryption.contains_key(&e3_id) {
            warn!(
                "Duplicate ShareDecryptionProofPending for E3 {} — ignoring",
                e3_id
            );
            return;
        }

        self.pending_share_decryption.insert(
            e3_id.clone(),
            PendingShareDecryptionProof {
                party_id: msg.party_id,
                node: msg.node,
                decryption_share: msg.decryption_share,
                ec: ec.clone(),
            },
        );

        let correlation_id = CorrelationId::new();
        self.share_decryption_correlation
            .insert(correlation_id, e3_id.clone());

        info!(
            "Requesting C6 ThresholdShareDecryption proof for E3 {}",
            e3_id
        );
        if let Err(err) = self.bus.publish(
            ComputeRequest::zk(
                ZkRequest::ThresholdShareDecryption(msg.proof_request),
                correlation_id,
                e3_id.clone(),
            ),
            ec,
        ) {
            error!("Failed to publish C6 proof request: {err}");
            self.share_decryption_correlation.remove(&correlation_id);
            self.pending_share_decryption.remove(&e3_id);
        }
    }

    /// Handle C6 proof response — sign proofs, publish DecryptionshareCreated.
    pub(in crate::actors::proof_request) fn handle_share_decryption_proof_response(
        &mut self,
        correlation_id: &CorrelationId,
        proofs: Vec<Proof>,
    ) {
        let Some(e3_id) = self
            .share_decryption_correlation
            .get(correlation_id)
            .cloned()
        else {
            return;
        };

        let Some(pending) = self.pending_share_decryption.get(&e3_id).cloned() else {
            error!(
                "No pending share decryption proof for E3 {} — orphan correlation",
                e3_id
            );
            return;
        };

        // Sign raw C6 proofs (for ShareVerification)
        let mut signed_proofs = Vec::with_capacity(proofs.len());
        for proof in proofs {
            let Some(signed) =
                self.sign_proof(&e3_id, ProofType::C6ThresholdShareDecryption, proof)
            else {
                error!("Failed to sign the local C6 proof; pending work is preserved");
                return;
            };
            signed_proofs.push(signed);
        }

        self.share_decryption_correlation.remove(correlation_id);
        self.pending_share_decryption.remove(&e3_id);

        info!(
            "All C6 proofs signed for E3 {} party {} (signer: {})",
            e3_id,
            pending.party_id,
            self.signer.address()
        );

        let ec = pending.ec;

        match self.bus.publish(
            DecryptionshareCreated {
                party_id: pending.party_id,
                node: pending.node,
                e3_id: e3_id.clone(),
                decryption_share: pending.decryption_share,
                signed_decryption_proofs: signed_proofs,
            },
            ec.clone(),
        ) {
            Ok(_) => {
                if let Err(err) = self.bus.publish(
                    DecryptionShareProofSigned {
                        e3_id: e3_id.clone(),
                    },
                    ec,
                ) {
                    error!("Failed to publish DecryptionShareProofSigned: {err}");
                }
            }
            Err(err) => {
                error!("Failed to publish DecryptionshareCreated: {err}");
            }
        }
    }
}
