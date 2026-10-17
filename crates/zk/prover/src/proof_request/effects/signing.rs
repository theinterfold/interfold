// SPDX-License-Identifier: LGPL-3.0-only

//! Shared proof signing, failure publication, and grouping helpers.

use super::*;

impl ProofRequestActor {
    pub(in crate::actors::proof_request) fn handle_threshold_proof_response(
        &mut self,
        correlation_id: &CorrelationId,
        proof: Proof,
        ec: &EventContext<Sequenced>,
    ) {
        let Some((e3_id, kind, seq)) = self.threshold_correlation.remove(correlation_id) else {
            return;
        };

        let Some(pending) = self.pending_threshold.get_mut(&e3_id) else {
            error!(
                "No pending threshold proofs for E3 {} — orphan correlation",
                e3_id
            );
            return;
        };

        let proof_for_agg = proof.clone();
        pending.store_proof(&kind, proof);
        info!(
            "Received {:?} proof for E3 {} ({}/{})",
            kind,
            e3_id,
            pending.total_received(),
            pending.total_expected()
        );

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
                        "Failed to publish DKGInnerProofReady for {:?} seq={}: {err}",
                        kind, seq
                    );
                }
            }
        }

        if pending.is_complete() {
            info!(
                "All {} threshold proofs complete for E3 {}",
                pending.total_expected(),
                e3_id
            );
            let pending = self.pending_threshold[&e3_id].clone();
            if self.publish_threshold_share_with_proofs(pending) {
                self.pending_threshold.remove(&e3_id);
                self.completed_threshold.insert(e3_id);
            }
        }
    }

    pub(in crate::actors::proof_request) fn sign_proof(
        &self,
        e3_id: &E3id,
        proof_type: ProofType,
        proof: Proof,
    ) -> Option<SignedProofPayload> {
        let payload = ProofPayload {
            e3_id: e3_id.clone(),
            proof_type,
            proof,
        };
        match SignedProofPayload::sign(payload, &self.signer) {
            Ok(signed) => Some(signed),
            Err(err) => {
                error!("Failed to sign {:?} proof: {err}", proof_type);
                None
            }
        }
    }

    pub(in crate::actors::proof_request) fn sign_and_group_proofs(
        &self,
        e3_id: &E3id,
        proof_type: ProofType,
        proofs: impl Iterator<Item = (usize, Proof)>,
    ) -> Option<BTreeMap<usize, Vec<SignedProofPayload>>> {
        let mut map: BTreeMap<usize, Vec<SignedProofPayload>> = BTreeMap::new();
        for (recipient, proof) in proofs {
            let signed = self.sign_proof(e3_id, proof_type, proof)?;
            map.entry(recipient).or_default().push(signed);
        }
        Some(map)
    }
}
