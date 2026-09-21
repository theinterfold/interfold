// SPDX-License-Identifier: LGPL-3.0-only

//! Assemble and publish a complete signed C1/C2/C3 threshold-share bundle.

use super::*;

impl ProofRequestActor {
    pub(in crate::actors::proof_request) fn publish_threshold_share_with_proofs(
        &mut self,
        pending: PendingThresholdProofs,
    ) -> bool {
        let e3_id = &pending.e3_id;
        let party_id = pending.full_share.party_id;
        let ec = &pending.ec;

        // Sign C1 (PkGeneration)
        let Some(signed_pk_gen) = self.sign_proof(
            e3_id,
            ProofType::C1PkGeneration,
            pending.pk_generation_proof.expect("checked"),
        ) else {
            error!("Failed to sign the local C1 proof; pending work is preserved");
            return false;
        };

        // Sign C2a (SkShareComputation)
        let Some(signed_c2a) = self.sign_proof(
            e3_id,
            ProofType::C2aSkShareComputation,
            pending.sk_share_computation_proof.expect("checked"),
        ) else {
            error!("Failed to sign the local C2a proof; pending work is preserved");
            return false;
        };

        // Sign C2b (ESmShareComputation)
        let Some(signed_c2b) = self.sign_proof(
            e3_id,
            ProofType::C2bESmShareComputation,
            pending.e_sm_share_computation_proof.expect("checked"),
        ) else {
            error!("Failed to sign the local C2b proof; pending work is preserved");
            return false;
        };

        let Some(signed_c3a_map) = self.sign_and_group_proofs(
            e3_id,
            ProofType::C3aSkShareEncryption,
            pending
                .sk_share_encryption_proofs
                .iter()
                .map(|((recipient, _row), proof)| (*recipient, proof.clone())),
        ) else {
            error!("Failed to sign the local C3a proofs; pending work is preserved");
            return false;
        };

        let Some(signed_c3b_map) = self.sign_and_group_proofs(
            e3_id,
            ProofType::C3bESmShareEncryption,
            pending
                .e_sm_share_encryption_proofs
                .iter()
                .map(|((_esi, recipient, _row), proof)| (*recipient, proof.clone())),
        ) else {
            error!("Failed to sign the local C3b proofs; pending work is preserved");
            return false;
        };

        info!(
            "All proofs signed for E3 {} party {} (signer: {})",
            e3_id,
            party_id,
            self.signer.address()
        );

        // Publish local proof events for the node's own state tracking
        if let Err(err) = self.bus.publish(
            PkGenerationProofSigned {
                e3_id: e3_id.clone(),
                party_id,
                signed_proof: signed_pk_gen,
            },
            ec.clone(),
        ) {
            error!("Failed to publish PkGenerationProofSigned: {err}");
        }

        if let Err(err) = self.bus.publish(
            DkgProofSigned {
                e3_id: e3_id.clone(),
                party_id,
                signed_proof: signed_c2a.clone(),
            },
            ec.clone(),
        ) {
            error!("Failed to publish SkDkgProofSigned: {err}");
        }

        if let Err(err) = self.bus.publish(
            DkgProofSigned {
                e3_id: e3_id.clone(),
                party_id,
                signed_proof: signed_c2b.clone(),
            },
            ec.clone(),
        ) {
            error!("Failed to publish ESmDkgProofSigned: {err}");
        }

        // Publish C3a signed proofs (reuse already-signed proofs from signed_c3a_map)
        for signed_proofs in signed_c3a_map.values() {
            for signed in signed_proofs {
                if let Err(err) = self.bus.publish(
                    DkgProofSigned {
                        e3_id: e3_id.clone(),
                        party_id,
                        signed_proof: signed.clone(),
                    },
                    ec.clone(),
                ) {
                    error!("Failed to publish SkShareEncryptionProofSigned: {err}");
                }
            }
        }

        // Publish C3b signed proofs (reuse already-signed proofs from signed_c3b_map)
        for signed_proofs in signed_c3b_map.values() {
            for signed in signed_proofs {
                if let Err(err) = self.bus.publish(
                    DkgProofSigned {
                        e3_id: e3_id.clone(),
                        party_id,
                        signed_proof: signed.clone(),
                    },
                    ec.clone(),
                ) {
                    error!("Failed to publish ESmShareEncryptionProofSigned: {err}");
                }
            }
        }

        // Publish ThresholdShareCreated with proofs attached for each recipient
        let share = &pending.full_share;
        info!(
            "Publishing ThresholdShareCreated for E3 {} to {} parties with C0 keys",
            e3_id,
            pending.recipient_party_ids.len().saturating_sub(1)
        );

        for &real_party_id in &pending.recipient_party_ids {
            match share.extract_for_party(real_party_id as usize) {
                Some(party_share) => {
                    let proof_key = real_party_id as usize;
                    let c3a_proofs = signed_c3a_map.get(&proof_key).cloned().unwrap_or_default();
                    let c3b_proofs = signed_c3b_map.get(&proof_key).cloned().unwrap_or_default();

                    if let Err(err) = self.bus.publish(
                        ThresholdShareCreated {
                            e3_id: e3_id.clone(),
                            share: Arc::new(party_share),
                            target_party_id: real_party_id,
                            external: false,
                            signed_c2a_proof: Some(signed_c2a.clone()),
                            signed_c2b_proof: Some(signed_c2b.clone()),
                            signed_c3a_proofs: c3a_proofs,
                            signed_c3b_proofs: c3b_proofs,
                        },
                        ec.clone(),
                    ) {
                        error!(
                            "Failed to publish ThresholdShareCreated for party {}: {err}",
                            real_party_id
                        );
                    }
                }
                None if real_party_id == party_id => {
                    // Own slot is sparse (no self-encryption); nothing to publish.
                    trace!(
                        "Skipping ThresholdShareCreated for own slot (party {})",
                        real_party_id
                    );
                }
                None => {
                    error!(
                        "Missing encrypted share for recipient party {} from sender party {}; ThresholdShareCreated will not be published for that recipient",
                        real_party_id, party_id
                    );
                }
            }
        }

        true
    }
}
