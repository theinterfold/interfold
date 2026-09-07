// SPDX-License-Identifier: LGPL-3.0-only

//! Apply a C0 proof result and emit the verified encryption-key artifact.

use super::*;

impl ProofRequestActor {
    pub(in crate::actors::proof_request) fn handle_pk_bfv_response(
        &mut self,
        correlation_id: &CorrelationId,
        proof: Proof,
        ec: &EventContext<Sequenced>,
    ) {
        let Some(pending) = self.pending.remove(correlation_id) else {
            warn!(
                "Ignoring orphaned or replayed PkBfv ComputeResponse with correlation_id {:?}",
                correlation_id
            );
            return;
        };

        let e3_id = pending.e3_id.clone();

        let mut key = (*pending.key).clone();
        key.proof = Some(proof.clone());

        // Always sign the proof payload — unsigned proofs are not published
        let payload = ProofPayload {
            e3_id: e3_id.clone(),
            proof_type: ProofType::C0PkBfv,
            proof: proof.clone(),
        };

        match SignedProofPayload::sign(payload, &self.signer) {
            Ok(signed) => {
                info!(
                    "Signed C0 proof for party {} (signer: {})",
                    key.party_id,
                    self.signer.address()
                );
                key.signed_payload = Some(signed);
            }
            Err(err) => {
                error!("Failed to sign C0 proof payload: {err} — proof will not be published");
                self.fail_dkg_round(e3_id, ec, "C0 signing error");
                return;
            }
        }

        let local_party_id = key.party_id;

        // Persist the own C0 first. It is produced once and never regenerated, and the
        // event that triggered it is not replayed after a restart (see `OwnC0Record`).
        if let Some(repo) = self.own_c0_repo(&e3_id) {
            repo.write(&OwnC0Record {
                party_id: local_party_id,
                proof: proof.clone(),
            });
        }

        if let Err(err) = self.bus.publish(
            EncryptionKeyCreated {
                e3_id: e3_id.clone(),
                key: Arc::new(key),
                external: false,
            },
            ec.clone(),
        ) {
            error!("Failed to publish EncryptionKeyCreated: {err}");
        }

        // Publish the local node's own C0 as ProofVerificationPassed so the
        // CommitmentConsistencyChecker caches it. Without this, C3 proofs from
        // other parties that encrypt under this node's pk would fail the C3→C0
        // consistency check (the local C0 target wouldn't exist in the cache).
        {
            let msg = (
                Bytes::copy_from_slice(&proof.data),
                Bytes::copy_from_slice(&proof.public_signals),
            )
                .abi_encode();
            let data_hash: [u8; 32] = keccak256(&msg).into();

            if let Err(err) = self.bus.publish(
                ProofVerificationPassed {
                    e3_id: e3_id.clone(),
                    party_id: local_party_id,
                    address: self.signer.address(),
                    proof_type: ProofType::C0PkBfv,
                    data_hash,
                    public_signals: proof.public_signals.clone(),
                    proof_data: proof.data.clone(),
                },
                ec.clone(),
            ) {
                error!("Failed to publish local C0 ProofVerificationPassed: {err}");
            }
        }

        // Emit DKGInnerProofReady for C0, or buffer if meta not yet available
        if let Some(meta) = self.node_agg_meta.get_mut(&e3_id) {
            if self.proof_aggregation_enabled {
                meta.c0_emitted = true;
                let party_id = meta.party_id;
                if let Err(err) = self.bus.publish(
                    DKGInnerProofReady {
                        e3_id: e3_id.clone(),
                        party_id,
                        proof: proof.clone(),
                        seq: 0,
                    },
                    ec.clone(),
                ) {
                    error!("Failed to publish DKGInnerProofReady for C0: {err}");
                }
            }
        } else {
            // ThresholdSharePending hasn't arrived yet — buffer C0 proof
            self.node_agg_meta.insert(
                e3_id.clone(),
                NodeAggregationMeta {
                    party_id: 0,
                    total_expected: 0,
                    pending_c0: Some(proof),
                    c0_emitted: false,
                },
            );
        }
    }
}
