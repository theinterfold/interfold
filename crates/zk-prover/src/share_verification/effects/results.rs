// SPDX-License-Identifier: LGPL-3.0-only

//! Tally ZK results, emit fault attribution, and handle worker errors.

use super::*;

impl ShareVerificationActor {
    /// Handle ZK verification response from multithread.
    pub(in crate::actors::share_verification) fn handle_compute_response(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
    ) {
        let (msg, _ec) = msg.into_components();

        let correlation_id = msg.correlation_id;
        let Some(pending) = self.pending.remove(&correlation_id) else {
            return; // Not our correlation ID
        };

        let zk_results: Vec<PartyVerificationResult> = match (&pending.kind, msg.response) {
            (
                VerificationKind::ShareProofs
                | VerificationKind::ThresholdDecryptionProofs
                | VerificationKind::PkGenerationProofs
                | VerificationKind::RelinRound1Proofs,
                ComputeResponseKind::Zk(ZkResponse::VerifyShareProofs(r)),
            ) => r.party_results,
            (
                VerificationKind::DecryptionProofs,
                ComputeResponseKind::Zk(ZkResponse::VerifyShareDecryptionProofs(r)),
            ) => r.party_results,
            _ => {
                error!("Unexpected ComputeResponse kind for verification — treating all dispatched parties as dishonest");
                let mut all_dishonest: BTreeSet<u64> = pending.pre_dishonest;
                all_dishonest.extend(pending.ecdsa_dishonest);
                all_dishonest.extend(pending.dispatched_party_ids);
                self.publish_complete(pending.e3_id, pending.kind, all_dishonest, pending.ec);
                return;
            }
        };

        // Pure tally (dishonest accounting + emission decisions) lives in the
        // domain service; the actor performs the resulting bus publishes.
        let tally = ShareVerifier::tally_zk_results(
            pending.pre_dishonest,
            &pending.ecdsa_dishonest,
            &pending.dispatched_party_ids,
            &zk_results,
        );

        for emission in tally.emissions {
            match emission {
                ZkPartyEmission::Failed { party_id, signed } => {
                    let addr = pending.party_addresses.get(&party_id).copied();
                    self.emit_signed_proof_failed(
                        &pending.e3_id,
                        &signed,
                        addr,
                        party_id,
                        &pending.ec,
                    );
                }
                ZkPartyEmission::Passed { party_id } => {
                    // Emit ProofVerificationPassed for each proof type from this party
                    if let Some(hashes) = pending.party_proof_hashes.get(&party_id) {
                        let addr = pending
                            .party_addresses
                            .get(&party_id)
                            .copied()
                            .unwrap_or_default();
                        let signals = pending.party_public_signals.get(&party_id);
                        let datas = pending.party_proof_data.get(&party_id);
                        for (i, &(proof_type, data_hash)) in hashes.iter().enumerate() {
                            let public_signals = signals
                                .and_then(|s| s.get(i))
                                .map(|(_, ps)| ps.clone())
                                .unwrap_or_default();
                            let proof_data = datas
                                .and_then(|d| d.get(i))
                                .map(|(_, pd)| pd.clone())
                                .unwrap_or_default();
                            if let Err(err) = self.bus.publish(
                                ProofVerificationPassed {
                                    e3_id: pending.e3_id.clone(),
                                    party_id,
                                    address: addr,
                                    proof_type,
                                    data_hash,
                                    public_signals,
                                    proof_data,
                                },
                                pending.ec.clone(),
                            ) {
                                error!("Failed to publish ProofVerificationPassed: {err}");
                            }
                        }
                    }
                }
            }
        }

        self.publish_complete(pending.e3_id, pending.kind, tally.dishonest, pending.ec);
    }

    pub(in crate::actors::share_verification) fn emit_signed_proof_failed(
        &self,
        e3_id: &E3id,
        signed_payload: &SignedProofPayload,
        recovered_addr: Option<Address>,
        party_id: u64,
        ec: &EventContext<Sequenced>,
    ) {
        let faulting_node = match recovered_addr {
            Some(addr) => addr,
            None => match signed_payload.recover_address() {
                Ok(addr) => addr,
                Err(err) => {
                    warn!(
                        "Signature recovery failed for party {} — using zero address for fault attribution: {err}",
                        party_id
                    );
                    Address::ZERO
                }
            },
        };

        if let Err(err) = self.bus.publish(
            SignedProofFailed {
                e3_id: e3_id.clone(),
                faulting_node,
                proof_type: signed_payload.payload.proof_type,
                signed_payload: signed_payload.clone(),
            },
            ec.clone(),
        ) {
            error!("Failed to publish SignedProofFailed: {err}");
        }

        // Also emit ProofVerificationFailed for AccusationManager
        let data_hash: [u8; 32] = {
            let msg = (
                Bytes::copy_from_slice(&signed_payload.payload.proof.data),
                Bytes::copy_from_slice(&signed_payload.payload.proof.public_signals),
            )
                .abi_encode();
            keccak256(&msg).into()
        };
        if let Err(err) = self.bus.publish(
            ProofVerificationFailed {
                e3_id: e3_id.clone(),
                accused_party_id: party_id,
                accused_address: faulting_node,
                proof_type: signed_payload.payload.proof_type,
                data_hash,
                signed_payload: signed_payload.clone(),
            },
            ec.clone(),
        ) {
            error!("Failed to publish ProofVerificationFailed: {err}");
        }
    }

    /// Handle computation error from multithread — clean up pending state and
    /// publish ShareVerificationComplete treating all dispatched parties as dishonest.
    pub(in crate::actors::share_verification) fn handle_compute_request_error(
        &mut self,
        msg: TypedEvent<ComputeRequestError>,
    ) {
        let (msg, _ec) = msg.into_components();

        let correlation_id = msg.correlation_id();
        let Some(pending) = self.pending.remove(correlation_id) else {
            return;
        };

        error!(
            "ZK verification computation failed for E3 {} ({:?}): {} — treating all dispatched parties as dishonest",
            pending.e3_id, pending.kind, msg
        );

        let mut all_dishonest: BTreeSet<u64> = pending.pre_dishonest;
        all_dishonest.extend(pending.ecdsa_dishonest);
        all_dishonest.extend(pending.dispatched_party_ids);
        self.publish_complete(pending.e3_id, pending.kind, all_dishonest, pending.ec);
    }
}
