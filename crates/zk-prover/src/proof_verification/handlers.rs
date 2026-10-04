// SPDX-License-Identifier: LGPL-3.0-only

//! Event routing and verification-result publication.

use super::*;

impl Actor for ProofVerificationActor {
    type Context = Context<Self>;
}

impl Handler<InterfoldEvent> for ProofVerificationActor {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        match msg {
            InterfoldEventData::CiphernodeSelected(data) => {
                self.store_preset(
                    data.e3_id,
                    data.params_preset,
                    data.threshold_m,
                    data.threshold_n,
                );
            }
            InterfoldEventData::CommitteeFinalized(mut data) => {
                // The EVM decoder already emits canonical address order, but sorting again keeps
                // this trust boundary correct for replayed/test-produced events as well.
                data.sort_by_address();
                self.store_committee(data.e3_id, &data.committee);
            }
            InterfoldEventData::EncryptionKeyReceived(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::E3RequestComplete(data) => {
                let e3_id = data.e3_id;
                self.presets.remove(&e3_id);
                self.committees.remove(&e3_id);
                self.pending.retain(|(pending_e3, _), pending| {
                    if pending_e3 != &e3_id {
                        return true;
                    }
                    if let Some(retry) = pending.retry {
                        ctx.cancel_future(retry);
                    }
                    false
                });
            }
            _ => (),
        }
    }
}

impl Handler<TypedEvent<EncryptionKeyReceived>> for ProofVerificationActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<EncryptionKeyReceived>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_encryption_key_received(msg, ctx)
    }
}

impl Handler<TypedEvent<ZkVerificationResponse>> for ProofVerificationActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ZkVerificationResponse>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        let pending_key = (msg.e3_id.clone(), msg.key.party_id);
        if let ZkVerificationOutcome::InfrastructureError(error) = &msg.outcome {
            error!(
                e3_id = %msg.e3_id,
                party_id = msg.key.party_id,
                %error,
                "C0 verification could not complete; retaining the input for retry"
            );
            self.retry_verification(pending_key, ctx);
            return;
        }
        let Some(PendingVerification {
            signed_payload,
            recovered_signer,
            retry,
            ..
        }) = self.pending.remove(&pending_key)
        else {
            return;
        };
        if let Some(retry) = retry {
            ctx.cancel_future(retry);
        }

        if matches!(msg.outcome, ZkVerificationOutcome::Valid) {
            info!(
                "C0 proof verified for party {} - accepting key",
                msg.key.party_id
            );
            let party_id = msg.key.party_id;
            let e3_id = msg.e3_id.clone();
            self.publish_key_created(msg.e3_id, msg.key, ec.clone());

            // Emit ProofVerificationPassed so AccusationManager can cache success
            {
                let data_hash: [u8; 32] = {
                    let msg = (
                        Bytes::copy_from_slice(&signed_payload.payload.proof.data),
                        Bytes::copy_from_slice(&signed_payload.payload.proof.public_signals),
                    )
                        .abi_encode();
                    keccak256(&msg).into()
                };
                if let Err(err) = self.bus.publish(
                    ProofVerificationPassed {
                        e3_id,
                        party_id,
                        address: recovered_signer,
                        proof_type: ProofType::C0PkBfv,
                        data_hash,
                        public_signals: signed_payload.payload.proof.public_signals.clone(),
                        proof_data: signed_payload.payload.proof.data.clone(),
                    },
                    ec,
                ) {
                    error!("Failed to publish ProofVerificationPassed: {err}");
                }
            }
        } else {
            error!(
                "C0 proof verification failed for party {} - rejecting key",
                msg.key.party_id
            );

            {
                warn!(
                    "Emitting SignedProofFailed for party {} (address: {recovered_signer})",
                    msg.key.party_id
                );
                if let Err(err) = self.bus.publish(
                    SignedProofFailed {
                        e3_id: msg.e3_id.clone(),
                        faulting_node: recovered_signer,
                        proof_type: signed_payload.payload.proof_type,
                        signed_payload: signed_payload.clone(),
                    },
                    ec.clone(),
                ) {
                    error!("Failed to publish SignedProofFailed: {err}");
                }

                // Emit ProofVerificationFailed for AccusationManager
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
                        e3_id: msg.e3_id.clone(),
                        accused_party_id: msg.key.party_id,
                        accused_address: recovered_signer,
                        proof_type: ProofType::C0PkBfv,
                        data_hash,
                        signed_payload,
                    },
                    ec.clone(),
                ) {
                    error!("Failed to publish ProofVerificationFailed: {err}");
                }
            }

            // NOTE: We do NOT emit E3Failed here. The on-chain SlashingManager
            // will expel the faulting node and check if the committee drops below
            // threshold. If it does, the contract emits E3Failed on-chain, which
            // the EVM reader picks up and propagates to all actors. If the committee
            // is still above threshold, the DKG continues with N-1 nodes.
        }
    }
}
