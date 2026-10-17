// SPDX-License-Identifier: LGPL-3.0-only

//! Event routing and verification-result publication.

use super::*;

impl Actor for ProofVerificationActor {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        for input in std::mem::take(&mut self.recovered) {
            self.handle_encryption_key_received(input, ctx);
        }
    }
}

impl Handler<InterfoldEvent> for ProofVerificationActor {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let source = msg.source();
        let (msg, ec) = msg.into_components();
        match msg {
            InterfoldEventData::EffectsEnabled(_) => {
                if !self.effects_enabled {
                    self.effects_enabled = true;
                    for key in self.pending.keys().cloned().collect::<Vec<_>>() {
                        self.dispatch_verification(key, ctx);
                    }
                }
            }
            InterfoldEventData::EncryptionKeyCreated(data)
                if source == e3_events::EventSource::Local && data.external =>
            {
                let key = (data.e3_id, data.key.party_id);
                if self
                    .pending
                    .get(&key)
                    .is_some_and(|pending| pending.request.key == data.key)
                {
                    if let Some(pending) = self.pending.remove(&key) {
                        if let Some(retry) = pending.retry {
                            ctx.cancel_future(retry);
                        }
                    }
                }
            }
            InterfoldEventData::ProofVerificationFailed(data)
                if source == e3_events::EventSource::Local
                    && data.proof_type == ProofType::C0PkBfv =>
            {
                let key = (data.e3_id, data.accused_party_id);
                if self
                    .pending
                    .get(&key)
                    .is_some_and(|pending| pending.signed_payload == data.signed_payload)
                {
                    if let Some(pending) = self.pending.remove(&key) {
                        if let Some(retry) = pending.retry {
                            ctx.cancel_future(retry);
                        }
                    }
                }
            }
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
                self.clear_e3(&data.e3_id, ctx);
            }
            InterfoldEventData::E3StageChanged(data)
                if source == e3_events::EventSource::Evm && dkg_has_ended(&data.new_stage) =>
            {
                self.clear_e3(&data.e3_id, ctx);
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
            self.retry_verification(pending_key, error.clone(), ctx);
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
