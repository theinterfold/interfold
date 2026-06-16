// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Verifies `EncryptionKeyReceived` events: recovers ECDSA address, delegates
//! ZK proof to `ZkActor`, and on failure emits [`SignedProofFailed`] for
//! on-chain fault attribution.

use std::collections::HashMap;
use std::sync::Arc;

use actix::{Actor, Addr, AsyncContext, Context, Handler, Message, Recipient};
use alloy::primitives::{keccak256, Address, Bytes};
use alloy::sol_types::SolValue;
use e3_events::{
    BusHandle, E3id, EncryptionKey, EncryptionKeyCreated, EncryptionKeyReceived, EventContext,
    EventPublisher, EventSubscriber, EventType, InterfoldEvent, InterfoldEventData, Proof,
    ProofType, ProofVerificationFailed, ProofVerificationPassed, Sequenced, SignedProofFailed,
    SignedProofPayload, TypedEvent,
};
use e3_fhe_params::BfvPreset;
use e3_utils::NotifySync;
use e3_zk_helpers::CiphernodesCommitteeSize;
use tracing::{error, info, warn};

use crate::domain::proof_verification::validate_external_key;

#[derive(Debug, Message)]
#[rtype(result = "()")]
pub struct ZkVerificationRequest {
    pub proof: Proof,
    pub e3_id: E3id,
    pub key: Arc<EncryptionKey>,
    pub sender: Recipient<TypedEvent<ZkVerificationResponse>>,
    pub artifacts_dir: String,
}

#[derive(Debug, Clone, Message)]
#[rtype(result = "()")]
pub struct ZkVerificationResponse {
    pub verified: bool,
    pub error: Option<String>,
    pub e3_id: E3id,
    pub key: Arc<EncryptionKey>,
}

#[derive(Clone, Debug)]
struct PendingVerification {
    signed_payload: SignedProofPayload,
    recovered_signer: Address,
}

pub struct ProofVerificationActor {
    bus: BusHandle,
    verifier: Recipient<TypedEvent<ZkVerificationRequest>>,
    pending: HashMap<(E3id, u64), PendingVerification>,
    /// Tracks preset + committee per E3 so we can derive `artifacts_dir` for proof verification.
    presets: HashMap<E3id, (BfvPreset, CiphernodesCommitteeSize)>,
}

impl ProofVerificationActor {
    pub fn new(bus: &BusHandle, verifier: Recipient<TypedEvent<ZkVerificationRequest>>) -> Self {
        Self {
            bus: bus.clone(),
            verifier,
            pending: HashMap::new(),
            presets: HashMap::new(),
        }
    }

    pub fn setup(
        bus: &BusHandle,
        verifier: Recipient<TypedEvent<ZkVerificationRequest>>,
    ) -> Addr<Self> {
        let addr = Self::new(bus, verifier).start();
        bus.subscribe(EventType::CiphernodeSelected, addr.clone().into());
        bus.subscribe(EventType::EncryptionKeyReceived, addr.clone().into());
        addr
    }

    fn handle_encryption_key_received(
        &mut self,
        msg: TypedEvent<EncryptionKeyReceived>,
        ctx: &Context<Self>,
    ) {
        let (msg, ec) = msg.into_components();
        let validated = match validate_external_key(
            msg.key.party_id,
            msg.key.proof.as_ref(),
            msg.key.signed_payload.as_ref(),
        ) {
            Ok(validated) => validated,
            Err(reason) => {
                error!("{reason}");
                return;
            }
        };
        let proof = msg
            .key
            .proof
            .clone()
            .expect("proof present after validation");

        // Store the signed payload so we can reference it in the verification response
        self.pending.insert(
            (msg.e3_id.clone(), msg.key.party_id),
            PendingVerification {
                signed_payload: validated.signed_payload,
                recovered_signer: validated.recovered_signer,
            },
        );

        let Some((preset, committee)) = self.presets.get(&msg.e3_id).copied() else {
            error!(
                "No BfvPreset known for e3_id={} — cannot determine circuit artifacts directory. \
                 This can happen if CiphernodeSelected was missed (e.g. after restart). Rejecting key from party {}.",
                msg.e3_id, msg.key.party_id
            );
            return;
        };
        let artifacts_dir = preset.artifacts_dir_for_committee(committee.as_str());

        let request = TypedEvent::new(
            ZkVerificationRequest {
                proof: proof.clone(),
                e3_id: msg.e3_id,
                key: msg.key,
                sender: ctx.address().recipient(),
                artifacts_dir,
            },
            ec,
        );

        self.verifier.do_send(request);
    }

    fn publish_key_created(
        &self,
        e3_id: E3id,
        key: Arc<EncryptionKey>,
        ec: EventContext<Sequenced>,
    ) {
        if let Err(err) = self.bus.publish(
            EncryptionKeyCreated {
                e3_id,
                key,
                external: true,
            },
            ec,
        ) {
            error!("Failed to publish EncryptionKeyCreated: {err}");
        }
    }
}

impl Actor for ProofVerificationActor {
    type Context = Context<Self>;
}

impl Handler<InterfoldEvent> for ProofVerificationActor {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        match msg {
            InterfoldEventData::CiphernodeSelected(data) => {
                match CiphernodesCommitteeSize::from_threshold(data.threshold_m, data.threshold_n) {
                    Ok(committee) => {
                        self.presets
                            .insert(data.e3_id.clone(), (data.params_preset, committee));
                    }
                    Err(e) => {
                        error!(
                            "ProofVerificationActor: unrecognised committee for E3 {} \
                             (threshold_m={}, threshold_n={}): {e} — skipping preset registration, \
                             proof verification will be rejected if a key arrives",
                            data.e3_id, data.threshold_m, data.threshold_n
                        );
                    }
                }
            }
            InterfoldEventData::EncryptionKeyReceived(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
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
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        let pending_key = (msg.e3_id.clone(), msg.key.party_id);
        let pending = self.pending.remove(&pending_key);

        if msg.verified {
            let Some(PendingVerification {
                signed_payload,
                recovered_signer,
            }) = pending
            else {
                warn!(
                    "No pending verification for verified party {} — ignoring duplicate response",
                    msg.key.party_id
                );
                return;
            };

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
            let error_msg = msg.error.unwrap_or_else(|| "unknown error".to_string());
            error!(
                "C0 proof verification FAILED for party {} - rejecting key and stopping E3: {}",
                msg.key.party_id, error_msg
            );

            if let Some(PendingVerification {
                signed_payload,
                recovered_signer,
            }) = pending
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
