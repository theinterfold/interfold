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
    BusHandle, Committee, E3id, EncryptionKey, EncryptionKeyCreated, EncryptionKeyReceived,
    EventContext, EventPublisher, EventSubscriber, EventType, InterfoldEvent, InterfoldEventData,
    Proof, ProofType, ProofVerificationFailed, ProofVerificationPassed, Sequenced,
    SignedProofFailed, SignedProofPayload, TypedEvent,
};
use e3_fhe_params::BfvPreset;
use e3_request::E3Meta;
use e3_utils::NotifySync;
use e3_zk_helpers::{compute_dkg_pk_commitment_from_public_key_bytes, CiphernodesCommitteeSize};
use tracing::{error, info, warn};

use crate::domain::proof_verification::{validate_external_key, validate_external_key_commitment};

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
    /// Canonical finalized committee in party-id order. A C0 signer must own the party slot whose
    /// BFV key it advertises; recovering any valid ECDSA address is not sufficient.
    committees: HashMap<E3id, Vec<Address>>,
    /// E3s whose CKKS proof posture makes C0 proof-free (the DKG
    /// transport escalated to `InsecureDkgWide512`, which has no compiled
    /// C0 circuit). Derived from `CkksProofPosture` over the E3's own
    /// params — never from the sender — so every actor on every node
    /// agrees.
    c0_proof_free: std::collections::HashSet<E3id>,
}

impl ProofVerificationActor {
    pub fn new(
        bus: &BusHandle,
        verifier: Recipient<TypedEvent<ZkVerificationRequest>>,
        persisted_committees: HashMap<E3id, Committee>,
        persisted_e3_metadata: HashMap<E3id, E3Meta>,
    ) -> Self {
        let mut actor = Self {
            bus: bus.clone(),
            verifier,
            pending: HashMap::new(),
            presets: HashMap::new(),
            committees: HashMap::new(),
            c0_proof_free: std::collections::HashSet::new(),
        };
        for (e3_id, meta) in persisted_e3_metadata {
            actor.store_preset(
                e3_id.clone(),
                meta.params_preset,
                meta.threshold_m,
                meta.threshold_n,
            );
            actor.record_c0_posture(e3_id, meta.scheme, meta.params_preset, &meta.params);
        }
        for (e3_id, committee) in persisted_committees {
            actor.store_committee(e3_id, committee.members());
        }
        actor
    }

    pub fn setup(
        bus: &BusHandle,
        verifier: Recipient<TypedEvent<ZkVerificationRequest>>,
        persisted_committees: HashMap<E3id, Committee>,
        persisted_e3_metadata: HashMap<E3id, E3Meta>,
    ) -> Addr<Self> {
        let addr = Self::new(bus, verifier, persisted_committees, persisted_e3_metadata).start();
        bus.subscribe(EventType::CiphernodeSelected, addr.clone().into());
        bus.subscribe(EventType::CommitteeFinalized, addr.clone().into());
        bus.subscribe(EventType::EncryptionKeyReceived, addr.clone().into());
        bus.subscribe(EventType::E3RequestComplete, addr.clone().into());
        addr
    }

    fn store_preset(
        &mut self,
        e3_id: E3id,
        preset: BfvPreset,
        threshold_m: usize,
        threshold_n: usize,
    ) {
        match CiphernodesCommitteeSize::from_threshold(threshold_m, threshold_n) {
            Ok(committee) => {
                self.presets.insert(e3_id, (preset, committee));
            }
            Err(error) => {
                error!(
                    %e3_id,
                    threshold_m,
                    threshold_n,
                    %error,
                    "ProofVerificationActor: unrecognised committee; C0 keys will be rejected"
                );
            }
        }
    }

    /// Derive + cache this E3's C0 posture from its CKKS params (the same
    /// `CkksProofPosture` the keyshare shell logs at CiphernodeSelected).
    pub(in crate::actors::proof_verification) fn store_c0_posture(
        &mut self,
        data: &e3_events::CiphernodeSelected,
    ) {
        self.record_c0_posture(
            data.e3_id.clone(),
            data.scheme,
            data.params_preset,
            &data.params,
        );
    }

    fn record_c0_posture(
        &mut self,
        e3_id: E3id,
        scheme: e3_events::E3Scheme,
        params_preset: BfvPreset,
        params: &[u8],
    ) {
        if scheme != e3_events::E3Scheme::Ckks {
            return;
        }
        let standard = params_preset.dkg_counterpart().unwrap_or(params_preset);
        match e3_fhe_params::ckks_presets::CkksProofPosture::from_bytes(standard, params) {
            Ok(posture) => {
                if let e3_fhe_params::ckks_presets::ProofPosture::ProofFree(reason) = posture.c0 {
                    info!(%e3_id, "C0 keys for this CKKS E3 are accepted proof-free: {reason}");
                    self.c0_proof_free.insert(e3_id);
                }
            }
            Err(error) => {
                error!(%e3_id, %error, "could not derive the CKKS proof posture");
            }
        }
    }

    pub(in crate::actors::proof_verification) fn is_c0_proof_free(&self, e3_id: &E3id) -> bool {
        self.c0_proof_free.contains(e3_id)
    }

    fn store_committee(&mut self, e3_id: E3id, members: &[String]) {
        match members
            .iter()
            .map(|node| node.parse())
            .collect::<Result<Vec<Address>, _>>()
        {
            Ok(committee) => {
                self.committees.insert(e3_id, committee);
            }
            Err(error) => {
                error!(
                    %e3_id,
                    %error,
                    "Finalized committee contains an invalid address; C0 keys will be rejected"
                );
            }
        }
    }
}

#[path = "effects.rs"]
mod effects;
#[path = "handlers.rs"]
mod handlers;

#[cfg(test)]
#[path = "actor_tests.rs"]
mod tests;
