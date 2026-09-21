// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::prelude::*;
use alloy::primitives::Address;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{anyhow, bail, Context, Result};
use e3_crypto::{Cipher, SensitiveBytes};
use e3_data::Persistable;
use e3_events::{
    prelude::*, trap, AggregationInputsReady, AggregationPhase, AggregatorChanged, BusHandle,
    CiphernodeSelected, CiphertextOutputPublished, CommitmentRosterSelected,
    CommitteeMemberExcluded, CommitteeMemberExpelled, ComputeRequest, ComputeRequestError,
    ComputeRequestErrorKind, ComputeResponse, ComputeResponseKind, CorrelationId,
    DecryptionKeyShared, DecryptionShareProofSigned, DecryptionShareProofsPending, Die,
    DkgCoordination, DkgCoordinationKind, DkgDealer, DkgProofSigned,
    DkgShareDecryptionProofRequest, E3Failed, E3RequestComplete, E3Stage, E3id, EType,
    EncryptionKey, EncryptionKeyCollectionFailed, EncryptionKeyCreated, EncryptionKeyPending,
    EventContext, FailureReason, InterfoldEvent, InterfoldEventData, KeyshareCreated,
    PartyProofsToVerify, PartyShareDecryptionProofsToVerify, PkGenerationProofSigned, ProofType,
    Sequenced, ShareDecryptionProofPending, ShareVerificationComplete, ShareVerificationDispatched,
    SignedProofPayload, ThresholdShare, ThresholdShareCollectionFailed, ThresholdShareCreated,
    ThresholdShareDecryptionProofRequest, ThresholdSharePending, TypedEvent, VerificationKind,
};
use e3_fhe_params::create_deterministic_crp_from_default_seed;
use e3_fhe_params::BfvPreset;
use e3_trbfv::{
    calculate_decryption_key::CalculateDecryptionKeyResponse,
    calculate_decryption_share::{
        CalculateDecryptionShareRequest, CalculateDecryptionShareResponse,
    },
    gen_esi_sss::{GenEsiSssRequest, GenEsiSssResponse},
    gen_pk_share_and_sk_sss::{GenPkShareAndSkSssRequest, GenPkShareAndSkSssResponse},
    shares::SharedSecret,
    TrBFVConfig, TrBFVRequest, TrBFVResponse,
};
use e3_utils::utility_types::ArcBytes;
use e3_utils::{NotifySync, MAILBOX_LIMIT};
use e3_zk_helpers::CiphernodesCommitteeSize;
use fhe_traits::Serialize;
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    future::Future,
    pin::Pin,
    sync::Arc,
};
use tracing::{error, info, trace, warn};

use crate::actors::decryption_key_shared_collector::{
    AllDecryptionKeySharesCollected, DecryptionKeySharedCollectionFailed,
    DecryptionKeySharedCollector, ExpelPartyFromDecryptionKeySharedCollection,
};
use crate::actors::encryption_key_collector::{
    AllEncryptionKeysCollected, EncryptionKeyCollector, ExpelPartyFromKeyCollection,
};
use crate::actors::threshold_share_collector::{
    ExpelPartyFromShareCollection, ThresholdShareCollector,
};
use crate::domain::timeout_policy::{
    resolve_threshold_share_schedule, resolve_timeout, DkgTimeoutPhase,
};
use crate::domain::{
    build_decryption_key_plan, build_shares_generated_plan, dealer_identity, generate_bfv_keypair,
    select_ready_roster, AggregatingDecryptionKey, BfvKeypairMaterial,
    CollectingEncryptionKeysData, Decrypting, DecryptionKeyPlan, GeneratingDecryptionProof,
    GeneratingThresholdShareData, KeyshareState, ProofRequestData, ReadyForDecryption,
    ReceivedShareProofs, ThresholdKeyshareState,
};

#[path = "recovery_state.rs"]
mod recovery_state;
pub use recovery_state::{
    RecoveryPayloadRef, ThresholdKeyshareRecoveryState, THRESHOLD_KEYSHARE_RECOVERY_SCHEMA_VERSION,
};
#[path = "recovery_payloads.rs"]
mod recovery_payloads;
pub use recovery_payloads::ThresholdKeyshareRecoveryPayloads;

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[rtype(result = "()")]
pub struct GenPkShareAndSkSss(CiphernodeSelected);

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[rtype(result = "()")]
pub struct GenEsiSss {
    pub ciphernode_selected: CiphernodeSelected,
    pub e_sm_raw: SensitiveBytes,
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct AllThresholdSharesCollected {
    /// Threshold shares sorted by ascending `party_id`.
    shares: Vec<Arc<ThresholdShare>>,
    /// Proofs from each sender, ordered by party_id (parallel to shares).
    share_proofs: Vec<ReceivedShareProofs>,
}

impl AllThresholdSharesCollected {
    pub fn new(
        shares: HashMap<u64, Arc<ThresholdShare>>,
        proofs: HashMap<u64, ReceivedShareProofs>,
    ) -> Self {
        let mut entries: Vec<_> = shares.into_iter().collect();
        entries.sort_by_key(|(k, _)| *k);
        let (party_ids, shares): (Vec<_>, Vec<_>) = entries.into_iter().unzip();
        let share_proofs = party_ids
            .iter()
            .map(|pid| {
                proofs.get(pid).cloned().unwrap_or(ReceivedShareProofs {
                    signed_c2a_proof: None,
                    signed_c2b_proof: None,
                    signed_c3a_proofs: Vec::new(),
                    signed_c3b_proofs: Vec::new(),
                })
            })
            .collect();
        Self {
            shares,
            share_proofs,
        }
    }
}

pub struct ThresholdKeyshareParams {
    pub bus: BusHandle,
    pub cipher: Arc<Cipher>,
    pub state: Persistable<ThresholdKeyshareState>,
    pub share_enc_preset: BfvPreset,
    pub interfold_address: Address,
    pub recovery: Persistable<ThresholdKeyshareRecoveryState>,
    pub recovery_payloads: ThresholdKeyshareRecoveryPayloads,
    pub dkg_timing_reader: DkgTimingReader,
    pub signer: PrivateKeySigner,
    pub effects_enabled: bool,
}

pub type DkgTimingFuture = Pin<Box<dyn Future<Output = Result<(u64, u64)>> + Send>>;
pub type DkgTimingReader = Arc<dyn Fn(E3id) -> DkgTimingFuture + Send + Sync>;

/// Process-local bridge data rebuilt from the versioned keyshare recovery record.
#[derive(Default)]
struct PendingKeyshareWork {
    /// Replayed key-generation output waiting for encryption-key recovery.
    gen_pk_response: Option<TypedEvent<ComputeResponse>>,
    /// Replayed ESI output waiting for key-generation recovery.
    gen_esi_response: Option<TypedEvent<ComputeResponse>>,
    /// Shares awaiting the C2/C3 verification result.
    shares: Vec<Arc<ThresholdShare>>,
    /// C4 requests awaiting the threshold-decryption-key result.
    share_decryption_data: Option<(
        DkgShareDecryptionProofRequest,
        Vec<DkgShareDecryptionProofRequest>,
    )>,
    /// Peer C4 artifacts awaiting verification.
    c4_verification_shares: Option<HashMap<u64, DecryptionKeyShared>>,
    /// Own plaintext DKG shares awaiting the aggregation transition.
    own_dkg_shares: Option<(SensitiveBytes, Vec<SensitiveBytes>)>,
    /// C4 completed before the signed C1 artifact became available.
    keyshare_publish: bool,
}

pub struct ThresholdKeyshare {
    bus: BusHandle,
    cipher: Arc<Cipher>,
    decryption_key_collector: Option<Addr<ThresholdShareCollector>>,
    encryption_key_collector: Option<Addr<EncryptionKeyCollector>>,
    decryption_key_shared_collector: Option<Addr<DecryptionKeySharedCollector>>,
    state: Persistable<ThresholdKeyshareState>,
    recovery: Persistable<ThresholdKeyshareRecoveryState>,
    recovery_payloads: ThresholdKeyshareRecoveryPayloads,
    share_enc_preset: BfvPreset,
    interfold_address: Address,
    dkg_timing_reader: DkgTimingReader,
    signer: PrivateKeySigner,
    active_aggregator_party_id: Option<u64>,
    is_aggregator: bool,
    effects_enabled: bool,
    roster_inputs_ready: bool,
    roster_proposal_pending: bool,
    selection_timing_pending: bool,
    pending: PendingKeyshareWork,
}

impl ThresholdKeyshare {
    fn buffer_replayed_compute_response(
        slot: &mut Option<TypedEvent<ComputeResponse>>,
        response: TypedEvent<ComputeResponse>,
        operation: &str,
    ) -> Result<()> {
        if let Some(existing) = slot.as_ref() {
            anyhow::ensure!(
                existing.response == response.response && existing.e3_id == response.e3_id,
                "conflicting replayed {operation} responses"
            );
        } else {
            *slot = Some(response);
        }
        Ok(())
    }

    pub fn new(params: ThresholdKeyshareParams) -> Self {
        let recovered = params.recovery.get().unwrap_or_default();
        let own_party_id = params.state.get().map(|state| state.party_id);
        let pending_shares = params
            .recovery_payloads
            .shares()
            .values()
            .filter(|event| Some(event.share.party_id) != own_party_id)
            .map(|event| event.share.clone())
            .collect();
        let share_decryption_data = recovered
            .decryption_share_proofs_pending
            .as_ref()
            .map(|event| (event.sk_request.clone(), event.esm_requests.clone()));
        let c4_verification_shares = (!recovered.decryption_key_shares.is_empty()).then(|| {
            recovered
                .decryption_key_shares
                .values()
                .map(|event| (event.party_id, event.clone().into_inner()))
                .collect()
        });
        Self {
            bus: params.bus,
            cipher: params.cipher,
            decryption_key_collector: None,
            encryption_key_collector: None,
            decryption_key_shared_collector: None,
            state: params.state,
            recovery: params.recovery,
            recovery_payloads: params.recovery_payloads,
            share_enc_preset: params.share_enc_preset,
            interfold_address: params.interfold_address,
            dkg_timing_reader: params.dkg_timing_reader,
            signer: params.signer,
            active_aggregator_party_id: recovered.active_aggregator_party_id,
            is_aggregator: recovered.is_aggregator,
            effects_enabled: params.effects_enabled,
            roster_inputs_ready: false,
            roster_proposal_pending: false,
            selection_timing_pending: false,
            pending: PendingKeyshareWork {
                shares: pending_shares,
                share_decryption_data,
                c4_verification_shares,
                keyshare_publish: recovered.keyshare_publish_authorized,
                ..Default::default()
            },
        }
    }

    fn store_signed_pk_generation_proof(
        &mut self,
        ec: &EventContext<Sequenced>,
        signed: SignedProofPayload,
    ) -> Result<()> {
        self.state.try_mutate(ec, |mut s| {
            match &mut s.state {
                KeyshareState::AggregatingDecryptionKey(adk) => {
                    adk.signed_pk_generation_proof = Some(signed.clone());
                }
                KeyshareState::ReadyForDecryption(rfd) => {
                    rfd.signed_pk_generation_proof = Some(signed.clone());
                }
                KeyshareState::Decrypting(d) => {
                    d.signed_pk_generation_proof = Some(signed.clone());
                }
                other => {
                    warn!(
                        "PkGenerationProofSigned in {:?} — C1 proof not stored (unexpected state)",
                        other.variant_name()
                    );
                }
            }
            Ok(s)
        })
    }

    fn keyshare_created_fields(
        state: &KeyshareState,
    ) -> Option<(&ArcBytes, &Option<SignedProofPayload>)> {
        use KeyshareState as K;
        match state {
            K::ReadyForDecryption(s) => Some((&s.pk_share, &s.signed_pk_generation_proof)),
            K::Decrypting(s) => Some((&s.pk_share, &s.signed_pk_generation_proof)),
            _ => None,
        }
    }

    fn try_finish_deferred_keyshare_publish(&mut self, ec: EventContext<Sequenced>) -> Result<()> {
        if !self.pending.keyshare_publish {
            return Ok(());
        }
        let state = self.state.try_get()?;
        let Some((_, signed)) = Self::keyshare_created_fields(&state.state) else {
            return Ok(());
        };
        if signed.is_none() {
            return Ok(());
        }
        self.pending.keyshare_publish = false;
        self.publish_keyshare_created(ec)
    }
}

impl Actor for ThresholdKeyshare {
    type Context = actix::Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

#[path = "effects/mod.rs"]
mod effects;
#[path = "handlers.rs"]
mod handlers;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
