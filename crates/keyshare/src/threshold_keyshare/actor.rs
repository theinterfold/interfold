// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::prelude::*;
use alloy::primitives::Address;
use anyhow::{anyhow, bail, Context, Result};
use e3_crypto::{Cipher, SensitiveBytes};
use e3_data::Persistable;
use e3_events::{
    prelude::*, trap, BusHandle, CiphernodeSelected, CiphertextOutputPublished,
    CommitteeMemberExcluded, CommitteeMemberExpelled, ComputeRequest, ComputeResponse,
    ComputeResponseKind, CorrelationId, DecryptionKeyShared, DecryptionShareProofSigned,
    DecryptionShareProofsPending, Die, DkgProofSigned, DkgShareDecryptionProofRequest, E3Failed,
    E3RequestComplete, E3Stage, EType, EncryptionKey, EncryptionKeyCollectionFailed,
    EncryptionKeyCreated, EncryptionKeyPending, EventContext, FailureReason, InterfoldEvent,
    InterfoldEventData, KeyshareCreated, PartyProofsToVerify, PartyShareDecryptionProofsToVerify,
    PkGenerationProofSigned, ProofType, Sequenced, ShareDecryptionProofPending,
    ShareVerificationComplete, ShareVerificationDispatched, SignedProofPayload, ThresholdShare,
    ThresholdShareCollectionFailed, ThresholdShareCreated, ThresholdShareDecryptionProofRequest,
    ThresholdSharePending, TypedEvent, VerificationKind,
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
use crate::domain::timeout_policy::{resolve_timeout, DkgTimeoutPhase};
use crate::domain::{
    build_decryption_key_plan, build_shares_generated_plan, generate_bfv_keypair,
    AggregatingDecryptionKey, BfvKeypairMaterial, CollectingEncryptionKeysData, Decrypting,
    DecryptionKeyPlan, GeneratingDecryptionProof, GeneratingThresholdShareData, KeyshareState,
    ProofRequestData, ReadyForDecryption, ReceivedShareProofs, ThresholdKeyshareState,
};

#[path = "recovery_state.rs"]
mod recovery_state;
pub use recovery_state::{
    ThresholdKeyshareRecoveryState, THRESHOLD_KEYSHARE_RECOVERY_SCHEMA_VERSION,
};

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
    /// Node-local directory for CKKS artifacts (joint relin keys land in
    /// `<dir>/relin-keys/<e3_id>/`). `None` = no persistent data dir
    /// (in-process tests); keys are then not written.
    pub ckks_artifacts_dir: Option<std::path::PathBuf>,
    /// ZK backend circuits directory for the fail-closed CKKS artifact
    /// gate (`None` = no backend; presence check skipped).
    pub zk_circuits_dir: Option<std::path::PathBuf>,
    /// Durable per-chunk log of received `RelinCeremonyShare` events for
    /// this E3 plus the chunks it held at hydrate (replayed into the
    /// rebuilt machine on `EffectsEnabled`). `None` = no durable log
    /// (in-process tests); a restart mid-ceremony then cannot resume.
    pub ckks_ceremony: Option<CkksCeremonyRecovery>,
}

/// The ceremony chunk log and the chunks recovered from it at hydrate.
pub struct CkksCeremonyRecovery {
    /// The durable log (records new chunks as they arrive).
    pub log: effects::ckks_ceremony_log::CeremonyChunkLog,
    /// Chunks recorded before the restart, to replay once.
    pub replay: Vec<effects::ckks_ceremony_log::StoredChunk>,
}

/// Process-local bridge data rebuilt from the versioned keyshare recovery record.
#[derive(Default)]
struct PendingKeyshareWork {
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
    share_enc_preset: BfvPreset,
    interfold_address: Address,
    pending: PendingKeyshareWork,
    /// CKKS branch runtime (fhe adaptor + pure state machine). `Some` only
    /// when `state.scheme == E3Scheme::Ckks`; rebuilt on hydrate from the
    /// recovery record's machine snapshot.
    ckks: Option<effects::ckks_shell::CkksRuntime>,
    /// See [`ThresholdKeyshareParams::ckks_artifacts_dir`].
    ckks_artifacts_dir: Option<std::path::PathBuf>,
    /// See [`ThresholdKeyshareParams::zk_circuits_dir`].
    zk_circuits_dir: Option<std::path::PathBuf>,
    /// See [`ThresholdKeyshareParams::ckks_ceremony`].
    ckks_ceremony: Option<CkksCeremonyRecovery>,
}

impl ThresholdKeyshare {
    pub fn new(params: ThresholdKeyshareParams) -> Self {
        let recovered = params.recovery.get().unwrap_or_default();
        let own_party_id = params.state.get().map(|state| state.party_id);
        let pending_shares = recovered
            .threshold_shares
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
            share_enc_preset: params.share_enc_preset,
            interfold_address: params.interfold_address,
            pending: PendingKeyshareWork {
                shares: pending_shares,
                share_decryption_data,
                c4_verification_shares,
                keyshare_publish: recovered.keyshare_publish_authorized,
                ..Default::default()
            },
            // Rebuilt lazily: hydrate() re-runs init_ckks_runtime with the
            // persisted machine snapshot for CKKS E3s.
            ckks: None,
            ckks_artifacts_dir: params.ckks_artifacts_dir,
            zk_circuits_dir: params.zk_circuits_dir,
            ckks_ceremony: params.ckks_ceremony,
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
pub(crate) mod effects;
#[path = "handlers.rs"]
mod handlers;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[cfg(test)]
#[path = "ckks_shell_tests.rs"]
mod ckks_shell_tests;
