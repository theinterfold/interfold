// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::prelude::*;
use anyhow::{anyhow, bail, Context, Result};
use e3_crypto::{Cipher, SensitiveBytes};
use e3_data::Persistable;
use e3_events::{
    prelude::*, trap, BusHandle, CiphernodeSelected, CiphertextOutputPublished,
    CommitteeMemberExpelled, ComputeRequest, ComputeResponse, ComputeResponseKind, CorrelationId,
    DecryptionKeyShared, DecryptionShareProofSigned, DecryptionShareProofsPending, Die,
    DkgProofSigned, DkgShareDecryptionProofRequest, E3Failed, E3RequestComplete, E3Stage, E3id,
    EType, EnclaveEvent, EnclaveEventData, EncryptionKey, EncryptionKeyCollectionFailed,
    EncryptionKeyCreated, EncryptionKeyPending, EventContext, FailureReason, KeyshareCreated,
    PartyId, PartyProofsToVerify, PartyShareDecryptionProofsToVerify, PkGenerationProofRequest,
    PkGenerationProofSigned, ProofType, Sequenced, ShareComputationProofRequest,
    ShareDecryptionProofPending, ShareEncryptionProofRequest, ShareVerificationComplete,
    ShareVerificationDispatched, SignedProofPayload, ThresholdShare,
    ThresholdShareCollectionFailed, ThresholdShareCreated, ThresholdShareDecryptionProofRequest,
    ThresholdSharePending, TypedEvent, VerificationKind,
};
use e3_fhe_params::create_deterministic_crp_from_default_seed;
use e3_fhe_params::{build_pair_for_preset, BfvParamSet, BfvPreset};
use e3_trbfv::{
    calculate_decryption_key::{CalculateDecryptionKeyRequest, CalculateDecryptionKeyResponse},
    calculate_decryption_share::{
        CalculateDecryptionShareRequest, CalculateDecryptionShareResponse,
    },
    gen_esi_sss::{GenEsiSssRequest, GenEsiSssResponse},
    gen_pk_share_and_sk_sss::{GenPkShareAndSkSssRequest, GenPkShareAndSkSssResponse},
    helpers::{deserialize_secret_key, serialize_secret_key},
    shares::{BfvEncryptedShares, EncryptableVec, Encrypted, ShamirShare, SharedSecret},
    TrBFVConfig, TrBFVRequest, TrBFVResponse,
};
use e3_utils::utility_types::ArcBytes;
use e3_utils::{NotifySync, MAILBOX_LIMIT};
use e3_zk_helpers::computation::DkgInputType;
use e3_zk_helpers::CiphernodesCommitteeSize;
use fhe::bfv::{PublicKey, SecretKey};
use fhe_traits::{DeserializeParametrized, Serialize};
use ndarray::Array2;
use rand::rngs::OsRng;
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    mem,
    sync::Arc,
};
use tracing::{error, info, trace, warn};

use crate::decryption_key_shared_collector::{
    AllDecryptionKeySharesCollected, DecryptionKeySharedCollectionFailed,
    DecryptionKeySharedCollector, ExpelPartyFromDecryptionKeySharedCollection,
};
use crate::encryption_key_collector::{
    AllEncryptionKeysCollected, EncryptionKeyCollector, ExpelPartyFromKeyCollection,
};
use crate::threshold_share_collector::{
    ExpelPartyFromShareCollection, ReceivedShareProofs, ThresholdShareCollector,
};
use crate::timeout_policy::{now_unix_secs, resolve_timeout, DkgTimeoutPhase};

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

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CollectingEncryptionKeysData {
    sk_bfv: SensitiveBytes,
    pk_bfv: ArcBytes,
    ciphernode_selected: CiphernodeSelected,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ProofRequestData {
    pub pk0_share_raw: ArcBytes,
    pub sk_raw: SensitiveBytes,
    pub eek_raw: SensitiveBytes,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GeneratingThresholdShareData {
    pk_share: Option<ArcBytes>,
    sk_sss: Option<Encrypted<SharedSecret>>,
    esi_sss: Option<Vec<Encrypted<SharedSecret>>>,
    e_sm_raw: Option<SensitiveBytes>,
    sk_bfv: SensitiveBytes,
    pk_bfv: ArcBytes,
    collected_encryption_keys: Vec<Arc<EncryptionKey>>,
    ciphernode_selected: Option<CiphernodeSelected>,
    proof_request_data: Option<ProofRequestData>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AggregatingDecryptionKey {
    pk_share: ArcBytes,
    sk_bfv: SensitiveBytes,
    /// Bincode-serialised `Vec<Vec<u64>>` of shape `[L][N]` — own party's plaintext sk
    /// share row per modulus. Used by C4a in lieu of self-encryption.
    own_sk_share_raw: SensitiveBytes,
    /// One bincode-serialised `Vec<Vec<u64>>` per smudging-noise (esi). Used by C4b.
    own_esi_shares_raw: Vec<SensitiveBytes>,
    signed_pk_generation_proof: Option<SignedProofPayload>,
    signed_sk_share_computation_proof: Option<SignedProofPayload>,
    signed_e_sm_share_computation_proof: Option<SignedProofPayload>,
    signed_sk_share_encryption_proofs: Vec<SignedProofPayload>,
    signed_e_sm_share_encryption_proofs: Vec<SignedProofPayload>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReadyForDecryption {
    pk_share: ArcBytes,
    sk_poly_sum: SensitiveBytes,
    es_poly_sum: Vec<SensitiveBytes>,
    signed_pk_generation_proof: Option<SignedProofPayload>,
    signed_sk_share_computation_proof: Option<SignedProofPayload>,
    signed_e_sm_share_computation_proof: Option<SignedProofPayload>,
    signed_sk_share_encryption_proofs: Vec<SignedProofPayload>,
    signed_e_sm_share_encryption_proofs: Vec<SignedProofPayload>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Decrypting {
    pk_share: ArcBytes,
    sk_poly_sum: SensitiveBytes,
    es_poly_sum: Vec<SensitiveBytes>,
    /// Ciphertext bytes from CiphertextOutputPublished, needed for C6 proof generation.
    ciphertext_output: Vec<ArcBytes>,
    signed_pk_generation_proof: Option<SignedProofPayload>,
    signed_sk_share_computation_proof: Option<SignedProofPayload>,
    signed_e_sm_share_computation_proof: Option<SignedProofPayload>,
    signed_sk_share_encryption_proofs: Vec<SignedProofPayload>,
    signed_e_sm_share_encryption_proofs: Vec<SignedProofPayload>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GeneratingDecryptionProof {
    pk_share: ArcBytes,
    decryption_share: Vec<ArcBytes>,
    signed_pk_generation_proof: Option<SignedProofPayload>,
    signed_sk_share_computation_proof: Option<SignedProofPayload>,
    signed_e_sm_share_computation_proof: Option<SignedProofPayload>,
    signed_sk_share_encryption_proofs: Vec<SignedProofPayload>,
    signed_e_sm_share_encryption_proofs: Vec<SignedProofPayload>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum KeyshareState {
    // Before anything
    Init,
    // Collecting BFV encryption keys from all parties
    CollectingEncryptionKeys(CollectingEncryptionKeysData),
    // Generating TrBFV share material
    GeneratingThresholdShare(GeneratingThresholdShareData),
    // Collecting remaining TrBFV shares to aggregate decryption key
    AggregatingDecryptionKey(AggregatingDecryptionKey),
    // Awaiting decryption
    ReadyForDecryption(ReadyForDecryption),
    // Decrypting something
    Decrypting(Decrypting),
    // Generating C6 proof of correct decryption
    GeneratingDecryptionProof(GeneratingDecryptionProof),
    // Finished
    Completed,
}

impl KeyshareState {
    pub fn next(self: &KeyshareState, new_state: KeyshareState) -> Result<KeyshareState> {
        use KeyshareState as K;
        // The following can be used to check that we are transitioning to a valid state
        let valid = {
            // If we are in the same branch the new state is valid
            if mem::discriminant(self) == mem::discriminant(&new_state) {
                true
            } else {
                match (self, &new_state) {
                    (K::Init, K::CollectingEncryptionKeys(_)) => true,
                    (K::CollectingEncryptionKeys(_), K::GeneratingThresholdShare(_)) => true,
                    (K::GeneratingThresholdShare(_), K::AggregatingDecryptionKey(_)) => true,
                    (K::AggregatingDecryptionKey(_), K::ReadyForDecryption(_)) => true,
                    (K::ReadyForDecryption(_), K::Decrypting(_)) => true,
                    (K::Decrypting(_), K::GeneratingDecryptionProof(_)) => true,
                    (K::GeneratingDecryptionProof(_), K::Completed) => true,
                    _ => false,
                }
            }
        };

        if valid {
            Ok(new_state)
        } else {
            Err(anyhow!(
                "Bad state transition {:?} -> {:?}",
                self.variant_name(),
                new_state.variant_name()
            ))
        }
    }
    pub fn variant_name(&self) -> &'static str {
        match self {
            Self::Init => "Init",
            Self::CollectingEncryptionKeys(_) => "CollectingEncryptionKeys",
            Self::GeneratingThresholdShare(_) => "GeneratingThresholdShare",
            Self::AggregatingDecryptionKey(_) => "AggregatingDecryptionKey",
            Self::ReadyForDecryption(_) => "ReadyForDecryption",
            Self::Decrypting(_) => "Decrypting",
            Self::GeneratingDecryptionProof(_) => "GeneratingDecryptionProof",
            Self::Completed => "Completed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ThresholdKeyshareState {
    pub e3_id: E3id,
    pub address: String,
    pub party_id: PartyId,
    pub state: KeyshareState,
    pub threshold_m: u64,
    pub threshold_n: u64,
    pub params: ArcBytes,
    /// Aggregated public key bytes, captured from PublicKeyAggregated event for C6 proof.
    pub aggregated_pk: Option<ArcBytes>,
    pub expelled_parties: HashSet<u64>,
    /// Honest party IDs in deterministic ascending order (`BTreeSet` guarantees this).
    /// Downstream proof circuits index parties by position in this sorted set.
    pub honest_parties: Option<BTreeSet<u64>>,
    #[serde(default)]
    pub dkg_started_at_unix_secs: Option<u64>,
    #[serde(default = "default_proof_agg")]
    pub proof_aggregation_enabled: bool,
}

fn default_proof_agg() -> bool {
    true
}

impl ThresholdKeyshareState {
    pub fn new(
        e3_id: E3id,
        party_id: PartyId,
        state: KeyshareState,
        threshold_m: u64,
        threshold_n: u64,
        params: ArcBytes,
        address: String,
        proof_aggregation_enabled: bool,
    ) -> Self {
        Self {
            e3_id,
            address,
            party_id,
            state,
            threshold_m,
            threshold_n,
            params,
            aggregated_pk: None,
            expelled_parties: HashSet::new(),
            honest_parties: None,
            dkg_started_at_unix_secs: Some(now_unix_secs()),
            proof_aggregation_enabled,
        }
    }

    /// Return a valid Self based on a new state struct.
    pub fn new_state(self, new_state: KeyshareState) -> Result<Self> {
        Ok(ThresholdKeyshareState {
            state: self.state.next(new_state)?,
            ..self
        })
    }

    pub fn get_trbfv_config(&self) -> TrBFVConfig {
        TrBFVConfig::new(self.params.clone(), self.threshold_n, self.threshold_m)
    }

    pub fn get_e3_id(&self) -> &E3id {
        &self.e3_id
    }

    pub fn get_party_id(&self) -> PartyId {
        self.party_id
    }

    pub fn get_threshold_m(&self) -> u64 {
        self.threshold_m
    }

    pub fn get_threshold_n(&self) -> u64 {
        self.threshold_n
    }

    pub fn get_params(&self) -> &ArcBytes {
        &self.params
    }

    pub fn get_address(&self) -> &str {
        &self.address
    }

    pub fn variant_name(&self) -> &str {
        self.state.variant_name()
    }
}

impl TryInto<CollectingEncryptionKeysData> for ThresholdKeyshareState {
    type Error = anyhow::Error;
    fn try_into(self) -> std::result::Result<CollectingEncryptionKeysData, Self::Error> {
        match self.state {
            KeyshareState::CollectingEncryptionKeys(s) => Ok(s),
            _ => Err(anyhow!("Invalid state: expected CollectingEncryptionKeys")),
        }
    }
}

impl TryInto<GeneratingThresholdShareData> for ThresholdKeyshareState {
    type Error = anyhow::Error;
    fn try_into(self) -> std::result::Result<GeneratingThresholdShareData, Self::Error> {
        match self.state {
            KeyshareState::GeneratingThresholdShare(s) => Ok(s),
            _ => Err(anyhow!("Invalid state")),
        }
    }
}

impl TryInto<AggregatingDecryptionKey> for ThresholdKeyshareState {
    type Error = anyhow::Error;
    fn try_into(self) -> std::result::Result<AggregatingDecryptionKey, Self::Error> {
        match self.state {
            KeyshareState::AggregatingDecryptionKey(s) => Ok(s),
            _ => Err(anyhow!("Invalid state")),
        }
    }
}

impl TryInto<ReadyForDecryption> for ThresholdKeyshareState {
    type Error = anyhow::Error;
    fn try_into(self) -> std::result::Result<ReadyForDecryption, Self::Error> {
        match self.state {
            KeyshareState::ReadyForDecryption(s) => Ok(s),
            _ => Err(anyhow!("Invalid state")),
        }
    }
}

impl TryInto<Decrypting> for ThresholdKeyshareState {
    type Error = anyhow::Error;
    fn try_into(self) -> std::result::Result<Decrypting, Self::Error> {
        match self.state {
            KeyshareState::Decrypting(s) => Ok(s),
            _ => Err(anyhow!("Invalid state")),
        }
    }
}

impl TryInto<GeneratingDecryptionProof> for ThresholdKeyshareState {
    type Error = anyhow::Error;
    fn try_into(self) -> std::result::Result<GeneratingDecryptionProof, Self::Error> {
        match self.state {
            KeyshareState::GeneratingDecryptionProof(s) => Ok(s),
            _ => Err(anyhow!("Invalid state: expected GeneratingDecryptionProof")),
        }
    }
}

pub struct ThresholdKeyshareParams {
    pub bus: BusHandle,
    pub cipher: Arc<Cipher>,
    pub state: Persistable<ThresholdKeyshareState>,
    pub share_enc_preset: BfvPreset,
}

pub struct ThresholdKeyshare {
    bus: BusHandle,
    cipher: Arc<Cipher>,
    decryption_key_collector: Option<Addr<ThresholdShareCollector>>,
    encryption_key_collector: Option<Addr<EncryptionKeyCollector>>,
    decryption_key_shared_collector: Option<Addr<DecryptionKeySharedCollector>>,
    state: Persistable<ThresholdKeyshareState>,
    share_enc_preset: BfvPreset,
    /// Transient coordination data bridging async gaps — not persisted.
    /// Shares pending C2/C3 verification, consumed in `proceed_with_decryption_key_calculation`.
    pending_shares: Vec<Arc<ThresholdShare>>,
    /// Share decryption proof data built during aggregation, consumed after CalculateDecryptionKey.
    pending_share_decryption_data: Option<(
        DkgShareDecryptionProofRequest,
        Vec<DkgShareDecryptionProofRequest>,
    )>,
    /// Temporarily stores DecryptionKeyShared while C4 verification is in flight.
    pending_c4_verification_shares: Option<HashMap<u64, DecryptionKeyShared>>,
    /// Own DKG plaintext shares captured during `handle_shares_generated`, consumed by
    /// the AggregatingDecryptionKey transition. Tuple is `(own_sk_share, own_esi_shares)`.
    /// Each entry is bincode-encoded `Vec<Vec<u64>>` of shape `[L][N]`.
    pending_own_dkg_shares: Option<(SensitiveBytes, Vec<SensitiveBytes>)>,
}

impl ThresholdKeyshare {
    pub fn new(params: ThresholdKeyshareParams) -> Self {
        Self {
            bus: params.bus,
            cipher: params.cipher,
            decryption_key_collector: None,
            encryption_key_collector: None,
            decryption_key_shared_collector: None,
            state: params.state,
            share_enc_preset: params.share_enc_preset,
            pending_shares: Vec::new(),
            pending_share_decryption_data: None,
            pending_c4_verification_shares: None,
            pending_own_dkg_shares: None,
        }
    }
}

impl Actor for ThresholdKeyshare {
    type Context = actix::Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

/// Build a `ShamirShare` (rows = moduli, cols = `N` coefficients) from a `Vec<Vec<u64>>`
/// of shape `[L][N]`. Used to lift our own plaintext DKG share into the same matrix
/// shape as BFV-decrypted external shares.
fn vec_of_rows_to_shamir_share(rows: &[Vec<u64>], degree: usize) -> Result<ShamirShare> {
    if rows.iter().any(|r| r.len() != degree) {
        bail!(
            "ShamirShare row length mismatch: each row must have {} coefficients",
            degree
        );
    }
    let l = rows.len();
    let flat: Vec<u64> = rows.iter().flatten().copied().collect();
    let arr = Array2::from_shape_vec((l, degree), flat)
        .context("Failed to build Array2 for ShamirShare")?;
    Ok(ShamirShare::new(arr))
}

impl ThresholdKeyshare {
    pub fn ensure_collector(
        &mut self,
        self_addr: Addr<Self>,
    ) -> Result<Addr<ThresholdShareCollector>> {
        let Some(state) = self.state.get() else {
            bail!("State not found on threshold keyshare. This should not happen.");
        };

        info!(
            "Setting up key collector for addr: {} and {} nodes",
            state.address, state.threshold_n
        );
        let e3_id = state.e3_id.clone();
        let threshold_n = state.threshold_n;
        let own_party_id = state.party_id;
        let timeout = resolve_timeout(
            DkgTimeoutPhase::ThresholdShareCollection,
            state.dkg_started_at_unix_secs,
        );
        info!(
            e3_id = %e3_id,
            timeout = ?timeout.duration,
            "{}",
            timeout.description
        );
        let addr = self.decryption_key_collector.get_or_insert_with(|| {
            ThresholdShareCollector::setup(
                self_addr,
                threshold_n,
                own_party_id,
                e3_id,
                timeout.duration,
            )
        });
        Ok(addr.clone())
    }

    pub fn ensure_encryption_key_collector(
        &mut self,
        self_addr: Addr<Self>,
    ) -> Result<Addr<EncryptionKeyCollector>> {
        let Some(state) = self.state.get() else {
            bail!("State not found on threshold keyshare. This should not happen.");
        };

        info!(
            "Setting up encryption key collector for addr: {} and {} nodes",
            state.address, state.threshold_n
        );
        let e3_id = state.e3_id.clone();
        let threshold_n = state.threshold_n;
        let timeout = resolve_timeout(
            DkgTimeoutPhase::EncryptionKeyCollection,
            state.dkg_started_at_unix_secs,
        );
        info!(
            e3_id = %e3_id,
            timeout = ?timeout.duration,
            "{}",
            timeout.description
        );
        let addr = self.encryption_key_collector.get_or_insert_with(|| {
            EncryptionKeyCollector::setup(self_addr, threshold_n, e3_id, timeout.duration)
        });
        Ok(addr.clone())
    }

    /// Create or return the DecryptionKeySharedCollector.
    /// Uses honest_parties from persisted state.
    pub fn ensure_decryption_key_shared_collector(
        &mut self,
        self_addr: Addr<Self>,
    ) -> Result<Addr<DecryptionKeySharedCollector>> {
        let state = self.state.try_get()?;
        let my_party_id = state.party_id;

        let honest = state
            .honest_parties
            .as_ref()
            .ok_or_else(|| anyhow!("honest_parties not set when creating collector"))?;

        let expected: HashSet<u64> = honest
            .iter()
            .filter(|&&pid| pid != my_party_id)
            .copied()
            .collect();

        let e3_id = state.e3_id.clone();
        let timeout = resolve_timeout(
            DkgTimeoutPhase::DecryptionKeySharedCollection,
            state.dkg_started_at_unix_secs,
        );
        info!(
            e3_id = %e3_id,
            timeout = ?timeout.duration,
            "{}",
            timeout.description
        );
        let addr = self.decryption_key_shared_collector.get_or_insert_with(|| {
            DecryptionKeySharedCollector::setup(self_addr, expected, e3_id, timeout.duration)
        });
        Ok(addr.clone())
    }

    fn handle_committee_member_expelled(
        &mut self,
        data: CommitteeMemberExpelled,
        ec: EventContext<Sequenced>,
    ) {
        // Only process enriched events (party_id resolved by Sortition).
        // Raw events from chain (party_id = None) are ignored here;
        // Sortition will re-publish them with party_id set.
        let Some(party_id) = data.party_id else {
            return;
        };

        let node_addr = data.node.to_string();
        info!(
            "CommitteeMemberExpelled received (enriched): node={}, party_id={}, e3_id={}, active_count_after={}",
            node_addr, party_id, data.e3_id, data.active_count_after
        );

        // Record permanently so late-arriving data is rejected even if
        // collectors haven't been created or have already completed.
        // Also clean honest_parties set for the expelled party.
        let _ = self.state.try_mutate(&ec, |mut s| {
            s.expelled_parties.insert(party_id);
            if let Some(ref mut honest) = s.honest_parties {
                honest.remove(&party_id);
            }
            Ok(s)
        });

        // Clean transient coordination state for the expelled party
        self.pending_shares.retain(|s| s.party_id != party_id);

        if let Some(ref mut pending_c4) = self.pending_c4_verification_shares {
            pending_c4.remove(&party_id);
        }

        if let Some(ref collector) = self.encryption_key_collector {
            collector.do_send(ExpelPartyFromKeyCollection {
                party_id,
                ec: ec.clone(),
            });
        }

        if let Some(ref collector) = self.decryption_key_collector {
            collector.do_send(ExpelPartyFromShareCollection {
                party_id,
                ec: ec.clone(),
            });
        }

        if let Some(ref collector) = self.decryption_key_shared_collector {
            collector.do_send(ExpelPartyFromDecryptionKeySharedCollection { party_id, ec });
        }
    }

    pub fn handle_threshold_share_created(
        &mut self,
        msg: TypedEvent<ThresholdShareCreated>,
        self_addr: Addr<Self>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        if !matches!(
            state.state,
            KeyshareState::CollectingEncryptionKeys(_)
                | KeyshareState::GeneratingThresholdShare(_)
                | KeyshareState::AggregatingDecryptionKey(_)
        ) {
            trace!(
                e3_id = %state.e3_id,
                state = state.variant_name(),
                sender_party_id = msg.share.party_id,
                "Ignoring ThresholdShareCreated outside share collection"
            );
            return Ok(());
        }

        let my_party_id = state.party_id;

        // Filter: only process shares intended for this party
        if msg.target_party_id != my_party_id {
            return Ok(());
        }

        // Reject shares from expelled parties
        if state.expelled_parties.contains(&msg.share.party_id) {
            info!(
                "Dropping ThresholdShareCreated from expelled party {} for us (party {})",
                msg.share.party_id, my_party_id
            );
            return Ok(());
        }

        info!(
            "Received ThresholdShareCreated from party {} for us (party {}), forwarding to collector!",
            msg.share.party_id, my_party_id
        );
        let collector = self.ensure_collector(self_addr)?;
        info!("got collector address!");
        collector.do_send(msg);
        Ok(())
    }

    pub fn handle_encryption_key_created(
        &mut self,
        msg: TypedEvent<EncryptionKeyCreated>,
        self_addr: Addr<Self>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        if !matches!(
            state.state,
            KeyshareState::Init | KeyshareState::CollectingEncryptionKeys(_)
        ) {
            trace!(
                e3_id = %state.e3_id,
                state = state.variant_name(),
                sender_party_id = msg.key.party_id,
                "Ignoring EncryptionKeyCreated outside key collection"
            );
            return Ok(());
        }

        // Reject keys from expelled parties
        if state.expelled_parties.contains(&msg.key.party_id) {
            info!(
                "Dropping EncryptionKeyCreated from expelled party {}",
                msg.key.party_id
            );
            return Ok(());
        }
        info!("Received EncryptionKeyCreated forwarding to encryption key collector!");
        let collector = self.ensure_encryption_key_collector(self_addr)?;
        collector.do_send(msg);
        Ok(())
    }

    /// Handle PkGenerationProofSigned - stores the signed C1 proof in state
    pub fn handle_pk_generation_proof_signed(
        &mut self,
        msg: TypedEvent<PkGenerationProofSigned>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();
        let state = self.state.try_get()?;

        // Only accept proof for our own party
        if msg.party_id != state.party_id {
            return Ok(());
        }

        info!(
            "Received PkGenerationProofSigned for party {} E3 {}",
            msg.party_id, msg.e3_id
        );

        // Store the signed proof in AggregatingDecryptionKey state
        self.state.try_mutate(&ec, |s| {
            let current: AggregatingDecryptionKey = s.clone().try_into()?;
            s.new_state(KeyshareState::AggregatingDecryptionKey(
                AggregatingDecryptionKey {
                    signed_pk_generation_proof: Some(msg.signed_proof),
                    ..current
                },
            ))
        })?;

        Ok(())
    }

    /// Handle DkgProofSigned - stores the signed proof in state based on proof type (C2a, C2b, C3a or C3b)
    pub fn handle_share_computation_proof_signed(
        &mut self,
        msg: TypedEvent<DkgProofSigned>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();
        let state = self.state.try_get()?;

        if msg.party_id != state.party_id {
            return Ok(());
        }

        let proof_type = msg.signed_proof.payload.proof_type;
        info!(
            "Received DkgProofSigned ({:?}) for party {} E3 {}",
            proof_type, msg.party_id, msg.e3_id
        );

        self.state.try_mutate(&ec, |s| {
            let current: AggregatingDecryptionKey = s.clone().try_into()?;
            let updated = match proof_type {
                ProofType::C2aSkShareComputation => AggregatingDecryptionKey {
                    signed_sk_share_computation_proof: Some(msg.signed_proof),
                    ..current
                },
                ProofType::C2bESmShareComputation => AggregatingDecryptionKey {
                    signed_e_sm_share_computation_proof: Some(msg.signed_proof),
                    ..current
                },
                ProofType::C3aSkShareEncryption => {
                    let mut updated = current;
                    updated
                        .signed_sk_share_encryption_proofs
                        .push(msg.signed_proof);
                    updated
                }
                ProofType::C3bESmShareEncryption => {
                    let mut updated = current;
                    updated
                        .signed_e_sm_share_encryption_proofs
                        .push(msg.signed_proof);
                    updated
                }
                other => {
                    warn!("Unexpected proof type {:?} in DkgProofSigned", other);
                    current
                }
            };
            s.new_state(KeyshareState::AggregatingDecryptionKey(updated))
        })?;

        Ok(())
    }

    pub fn handle_compute_response(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
        self_addr: Addr<Self>,
    ) -> Result<()> {
        match &msg.response {
            ComputeResponseKind::TrBFV(trbfv) => match trbfv {
                TrBFVResponse::GenEsiSss(_) => self.handle_gen_esi_sss_response(msg),
                TrBFVResponse::GenPkShareAndSkSss(_) => {
                    self.handle_gen_pk_share_and_sk_sss_response(msg)
                }
                TrBFVResponse::CalculateDecryptionKey(_) => {
                    self.handle_calculate_decryption_key_response(msg, self_addr)
                }
                TrBFVResponse::CalculateDecryptionShare(_) => {
                    self.handle_calculate_decryption_share_response(msg)
                }
                _ => Ok(()),
            },
            // ZK responses: proofs and verification are handled by
            // ProofRequestActor and ShareVerificationActor respectively.
            ComputeResponseKind::Zk(_) => Ok(()),
        }
    }

    /// 1. CiphernodeSelected - Generate BFV keys and publish EncryptionKeyPending
    pub fn handle_ciphernode_selected(
        &mut self,
        msg: TypedEvent<CiphernodeSelected>,
        address: Addr<Self>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();
        let state = self.state.try_get()?;
        if !matches!(state.state, KeyshareState::Init) {
            info!(
                e3_id = %state.e3_id,
                state = state.variant_name(),
                "Ignoring replayed CiphernodeSelected; keyshare already initialized"
            );
            return Ok(());
        }

        info!(
            e3_id = %state.e3_id,
            party_id = state.party_id,
            threshold_m = state.threshold_m,
            threshold_n = state.threshold_n,
            "CiphernodeSelected: node is party {}/{} for E3 {} (m={} of n={})",
            state.party_id, state.threshold_n,
            state.e3_id, state.threshold_m, state.threshold_n
        );
        // Ensure the collectors are created
        let _ = self.ensure_collector(address.clone());
        let _ = self.ensure_encryption_key_collector(address.clone());

        let params = BfvParamSet::from(self.share_enc_preset.clone()).build_arc();
        let mut rng = OsRng;
        let sk_bfv = SecretKey::random(&params, &mut rng);
        let pk_bfv = PublicKey::new(&sk_bfv, &mut rng);

        let sk_bytes = serialize_secret_key(&sk_bfv)?;
        let sk_bfv_encrypted = SensitiveBytes::new(sk_bytes, &self.cipher)?;
        let pk_bfv_bytes = ArcBytes::from_bytes(&pk_bfv.to_bytes());

        let e3_id = state.e3_id.clone();

        self.state.try_mutate(&ec, |s| {
            s.new_state(KeyshareState::CollectingEncryptionKeys(
                CollectingEncryptionKeysData {
                    sk_bfv: sk_bfv_encrypted.clone(),
                    pk_bfv: pk_bfv_bytes.clone(),
                    ciphernode_selected: msg,
                },
            ))
        })?;

        self.bus.publish(
            EncryptionKeyPending {
                e3_id,
                key: Arc::new(EncryptionKey::new(state.party_id, pk_bfv_bytes)),
                params_preset: self.share_enc_preset,
            },
            ec,
        )?;

        Ok(())
    }

    /// 1a. AllEncryptionKeysCollected - All BFV keys received, start share generation
    pub fn handle_all_encryption_keys_collected(
        &mut self,
        msg: TypedEvent<AllEncryptionKeysCollected>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();
        let total_keys = msg.keys.len();

        let state = self.state.try_get()?;
        let expelled_count = if state.expelled_parties.is_empty() { 0 } else { state.expelled_parties.len() };

        // Filter out any keys from parties expelled after collection started
        let filtered_keys: Vec<_> = if state.expelled_parties.is_empty() {
            msg.keys
        } else {
            msg.keys
                .into_iter()
                .filter(|k| !state.expelled_parties.contains(&k.party_id))
                .collect()
        };

        info!(
            e3_id = %state.e3_id,
            received = total_keys,
            expelled = expelled_count,
            proceeding_with = filtered_keys.len(),
            "AllEncryptionKeysCollected: {} keys received, {} expelled, proceeding with {}",
            total_keys, expelled_count, filtered_keys.len()
        );

        let current: CollectingEncryptionKeysData = state.clone().try_into()?;

        self.state.try_mutate(&ec, |s| {
            s.new_state(KeyshareState::GeneratingThresholdShare(
                GeneratingThresholdShareData {
                    sk_sss: None,
                    pk_share: None,
                    esi_sss: None,
                    e_sm_raw: None,
                    sk_bfv: current.sk_bfv,
                    pk_bfv: current.pk_bfv,
                    collected_encryption_keys: filtered_keys,
                    ciphernode_selected: Some(current.ciphernode_selected.clone()),
                    proof_request_data: None,
                },
            ))
        })?;

        self.handle_gen_pk_share_and_sk_sss_requested(TypedEvent::new(
            GenPkShareAndSkSss(current.ciphernode_selected),
            ec,
        ))?;

        Ok(())
    }

    /// 2. GenPkShareAndSkSss
    pub fn handle_gen_pk_share_and_sk_sss_requested(
        &self,
        msg: TypedEvent<GenPkShareAndSkSss>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();
        info!("GenPkShareAndSkSss on ThresholdKeyshare");
        let CiphernodeSelected { e3_id, .. } = msg.0;
        let state = self
            .state
            .get()
            .ok_or(anyhow!("State not found on ThrehsoldKeyshare"))?;

        let trbfv_config: TrBFVConfig = state.get_trbfv_config();

        let crp = ArcBytes::from_bytes(
            &create_deterministic_crp_from_default_seed(&trbfv_config.params()).to_bytes(),
        );

        let threshold_preset = self
            .share_enc_preset
            .threshold_counterpart()
            .ok_or_else(|| anyhow!("No threshold counterpart for {:?}", self.share_enc_preset))?;
        let defaults = threshold_preset
            .search_defaults()
            .ok_or_else(|| anyhow!("No search defaults for {:?}", threshold_preset))?;

        let event = ComputeRequest::trbfv(
            TrBFVRequest::GenPkShareAndSkSss(
                GenPkShareAndSkSssRequest {
                    trbfv_config,
                    crp,
                    lambda: defaults.lambda as usize,
                    num_ciphertexts: defaults.z as usize,
                }
                .into(),
            ),
            CorrelationId::new(),
            e3_id,
        );

        self.bus.publish(event, ec)?;
        Ok(())
    }

    /// 2a. GenPkShareAndSkSss result
    pub fn handle_gen_pk_share_and_sk_sss_response(
        &mut self,
        res: TypedEvent<ComputeResponse>,
    ) -> Result<()> {
        let (res, ec) = res.into_components();

        let output: GenPkShareAndSkSssResponse = res
            .try_into()
            .context("Error extracting data from compute process")?;

        let (pk_share, sk_sss, e_sm_raw) = (
            output.pk_share.clone(),
            output.sk_sss,
            output.e_sm_raw.clone(),
        );

        // Store proof request data for later use by ProofRequestActor
        let proof_request_data = ProofRequestData {
            pk0_share_raw: output.pk0_share_raw,
            sk_raw: output.sk_raw,
            eek_raw: output.eek_raw,
        };

        self.state.try_mutate(&ec, |s| {
            info!("try_store_pk_share_and_sk_sss");
            let current: GeneratingThresholdShareData = s.clone().try_into()?;
            s.new_state(KeyshareState::GeneratingThresholdShare(
                GeneratingThresholdShareData {
                    pk_share: Some(pk_share),
                    sk_sss: Some(sk_sss),
                    e_sm_raw: Some(e_sm_raw.clone()),
                    proof_request_data: Some(proof_request_data),
                    ..current
                },
            ))
        })?;

        // Fire gen_esi_sss with the e_sm_raw
        let current_state: GeneratingThresholdShareData = self.state.try_get()?.try_into()?;
        if let Some(ciphernode_selected) = current_state.ciphernode_selected {
            self.handle_gen_esi_sss_requested(TypedEvent::new(
                GenEsiSss {
                    ciphernode_selected,
                    e_sm_raw: current_state
                        .e_sm_raw
                        .expect("e_sm_raw should be set at this point"),
                },
                ec.clone(),
            ))?;
        }

        Ok(())
    }

    /// 3. GenEsiSss
    pub fn handle_gen_esi_sss_requested(&self, msg: TypedEvent<GenEsiSss>) -> Result<()> {
        let (msg, ec) = msg.into_components();
        info!("GenEsiSss on ThresholdKeyshare");

        let e_sm_raw = msg.e_sm_raw;
        let CiphernodeSelected { e3_id, .. } = msg.ciphernode_selected;

        let state = self
            .state
            .get()
            .ok_or(anyhow!("State not found on ThrehsoldKeyshare"))?;

        let trbfv_config = state.get_trbfv_config();

        let event = ComputeRequest::trbfv(
            TrBFVRequest::GenEsiSss(GenEsiSssRequest {
                trbfv_config,
                e_sm_raw,
            }),
            CorrelationId::new(),
            e3_id,
        );

        self.bus.publish(event, ec)?;
        Ok(())
    }

    /// 3a. GenEsiSss result
    pub fn handle_gen_esi_sss_response(&mut self, res: TypedEvent<ComputeResponse>) -> Result<()> {
        let (res, ec) = res.into_components();
        let output: GenEsiSssResponse = res.try_into()?;

        let esi_sss = output.esi_sss;

        // First store esi_sss in GeneratingThresholdShareData
        self.state.try_mutate(&ec, |s| {
            info!("try_store_esi_sss");
            let current: GeneratingThresholdShareData = s.clone().try_into()?;
            s.new_state(KeyshareState::GeneratingThresholdShare(
                GeneratingThresholdShareData {
                    esi_sss: Some(esi_sss),
                    ..current
                },
            ))
        })?;

        info!("esi stored");

        // Check if all data is ready, if so call handle_shares_generated BEFORE transitioning
        let current: GeneratingThresholdShareData = self.state.try_get()?.try_into()?;
        let ready = current.pk_share.is_some()
            && current.sk_sss.is_some()
            && current.esi_sss.is_some()
            && current.e_sm_raw.is_some()
            && current.proof_request_data.is_some();

        if ready {
            // Call handle_shares_generated while still in GeneratingThresholdShare state
            self.handle_shares_generated(ec.clone())?;

            // Consume the own plaintext shares stashed transiently by handle_shares_generated.
            let (own_sk_share_raw, own_esi_shares_raw) =
                self.pending_own_dkg_shares.take().ok_or_else(|| {
                    anyhow!("pending_own_dkg_shares missing — handle_shares_generated did not run")
                })?;

            // Now transition to AggregatingDecryptionKey with minimal state
            self.state.try_mutate(&ec, |s| {
                let current: GeneratingThresholdShareData = s.clone().try_into()?;
                s.new_state(KeyshareState::AggregatingDecryptionKey(
                    AggregatingDecryptionKey {
                        pk_share: current.pk_share.expect("pk_share checked above"),
                        sk_bfv: current.sk_bfv,
                        own_sk_share_raw: own_sk_share_raw.clone(),
                        own_esi_shares_raw: own_esi_shares_raw.clone(),
                        signed_pk_generation_proof: None,
                        signed_sk_share_computation_proof: None,
                        signed_e_sm_share_computation_proof: None,
                        signed_sk_share_encryption_proofs: Vec::new(),
                        signed_e_sm_share_encryption_proofs: Vec::new(),
                    },
                ))
            })?;
        }
        Ok(())
    }

    /// 4. SharesGenerated - Encrypt shares with BFV and publish
    pub fn handle_shares_generated(&mut self, ec: EventContext<Sequenced>) -> Result<()> {
        let Some(ThresholdKeyshareState {
            state:
                KeyshareState::GeneratingThresholdShare(GeneratingThresholdShareData {
                    pk_share: Some(pk_share),
                    sk_sss: Some(sk_sss),
                    esi_sss: Some(esi_sss),
                    e_sm_raw: Some(e_sm_raw),
                    proof_request_data: Some(proof_request_data),
                    collected_encryption_keys,
                    ..
                }),
            party_id,
            e3_id,
            threshold_m,
            threshold_n,
            ..
        }) = self.state.get()
        else {
            bail!("Invalid state - expected GeneratingThresholdShare with all data");
        };

        let derived_committee_size =
            CiphernodesCommitteeSize::from_threshold(threshold_m as usize, threshold_n as usize)?;

        // Get collected BFV public keys from all parties (from persisted state)
        let encryption_keys = &collected_encryption_keys;

        // Convert to BFV public keys using DKG params
        let threshold_preset = self
            .share_enc_preset
            .threshold_counterpart()
            .ok_or_else(|| anyhow!("No threshold counterpart for {:?}", self.share_enc_preset))?;
        let (_, params) = build_pair_for_preset(threshold_preset)?;
        let recipient_pks: Vec<PublicKey> = encryption_keys
            .iter()
            .map(|k| {
                PublicKey::from_bytes(&k.pk_bfv, &params)
                    .map_err(|e| anyhow!("Failed to deserialize BFV public key: {:?}", e))
            })
            .collect::<Result<_>>()?;
        let recipient_party_ids: Vec<u64> = encryption_keys.iter().map(|k| k.party_id).collect();
        let recipient_share_indices: Vec<usize> = recipient_party_ids
            .iter()
            .map(|&recipient_party_id| recipient_party_id as usize)
            .collect();
        let own_idx = recipient_party_ids
            .iter()
            .position(|&recipient_party_id| recipient_party_id == party_id)
            .ok_or_else(|| {
                anyhow!(
                    "own party {} missing from collected encryption keys",
                    party_id
                )
            })?;

        // Decrypt our shares from local storage
        let decrypted_sk_sss: SharedSecret = sk_sss.decrypt(&self.cipher)?;
        let decrypted_esi_sss: Vec<SharedSecret> = esi_sss
            .into_iter()
            .map(|s| s.decrypt(&self.cipher))
            .collect::<Result<_>>()?;

        // Serialize for C2a/C2b proof requests (encrypted at rest)
        let sk_sss_raw = SensitiveBytes::new(
            bincode::serialize(&decrypted_sk_sss)
                .map_err(|e| anyhow!("Failed to serialize sk_sss: {}", e))?,
            &self.cipher,
        )?;
        let esi_sss_raw: Vec<SensitiveBytes> = decrypted_esi_sss
            .iter()
            .map(|s| {
                let bytes = bincode::serialize(s)
                    .map_err(|e| anyhow!("Failed to serialize esi_sss: {}", e))?;
                SensitiveBytes::new(bytes, &self.cipher)
            })
            .collect::<Result<_>>()?;

        // Cache own plaintext share rows for C4 (no self-encryption); stored encrypted at rest.
        let own_sk_shamir = decrypted_sk_sss.extract_party_share(party_id as usize)?;
        let own_sk_rows: Vec<Vec<u64>> = own_sk_shamir
            .rows()
            .into_iter()
            .map(|row| row.iter().copied().collect())
            .collect();
        let own_sk_share_raw = SensitiveBytes::new(
            bincode::serialize(&own_sk_rows)
                .map_err(|e| anyhow!("Failed to serialize own sk share: {}", e))?,
            &self.cipher,
        )?;

        let own_esi_shares_raw: Vec<SensitiveBytes> = decrypted_esi_sss
            .iter()
            .map(|esi| {
                let shamir = esi.extract_party_share(party_id as usize)?;
                let rows: Vec<Vec<u64>> = shamir
                    .rows()
                    .into_iter()
                    .map(|row| row.iter().copied().collect())
                    .collect();
                let bytes = bincode::serialize(&rows)
                    .map_err(|e| anyhow!("Failed to serialize own esi share: {}", e))?;
                SensitiveBytes::new(bytes, &self.cipher)
            })
            .collect::<Result<_>>()?;
        self.pending_own_dkg_shares = Some((own_sk_share_raw, own_esi_shares_raw));

        // BFV-encrypt shares to all recipients except own slot (own share is bound via C2,
        // consumed locally by C4). Returns per-row randomness for C3 proofs.
        let mut rng = OsRng;
        let (encrypted_sk_sss, sk_witnesses) =
            BfvEncryptedShares::encrypt_all_extended_for_share_indices(
                &decrypted_sk_sss,
                &recipient_pks,
                &recipient_share_indices,
                &params,
                &mut rng,
                Some(own_idx),
            )?;

        let (encrypted_esi_sss, esi_witnesses): (Vec<_>, Vec<_>) = decrypted_esi_sss
            .iter()
            .map(|esi| {
                BfvEncryptedShares::encrypt_all_extended_for_share_indices(
                    esi,
                    &recipient_pks,
                    &recipient_share_indices,
                    &params,
                    &mut rng,
                    Some(own_idx),
                )
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .unzip();

        // Create the full share with all parties' encrypted data
        let full_share = ThresholdShare {
            party_id,
            pk_share,
            sk_sss: encrypted_sk_sss,
            esi_sss: encrypted_esi_sss,
        };

        // Build C1 request (PkGenerationProof)
        let proof_request = PkGenerationProofRequest::new(
            proof_request_data.pk0_share_raw.clone(),
            proof_request_data.sk_raw.clone(),
            proof_request_data.eek_raw.clone(),
            e_sm_raw.clone(),
            threshold_preset,
            derived_committee_size,
        );

        // Build C2a request (SkShareComputation)
        let sk_share_computation_request = ShareComputationProofRequest {
            secret_raw: proof_request_data.sk_raw.clone(),
            secret_sss_raw: sk_sss_raw,
            dkg_input_type: DkgInputType::SecretKey,
            params_preset: threshold_preset,
            committee_size: derived_committee_size,
        };

        // Build C2b request (ESmShareComputation)
        let e_sm_share_computation_request = ShareComputationProofRequest {
            secret_raw: e_sm_raw.clone(),
            secret_sss_raw: esi_sss_raw
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("esi_sss_raw is empty — expected at least one entry"))?,
            dkg_input_type: DkgInputType::SmudgingNoise,
            params_preset: threshold_preset,
            committee_size: derived_committee_size,
        };

        // Build C3a proof requests (SK share encryption) from witnesses.
        // The own slot was skipped during BFV encryption (witness vec empty), so it
        // contributes no C3a request.
        let mut sk_share_encryption_requests = Vec::new();
        for (recipient_idx, recipient_witnesses) in sk_witnesses.iter().enumerate() {
            if recipient_idx == own_idx {
                continue;
            }
            let recipient_party_id = recipient_share_indices[recipient_idx];
            for (row_idx, witness) in recipient_witnesses.iter().enumerate() {
                sk_share_encryption_requests.push(ShareEncryptionProofRequest {
                    share_row_raw: SensitiveBytes::new(
                        bincode::serialize(&witness.share_row)
                            .map_err(|e| anyhow!("Failed to serialize share_row: {}", e))?,
                        &self.cipher,
                    )?,
                    ciphertext_raw: ArcBytes::from_bytes(&witness.ciphertext.to_bytes()),
                    recipient_pk_raw: ArcBytes::from_bytes(
                        &recipient_pks[recipient_idx].to_bytes(),
                    ),
                    u_rns_raw: SensitiveBytes::new(witness.u_rns.to_bytes(), &self.cipher)?,
                    e0_rns_raw: SensitiveBytes::new(witness.e0_rns.to_bytes(), &self.cipher)?,
                    e1_rns_raw: SensitiveBytes::new(witness.e1_rns.to_bytes(), &self.cipher)?,
                    dkg_input_type: DkgInputType::SecretKey,
                    params_preset: threshold_preset,
                    committee_size: derived_committee_size,
                    recipient_party_id,
                    row_index: row_idx,
                    esi_index: 0,
                });
            }
        }

        // Build C3b proof requests (E_SM share encryption) from witnesses; skip own slot.
        let mut e_sm_share_encryption_requests = Vec::new();
        for (esi_idx, esi_recipient_witnesses) in esi_witnesses.iter().enumerate() {
            for (recipient_idx, recipient_witnesses) in esi_recipient_witnesses.iter().enumerate() {
                if recipient_idx == own_idx {
                    continue;
                }
                let recipient_party_id = recipient_share_indices[recipient_idx];
                for (row_idx, witness) in recipient_witnesses.iter().enumerate() {
                    e_sm_share_encryption_requests.push(ShareEncryptionProofRequest {
                        share_row_raw: SensitiveBytes::new(
                            bincode::serialize(&witness.share_row)
                                .map_err(|e| anyhow!("Failed to serialize share_row: {}", e))?,
                            &self.cipher,
                        )?,
                        ciphertext_raw: ArcBytes::from_bytes(&witness.ciphertext.to_bytes()),
                        recipient_pk_raw: ArcBytes::from_bytes(
                            &recipient_pks[recipient_idx].to_bytes(),
                        ),
                        u_rns_raw: SensitiveBytes::new(witness.u_rns.to_bytes(), &self.cipher)?,
                        e0_rns_raw: SensitiveBytes::new(witness.e0_rns.to_bytes(), &self.cipher)?,
                        e1_rns_raw: SensitiveBytes::new(witness.e1_rns.to_bytes(), &self.cipher)?,
                        dkg_input_type: DkgInputType::SmudgingNoise,
                        params_preset: threshold_preset,
                        committee_size: derived_committee_size,
                        recipient_party_id,
                        row_index: row_idx,
                        esi_index: esi_idx,
                    });
                }
            }
        }

        let total_proofs =
            3 + sk_share_encryption_requests.len() + e_sm_share_encryption_requests.len();
        info!(
            "Publishing ThresholdSharePending for E3 {} ({} proofs: C1, C2a, C2b + {} C3a + {} C3b)",
            e3_id, total_proofs,
            sk_share_encryption_requests.len(),
            e_sm_share_encryption_requests.len()
        );

        // Publish ThresholdSharePending - ProofRequestActor will generate proof, sign, and publish ThresholdShareCreated
        self.bus.publish(
            ThresholdSharePending {
                e3_id: e3_id.clone(),
                full_share: Arc::new(full_share),
                proof_request,
                sk_share_computation_request,
                e_sm_share_computation_request,
                sk_share_encryption_requests,
                e_sm_share_encryption_requests,
                recipient_party_ids,
                proof_aggregation_enabled: self
                    .state
                    .try_get()
                    .map(|s| s.proof_aggregation_enabled)
                    .unwrap_or(true),
            },
            ec.clone(),
        )?;

        Ok(())
    }

    /// 5. AllThresholdSharesCollected - Verify C2/C3 proofs, then decrypt and aggregate
    pub fn handle_all_threshold_shares_collected(
        &mut self,
        msg: TypedEvent<AllThresholdSharesCollected>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();
        let state = self.state.try_get()?;
        let e3_id = state.get_e3_id();
        let own_party_id = state.party_id;
        info!(
            e3_id = %e3_id,
            party_id = own_party_id,
            share_count = msg.shares.len(),
            "AllThresholdSharesCollected: {} shares received for E3 {}",
            msg.shares.len(), e3_id
        );

        // Filter out expelled parties before any processing. The collector may
        // have accepted shares before the expulsion arrived, so we scrub here.
        let expelled = &state.expelled_parties;
        let (shares, share_proofs): (Vec<_>, Vec<_>) = if expelled.is_empty() {
            (msg.shares, msg.share_proofs)
        } else {
            warn!(
                "Filtering {} expelled parties from AllThresholdSharesCollected for E3 {}: {:?}",
                expelled.len(),
                e3_id,
                expelled
            );
            msg.shares
                .into_iter()
                .zip(msg.share_proofs.into_iter())
                .filter(|(s, _)| !expelled.contains(&s.party_id))
                .unzip()
        };

        // Expected proof counts come from local cached own shares (trusted source); the
        // collector excludes self from `shares`, so we cannot read them from there.
        let current: AggregatingDecryptionKey = state.clone().try_into()?;
        let own_sk_rows: Vec<Vec<u64>> =
            bincode::deserialize(&current.own_sk_share_raw.access_raw(&self.cipher)?)
                .context("Failed to deserialize own_sk_share_raw")?;
        let expected_c3a = own_sk_rows.len();
        let expected_num_esi = current.own_esi_shares_raw.len();
        let mut expected_c3b: usize = 0;
        for esi_raw in current.own_esi_shares_raw.iter() {
            let rows: Vec<Vec<u64>> = bincode::deserialize(&esi_raw.access_raw(&self.cipher)?)
                .context("Failed to deserialize own esi share")?;
            expected_c3b += rows.len();
        }

        // Build verification requests for other parties' proofs
        let mut party_proofs_to_verify: Vec<PartyProofsToVerify> = Vec::new();
        let mut no_proof_parties: HashSet<u64> = HashSet::new();
        let mut incomplete_proof_parties: HashSet<u64> = HashSet::new();
        for (share, proofs) in shares.iter().zip(share_proofs.iter()) {
            if share.party_id == own_party_id {
                continue;
            }

            let has_any_proof = proofs.signed_c2a_proof.is_some()
                || proofs.signed_c2b_proof.is_some()
                || !proofs.signed_c3a_proofs.is_empty()
                || !proofs.signed_c3b_proofs.is_empty();

            if !has_any_proof {
                no_proof_parties.insert(share.party_id);
                continue;
            }

            // Validate proof set completeness against trusted expected counts.
            // A malicious sender could omit proofs that would fail verification,
            // so we must check that all expected proofs are present.
            let is_complete = proofs.signed_c2a_proof.is_some()
                && proofs.signed_c2b_proof.is_some()
                && proofs.signed_c3a_proofs.len() == expected_c3a
                && proofs.signed_c3b_proofs.len() == expected_c3b
                && share.esi_sss.len() == expected_num_esi;

            if !is_complete {
                warn!(
                    "Party {} has incomplete proof set (c2a={}, c2b={}, c3a={}/{}, c3b={}/{}, esi={}/{}), treating as dishonest",
                    share.party_id,
                    proofs.signed_c2a_proof.is_some(),
                    proofs.signed_c2b_proof.is_some(),
                    proofs.signed_c3a_proofs.len(), expected_c3a,
                    proofs.signed_c3b_proofs.len(), expected_c3b,
                    share.esi_sss.len(), expected_num_esi,
                );
                incomplete_proof_parties.insert(share.party_id);
                continue;
            }

            // Complete proof set — collect for verification
            let mut signed_proofs = Vec::new();
            // SAFETY: is_complete guarantees c2a and c2b are Some
            signed_proofs.push(proofs.signed_c2a_proof.clone().unwrap());
            signed_proofs.push(proofs.signed_c2b_proof.clone().unwrap());
            signed_proofs.extend(proofs.signed_c3a_proofs.iter().cloned());
            signed_proofs.extend(proofs.signed_c3b_proofs.iter().cloned());

            party_proofs_to_verify.push(PartyProofsToVerify {
                sender_party_id: share.party_id,
                signed_proofs,
            });
        }

        // Store shares on the actor for use after verification completes (keep Arc to avoid deep clone)
        self.pending_shares = shares.iter().cloned().collect();

        // Merge no-proof and incomplete-proof parties — both are dishonest
        let mut pre_dishonest: BTreeSet<u64> = BTreeSet::new();
        pre_dishonest.extend(incomplete_proof_parties);
        pre_dishonest.extend(no_proof_parties);
        if !pre_dishonest.is_empty() {
            warn!(
                "{} parties have missing/incomplete C2/C3 proofs for E3 {} — marking as pre-dishonest: {:?}",
                pre_dishonest.len(),
                e3_id,
                pre_dishonest
            );
        }

        if party_proofs_to_verify.is_empty() {
            // All non-self parties are dishonest (missing or incomplete proofs), none to verify
            let threshold = state.threshold_m;
            let total = state.threshold_n;
            let dishonest_count = (pre_dishonest.len() as u64).min(total);
            let honest_count = total - dishonest_count;

            if honest_count <= threshold {
                warn!(
                    "Too few honest parties for E3 {} ({} honest, need at least {}) after C2/C3 pre-dishonest filtering — cannot proceed",
                    e3_id, honest_count, threshold + 1
                );
                self.pending_shares.clear();
                self.bus.publish(
                    E3Failed {
                        e3_id: e3_id.clone(),
                        failed_at_stage: E3Stage::CommitteeFinalized,
                        reason: FailureReason::InsufficientCommitteeMembers,
                    },
                    ec,
                )?;
                return Ok(());
            }

            let dishonest_set: HashSet<u64> = pre_dishonest.into_iter().collect();
            return self.proceed_with_decryption_key_calculation(Some(dishonest_set), ec);
        }

        info!(
            "Dispatching C2/C3 share verification for E3 {} ({} parties, {} pre-dishonest)",
            e3_id,
            party_proofs_to_verify.len(),
            pre_dishonest.len()
        );

        self.bus.publish(
            ShareVerificationDispatched {
                e3_id: e3_id.clone(),
                kind: VerificationKind::ShareProofs,
                share_proofs: party_proofs_to_verify,
                decryption_proofs: Vec::new(),
                pre_dishonest,
                params_preset: self.share_enc_preset,
            },
            ec,
        )?;
        Ok(())
    }

    /// Handle ShareVerificationComplete from ShareVerificationActor.
    /// Dispatched for both C2/C3 and C4 verification.
    pub fn handle_share_verification_complete(
        &mut self,
        msg: TypedEvent<ShareVerificationComplete>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();
        let state = self.state.try_get()?;
        let e3_id = state.get_e3_id();

        match msg.kind {
            VerificationKind::ShareProofs => {
                // C2/C3 verification complete
                if msg.dishonest_parties.is_empty() {
                    info!(
                        "All parties passed C2/C3 verification for E3 {} — proceeding",
                        e3_id
                    );
                    self.proceed_with_decryption_key_calculation(None, ec)
                } else {
                    let threshold = state.threshold_m;
                    let total = state.threshold_n;
                    let dishonest_count = (msg.dishonest_parties.len() as u64).min(total);
                    let honest_count = total - dishonest_count;

                    if honest_count <= threshold {
                        warn!(
                            "Too few honest parties for E3 {} ({} honest, need at least {}) — cannot proceed",
                            e3_id, honest_count, threshold + 1
                        );
                        // Clear pending shares
                        self.pending_shares.clear();
                        self.bus.publish(
                            E3Failed {
                                e3_id: e3_id.clone(),
                                failed_at_stage: E3Stage::CommitteeFinalized,
                                reason: FailureReason::InsufficientCommitteeMembers,
                            },
                            ec,
                        )?;
                        return Ok(());
                    }

                    let dishonest_set: HashSet<u64> = msg.dishonest_parties.into_iter().collect();
                    info!(
                        "Proceeding with {} honest parties for E3 {} ({} dishonest excluded)",
                        honest_count,
                        e3_id,
                        dishonest_set.len()
                    );
                    self.proceed_with_decryption_key_calculation(Some(dishonest_set), ec)
                }
            }
            VerificationKind::DecryptionProofs => {
                // C4 verification complete — update honest set and publish KeyshareCreated
                if !msg.dishonest_parties.is_empty() {
                    self.state.try_mutate(&ec, |mut s| {
                        if let Some(ref mut honest) = s.honest_parties {
                            honest.retain(|pid| !msg.dishonest_parties.contains(pid));
                        }
                        Ok(s)
                    })?;

                    let state = self.state.try_get()?;
                    let threshold = state.threshold_m;
                    let honest_count = state
                        .honest_parties
                        .as_ref()
                        .map(|h| h.len() as u64)
                        .unwrap_or(0);

                    if honest_count <= threshold {
                        warn!(
                            "Too few honest parties after C4 for E3 {} ({} honest, need at least {})",
                            e3_id, honest_count, threshold + 1
                        );
                        self.bus.publish(
                            E3Failed {
                                e3_id: e3_id.clone(),
                                failed_at_stage: E3Stage::CommitteeFinalized,
                                reason: FailureReason::InsufficientCommitteeMembers,
                            },
                            ec,
                        )?;
                        return Ok(());
                    }

                    info!(
                        "Updated honest set after C4 for E3 {}: {} honest ({} removed)",
                        e3_id,
                        honest_count,
                        msg.dishonest_parties.len()
                    );
                } else {
                    info!(
                        "All parties passed C4 verification for E3 {} — publishing KeyshareCreated",
                        e3_id
                    );
                }

                self.publish_keyshare_created(ec)
            }
            _ => Ok(()),
        }
    }

    /// After verification, decrypt shares from honest parties and compute decryption key.
    /// C4 proof generation is deferred to ProofRequestActor via DecryptionShareProofsPending.
    fn proceed_with_decryption_key_calculation(
        &mut self,
        dishonest_parties: Option<HashSet<u64>>,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let cipher = self.cipher.clone();
        let state = self.state.try_get()?;
        let e3_id = state.get_e3_id();
        let party_id = state.party_id as usize;
        let own_party_id = state.party_id as u64;
        let trbfv_config = state.get_trbfv_config();

        // Get our BFV secret key from state, pending shares from the actor
        let current: AggregatingDecryptionKey = state.clone().try_into()?;
        let shares = std::mem::take(&mut self.pending_shares);
        if shares.is_empty() {
            bail!("No pending verification shares");
        }
        let sk_bytes = current.sk_bfv.access(&cipher)?;
        let params = BfvParamSet::from(self.share_enc_preset.clone()).build_arc();
        let sk_bfv = deserialize_secret_key(&sk_bytes, &params)?;
        let degree = params.degree();

        // Own plaintext shares (bincode `Vec<Vec<u64>>` shape [L][N]) cached at generation time.
        let own_sk_rows: Vec<Vec<u64>> =
            bincode::deserialize(&current.own_sk_share_raw.access_raw(&cipher)?)
                .context("Failed to deserialize own_sk_share_raw")?;
        let own_esi_rows_per_esi: Vec<Vec<Vec<u64>>> = current
            .own_esi_shares_raw
            .iter()
            .map(|sb| {
                let bytes = sb.access_raw(&cipher)?;
                bincode::deserialize::<Vec<Vec<u64>>>(&bytes)
                    .context("Failed to deserialize own esi share")
            })
            .collect::<Result<_>>()?;

        // Expected dimensions derived from own (trusted) shares.
        let expected_num_esi = own_esi_rows_per_esi.len();
        let expected_num_moduli_sk = own_sk_rows.len();
        let expected_num_moduli_esi = own_esi_rows_per_esi
            .first()
            .map(|rows| rows.len())
            .unwrap_or(0);

        // Filter to honest external parties (collector already excludes self).
        let honest_shares: Vec<_> = shares
            .iter()
            .filter(|ts| {
                dishonest_parties
                    .as_ref()
                    .map_or(true, |dp| !dp.contains(&ts.party_id))
            })
            .collect();

        // Validate per-party dimensions and exclude mismatched parties.
        let mut dimension_excluded: Vec<u64> = Vec::new();
        let honest_shares: Vec<_> = honest_shares
            .into_iter()
            .filter(|ts| {
                if ts.esi_sss.len() != expected_num_esi {
                    warn!(
                        "Party {} has wrong esi_sss count ({} vs expected {}) — excluding from honest set",
                        ts.party_id, ts.esi_sss.len(), expected_num_esi
                    );
                    dimension_excluded.push(ts.party_id);
                    return false;
                }
                let idx = if ts.sk_sss.len() == 1 { 0 } else { party_id };
                match ts.sk_sss.clone_share(idx) {
                    Some(share) if share.num_moduli() != expected_num_moduli_sk => {
                        warn!(
                            "Party {} has wrong sk num_moduli ({} vs expected {}) — excluding from honest set",
                            ts.party_id, share.num_moduli(), expected_num_moduli_sk
                        );
                        dimension_excluded.push(ts.party_id);
                        return false;
                    }
                    None => {
                        warn!(
                            "Party {} has no sk_sss share at index {} — excluding from honest set",
                            ts.party_id, idx
                        );
                        dimension_excluded.push(ts.party_id);
                        return false;
                    }
                    _ => {}
                }
                for (esi_idx, esi_shares) in ts.esi_sss.iter().enumerate() {
                    let idx = if esi_shares.len() == 1 { 0 } else { party_id };
                    match esi_shares.clone_share(idx) {
                        Some(share) if share.num_moduli() != expected_num_moduli_esi => {
                            warn!(
                                "Party {} has wrong esi num_moduli at index {} ({} vs expected {}) — excluding from honest set",
                                ts.party_id, esi_idx, share.num_moduli(), expected_num_moduli_esi
                            );
                            dimension_excluded.push(ts.party_id);
                            return false;
                        }
                        None => {
                            warn!(
                                "Party {} has no esi_sss share at index {} (esi {}) — excluding from honest set",
                                ts.party_id, idx, esi_idx
                            );
                            dimension_excluded.push(ts.party_id);
                            return false;
                        }
                        _ => {}
                    }
                }
                true
            })
            .collect();

        if !dimension_excluded.is_empty() {
            warn!(
                "Excluded {} parties with dimension mismatches: {:?}",
                dimension_excluded.len(),
                dimension_excluded
            );
            // Re-check threshold after exclusion (+1 for own share).
            let threshold = state.threshold_m;
            if (honest_shares.len() as u64 + 1) <= threshold {
                self.pending_shares.clear();
                self.bus.publish(
                    E3Failed {
                        e3_id: e3_id.clone(),
                        failed_at_stage: E3Stage::CommitteeFinalized,
                        reason: FailureReason::InsufficientCommitteeMembers,
                    },
                    ec,
                )?;
                return Ok(());
            }
        }

        // Honest party IDs include self (signing/aggregation treats own party as honest).
        let mut honest_party_ids: BTreeSet<u64> =
            honest_shares.iter().map(|s| s.party_id).collect();
        honest_party_ids.insert(own_party_id);

        debug_assert!(
            honest_shares
                .windows(2)
                .all(|w| w[0].party_id < w[1].party_id),
            "honest_shares must be strictly ascending by party_id"
        );

        // Position of own party within sorted {own} ∪ external honest set.
        let own_plaintext_idx = honest_shares
            .iter()
            .position(|ts| ts.party_id > own_party_id)
            .unwrap_or(honest_shares.len());

        let num_honest = honest_shares.len() + 1;
        info!(
            "Decrypting shares from {} honest parties (incl. self) for E3 {}",
            num_honest, e3_id
        );

        // External ciphertexts for C4: own slot omitted from wire (rides as `own_share_raw`).
        // C4a: sk_sss external ciphertexts [(H-1) * L]
        let num_moduli_sk = expected_num_moduli_sk;
        let mut sk_ciphertexts_raw = Vec::new();
        for ts in &honest_shares {
            let idx = if ts.sk_sss.len() == 1 { 0 } else { party_id };
            let share = ts
                .sk_sss
                .clone_share(idx)
                .ok_or(anyhow!("No sk_sss share at index {}", idx))?;
            for ct_bytes in share.ciphertext_bytes() {
                sk_ciphertexts_raw.push(ct_bytes.clone());
            }
        }

        // C4b: esi_sss external ciphertexts — one set per smudging noise
        let num_esi = expected_num_esi;
        let num_moduli_esi = expected_num_moduli_esi;
        let mut esi_ciphertexts_raw: Vec<Vec<ArcBytes>> = vec![Vec::new(); num_esi];
        for ts in &honest_shares {
            for (esi_idx, esi_shares) in ts.esi_sss.iter().enumerate() {
                let idx = if esi_shares.len() == 1 { 0 } else { party_id };
                let share = esi_shares
                    .clone_share(idx)
                    .ok_or(anyhow!("No esi_sss share at index {}", idx))?;
                for ct_bytes in share.ciphertext_bytes() {
                    esi_ciphertexts_raw[esi_idx].push(ct_bytes.clone());
                }
            }
        }

        // Decrypt our share row from each external honest sender using BFV.
        let mut sk_sss_collected: Vec<ShamirShare> = honest_shares
            .iter()
            .map(|ts| {
                let idx = if ts.sk_sss.len() == 1 { 0 } else { party_id };
                let encrypted = ts
                    .sk_sss
                    .clone_share(idx)
                    .ok_or(anyhow!("No sk_sss share at index {}", idx))?;
                encrypted.decrypt(&sk_bfv, &params, degree)
            })
            .collect::<Result<_>>()?;

        // Splice own sk share at the sorted-party position.
        let own_sk_shamir = vec_of_rows_to_shamir_share(&own_sk_rows, degree)?;
        sk_sss_collected.insert(own_plaintext_idx, own_sk_shamir);

        // Decrypt per-party ESI shares: shape [external_party][esm_idx]
        let mut per_party_esi: Vec<Vec<ShamirShare>> = honest_shares
            .iter()
            .map(|ts| {
                ts.esi_sss
                    .iter()
                    .map(|esi_shares| {
                        let idx = if esi_shares.len() == 1 { 0 } else { party_id };
                        let encrypted = esi_shares
                            .clone_share(idx)
                            .ok_or(anyhow!("No esi_sss share at index {}", idx))?;
                        encrypted.decrypt(&sk_bfv, &params, degree)
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .collect::<Result<_>>()?;

        // Splice own esi shares (one per smudging noise).
        let own_esi_shamirs: Vec<ShamirShare> = own_esi_rows_per_esi
            .iter()
            .map(|rows| vec_of_rows_to_shamir_share(rows, degree))
            .collect::<Result<_>>()?;
        per_party_esi.insert(own_plaintext_idx, own_esi_shamirs);

        // Transpose to [esm_idx][party] — CalculateDecryptionKey aggregates per smudging noise
        let esi_sss_collected: Vec<Vec<ShamirShare>> = (0..num_esi)
            .map(|esm_idx| {
                per_party_esi
                    .iter()
                    .map(|party_esi| party_esi[esm_idx].clone())
                    .collect()
            })
            .collect();

        // Publish CalculateDecryptionKey request
        let request = CalculateDecryptionKeyRequest {
            trbfv_config,
            esi_sss_collected: esi_sss_collected
                .into_iter()
                .map(|s| s.encrypt(&cipher))
                .collect::<Result<_>>()?,
            sk_sss_collected: sk_sss_collected.encrypt(&cipher)?,
        };

        let event = ComputeRequest::trbfv(
            TrBFVRequest::CalculateDecryptionKey(request),
            CorrelationId::new(),
            e3_id.clone(),
        );
        self.bus.publish(event, ec.clone())?;

        // Build C4 proof requests — stored for sending after CalculateDecryptionKey completes
        let threshold_preset = self
            .share_enc_preset
            .threshold_counterpart()
            .ok_or_else(|| anyhow!("No threshold counterpart for {:?}", self.share_enc_preset))?;

        let sk_request = DkgShareDecryptionProofRequest {
            sk_bfv: current.sk_bfv.clone(),
            honest_ciphertexts_raw: sk_ciphertexts_raw,
            num_honest_parties: num_honest,
            num_moduli: num_moduli_sk,
            own_plaintext_idx,
            own_share_raw: current.own_sk_share_raw.clone(),
            dkg_input_type: DkgInputType::SecretKey,
            params_preset: threshold_preset,
        };

        let esm_requests: Vec<DkgShareDecryptionProofRequest> = esi_ciphertexts_raw
            .into_iter()
            .enumerate()
            .map(|(esi_idx, esi_cts)| DkgShareDecryptionProofRequest {
                sk_bfv: current.sk_bfv.clone(),
                honest_ciphertexts_raw: esi_cts,
                num_honest_parties: num_honest,
                num_moduli: num_moduli_esi,
                own_plaintext_idx,
                own_share_raw: current.own_esi_shares_raw[esi_idx].clone(),
                dkg_input_type: DkgInputType::SmudgingNoise,
                params_preset: threshold_preset,
            })
            .collect();

        // Store honest parties and C4 data on the actor (transient coordination)
        self.state.try_mutate(&ec, |mut s| {
            s.honest_parties = Some(honest_party_ids);
            Ok(s)
        })?;
        self.pending_share_decryption_data = Some((sk_request, esm_requests));

        Ok(())
    }

    /// 5a. CalculateDecryptionKeyResponse — transition to ReadyForDecryption,
    /// then publish DecryptionShareProofsPending so ProofRequestActor can
    /// generate C4 proofs, sign them, and publish DecryptionKeyShared.
    pub fn handle_calculate_decryption_key_response(
        &mut self,
        res: TypedEvent<ComputeResponse>,
        self_addr: Addr<Self>,
    ) -> Result<()> {
        let (res, ec) = res.into_components();
        let output: CalculateDecryptionKeyResponse = res
            .try_into()
            .context("Error extracting data from compute process")?;

        let (sk_poly_sum, es_poly_sum) = (output.sk_poly_sum, output.es_poly_sum);

        // Extract C4 data from the actor (stored by proceed_with_decryption_key_calculation)
        let (sk_request, esm_requests) = self
            .pending_share_decryption_data
            .take()
            .ok_or_else(|| anyhow!("No pending share decryption data — CalculateDecryptionKey responded before proof requests were built"))?;

        // Take early shares from the actor before transitioning
        let early_shares = self
            .pending_c4_verification_shares
            .take()
            .unwrap_or_default();

        // Transition to ReadyForDecryption
        self.state.try_mutate(&ec, |s| {
            use KeyshareState as K;
            info!("Try store decryption key");

            let current: AggregatingDecryptionKey = s.clone().try_into()?;

            let next = K::ReadyForDecryption(ReadyForDecryption {
                pk_share: current.pk_share,
                sk_poly_sum,
                es_poly_sum,
                signed_pk_generation_proof: current.signed_pk_generation_proof,
                signed_sk_share_computation_proof: current.signed_sk_share_computation_proof,
                signed_e_sm_share_computation_proof: current.signed_e_sm_share_computation_proof,
                signed_sk_share_encryption_proofs: current.signed_sk_share_encryption_proofs,
                signed_e_sm_share_encryption_proofs: current.signed_e_sm_share_encryption_proofs,
            });

            s.new_state(next)
        })?;

        // Publish DecryptionShareProofsPending to ProofRequestActor
        let state = self.state.try_get()?;
        let e3_id = state.get_e3_id();
        let party_id = state.party_id;
        let node = state.address.clone();

        info!(
            "Publishing DecryptionShareProofsPending for E3 {} party {} (1 SK + {} ESM requests)",
            e3_id,
            party_id,
            esm_requests.len()
        );

        self.bus.publish(
            DecryptionShareProofsPending {
                e3_id: e3_id.clone(),
                party_id,
                node,
                sk_request,
                esm_requests,
            },
            ec.clone(),
        )?;

        // Create collector and replay any early-arriving DecryptionKeyShared events
        let state = self.state.try_get()?;
        let my_party_id = state.party_id;
        let honest = state.honest_parties.as_ref().cloned().unwrap_or_default();
        let expected: HashSet<u64> = honest
            .iter()
            .filter(|&&pid| pid != my_party_id)
            .copied()
            .collect();

        if !expected.is_empty() {
            let collector = self.ensure_decryption_key_shared_collector(self_addr)?;
            for (_pid, share) in early_shares {
                collector.do_send(TypedEvent::new(share, ec.clone()));
            }
        }

        Ok(())
    }

    /// Handle an external DecryptionKeyShared event while in AggregatingDecryptionKey state.
    /// Store it for later processing when we transition to ReadyForDecryption.
    fn handle_early_decryption_key_share(
        &mut self,
        data: DecryptionKeyShared,
        _ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let party_id = data.party_id;
        let state = self.state.try_get()?;
        if state.expelled_parties.contains(&party_id) {
            info!(
                "Dropping early DecryptionKeyShared from expelled party {}",
                party_id
            );
            return Ok(());
        }
        info!(
            "Storing early DecryptionKeyShared from party {} (state: AggregatingDecryptionKey)",
            party_id
        );
        self.pending_c4_verification_shares
            .get_or_insert_with(HashMap::new)
            .insert(party_id, data);
        Ok(())
    }

    /// Dispatch C4 verification for all collected DecryptionKeyShared events.
    /// Shares are provided by the DecryptionKeySharedCollector.
    fn dispatch_c4_verification(
        &mut self,
        collected_shares: HashMap<u64, DecryptionKeyShared>,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        let e3_id = state.get_e3_id();
        let ready: ReadyForDecryption = state.clone().try_into()?;

        info!(
            "All DecryptionKeyShared collected for E3 {} ({} shares)",
            e3_id,
            collected_shares.len()
        );

        // Validate ESM proof count — each party must provide exactly
        // one C4b proof per smudging noise index.
        let expected_esm = ready.es_poly_sum.len();
        let mut c4_count_dishonest: HashSet<u64> = HashSet::new();
        let party_proofs: Vec<PartyShareDecryptionProofsToVerify> = collected_shares
            .iter()
            .filter_map(|(&party_id, share)| {
                if share.signed_e_sm_decryption_proofs.len() != expected_esm {
                    warn!(
                        "Party {} has wrong ESM proof count ({} vs expected {}) for E3 {} — treating as dishonest",
                        party_id,
                        share.signed_e_sm_decryption_proofs.len(),
                        expected_esm,
                        e3_id
                    );
                    c4_count_dishonest.insert(party_id);
                    None
                } else {
                    Some(PartyShareDecryptionProofsToVerify {
                        sender_party_id: party_id,
                        signed_sk_decryption_proof: share.signed_sk_decryption_proof.clone(),
                        signed_e_sm_decryption_proofs: share.signed_e_sm_decryption_proofs.clone(),
                    })
                }
            })
            .collect();

        // Evict pre-dishonest parties (wrong ESM count) from honest set
        if !c4_count_dishonest.is_empty() {
            self.state.try_mutate(&ec, |mut s| {
                if let Some(ref mut honest) = s.honest_parties {
                    honest.retain(|pid| !c4_count_dishonest.contains(pid));
                }
                Ok(s)
            })?;
        }

        if party_proofs.is_empty() {
            // Check threshold viability after removing pre-dishonest parties
            let state = self.state.try_get()?;
            let threshold = state.threshold_m;
            let honest_count = state
                .honest_parties
                .as_ref()
                .map(|h| h.len() as u64)
                .unwrap_or(0);

            if honest_count <= threshold {
                warn!(
                    "Too few honest parties after C4 pre-filtering for E3 {} ({} honest, need at least {})",
                    e3_id, honest_count, threshold + 1
                );
                self.bus.publish(
                    E3Failed {
                        e3_id: e3_id.clone(),
                        failed_at_stage: E3Stage::CommitteeFinalized,
                        reason: FailureReason::InsufficientCommitteeMembers,
                    },
                    ec,
                )?;
                return Ok(());
            }

            info!("No C4 proofs to verify — publishing KeyshareCreated directly");
            return self.publish_keyshare_created(ec);
        }

        let pre_dishonest: BTreeSet<u64> = c4_count_dishonest.into_iter().collect();

        info!(
            "Dispatching C4 share verification for E3 {} ({} parties, {} pre-dishonest)",
            e3_id,
            party_proofs.len(),
            pre_dishonest.len()
        );

        self.bus.publish(
            ShareVerificationDispatched {
                e3_id: e3_id.clone(),
                kind: VerificationKind::DecryptionProofs,
                share_proofs: Vec::new(),
                decryption_proofs: party_proofs,
                pre_dishonest,
                params_preset: self.share_enc_preset,
            },
            ec,
        )?;
        Ok(())
    }

    /// Publish KeyshareCreated (Exchange #4) with pk_share and signed C1 proof.
    fn publish_keyshare_created(&mut self, ec: EventContext<Sequenced>) -> Result<()> {
        let state = self.state.try_get()?;
        let e3_id = state.get_e3_id();
        let address = state.get_address().to_owned();
        let party_id = state.get_party_id();
        let current: ReadyForDecryption = state.clone().try_into()?;

        info!("Publishing Exchange #4 (KeyshareCreated) for E3 {}", e3_id);

        self.bus.publish(
            KeyshareCreated {
                pubkey: current.pk_share,
                e3_id: e3_id.clone(),
                node: address,
                party_id,
                signed_pk_generation_proof: current.signed_pk_generation_proof,
            },
            ec,
        )?;

        Ok(())
    }

    /// CiphertextOutputPublished
    pub fn handle_ciphertext_output_published(
        &mut self,
        msg: TypedEvent<CiphertextOutputPublished>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();
        let ciphertext_output = msg.ciphertext_output;

        // Set state to decrypting, storing ciphertext for later C6 proof generation
        self.state.try_mutate(&ec, |s| {
            use KeyshareState as K;

            let current: ReadyForDecryption = s.clone().try_into()?;

            let next = K::Decrypting(Decrypting {
                pk_share: current.pk_share,
                sk_poly_sum: current.sk_poly_sum,
                es_poly_sum: current.es_poly_sum,
                ciphertext_output: ciphertext_output.clone(),
                signed_pk_generation_proof: current.signed_pk_generation_proof,
                signed_sk_share_computation_proof: current.signed_sk_share_computation_proof,
                signed_e_sm_share_computation_proof: current.signed_e_sm_share_computation_proof,
                signed_sk_share_encryption_proofs: current.signed_sk_share_encryption_proofs,
                signed_e_sm_share_encryption_proofs: current.signed_e_sm_share_encryption_proofs,
            });

            s.new_state(next)
        })?;

        let state = self.state.try_get()?;
        let e3_id = state.get_e3_id();
        let decrypting: Decrypting = state.clone().try_into()?;
        let trbfv_config = state.get_trbfv_config();
        let event = ComputeRequest::trbfv(
            TrBFVRequest::CalculateDecryptionShare(
                CalculateDecryptionShareRequest {
                    name: format!("party_id({})", state.party_id),
                    ciphertexts: ciphertext_output,
                    sk_poly_sum: decrypting.sk_poly_sum,
                    es_poly_sum: decrypting.es_poly_sum,
                    trbfv_config,
                }
                .into(),
            ),
            CorrelationId::new(),
            e3_id.clone(),
        );
        self.bus.publish(event, ec)?; // CalculateDecryptionShareRequest
        Ok(())
    }

    /// CalculateDecryptionShareResponse — publish ShareDecryptionProofPending
    /// so ProofRequestActor generates and signs C6 proofs.
    pub fn handle_calculate_decryption_share_response(
        &mut self,
        res: TypedEvent<ComputeResponse>,
    ) -> Result<()> {
        let (res, ec) = res.into_components();
        let msg: CalculateDecryptionShareResponse = res.try_into()?;
        let state = self.state.try_get()?;
        let e3_id = state.e3_id.clone();
        let decrypting: Decrypting = state.clone().try_into()?;
        let d_share_poly = msg.d_share_poly;

        let aggregated_pk_bytes = state
            .aggregated_pk
            .clone()
            .ok_or_else(|| anyhow!("Aggregated public key not available for C6 proof"))?;

        let threshold_preset = self
            .share_enc_preset
            .clone()
            .threshold_counterpart()
            .ok_or_else(|| {
                anyhow!(
                    "No threshold counterpart for preset {:?}",
                    self.share_enc_preset
                )
            })?;

        info!("Publishing ShareDecryptionProofPending for C6 proof generation...");

        // Publish pending event before transitioning state so a publish
        // failure leaves us in Decrypting (retryable) rather than
        // GeneratingDecryptionProof (no retry path).
        self.bus.publish(
            ShareDecryptionProofPending {
                e3_id: e3_id.clone(),
                party_id: state.party_id,
                node: state.address.clone(),
                decryption_share: d_share_poly.clone(),
                proof_request: ThresholdShareDecryptionProofRequest {
                    ciphertext_bytes: decrypting.ciphertext_output,
                    aggregated_pk_bytes,
                    sk_poly_sum: decrypting.sk_poly_sum,
                    es_poly_sum: decrypting.es_poly_sum,
                    d_share_bytes: d_share_poly.clone(),
                    params_preset: threshold_preset,
                },
            },
            ec.clone(),
        )?;

        // Transition to GeneratingDecryptionProof state
        self.state.try_mutate(&ec, |s| {
            use KeyshareState as K;
            s.new_state(K::GeneratingDecryptionProof(GeneratingDecryptionProof {
                pk_share: decrypting.pk_share.clone(),
                decryption_share: d_share_poly,
                signed_pk_generation_proof: decrypting.signed_pk_generation_proof.clone(),
                signed_sk_share_computation_proof: decrypting
                    .signed_sk_share_computation_proof
                    .clone(),
                signed_e_sm_share_computation_proof: decrypting
                    .signed_e_sm_share_computation_proof
                    .clone(),
                signed_sk_share_encryption_proofs: decrypting
                    .signed_sk_share_encryption_proofs
                    .clone(),
                signed_e_sm_share_encryption_proofs: decrypting
                    .signed_e_sm_share_encryption_proofs
                    .clone(),
            }))
        })?;
        Ok(())
    }

    pub fn handle_decryption_share_proof_signed(
        &mut self,
        msg: TypedEvent<DecryptionShareProofSigned>,
    ) -> Result<()> {
        let (_msg, ec) = msg.into_components();

        self.state.try_mutate(&ec, |s| {
            use KeyshareState as K;
            info!("Decryption share sending process is complete");
            s.new_state(K::Completed)
        })?;

        Ok(())
    }
}

// Will only receive events that are for this specific e3_id
impl Handler<EnclaveEvent> for ThresholdKeyshare {
    type Result = ();
    fn handle(&mut self, msg: EnclaveEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        match msg {
            EnclaveEventData::CiphernodeSelected(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            EnclaveEventData::CiphertextOutputPublished(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            EnclaveEventData::PublicKeyAggregated(data) => {
                let pk = ArcBytes::from_bytes(&data.pubkey);
                let _ = self.state.try_mutate(&ec, |mut s| {
                    s.aggregated_pk = Some(pk);
                    Ok(s)
                });
            }
            EnclaveEventData::ThresholdShareCreated(data) => {
                let _ =
                    self.handle_threshold_share_created(TypedEvent::new(data, ec), ctx.address());
            }
            EnclaveEventData::EncryptionKeyCreated(data) => {
                let _ =
                    self.handle_encryption_key_created(TypedEvent::new(data, ec), ctx.address());
            }
            EnclaveEventData::PkGenerationProofSigned(data) => {
                let _ = self.handle_pk_generation_proof_signed(TypedEvent::new(data, ec));
            }
            EnclaveEventData::DkgProofSigned(data) => {
                let _ = self.handle_share_computation_proof_signed(TypedEvent::new(data, ec));
            }
            EnclaveEventData::E3RequestComplete(data) => self.notify_sync(ctx, data),
            EnclaveEventData::E3Failed(data) => {
                warn!(
                    "E3 failed: {:?}. Shutting down ThresholdKeyshare for e3_id={}",
                    data.reason, data.e3_id
                );
                self.notify_sync(ctx, E3RequestComplete { e3_id: data.e3_id });
            }
            EnclaveEventData::E3StageChanged(data) => {
                use e3_events::E3Stage;
                match &data.new_stage {
                    E3Stage::Complete | E3Stage::Failed => {
                        info!("E3 reached terminal stage {:?}. Shutting down ThresholdKeyshare for e3_id={}", data.new_stage, data.e3_id);
                        self.notify_sync(ctx, E3RequestComplete { e3_id: data.e3_id });
                    }
                    _ => {
                        trace!(
                            "E3 stage changed to {:?} for e3_id={}",
                            data.new_stage,
                            data.e3_id
                        );
                    }
                }
            }
            EnclaveEventData::DecryptionKeyShared(data) => {
                if data.external {
                    // Route based on current state
                    if let Some(state) = self.state.get() {
                        if state.expelled_parties.contains(&data.party_id) {
                            info!(
                                "Dropping DecryptionKeyShared from expelled party {}",
                                data.party_id
                            );
                            return;
                        }
                        let result = match &state.state {
                            KeyshareState::AggregatingDecryptionKey(_) => {
                                self.handle_early_decryption_key_share(data, ec)
                            }
                            KeyshareState::ReadyForDecryption(_) => {
                                // Delegate to the collector actor
                                if let Some(ref collector) = self.decryption_key_shared_collector {
                                    collector.do_send(TypedEvent::new(data, ec));
                                    Ok(())
                                } else {
                                    warn!(
                                        "DecryptionKeyShared from party {} dropped — no collector (sole honest party)",
                                        data.party_id
                                    );
                                    Ok(())
                                }
                            }
                            other => {
                                trace!(
                                    "DecryptionKeyShared from party {} in unexpected state {:?}, ignoring",
                                    data.party_id,
                                    other.variant_name()
                                );
                                Ok(())
                            }
                        };
                        if let Err(err) = result {
                            error!("Failed to handle DecryptionKeyShared: {err}");
                        }
                    }
                } else {
                    // Own DecryptionKeyShared published by ProofRequestActor.
                    // A3 fast-path: if no other honest parties, publish KeyshareCreated directly.
                    if let Some(state) = self.state.get() {
                        if data.party_id == state.party_id {
                            if let KeyshareState::ReadyForDecryption(_) = state.state {
                                let others = state
                                    .honest_parties
                                    .as_ref()
                                    .map(|h| h.iter().filter(|&&pid| pid != state.party_id).count())
                                    .unwrap_or(0);
                                if others == 0 {
                                    info!(
                                        "No other honest parties for E3 {} — publishing KeyshareCreated directly",
                                        data.e3_id
                                    );
                                    if let Err(err) = self.publish_keyshare_created(ec) {
                                        error!("Failed to publish KeyshareCreated: {err}");
                                    }
                                }
                            }
                        }
                    }
                }
            }
            EnclaveEventData::DecryptionShareProofSigned(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            EnclaveEventData::ShareVerificationComplete(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            EnclaveEventData::ComputeResponse(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            EnclaveEventData::CommitteeMemberExpelled(data) => {
                self.handle_committee_member_expelled(data, ec);
            }
            _ => (),
        }
    }
}

impl Handler<TypedEvent<DecryptionShareProofSigned>> for ThresholdKeyshare {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<DecryptionShareProofSigned>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::KeyGeneration,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_decryption_share_proof_signed(msg),
        )
    }
}

impl Handler<TypedEvent<ComputeResponse>> for ThresholdKeyshare {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::KeyGeneration,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_compute_response(msg, ctx.address()),
        )
    }
}

impl Handler<TypedEvent<CiphernodeSelected>> for ThresholdKeyshare {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<CiphernodeSelected>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::KeyGeneration,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_ciphernode_selected(msg, ctx.address()),
        )
    }
}

impl Handler<TypedEvent<AllEncryptionKeysCollected>> for ThresholdKeyshare {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<AllEncryptionKeysCollected>,
        _: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::KeyGeneration,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_all_encryption_keys_collected(msg),
        )
    }
}

impl Handler<TypedEvent<ShareVerificationComplete>> for ThresholdKeyshare {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<ShareVerificationComplete>,
        _: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::KeyGeneration,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_share_verification_complete(msg),
        )
    }
}

impl Handler<TypedEvent<AllThresholdSharesCollected>> for ThresholdKeyshare {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<AllThresholdSharesCollected>,
        _: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::KeyGeneration,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_all_threshold_shares_collected(msg),
        )
    }
}

impl Handler<TypedEvent<CiphertextOutputPublished>> for ThresholdKeyshare {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<CiphertextOutputPublished>,
        _: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::KeyGeneration,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_ciphertext_output_published(msg),
        )
    }
}

impl Handler<EncryptionKeyCollectionFailed> for ThresholdKeyshare {
    type Result = ();
    fn handle(
        &mut self,
        msg: EncryptionKeyCollectionFailed,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(EType::KeyGeneration, &self.bus.clone(), || {
            warn!(
                e3_id = %msg.e3_id,
                missing_parties = ?msg.missing_parties,
                "Encryption key collection failed: {}",
                msg.reason
            );

            // Clear the collector reference since it's stopped
            self.encryption_key_collector = None;

            // Publish failure event to event bus for sync tracking
            self.bus.publish_without_context(msg.clone())?;

            self.bus.publish_without_context(E3Failed {
                e3_id: msg.e3_id,
                failed_at_stage: E3Stage::CommitteeFinalized,
                reason: FailureReason::InsufficientCommitteeMembers,
            })?;

            // Stop this actor since we can't proceed without all encryption keys
            ctx.stop();
            Ok(())
        })
    }
}

impl Handler<ThresholdShareCollectionFailed> for ThresholdKeyshare {
    type Result = ();
    fn handle(
        &mut self,
        msg: ThresholdShareCollectionFailed,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(EType::KeyGeneration, &self.bus.clone(), || {
            warn!(
                e3_id = %msg.e3_id,
                missing_parties = ?msg.missing_parties,
                "Threshold share collection failed: {}",
                msg.reason
            );

            // Clear the collector reference since it's stopped
            self.decryption_key_collector = None;

            // Publish failure event to event bus for sync tracking
            self.bus.publish_without_context(msg.clone())?;

            self.bus.publish_without_context(E3Failed {
                e3_id: msg.e3_id,
                failed_at_stage: E3Stage::CommitteeFinalized,
                reason: FailureReason::InsufficientCommitteeMembers,
            })?;

            ctx.stop();
            Ok(())
        })
    }
}

impl Handler<TypedEvent<AllDecryptionKeySharesCollected>> for ThresholdKeyshare {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<AllDecryptionKeySharesCollected>,
        _: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::KeyGeneration,
            &self.bus.with_ec(msg.get_ctx()),
            || {
                let (msg, ec) = msg.into_components();
                self.decryption_key_shared_collector = None;
                self.dispatch_c4_verification(msg.shares, ec)
            },
        )
    }
}

impl Handler<DecryptionKeySharedCollectionFailed> for ThresholdKeyshare {
    type Result = ();
    fn handle(
        &mut self,
        msg: DecryptionKeySharedCollectionFailed,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(EType::KeyGeneration, &self.bus.clone(), || {
            warn!(
                e3_id = %msg.e3_id,
                missing_parties = ?msg.missing_parties,
                "DecryptionKeyShared collection failed: {}",
                msg.reason
            );

            self.decryption_key_shared_collector = None;

            self.bus.publish_without_context(E3Failed {
                e3_id: msg.e3_id.clone(),
                failed_at_stage: E3Stage::CommitteeFinalized,
                reason: FailureReason::InsufficientCommitteeMembers,
            })?;

            ctx.stop();
            Ok(())
        })
    }
}

impl Handler<E3RequestComplete> for ThresholdKeyshare {
    type Result = ();
    fn handle(&mut self, _: E3RequestComplete, ctx: &mut Self::Context) -> Self::Result {
        self.encryption_key_collector = None;
        self.decryption_key_collector = None;
        self.decryption_key_shared_collector = None;
        self.pending_shares.clear();
        self.pending_share_decryption_data = None;
        self.pending_c4_verification_shares = None;
        self.notify_sync(ctx, Die);
    }
}

impl Handler<Die> for ThresholdKeyshare {
    type Result = ();
    fn handle(&mut self, _: Die, ctx: &mut Self::Context) -> Self::Result {
        warn!("ThresholdKeyshare is shutting down");
        ctx.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decryption_key_shared_collector::DecryptionKeySharedCollectionFailed;
    use actix::{Actor, Addr, Handler};
    use anyhow::Result;
    use e3_crypto::Cipher;
    use e3_data::{AutoPersist, DataStore, InMemStore, Persistable, Repository};
    use e3_events::{
        hlc_factory::HlcFactory, BusHandle, E3Stage, E3id, EnclaveEvent, EnclaveEventData,
        EventBus, EventBusConfig, FailureReason, HistoryCollector, Sequencer, StoreEventRequested,
        StoreEventResponse, TakeEvents,
    };
    use e3_fhe_params::DEFAULT_BFV_PRESET;
    use std::sync::Arc;

    #[derive(Default)]
    struct TestEventStore {
        next_seq: u64,
    }

    impl Actor for TestEventStore {
        type Context = actix::Context<Self>;
    }

    impl Handler<StoreEventRequested> for TestEventStore {
        type Result = ();

        fn handle(&mut self, msg: StoreEventRequested, _: &mut Self::Context) -> Self::Result {
            let StoreEventRequested { event, sender } = msg;
            let seq = self.next_seq;
            self.next_seq += 1;
            sender.do_send(StoreEventResponse(event.into_sequenced(seq)));
        }
    }

    fn test_bus() -> (BusHandle, Addr<HistoryCollector<EnclaveEvent>>) {
        let event_bus = EventBus::<EnclaveEvent>::new(EventBusConfig { deduplicate: true }).start();
        let store = TestEventStore::default().start();
        let sequencer = Sequencer::new(&event_bus, store.recipient()).start();
        let bus = BusHandle::new(event_bus, sequencer, HlcFactory::new()).enable("test-keyshare");
        let history = bus.history();
        (bus, history)
    }

    fn test_state() -> Persistable<ThresholdKeyshareState> {
        let store = InMemStore::new(false).start();
        let repo = Repository::<ThresholdKeyshareState>::new(DataStore::from_in_mem(&store));
        repo.send(None)
    }

    async fn start_actor() -> Result<(
        Addr<ThresholdKeyshare>,
        Addr<HistoryCollector<EnclaveEvent>>,
        E3id,
    )> {
        let (bus, history) = test_bus();
        let actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
            bus,
            cipher: Arc::new(Cipher::from_password("test-password").await?),
            state: test_state(),
            share_enc_preset: DEFAULT_BFV_PRESET,
        })
        .start();

        Ok((actor, history, E3id::new("42", 1)))
    }

    async fn next_event(history: &Addr<HistoryCollector<EnclaveEvent>>) -> Result<EnclaveEvent> {
        let mut result = history.send(TakeEvents::<EnclaveEvent>::new(1)).await?;
        assert!(!result.timed_out, "timed out waiting for an event");
        Ok(result.events.pop().expect("expected one event"))
    }

    async fn next_events(
        history: &Addr<HistoryCollector<EnclaveEvent>>,
        count: usize,
    ) -> Result<Vec<EnclaveEvent>> {
        let result = history.send(TakeEvents::<EnclaveEvent>::new(count)).await?;
        assert!(!result.timed_out, "timed out waiting for events");
        assert_eq!(result.events.len(), count, "expected {count} events");
        Ok(result.events)
    }

    #[actix::test]
    async fn encryption_key_collection_failure_preserves_telemetry_and_emits_e3_failed(
    ) -> Result<()> {
        let (actor, history, e3_id) = start_actor().await?;
        let failure = EncryptionKeyCollectionFailed {
            e3_id,
            reason: "missing encryption keys".to_string(),
            missing_parties: vec![2, 3],
        };

        actor.send(failure.clone()).await?;

        let mut events = next_events(&history, 2).await?;
        let event = events.remove(0);
        assert!(matches!(
            event.into_data(),
            EnclaveEventData::EncryptionKeyCollectionFailed(data) if data == failure
        ));

        let event = events.remove(0);
        assert!(matches!(
            event.into_data(),
            EnclaveEventData::E3Failed(data)
                if data.e3_id == failure.e3_id
                    && data.failed_at_stage == E3Stage::CommitteeFinalized
                    && data.reason == FailureReason::InsufficientCommitteeMembers
        ));

        Ok(())
    }

    #[actix::test]
    async fn threshold_share_collection_failure_preserves_telemetry_and_emits_e3_failed(
    ) -> Result<()> {
        let (actor, history, e3_id) = start_actor().await?;
        let failure = ThresholdShareCollectionFailed {
            e3_id,
            reason: "missing threshold shares".to_string(),
            missing_parties: vec![4, 5],
        };

        actor.send(failure.clone()).await?;

        let mut events = next_events(&history, 2).await?;
        let event = events.remove(0);
        assert!(matches!(
            event.into_data(),
            EnclaveEventData::ThresholdShareCollectionFailed(data) if data == failure
        ));

        let event = events.remove(0);
        assert!(matches!(
            event.into_data(),
            EnclaveEventData::E3Failed(data)
                if data.e3_id == failure.e3_id
                    && data.failed_at_stage == E3Stage::CommitteeFinalized
                    && data.reason == FailureReason::InsufficientCommitteeMembers
        ));

        Ok(())
    }

    #[actix::test]
    async fn decryption_key_shared_collection_failure_emits_e3_failed() -> Result<()> {
        let (actor, history, e3_id) = start_actor().await?;
        let failure = DecryptionKeySharedCollectionFailed {
            e3_id,
            reason: "missing decryption key shares".to_string(),
            missing_parties: vec![6, 7],
        };

        actor.send(failure.clone()).await?;

        let event = next_event(&history).await?;
        assert!(matches!(
            event.into_data(),
            EnclaveEventData::E3Failed(data)
                if data.e3_id == failure.e3_id
                    && data.failed_at_stage == E3Stage::CommitteeFinalized
                    && data.reason == FailureReason::InsufficientCommitteeMembers
        ));

        Ok(())
    }
}
