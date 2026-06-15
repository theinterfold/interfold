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
    DkgProofSigned, DkgShareDecryptionProofRequest, E3Failed, E3RequestComplete, E3Stage, EType,
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
    /// Set when C4 verification completes before `PkGenerationProofSigned` is applied.
    pending_keyshare_publish: bool,
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
            pending_keyshare_publish: false,
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
        if !self.pending_keyshare_publish {
            return Ok(());
        }
        let state = self.state.try_get()?;
        let Some((_, signed)) = Self::keyshare_created_fields(&state.state) else {
            return Ok(());
        };
        if signed.is_none() {
            return Ok(());
        }
        self.pending_keyshare_publish = false;
        self.publish_keyshare_created(ec)
    }
}

impl Actor for ThresholdKeyshare {
    type Context = actix::Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
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

        self.store_signed_pk_generation_proof(&ec, msg.signed_proof)?;
        self.try_finish_deferred_keyshare_publish(ec)?;

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

        info!("CiphernodeSelected received.");
        // Ensure the collectors are created
        let _ = self.ensure_collector(address.clone());
        let _ = self.ensure_encryption_key_collector(address.clone());

        let BfvKeypairMaterial {
            sk_bfv: sk_bfv_encrypted,
            pk_bfv: pk_bfv_bytes,
        } = generate_bfv_keypair(&self.share_enc_preset, &self.cipher)?;

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

        let committee_size = CiphernodesCommitteeSize::from_threshold(
            state.threshold_m as usize,
            state.threshold_n as usize,
        )?;
        self.bus.publish(
            EncryptionKeyPending {
                e3_id,
                key: Arc::new(EncryptionKey::new(state.party_id, pk_bfv_bytes)),
                params_preset: self.share_enc_preset,
                committee_size,
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
        info!(
            "AllEncryptionKeysCollected - {} keys received",
            msg.keys.len()
        );

        let state = self.state.try_get()?;
        let current: CollectingEncryptionKeysData = state.clone().try_into()?;

        // Filter out any keys from parties expelled after collection started
        let filtered_keys: Vec<_> = if state.expelled_parties.is_empty() {
            msg.keys
        } else {
            msg.keys
                .into_iter()
                .filter(|k| !state.expelled_parties.contains(&k.party_id))
                .collect()
        };

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
            TrBFVRequest::GenPkShareAndSkSss(GenPkShareAndSkSssRequest {
                trbfv_config,
                crp,
                lambda: threshold_preset.lambda_config(),
                num_ciphertexts: defaults.z as usize,
            }),
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

        // Decrypt our shares from local storage
        let decrypted_sk_sss: SharedSecret = sk_sss.decrypt(&self.cipher)?;
        let decrypted_esi_sss: Vec<SharedSecret> = esi_sss
            .into_iter()
            .map(|s| s.decrypt(&self.cipher))
            .collect::<Result<_>>()?;

        let plan = build_shares_generated_plan(
            &self.cipher,
            self.share_enc_preset,
            party_id,
            threshold_m,
            threshold_n,
            pk_share,
            decrypted_sk_sss,
            decrypted_esi_sss,
            e_sm_raw,
            proof_request_data,
            &collected_encryption_keys,
        )?;

        // Cache own plaintext share rows for the AggregatingDecryptionKey transition.
        self.pending_own_dkg_shares = Some((plan.own_sk_share_raw, plan.own_esi_shares_raw));

        let proof_aggregation_enabled = self
            .state
            .try_get()
            .map(|s| s.proof_aggregation_enabled)
            .unwrap_or(true);

        info!("Publishing ThresholdSharePending for E3 {}", e3_id);

        // Publish ThresholdSharePending - ProofRequestActor will generate proof, sign, and publish ThresholdShareCreated
        self.bus.publish(
            ThresholdSharePending {
                e3_id,
                full_share: Arc::new(plan.full_share),
                proof_request: plan.proof_request,
                sk_share_computation_request: plan.sk_share_computation_request,
                e_sm_share_computation_request: plan.e_sm_share_computation_request,
                sk_share_encryption_requests: plan.sk_share_encryption_requests,
                e_sm_share_encryption_requests: plan.e_sm_share_encryption_requests,
                recipient_party_ids: plan.recipient_party_ids,
                proof_aggregation_enabled,
            },
            ec,
        )?;

        Ok(())
    }

    /// 5. AllThresholdSharesCollected - Verify C2/C3 proofs, then decrypt and aggregate
    pub fn handle_all_threshold_shares_collected(
        &mut self,
        msg: TypedEvent<AllThresholdSharesCollected>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();
        info!("AllThresholdSharesCollected");
        let state = self.state.try_get()?;
        let e3_id = state.get_e3_id();
        let own_party_id = state.party_id;

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
                .zip(msg.share_proofs)
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
        self.pending_shares = shares.to_vec();

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

        let committee_size = CiphernodesCommitteeSize::from_threshold(
            state.threshold_m as usize,
            state.threshold_n as usize,
        )?;
        self.bus.publish(
            ShareVerificationDispatched {
                e3_id: e3_id.clone(),
                kind: VerificationKind::ShareProofs,
                share_proofs: party_proofs_to_verify,
                decryption_proofs: Vec::new(),
                pre_dishonest,
                params_preset: self.share_enc_preset,
                committee_size,
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
        let state = self.state.try_get()?;
        let e3_id = state.get_e3_id();
        let trbfv_config = state.get_trbfv_config();

        // Get our BFV secret key from state, pending shares from the actor
        let current: AggregatingDecryptionKey = state.clone().try_into()?;
        let shares = std::mem::take(&mut self.pending_shares);

        let plan = build_decryption_key_plan(
            &self.cipher,
            self.share_enc_preset,
            state.party_id,
            state.threshold_m,
            state.threshold_n,
            trbfv_config,
            &current,
            shares,
            dishonest_parties,
            e3_id,
        )?;

        match plan {
            DecryptionKeyPlan::Insufficient => {
                self.pending_shares.clear();
                self.bus.publish(
                    E3Failed {
                        e3_id: e3_id.clone(),
                        failed_at_stage: E3Stage::CommitteeFinalized,
                        reason: FailureReason::InsufficientCommitteeMembers,
                    },
                    ec,
                )?;
            }
            DecryptionKeyPlan::Proceed {
                calc_request,
                sk_request,
                esm_requests,
                honest_party_ids,
            } => {
                // Publish CalculateDecryptionKey request before persisting (ordering preserved).
                let event = ComputeRequest::trbfv(
                    TrBFVRequest::CalculateDecryptionKey(calc_request),
                    CorrelationId::new(),
                    e3_id.clone(),
                );
                self.bus.publish(event, ec.clone())?;

                // Store honest parties and C4 data on the actor (transient coordination)
                self.state.try_mutate(&ec, |mut s| {
                    s.honest_parties = Some(honest_party_ids.clone());
                    Ok(s)
                })?;
                self.pending_share_decryption_data = Some((sk_request, esm_requests));
            }
        }

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

        let committee_size = CiphernodesCommitteeSize::from_threshold(
            state.threshold_m as usize,
            state.threshold_n as usize,
        )?;
        self.bus.publish(
            ShareVerificationDispatched {
                e3_id: e3_id.clone(),
                kind: VerificationKind::DecryptionProofs,
                share_proofs: Vec::new(),
                decryption_proofs: party_proofs,
                pre_dishonest,
                params_preset: self.share_enc_preset,
                committee_size,
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
        let Some((pk_share, signed_pk_generation_proof)) =
            Self::keyshare_created_fields(&state.state)
        else {
            warn!(
                "Deferring KeyshareCreated for party {} E3 {} — not in ReadyForDecryption/Decrypting ({})",
                party_id,
                e3_id,
                state.state.variant_name()
            );
            self.pending_keyshare_publish = true;
            return Ok(());
        };

        if signed_pk_generation_proof.is_none() {
            warn!(
                "Deferring KeyshareCreated for party {} E3 {} — C1 proof not stored yet (PkGenerationProofSigned race)",
                party_id, e3_id
            );
            self.pending_keyshare_publish = true;
            return Ok(());
        }

        info!("Publishing Exchange #4 (KeyshareCreated) for E3 {}", e3_id);

        self.bus.publish(
            KeyshareCreated {
                pubkey: pk_share.clone(),
                e3_id: e3_id.clone(),
                node: address,
                party_id,
                signed_pk_generation_proof: signed_pk_generation_proof.clone(),
            },
            ec.clone(),
        )?;

        // Record that publishing was authorized and has occurred, so resume-after-crash
        // may safely re-publish (idempotent at the aggregator) without ever emitting a
        // keyshare for a state that had not yet passed C4 honest-set filtering.
        self.state.try_mutate(&ec, |mut s| {
            s.keyshare_published = true;
            Ok(s)
        })?;

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
            TrBFVRequest::CalculateDecryptionShare(CalculateDecryptionShareRequest {
                name: format!("party_id({})", state.party_id),
                ciphertexts: ciphertext_output,
                sk_poly_sum: decrypting.sk_poly_sum,
                es_poly_sum: decrypting.es_poly_sum,
                trbfv_config,
            }),
            CorrelationId::new(),
            e3_id.clone(),
        );
        self.bus.publish(event, ec)?; // CalculateDecryptionShareRequest
        Ok(())
    }

    /// (Re)issue the `CalculateDecryptionShare` compute request from the current
    /// `Decrypting` state. Factored out of `handle_ciphertext_output_published` so the
    /// boot-time resume path can re-drive the decryption-share computation idempotently
    /// (the resulting `DecryptionshareCreated` is deduped by `party_id` at the aggregator).
    fn issue_decryption_share_request(&self, ec: EventContext<Sequenced>) -> Result<()> {
        let state = self.state.try_get()?;
        let e3_id = state.get_e3_id();
        let decrypting: Decrypting = state.clone().try_into()?;
        let trbfv_config = state.get_trbfv_config();
        let event = ComputeRequest::trbfv(
            TrBFVRequest::CalculateDecryptionShare(CalculateDecryptionShareRequest {
                name: format!("party_id({})", state.party_id),
                ciphertexts: decrypting.ciphertext_output,
                sk_poly_sum: decrypting.sk_poly_sum,
                es_poly_sum: decrypting.es_poly_sum,
                trbfv_config,
            }),
            CorrelationId::new(),
            e3_id.clone(),
        );
        self.bus.publish(event, ec)?;
        Ok(())
    }

    /// Re-drive this node's own in-flight DKG/decryption work after a crash or restart.
    ///
    /// Invoked when `EffectsEnabled` is broadcast at the end of boot sync, *after* this
    /// actor has been hydrated from its persisted state. The dangerous, value-bearing
    /// concern with re-driving is double-emission; this is safe here because every output
    /// re-emitted below is deduplicated downstream by `party_id`:
    ///   * `KeyshareCreated` — `PublicKeyAggregation::add_keyshare` ignores a `party_id`
    ///     that already submitted (idempotent), and
    ///   * `DecryptionshareCreated` — threshold plaintext aggregation keys shares by
    ///     `party_id` (re-insert overwrites with the identical deterministic share).
    ///
    /// Only states where the local result is already determined are re-driven. Earlier
    /// phases depend on peer gossip that cannot be reconstructed locally and are surfaced
    /// (non-destructively) by `interfold node validate` instead of being force-re-driven.
    fn resume_in_flight_work(&mut self, ec: EventContext<Sequenced>) -> Result<()> {
        let Some(state) = self.state.get() else {
            return Ok(());
        };
        match &state.state {
            // We have produced our public-key share but may have crashed before (or while)
            // publishing KeyshareCreated. Re-publishing is idempotent at the aggregator, but
            // ReadyForDecryption is entered *before* C4 honest-set verification authorizes the
            // publish, so only re-drive when a prior authorized publish was recorded. An
            // un-published ReadyForDecryption is a loose end surfaced by `interfold node validate`.
            KeyshareState::ReadyForDecryption(_) if state.keyshare_published => {
                info!(
                    e3_id = %state.e3_id,
                    "Resuming in-flight work: re-publishing KeyshareCreated"
                );
                self.publish_keyshare_created(ec)?;
            }
            // The ciphertext to decrypt has arrived. Re-publish our keyshare (in case the
            // crash happened before it propagated) and re-issue the decryption-share
            // computation so a DecryptionshareCreated is (re)produced.
            KeyshareState::Decrypting(_) => {
                info!(
                    e3_id = %state.e3_id,
                    "Resuming in-flight work: re-publishing KeyshareCreated and re-issuing decryption-share request"
                );
                self.publish_keyshare_created(ec.clone())?;
                self.issue_decryption_share_request(ec)?;
            }
            other => {
                trace!(
                    e3_id = %state.e3_id,
                    state = %other.variant_name(),
                    "No locally re-drivable work on resume; loose ends are surfaced by `interfold node validate`"
                );
            }
        }
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
            .threshold_counterpart()
            .ok_or_else(|| {
                anyhow!(
                    "No threshold counterpart for preset {:?}",
                    self.share_enc_preset
                )
            })?;

        info!("Publishing ShareDecryptionProofPending for C6 proof generation...");

        let committee_size = CiphernodesCommitteeSize::from_threshold(
            state.threshold_m as usize,
            state.threshold_n as usize,
        )?;

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
                    committee_size,
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
impl Handler<InterfoldEvent> for ThresholdKeyshare {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        match msg {
            InterfoldEventData::CiphernodeSelected(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CiphertextOutputPublished(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::PublicKeyAggregated(data) => {
                let pk = ArcBytes::from_bytes(&data.pubkey);
                let _ = self.state.try_mutate(&ec, |mut s| {
                    s.aggregated_pk = Some(pk);
                    Ok(s)
                });
            }
            InterfoldEventData::ThresholdShareCreated(data) => {
                let _ =
                    self.handle_threshold_share_created(TypedEvent::new(data, ec), ctx.address());
            }
            InterfoldEventData::EncryptionKeyCreated(data) => {
                let _ =
                    self.handle_encryption_key_created(TypedEvent::new(data, ec), ctx.address());
            }
            InterfoldEventData::PkGenerationProofSigned(data) => {
                let _ = self.handle_pk_generation_proof_signed(TypedEvent::new(data, ec));
            }
            InterfoldEventData::DkgProofSigned(data) => {
                let _ = self.handle_share_computation_proof_signed(TypedEvent::new(data, ec));
            }
            InterfoldEventData::E3RequestComplete(data) => self.notify_sync(ctx, data),
            InterfoldEventData::E3Failed(data) => {
                warn!(
                    "E3 failed: {:?}. Shutting down ThresholdKeyshare for e3_id={}",
                    data.reason, data.e3_id
                );
                self.notify_sync(ctx, E3RequestComplete { e3_id: data.e3_id });
            }
            InterfoldEventData::E3StageChanged(data) => {
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
            InterfoldEventData::DecryptionKeyShared(data) => {
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
            InterfoldEventData::DecryptionShareProofSigned(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ShareVerificationComplete(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ComputeResponse(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CommitteeMemberExpelled(data) => {
                self.handle_committee_member_expelled(data, ec);
            }
            InterfoldEventData::EffectsEnabled(_) => {
                // Broadcast once at the end of boot sync. Re-drive any of this node's own
                // in-flight work that a crash may have interrupted (idempotent downstream).
                if let Err(err) = self.resume_in_flight_work(ec) {
                    warn!("resume_in_flight_work failed: {err}");
                }
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
                reason: FailureReason::DKGTimeout,
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
                reason: FailureReason::DKGTimeout,
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
                reason: FailureReason::DecryptionTimeout,
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
        self.pending_keyshare_publish = false;
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
    use crate::actors::decryption_key_shared_collector::DecryptionKeySharedCollectionFailed;
    use actix::{Actor, Addr, Handler};
    use anyhow::Result;
    use e3_crypto::Cipher;
    use e3_data::{AutoPersist, DataStore, InMemStore, Persistable, Repository};
    use e3_events::{
        hlc_factory::HlcFactory, BusHandle, E3Stage, E3id, EventBus, EventBusConfig, FailureReason,
        HistoryCollector, InterfoldEvent, InterfoldEventData, Sequencer, StoreEventRequested,
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

    fn test_bus() -> (BusHandle, Addr<HistoryCollector<InterfoldEvent>>) {
        let event_bus =
            EventBus::<InterfoldEvent>::new(EventBusConfig { deduplicate: true }).start();
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
        Addr<HistoryCollector<InterfoldEvent>>,
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

    async fn next_event(
        history: &Addr<HistoryCollector<InterfoldEvent>>,
    ) -> Result<InterfoldEvent> {
        let mut result = history.send(TakeEvents::<InterfoldEvent>::new(1)).await?;
        assert!(!result.timed_out, "timed out waiting for an event");
        Ok(result.events.pop().expect("expected one event"))
    }

    async fn next_events(
        history: &Addr<HistoryCollector<InterfoldEvent>>,
        count: usize,
    ) -> Result<Vec<InterfoldEvent>> {
        let result = history
            .send(TakeEvents::<InterfoldEvent>::new(count))
            .await?;
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
            InterfoldEventData::EncryptionKeyCollectionFailed(data) if data == failure
        ));

        let event = events.remove(0);
        assert!(matches!(
            event.into_data(),
            InterfoldEventData::E3Failed(data)
                if data.e3_id == failure.e3_id
                    && data.failed_at_stage == E3Stage::CommitteeFinalized
                    && data.reason == FailureReason::DKGTimeout
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
            InterfoldEventData::ThresholdShareCollectionFailed(data) if data == failure
        ));

        let event = events.remove(0);
        assert!(matches!(
            event.into_data(),
            InterfoldEventData::E3Failed(data)
                if data.e3_id == failure.e3_id
                    && data.failed_at_stage == E3Stage::CommitteeFinalized
                    && data.reason == FailureReason::DKGTimeout
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
            InterfoldEventData::E3Failed(data)
                if data.e3_id == failure.e3_id
                    && data.failed_at_stage == E3Stage::CommitteeFinalized
                    && data.reason == FailureReason::DecryptionTimeout
        ));

        Ok(())
    }
}
