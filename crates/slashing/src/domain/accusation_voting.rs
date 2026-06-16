// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Plain, synchronous domain service for the off-chain accusation quorum
//! protocol.
//!
//! This module contains **all** the business logic that used to live inside
//! the `AccusationManager` actix actor:
//!
//! - EIP-712 digest computation (accusation + vote)
//! - ECDSA signature creation and verification
//! - deadline stamping / peer-deadline validation
//! - pending-accusation bookkeeping (votes, dedup, buffering)
//! - vote tallying, quorum threshold checks, and equivocation detection
//!
//! [`AccusationVoting`] owns the protocol state and exposes plain methods that
//! mutate that state and **return a list of [`VoteAction`]s** describing the
//! I/O the actor must perform (publish a gossip event, dispatch a ZK request,
//! start/cancel a vote timeout). The service itself performs **no** I/O: it
//! never touches the event bus, the actix context, or timers. This makes the
//! whole protocol deterministically unit-testable without spinning up an actor
//! system.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{keccak256, Address, Bytes, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy::sol_types::SolValue;
use e3_events::{
    AccusationOutcome, AccusationQuorumReached, AccusationVote, CommitmentConsistencyViolation,
    ComputeRequest, ComputeRequestError, ComputeResponse, ComputeResponseKind, CorrelationId, E3id,
    EventContext, PartyProofsToVerify, ProofFailureAccusation, ProofType, ProofVerificationFailed,
    ProofVerificationPassed, Sequenced, SignedProofPayload, SlashExecuted, TypedEvent,
    VerifyShareProofsRequest, ZkRequest, ZkResponse, VOTE_DOMAIN_NAME, VOTE_DOMAIN_VERSION,
    VOTE_TYPEHASH_STR,
};
use e3_utils::ArcBytes;
use e3_zk_helpers::CiphernodesCommitteeSize;
use tracing::{error, info, warn};

use crate::actors::accusation_manager::Clock;

/// How long to wait for votes before declaring the accusation inconclusive.
pub(crate) const DEFAULT_VOTE_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes

/// An I/O effect the actor must perform on behalf of the [`AccusationVoting`]
/// service. The service returns these instead of performing the I/O itself, so
/// all protocol logic stays pure and testable.
pub(crate) enum VoteAction {
    /// Broadcast our own accusation over gossip. `dedup_key` lets the actor
    /// roll back the dedup entry if the (rare) publish fails, preserving the
    /// original actor's behaviour of re-allowing the accusation on a dead bus.
    PublishAccusation {
        accusation: ProofFailureAccusation,
        ec: EventContext<Sequenced>,
        dedup_key: (Address, ProofType),
    },
    /// Broadcast an [`AccusationVote`] over gossip.
    PublishVote {
        vote: AccusationVote,
        ec: EventContext<Sequenced>,
    },
    /// Publish the terminal [`AccusationQuorumReached`] decision.
    PublishQuorum {
        quorum: AccusationQuorumReached,
        ec: EventContext<Sequenced>,
    },
    /// Dispatch an async ZK re-verification request (C3a/C3b forwarding).
    /// `correlation_id` lets the actor discard the pending re-verification if
    /// the publish fails.
    DispatchZk {
        request: ComputeRequest,
        ec: EventContext<Sequenced>,
        correlation_id: CorrelationId,
    },
    /// Start the vote-collection timeout for an accusation.
    StartTimeout([u8; 32]),
    /// Cancel a previously started vote-collection timeout (early quorum).
    CancelTimeout([u8; 32]),
}

/// An active accusation awaiting agreement votes from committee members.
///
/// There is no `votes_against` field: a peer who finds the disputed proof
/// passes simply stays silent rather than broadcasting a signed disagreement.
/// The accusation runs to quorum or to `vote_timeout`.
pub(crate) struct PendingAccusation {
    pub(crate) accusation: ProofFailureAccusation,
    pub(crate) votes_for: Vec<AccusationVote>,
    /// The EventContext from when this accusation was created — used for
    /// timeout emission.
    pub(crate) ec: EventContext<Sequenced>,
}

/// Cached verification result for a proof from a specific (accused, proof_type)
/// pair. Populated as proofs are received and verified (pass or fail).
struct ReceivedProofData {
    data_hash: [u8; 32],
    /// `true` if our local verification passed, `false` if it failed.
    verification_passed: bool,
    /// Raw `abi.encode(proof.data, proof.public_signals)` — preimage of
    /// `data_hash`. Forwarded to the on-chain slashing contract so it can
    /// recompute and verify the dataHash bound in voter signatures.
    evidence: Bytes,
}

/// Tracks an in-flight ZK re-verification for a forwarded C3a/C3b proof.
struct PendingReVerification {
    accusation_id: [u8; 32],
    data_hash: [u8; 32],
    accused: Address,
    proof_type: ProofType,
    /// Evidence preimage bytes from the forwarded proof.
    evidence: Bytes,
}

/// Pure, synchronous core of the accusation quorum protocol.
///
/// Owns all protocol state. Every public method mutates this state and returns
/// the I/O the actor must perform. It performs no I/O of its own.
pub(crate) struct AccusationVoting {
    e3_id: E3id,
    my_address: Address,
    signer: PrivateKeySigner,

    /// On-chain `SlashingManager` address (EIP-712 `verifyingContract`).
    slashing_manager: Address,

    /// All committee member addresses for this E3.
    committee: Vec<Address>,
    /// Quorum threshold — matches the cryptographic threshold M.
    threshold_m: usize,
    /// Original committee N fixed at construction for ZK circuit resolution.
    /// Do not derive from [`Self::committee`] after [`Self::on_slash_executed`] shrinks the roster.
    committee_n: usize,

    /// Active accusations keyed by accusation_id.
    pending: HashMap<[u8; 32], PendingAccusation>,

    /// Dedup: (accused, proof_type) pairs we've already accused.
    accused_proofs: HashSet<(Address, ProofType)>,

    /// Cache of received data hashes per (accused, proof_type).
    received_data: HashMap<(Address, ProofType), ReceivedProofData>,

    /// Votes received before the corresponding accusation.
    buffered_votes: HashMap<[u8; 32], Vec<AccusationVote>>,

    /// In-flight C3a/C3b ZK re-verifications, keyed by CorrelationId.
    pending_reverifications: HashMap<CorrelationId, PendingReVerification>,

    /// Vote timeout duration.
    vote_timeout: Duration,

    /// Registry-wide off-chain freshness window (seconds).
    vote_validity_secs: u64,
    /// Clock-skew allowance when validating peer accusation deadlines.
    accusation_deadline_skew_secs: u64,

    /// Wall-clock source used to derive accusation deadlines.
    clock: Arc<dyn Clock>,

    /// BFV preset for circuit artifact resolution.
    params_preset: e3_fhe_params::BfvPreset,
}

impl AccusationVoting {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        e3_id: E3id,
        signer: PrivateKeySigner,
        slashing_manager: Address,
        committee: Vec<Address>,
        threshold_m: usize,
        vote_validity_secs: u64,
        accusation_deadline_skew_secs: u64,
        params_preset: e3_fhe_params::BfvPreset,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let my_address = signer.address();
        let committee_n = committee.len();
        Self {
            e3_id,
            my_address,
            signer,
            slashing_manager,
            committee,
            threshold_m,
            committee_n,
            pending: HashMap::new(),
            accused_proofs: HashSet::new(),
            received_data: HashMap::new(),
            buffered_votes: HashMap::new(),
            pending_reverifications: HashMap::new(),
            vote_timeout: DEFAULT_VOTE_TIMEOUT,
            vote_validity_secs,
            accusation_deadline_skew_secs,
            clock,
            params_preset,
        }
    }

    /// The vote-collection timeout the actor should schedule.
    pub(crate) fn vote_timeout(&self) -> Duration {
        self.vote_timeout
    }

    // ─── Deadline computation ────────────────────────────────────────────

    /// Compute the on-chain vote-validity deadline (Unix seconds) the accuser
    /// stamps on a fresh accusation.
    fn compute_deadline(&self) -> u64 {
        self.clock
            .unix_now_secs()
            .saturating_add(self.vote_validity_secs)
    }

    /// Validate a peer-provided accusation deadline against this node's local
    /// vote-validity policy and wall clock.
    pub(crate) fn is_peer_deadline_acceptable(
        deadline: u64,
        now: u64,
        vote_validity_secs: u64,
        skew_secs: u64,
    ) -> bool {
        if vote_validity_secs == 0 {
            return false;
        }
        let max_deadline = now
            .saturating_add(vote_validity_secs)
            .saturating_add(skew_secs);
        deadline > now && deadline <= max_deadline
    }

    // ─── Accusation ID computation ───────────────────────────────────────

    /// Compute a deterministic ID for an accusation based on its key fields.
    ///
    /// `keccak256(abi.encodePacked(chainId, e3Id, accused, proofType))`
    pub(crate) fn accusation_id(accusation: &ProofFailureAccusation) -> [u8; 32] {
        let e3_id_u256: U256 = accusation
            .e3_id
            .clone()
            .try_into()
            .expect("E3id should be valid U256");
        let msg = (
            U256::from(accusation.e3_id.chain_id()),
            e3_id_u256,
            accusation.accused,
            U256::from(accusation.proof_type as u8),
        )
            .abi_encode_packed();
        keccak256(&msg).into()
    }

    // ─── Signing / Verification ──────────────────────────────────────────

    fn sign_accusation_digest(
        &self,
        accusation: &ProofFailureAccusation,
    ) -> Result<Vec<u8>, alloy::signers::Error> {
        let digest = Self::accusation_digest(accusation);
        let sig = self.signer.sign_message_sync(&digest)?;
        Ok(sig.as_bytes().to_vec())
    }

    /// Structured digest for ECDSA signing of accusations. Off-chain only.
    pub(crate) fn accusation_digest(accusation: &ProofFailureAccusation) -> [u8; 32] {
        let e3_id_u256: U256 = accusation
            .e3_id
            .clone()
            .try_into()
            .expect("E3id should be valid U256");
        let typehash: [u8; 32] = keccak256(
            "ProofFailureAccusation(uint256 chainId,uint256 e3Id,address accuser,address accused,uint256 proofType,bytes32 dataHash,uint256 deadline)"
        ).into();
        let encoded = (
            typehash,
            U256::from(accusation.e3_id.chain_id()),
            e3_id_u256,
            accusation.accuser,
            accusation.accused,
            U256::from(accusation.proof_type as u8),
            accusation.data_hash,
            U256::from(accusation.deadline),
        )
            .abi_encode();
        keccak256(&encoded).into()
    }

    fn verify_accusation_signature(&self, accusation: &ProofFailureAccusation) -> bool {
        let digest = Self::accusation_digest(accusation);
        let sig = match alloy::primitives::Signature::try_from(
            accusation.signature.extract_bytes().as_ref(),
        ) {
            Ok(s) => s,
            Err(_) => return false,
        };
        match sig.recover_address_from_msg(digest) {
            Ok(addr) => addr == accusation.accuser,
            Err(_) => false,
        }
    }

    fn sign_vote_digest(&self, vote: &AccusationVote) -> Result<Vec<u8>, alloy::signers::Error> {
        let digest = Self::vote_digest(vote, self.slashing_manager);
        // `sign_hash_sync` signs the raw 32-byte hash without EIP-191 wrapping,
        // which is what EIP-712 requires.
        let sig = self.signer.sign_hash_sync(&digest.into())?;
        Ok(sig.as_bytes().to_vec())
    }

    /// Canonical EIP-712 domain separator for vote signatures.
    ///
    /// Must match `SlashingManager`'s domain construction exactly.
    fn vote_domain_separator(chain_id: u64, verifying_contract: Address) -> [u8; 32] {
        let domain_typehash: [u8; 32] = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        )
        .into();
        let name_hash: [u8; 32] = keccak256(VOTE_DOMAIN_NAME).into();
        let version_hash: [u8; 32] = keccak256(VOTE_DOMAIN_VERSION).into();
        let encoded = (
            domain_typehash,
            name_hash,
            version_hash,
            U256::from(chain_id),
            verifying_contract,
        )
            .abi_encode();
        keccak256(&encoded).into()
    }

    /// Canonical EIP-712 typed-data hash for a vote.
    ///
    /// `keccak256("\x19\x01" || domainSeparator || structHash)`.
    pub(crate) fn vote_digest(vote: &AccusationVote, verifying_contract: Address) -> [u8; 32] {
        let e3_id_u256: U256 = vote
            .e3_id
            .clone()
            .try_into()
            .expect("E3id should be valid U256");
        let typehash: [u8; 32] = keccak256(VOTE_TYPEHASH_STR).into();
        let struct_hash: [u8; 32] = keccak256(
            (
                typehash,
                e3_id_u256,
                vote.accusation_id,
                vote.voter,
                vote.data_hash,
                U256::from(vote.deadline),
            )
                .abi_encode(),
        )
        .into();
        let domain = Self::vote_domain_separator(vote.e3_id.chain_id(), verifying_contract);
        let mut buf = Vec::with_capacity(2 + 32 + 32);
        buf.push(0x19);
        buf.push(0x01);
        buf.extend_from_slice(&domain);
        buf.extend_from_slice(&struct_hash);
        keccak256(&buf).into()
    }

    fn verify_vote_signature(&self, vote: &AccusationVote) -> bool {
        let digest = Self::vote_digest(vote, self.slashing_manager);
        let sig =
            match alloy::primitives::Signature::try_from(vote.signature.extract_bytes().as_ref()) {
                Ok(s) => s,
                Err(_) => return false,
            };
        match sig.recover_address_from_prehash(&digest.into()) {
            Ok(addr) => addr == vote.voter,
            Err(_) => false,
        }
    }

    /// Compute a keccak256 hash of a SignedProofPayload for data_hash comparison.
    fn compute_payload_hash(payload: &SignedProofPayload) -> [u8; 32] {
        let msg = (
            Bytes::copy_from_slice(&payload.payload.proof.data),
            Bytes::copy_from_slice(&payload.payload.proof.public_signals),
        )
            .abi_encode();
        keccak256(&msg).into()
    }

    // ─── Caching ─────────────────────────────────────────────────────────

    /// Cache a successful (or failed) proof verification result.
    pub(crate) fn cache_verification_result(
        &mut self,
        accused: Address,
        proof_type: ProofType,
        data_hash: [u8; 32],
        passed: bool,
        evidence: Bytes,
    ) {
        self.received_data.insert(
            (accused, proof_type),
            ReceivedProofData {
                data_hash,
                verification_passed: passed,
                evidence,
            },
        );
    }

    /// Cache a successful proof verification reported via `ProofVerificationPassed`.
    pub(crate) fn on_proof_verification_passed(&mut self, data: ProofVerificationPassed) {
        if data.e3_id != self.e3_id {
            return;
        }
        if !self.committee.contains(&data.address) {
            return;
        }
        // Evidence preimage = `abi.encode(proof.data, public_signals)`.
        let evidence: Bytes = (
            Bytes::copy_from_slice(&data.proof_data),
            Bytes::copy_from_slice(&data.public_signals),
        )
            .abi_encode()
            .into();
        self.received_data.insert(
            (data.address, data.proof_type),
            ReceivedProofData {
                data_hash: data.data_hash,
                verification_passed: true,
                evidence,
            },
        );
    }

    // ─── Rollback helpers (publish-failure paths) ────────────────────────

    /// Roll back an initiation whose accusation broadcast failed. Mirrors the
    /// original actor's behaviour of removing the dedup entry so a future
    /// identical failure may retry.
    pub(crate) fn rollback_initiation(&mut self, dedup_key: &(Address, ProofType)) {
        self.accused_proofs.remove(dedup_key);
    }

    /// Discard a pending ZK re-verification whose dispatch failed.
    pub(crate) fn discard_reverification(&mut self, correlation_id: &CorrelationId) {
        self.pending_reverifications.remove(correlation_id);
    }

    // ─── Core Protocol ───────────────────────────────────────────────────

    /// Called when the local node detects a proof failure.
    pub(crate) fn on_local_proof_failure(
        &mut self,
        event: ProofVerificationFailed,
        ec: &EventContext<Sequenced>,
    ) -> Vec<VoteAction> {
        if event.e3_id != self.e3_id {
            return Vec::new();
        }

        let accused_address = if event.accused_address == Address::ZERO {
            if let Some(&addr) = self.committee.get(event.accused_party_id as usize) {
                warn!(
                    "Resolved Address::ZERO for party {} to committee address {}",
                    event.accused_party_id, addr
                );
                addr
            } else {
                error!(
                    "Cannot resolve address for party {} (out of committee bounds) — dropping accusation",
                    event.accused_party_id
                );
                return Vec::new();
            }
        } else {
            event.accused_address
        };

        if !self.committee.contains(&accused_address) {
            warn!(
                "Ignoring proof failure for {} — not on E3 {} committee",
                accused_address, self.e3_id
            );
            return Vec::new();
        }

        // Cache the failed verification result.
        let evidence = Bytes::from(
            (
                Bytes::copy_from_slice(&event.signed_payload.payload.proof.data),
                Bytes::copy_from_slice(&event.signed_payload.payload.proof.public_signals),
            )
                .abi_encode(),
        );
        self.received_data.insert(
            (accused_address, event.proof_type),
            ReceivedProofData {
                data_hash: event.data_hash,
                verification_passed: false,
                evidence,
            },
        );

        // For C3a/C3b, include the signed payload so other nodes can re-verify
        let forwarded_payload = match event.proof_type {
            ProofType::C3aSkShareEncryption | ProofType::C3bESmShareEncryption => {
                Some(event.signed_payload.clone())
            }
            _ => None,
        };

        let mut actions = Vec::new();
        self.initiate_accusation(
            accused_address,
            event.accused_party_id,
            event.proof_type,
            event.data_hash,
            forwarded_payload,
            ec,
            &mut actions,
        );
        actions
    }

    /// Called when the `CommitmentConsistencyChecker` detects a cross-circuit
    /// commitment mismatch for a party.
    pub(crate) fn on_consistency_violation(
        &mut self,
        data: CommitmentConsistencyViolation,
        ec: &EventContext<Sequenced>,
    ) -> Vec<VoteAction> {
        if data.e3_id != self.e3_id {
            return Vec::new();
        }

        if !self.committee.contains(&data.accused_address) {
            warn!(
                "Ignoring commitment violation for {} — not on E3 {} committee",
                data.accused_address, self.e3_id
            );
            return Vec::new();
        }

        self.received_data.insert(
            (data.accused_address, data.proof_type),
            ReceivedProofData {
                data_hash: data.data_hash,
                verification_passed: false,
                evidence: data.evidence.clone(),
            },
        );

        let mut actions = Vec::new();
        self.initiate_accusation(
            data.accused_address,
            data.accused_party_id,
            data.proof_type,
            data.data_hash,
            None,
            ec,
            &mut actions,
        );
        actions
    }

    /// Shared accusation creation and broadcast logic.
    #[allow(clippy::too_many_arguments)]
    fn initiate_accusation(
        &mut self,
        accused_address: Address,
        accused_party_id: u64,
        proof_type: ProofType,
        data_hash: [u8; 32],
        forwarded_payload: Option<SignedProofPayload>,
        ec: &EventContext<Sequenced>,
        actions: &mut Vec<VoteAction>,
    ) {
        if !self.committee.contains(&accused_address) {
            warn!(
                "Refusing accusation against {} — not on E3 {} committee",
                accused_address, self.e3_id
            );
            return;
        }

        let key = (accused_address, proof_type);

        // Dedup: don't create multiple accusations for the same (accused, proof_type)
        if !self.accused_proofs.insert(key) {
            info!(
                "Already accused {:?} for {:?} — skipping duplicate",
                accused_address, proof_type
            );
            return;
        }

        // Governance-disabled validity window means no accusation voting.
        if self.vote_validity_secs == 0 {
            warn!(
                "Refusing accusation initiation for {:?} on E3 {}: vote_validity_secs is 0",
                accused_address, self.e3_id
            );
            self.accused_proofs.remove(&key);
            return;
        }

        // Pick the on-chain validity deadline once per accusation.
        let deadline = self.compute_deadline();

        // Create the accusation
        let mut accusation = ProofFailureAccusation {
            e3_id: self.e3_id.clone(),
            accuser: self.my_address,
            accused: accused_address,
            accused_party_id,
            proof_type,
            data_hash,
            deadline,
            signed_payload: forwarded_payload,
            signature: ArcBytes::default(),
        };
        match self.sign_accusation_digest(&accusation) {
            Ok(sig) => accusation.signature = ArcBytes::from_bytes(&sig),
            Err(err) => {
                error!("Failed to sign ProofFailureAccusation: {err}");
                self.accused_proofs.remove(&key);
                return;
            }
        }

        let accusation_id = Self::accusation_id(&accusation);

        info!(
            "Broadcasting accusation against {} for {:?} failure",
            accused_address, proof_type
        );

        // Broadcast accusation via gossip
        actions.push(VoteAction::PublishAccusation {
            accusation: accusation.clone(),
            ec: ec.clone(),
            dedup_key: key,
        });

        // Cast our own agreement vote (we just observed the failure locally).
        let mut own_vote = AccusationVote {
            e3_id: self.e3_id.clone(),
            accusation_id,
            voter: self.my_address,
            data_hash,
            deadline,
            signature: ArcBytes::default(),
        };
        match self.sign_vote_digest(&own_vote) {
            Ok(sig) => own_vote.signature = ArcBytes::from_bytes(&sig),
            Err(err) => {
                error!("Failed to sign own AccusationVote: {err}");
                self.accused_proofs.remove(&key);
                return;
            }
        }

        actions.push(VoteAction::PublishVote {
            vote: own_vote.clone(),
            ec: ec.clone(),
        });

        // Start timeout
        actions.push(VoteAction::StartTimeout(accusation_id));

        // Store pending accusation with own vote
        self.pending.insert(
            accusation_id,
            PendingAccusation {
                accusation,
                votes_for: vec![own_vote],
                ec: ec.clone(),
            },
        );

        // Replay any votes that arrived before this accusation
        if let Some(buffered) = self.buffered_votes.remove(&accusation_id) {
            for vote in buffered {
                self.on_vote_received_inner(vote, ec, actions);
            }
        }

        // Check quorum immediately (in case threshold_m == 1)
        self.check_quorum(accusation_id, ec, actions);
    }

    /// Called when we receive an accusation from another node via gossip.
    pub(crate) fn on_accusation_received(
        &mut self,
        accusation: ProofFailureAccusation,
        ec: &EventContext<Sequenced>,
    ) -> Vec<VoteAction> {
        let mut actions = Vec::new();
        self.on_accusation_received_inner(accusation, ec, &mut actions);
        actions
    }

    fn on_accusation_received_inner(
        &mut self,
        accusation: ProofFailureAccusation,
        ec: &EventContext<Sequenced>,
        actions: &mut Vec<VoteAction>,
    ) {
        // Ignore accusations for other E3s
        if accusation.e3_id != self.e3_id {
            return;
        }

        let now = self.clock.unix_now_secs();
        if !Self::is_peer_deadline_acceptable(
            accusation.deadline,
            now,
            self.vote_validity_secs,
            self.accusation_deadline_skew_secs,
        ) {
            let max_deadline = now
                .saturating_add(self.vote_validity_secs)
                .saturating_add(self.accusation_deadline_skew_secs);
            warn!(
                "Ignoring accusation from {} — deadline {} outside local validity window \
                 (now={}, vote_validity_secs={}, skew_secs={}, max_accepted_deadline={})",
                accusation.accuser,
                accusation.deadline,
                now,
                self.vote_validity_secs,
                self.accusation_deadline_skew_secs,
                max_deadline
            );
            return;
        }

        // Verify accuser is in committee
        if !self.committee.contains(&accusation.accuser) {
            warn!(
                "Ignoring accusation from non-committee member {}",
                accusation.accuser
            );
            return;
        }

        // Verify accused is a committee member (defense-in-depth)
        if !self.committee.contains(&accusation.accused) {
            warn!(
                "Ignoring accusation against non-committee member {}",
                accusation.accused
            );
            return;
        }

        // Ignore our own accusations (we already voted)
        if accusation.accuser == self.my_address {
            return;
        }

        // Verify accuser's ECDSA signature
        if !self.verify_accusation_signature(&accusation) {
            warn!(
                "Invalid signature on accusation from {} — ignoring",
                accusation.accuser
            );
            return;
        }

        let accusation_id = Self::accusation_id(&accusation);

        // Don't process duplicate accusations
        if self.pending.contains_key(&accusation_id) {
            return;
        }

        // Determine our position based on our local verification state.
        let key = (accusation.accused, accusation.proof_type);
        let our_data_hash = if let Some(received) = self.received_data.get(&key) {
            if received.verification_passed {
                info!(
                    "Local verification of {:?} from {} passed — abstaining \
                     (no disagreement vote on the wire)",
                    accusation.proof_type, accusation.accused
                );
                return;
            }
            received.data_hash
        } else if let Some(ref forwarded) = accusation.signed_payload {
            // C3a/C3b case: we didn't receive this proof directly.
            let forwarded_valid = match forwarded.recover_address() {
                Ok(addr) => {
                    if addr != accusation.accused {
                        warn!(
                            "Forwarded C3a/C3b payload signer {} != accused {} — cannot verify",
                            addr, accusation.accused
                        );
                        false
                    } else if forwarded.payload.e3_id != self.e3_id {
                        warn!("Forwarded C3a/C3b payload e3_id mismatch — cannot verify");
                        false
                    } else {
                        let expected = forwarded.payload.proof_type.circuit_names();
                        expected.contains(&forwarded.payload.proof.circuit)
                    }
                }
                Err(e) => {
                    warn!("Forwarded C3a/C3b payload signature invalid: {e} — cannot verify");
                    false
                }
            };

            if !forwarded_valid {
                // Can't trust the forwarded proof — abstain
                return;
            }

            // Bind the forwarded proof to the accusation.
            if forwarded.payload.proof_type != accusation.proof_type {
                warn!(
                    "Forwarded C3a/C3b proof_type {:?} != accusation proof_type {:?} — cannot verify",
                    forwarded.payload.proof_type, accusation.proof_type
                );
                return;
            }
            let computed_hash = Self::compute_payload_hash(forwarded);
            if computed_hash != accusation.data_hash {
                warn!(
                    "Forwarded C3a/C3b data_hash mismatch (len {} vs {}) — cannot verify",
                    computed_hash.len(),
                    accusation.data_hash.len()
                );
                return;
            }

            let data_hash = Self::compute_payload_hash(forwarded);
            let evidence: Bytes = (
                Bytes::copy_from_slice(&forwarded.payload.proof.data),
                Bytes::copy_from_slice(&forwarded.payload.proof.public_signals),
            )
                .abi_encode()
                .into();
            let accused_party_id = accusation.accused_party_id;
            let forwarded_clone = forwarded.clone();

            let committee_size = match CiphernodesCommitteeSize::from_threshold(
                self.threshold_m,
                self.committee_n,
            ) {
                Ok(c) => c,
                Err(e) => {
                    warn!("Cannot derive committee size for ZK re-verification: {e}");
                    return;
                }
            };

            // Create PendingAccusation without our vote — it arrives after ZK completes.
            actions.push(VoteAction::StartTimeout(accusation_id));
            self.pending.insert(
                accusation_id,
                PendingAccusation {
                    accusation,
                    votes_for: Vec::new(),
                    ec: ec.clone(),
                },
            );

            // Replay any buffered votes
            if let Some(buffered) = self.buffered_votes.remove(&accusation_id) {
                for vote in buffered {
                    self.on_vote_received_inner(vote, ec, actions);
                }
            }

            // Dispatch ZK re-verification
            let correlation_id = CorrelationId::new();
            self.pending_reverifications.insert(
                correlation_id,
                PendingReVerification {
                    accusation_id,
                    data_hash,
                    accused: key.0,
                    proof_type: key.1,
                    evidence,
                },
            );

            let party_proof = PartyProofsToVerify {
                sender_party_id: accused_party_id,
                signed_proofs: vec![forwarded_clone],
            };
            let request = ComputeRequest::zk(
                ZkRequest::VerifyShareProofs(VerifyShareProofsRequest {
                    party_proofs: vec![party_proof],
                    params_preset: self.params_preset,
                    committee_size,
                }),
                correlation_id,
                self.e3_id.clone(),
            );

            actions.push(VoteAction::DispatchZk {
                request,
                ec: ec.clone(),
                correlation_id,
            });

            // Vote deferred — return without falling through to the normal vote path
            return;
        } else {
            // We don't have the data and no payload was forwarded — abstain
            info!(
                "No local data for accused {} proof {:?} — abstaining from vote",
                accusation.accused, accusation.proof_type
            );
            return;
        };

        // We saw the proof fail locally — agree with the accusation.
        let mut vote = AccusationVote {
            e3_id: self.e3_id.clone(),
            accusation_id,
            voter: self.my_address,
            data_hash: our_data_hash,
            deadline: accusation.deadline,
            signature: ArcBytes::default(),
        };
        match self.sign_vote_digest(&vote) {
            Ok(sig) => vote.signature = ArcBytes::from_bytes(&sig),
            Err(err) => {
                error!("Failed to sign AccusationVote: {err}");
                return;
            }
        }

        info!(
            "Agreeing with accusation against {} for {:?}",
            accusation.accused, accusation.proof_type
        );

        // Broadcast vote via gossip
        actions.push(VoteAction::PublishVote {
            vote: vote.clone(),
            ec: ec.clone(),
        });

        // Start timeout for this accusation
        actions.push(VoteAction::StartTimeout(accusation_id));

        // Record in pending
        let pending = PendingAccusation {
            accusation,
            votes_for: vec![vote],
            ec: ec.clone(),
        };
        self.pending.insert(accusation_id, pending);

        // Replay any votes that arrived before this accusation
        if let Some(buffered) = self.buffered_votes.remove(&accusation_id) {
            for vote in buffered {
                self.on_vote_received_inner(vote, ec, actions);
            }
        }

        // Check quorum
        self.check_quorum(accusation_id, ec, actions);
    }

    /// Called when we receive a vote from another node via gossip.
    pub(crate) fn on_vote_received(
        &mut self,
        vote: AccusationVote,
        ec: &EventContext<Sequenced>,
    ) -> Vec<VoteAction> {
        let mut actions = Vec::new();
        self.on_vote_received_inner(vote, ec, &mut actions);
        actions
    }

    fn on_vote_received_inner(
        &mut self,
        vote: AccusationVote,
        ec: &EventContext<Sequenced>,
        actions: &mut Vec<VoteAction>,
    ) {
        // Ignore votes for other E3s
        if vote.e3_id != self.e3_id {
            return;
        }

        // Verify voter is in committee
        if !self.committee.contains(&vote.voter) {
            warn!("Ignoring vote from non-committee member {}", vote.voter);
            return;
        }

        // Ignore our own votes (already recorded)
        if vote.voter == self.my_address {
            return;
        }

        // Verify voter's ECDSA signature
        if !self.verify_vote_signature(&vote) {
            warn!("Invalid signature on vote from {} — ignoring", vote.voter);
            return;
        }

        let vote_accusation_id = vote.accusation_id;

        // Find the pending accusation
        let Some(pending) = self.pending.get_mut(&vote_accusation_id) else {
            // Unknown accusation — buffer the vote for replay.
            let committee_len = self.committee.len();
            let buf = self.buffered_votes.entry(vote_accusation_id).or_default();
            if buf.len() < committee_len {
                buf.push(vote);
            } else {
                warn!(
                    "Buffered votes for unknown accusation {:?} reached committee-size cap — dropping vote",
                    vote_accusation_id
                );
            }
            return;
        };

        // Reject votes whose deadline disagrees with the accusation's deadline.
        if vote.deadline != pending.accusation.deadline {
            warn!(
                "Ignoring vote from {} — deadline {} does not match accusation deadline {}",
                vote.voter, vote.deadline, pending.accusation.deadline
            );
            return;
        }

        // Reject votes from the accused party — conflict of interest
        if vote.voter == pending.accusation.accused {
            warn!(
                "Ignoring vote from accused party {} on their own accusation",
                vote.voter
            );
            return;
        }

        // Dedup: don't count same voter twice
        let already_voted = pending.votes_for.iter().any(|v| v.voter == vote.voter);
        if already_voted {
            return;
        }

        // Accuser's vote data_hash must match the accusation's data_hash.
        if vote.voter == pending.accusation.accuser
            && vote.data_hash != pending.accusation.data_hash
        {
            warn!(
                "Accuser {} sent vote with data_hash inconsistent with their accusation — rejecting vote",
                vote.voter
            );
            return;
        }

        // Every received `AccusationVote` is an agreement.
        pending.votes_for.push(vote);

        self.check_quorum(vote_accusation_id, ec, actions);
    }

    /// Evaluate whether we have enough agreeing votes to decide.
    fn check_quorum(
        &mut self,
        accusation_id: [u8; 32],
        ec: &EventContext<Sequenced>,
        actions: &mut Vec<VoteAction>,
    ) {
        let Some(pending) = self.pending.get(&accusation_id) else {
            return;
        };

        let agree_count = pending.votes_for.len();
        if agree_count < self.threshold_m {
            // Not yet at quorum.
            return;
        }

        // Reached `M` — decide between AccusedFaulted and Equivocation.
        let agree_hashes: HashSet<[u8; 32]> =
            pending.votes_for.iter().map(|v| v.data_hash).collect();
        if agree_hashes.len() > 1 {
            info!(
                "Equivocation detected at quorum: {} unique data hashes among {} agreeing voters for {} {:?}",
                agree_hashes.len(),
                agree_count,
                pending.accusation.accused,
                pending.accusation.proof_type
            );
            self.emit_quorum_reached(accusation_id, AccusationOutcome::Equivocation, ec, actions);
        } else {
            info!(
                "Quorum reached: {} votes confirm {} sent bad {:?} proof — AccusedFaulted",
                agree_count, pending.accusation.accused, pending.accusation.proof_type
            );
            self.emit_quorum_reached(
                accusation_id,
                AccusationOutcome::AccusedFaulted,
                ec,
                actions,
            );
        }
    }

    /// Called when the vote timeout expires for an accusation. Returns the
    /// terminal quorum event the actor must publish, if the accusation was
    /// still pending.
    pub(crate) fn on_vote_timeout(
        &mut self,
        accusation_id: [u8; 32],
    ) -> Option<(AccusationQuorumReached, EventContext<Sequenced>)> {
        let pending = self.pending.remove(&accusation_id)?; // Already resolved

        let outcome = if pending.votes_for.len() >= self.threshold_m {
            let agree_hashes: HashSet<[u8; 32]> =
                pending.votes_for.iter().map(|v| v.data_hash).collect();
            if agree_hashes.len() > 1 {
                AccusationOutcome::Equivocation
            } else {
                AccusationOutcome::AccusedFaulted
            }
        } else {
            AccusationOutcome::Inconclusive
        };

        warn!(
            "Accusation against {} for {:?} timed out with {} agreeing votes — outcome: {:?}",
            pending.accusation.accused,
            pending.accusation.proof_type,
            pending.votes_for.len(),
            outcome
        );

        let evidence = self
            .received_data
            .get(&(pending.accusation.accused, pending.accusation.proof_type))
            .map(|d| d.evidence.clone())
            .unwrap_or_default();
        Some((
            AccusationQuorumReached {
                e3_id: self.e3_id.clone(),
                accuser: pending.accusation.accuser,
                accused: pending.accusation.accused,
                proof_type: pending.accusation.proof_type,
                votes_for: pending.votes_for,
                outcome,
                evidence,
            },
            pending.ec,
        ))
    }

    fn emit_quorum_reached(
        &mut self,
        accusation_id: [u8; 32],
        outcome: AccusationOutcome,
        ec: &EventContext<Sequenced>,
        actions: &mut Vec<VoteAction>,
    ) {
        let Some(pending) = self.pending.remove(&accusation_id) else {
            return;
        };

        // Cancel the timeout to avoid unnecessary timer fires
        actions.push(VoteAction::CancelTimeout(accusation_id));

        info!(
            "Accusation quorum reached for {} {:?}: {} agreeing votes — outcome: {}",
            pending.accusation.accused,
            pending.accusation.proof_type,
            pending.votes_for.len(),
            outcome
        );

        let evidence = self
            .received_data
            .get(&(pending.accusation.accused, pending.accusation.proof_type))
            .map(|d| d.evidence.clone())
            .unwrap_or_default();
        actions.push(VoteAction::PublishQuorum {
            quorum: AccusationQuorumReached {
                e3_id: self.e3_id.clone(),
                accuser: pending.accusation.accuser,
                accused: pending.accusation.accused,
                proof_type: pending.accusation.proof_type,
                votes_for: pending.votes_for,
                outcome,
                evidence,
            },
            ec: ec.clone(),
        });
    }

    /// Handle an on-chain SlashExecuted event for this E3.
    pub(crate) fn on_slash_executed(&mut self, data: SlashExecuted) {
        if data.e3_id != self.e3_id {
            return;
        }
        let prev_len = self.committee.len();
        self.committee.retain(|addr| *addr != data.operator);
        if self.committee.len() < prev_len {
            info!(
                "Removed slashed operator {} from committee (now {} members)",
                data.operator,
                self.committee.len()
            );

            // Purge any votes from the expelled node in pending accusations
            for pending in self.pending.values_mut() {
                pending.votes_for.retain(|v| v.voter != data.operator);
            }

            // Purge from buffered votes
            for buf in self.buffered_votes.values_mut() {
                buf.retain(|v| v.voter != data.operator);
            }
        }
    }

    /// Handle ZK re-verification response for a forwarded C3a/C3b proof.
    pub(crate) fn handle_reverification_response(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
    ) -> Vec<VoteAction> {
        let (msg, _ec) = msg.into_components();
        let mut actions = Vec::new();

        let correlation_id = msg.correlation_id;
        let Some(reverif) = self.pending_reverifications.remove(&correlation_id) else {
            return actions; // Not our correlation ID
        };

        let zk_passed = match msg.response {
            ComputeResponseKind::Zk(ZkResponse::VerifyShareProofs(r)) => {
                if r.party_results.is_empty() {
                    warn!("Empty ZK re-verification results — abstaining");
                    return actions;
                }
                r.party_results.first().is_some_and(|r| r.all_verified)
            }
            _ => {
                warn!("Unexpected ComputeResponse kind for C3a/C3b re-verification — abstaining");
                return actions;
            }
        };

        // Cache the result for future accusations regardless of outcome.
        self.cache_verification_result(
            reverif.accused,
            reverif.proof_type,
            reverif.data_hash,
            zk_passed,
            reverif.evidence.clone(),
        );

        // ZK re-verification passed ⇒ proof is valid ⇒ we disagree ⇒ abstain.
        if zk_passed {
            info!(
                "C3a/C3b re-verification passed for {:?} — abstaining from vote",
                reverif.proof_type
            );
            return actions;
        }

        // ZK re-verification failed ⇒ we agree with the accusation.
        let (ec, deadline) = match self.pending.get(&reverif.accusation_id) {
            Some(pending) => (pending.ec.clone(), pending.accusation.deadline),
            None => {
                // Accusation already resolved before ZK finished
                return actions;
            }
        };

        let mut vote = AccusationVote {
            e3_id: self.e3_id.clone(),
            accusation_id: reverif.accusation_id,
            voter: self.my_address,
            data_hash: reverif.data_hash,
            deadline,
            signature: ArcBytes::default(),
        };
        match self.sign_vote_digest(&vote) {
            Ok(sig) => vote.signature = ArcBytes::from_bytes(&sig),
            Err(err) => {
                error!("Failed to sign C3a/C3b AccusationVote: {err}");
                return actions;
            }
        }

        info!(
            "C3a/C3b re-verification confirmed failure for {:?} — agreeing with accusation",
            reverif.proof_type
        );

        // Broadcast vote via gossip
        actions.push(VoteAction::PublishVote {
            vote: vote.clone(),
            ec: ec.clone(),
        });

        // Record in pending
        if let Some(pending) = self.pending.get_mut(&reverif.accusation_id) {
            pending.votes_for.push(vote);
        }

        // Check quorum
        self.check_quorum(reverif.accusation_id, &ec, &mut actions);
        actions
    }

    /// Handle ZK re-verification error for a forwarded C3a/C3b proof.
    pub(crate) fn handle_reverification_error(&mut self, msg: TypedEvent<ComputeRequestError>) {
        let (msg, _ec) = msg.into_components();

        let correlation_id = msg.correlation_id();
        let Some(reverif) = self.pending_reverifications.remove(correlation_id) else {
            return; // Not our correlation ID
        };

        error!(
            "C3a/C3b ZK re-verification failed for {:?} — abstaining from vote",
            reverif.proof_type
        );
        // Don't vote — effectively abstain
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::FixedBytes;
    use e3_events::{InterfoldEventData, Unsequenced};

    struct FixedClock(u64);
    impl Clock for FixedClock {
        fn unix_now_secs(&self) -> u64 {
            self.0
        }
    }

    /// A throwaway sequenced [`EventContext`] for driving service calls in
    /// tests. The service never inspects the context beyond cloning it onto
    /// emitted actions, so any well-formed origin context works.
    fn ctx() -> EventContext<Sequenced> {
        let vote = AccusationVote {
            e3_id: E3id::new("42", CHAIN_ID),
            accusation_id: [0u8; 32],
            voter: Address::ZERO,
            data_hash: [0u8; 32],
            deadline: 0,
            signature: ArcBytes::default(),
        };
        EventContext::<Unsequenced>::from(InterfoldEventData::from(vote)).sequence(0)
    }

    const CHAIN_ID: u64 = 31337;
    const VALIDITY: u64 = 1_800;
    const SKEW: u64 = 30;
    const NOW: u64 = 1_700_000_000;

    fn signer(byte: u8) -> PrivateKeySigner {
        let mut bytes = [0u8; 32];
        bytes[31] = byte;
        PrivateKeySigner::from_bytes(&FixedBytes::<32>::from(bytes)).unwrap()
    }

    fn voting_with(
        me: &PrivateKeySigner,
        committee: Vec<Address>,
        threshold_m: usize,
    ) -> AccusationVoting {
        AccusationVoting::new(
            E3id::new("42", CHAIN_ID),
            me.clone(),
            "0x9999999999999999999999999999999999999999"
                .parse()
                .unwrap(),
            committee,
            threshold_m,
            VALIDITY,
            SKEW,
            e3_fhe_params::BfvPreset::default(),
            Arc::new(FixedClock(NOW)),
        )
    }

    /// Build and sign a vote as `who` for the given accusation/data hash.
    fn signed_vote(
        who: &PrivateKeySigner,
        slashing_manager: Address,
        e3_id: &E3id,
        accusation_id: [u8; 32],
        data_hash: [u8; 32],
        deadline: u64,
    ) -> AccusationVote {
        let mut vote = AccusationVote {
            e3_id: e3_id.clone(),
            accusation_id,
            voter: who.address(),
            data_hash,
            deadline,
            signature: ArcBytes::default(),
        };
        let digest = AccusationVoting::vote_digest(&vote, slashing_manager);
        let sig = who.sign_hash_sync(&FixedBytes::<32>::from(digest)).unwrap();
        vote.signature = ArcBytes::from_bytes(&sig.as_bytes());
        vote
    }

    fn insert_pending(
        v: &mut AccusationVoting,
        accuser: &PrivateKeySigner,
        accused: Address,
        data_hash: [u8; 32],
        deadline: u64,
        own_vote: AccusationVote,
    ) -> [u8; 32] {
        let accusation = ProofFailureAccusation {
            e3_id: v.e3_id.clone(),
            accuser: accuser.address(),
            accused,
            accused_party_id: 1,
            proof_type: ProofType::C1PkGeneration,
            data_hash,
            deadline,
            signed_payload: None,
            signature: ArcBytes::default(),
        };
        let id = AccusationVoting::accusation_id(&accusation);
        v.pending.insert(
            id,
            PendingAccusation {
                accusation,
                votes_for: vec![own_vote],
                ec: ctx(),
            },
        );
        id
    }

    /// Digest computation must be deterministic for identical inputs and must
    /// differ when any bound field changes.
    #[test]
    fn vote_digest_is_deterministic() {
        let sm: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();
        let voter: Address = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();
        let vote = AccusationVote {
            e3_id: E3id::new("42", CHAIN_ID),
            accusation_id: [0xab; 32],
            voter,
            data_hash: [0xcd; 32],
            deadline: NOW,
            signature: ArcBytes::default(),
        };
        let a = AccusationVoting::vote_digest(&vote, sm);
        let b = AccusationVoting::vote_digest(&vote, sm);
        assert_eq!(a, b, "vote digest must be deterministic");

        let mut vote2 = vote.clone();
        vote2.deadline = NOW + 1;
        assert_ne!(
            a,
            AccusationVoting::vote_digest(&vote2, sm),
            "changing deadline must change the digest"
        );
    }

    /// A second agreeing vote that reaches `threshold_m` must produce a single
    /// AccusedFaulted quorum decision and remove the pending accusation.
    #[test]
    fn tally_reaches_quorum_at_threshold() {
        let me = signer(1);
        let b = signer(2);
        let accused = signer(9).address();
        let committee = vec![me.address(), b.address(), accused];
        let mut v = voting_with(&me, committee, 2);
        let sm = v.slashing_manager;
        let data_hash = [0x11; 32];

        let own = signed_vote(&me, sm, &v.e3_id, [0u8; 32], data_hash, NOW + VALIDITY);
        let id = insert_pending(&mut v, &me, accused, data_hash, NOW + VALIDITY, own);
        // own vote's accusation_id was a placeholder; fix it to the real id.
        v.pending.get_mut(&id).unwrap().votes_for[0].accusation_id = id;

        let vote_b = signed_vote(&b, sm, &v.e3_id, id, data_hash, NOW + VALIDITY);
        let actions = v.on_vote_received(vote_b, &ctx());

        let quorum = actions
            .iter()
            .filter_map(|a| match a {
                VoteAction::PublishQuorum { quorum, .. } => Some(quorum),
                _ => None,
            })
            .count();
        assert_eq!(quorum, 1, "exactly one quorum decision expected");
        assert!(
            !v.pending.contains_key(&id),
            "pending accusation removed after quorum"
        );
    }

    /// Inserting the same voter twice must not double-count nor re-trigger quorum.
    #[test]
    fn idempotent_vote_insert() {
        let me = signer(1);
        let b = signer(2);
        let accused = signer(9).address();
        let committee = vec![me.address(), b.address(), accused];
        let mut v = voting_with(&me, committee, 3); // threshold above what 2 votes reach
        let sm = v.slashing_manager;
        let data_hash = [0x11; 32];

        let own = signed_vote(&me, sm, &v.e3_id, [0u8; 32], data_hash, NOW + VALIDITY);
        let id = insert_pending(&mut v, &me, accused, data_hash, NOW + VALIDITY, own);
        v.pending.get_mut(&id).unwrap().votes_for[0].accusation_id = id;

        let vote_b = signed_vote(&b, sm, &v.e3_id, id, data_hash, NOW + VALIDITY);
        let _ = v.on_vote_received(vote_b.clone(), &ctx());
        let len_after_first = v.pending.get(&id).unwrap().votes_for.len();

        // Same voter again — must be ignored.
        let actions = v.on_vote_received(vote_b, &ctx());
        let len_after_second = v.pending.get(&id).unwrap().votes_for.len();
        assert_eq!(
            len_after_first, len_after_second,
            "duplicate voter must not be counted twice"
        );
        assert!(
            actions.is_empty(),
            "duplicate vote must not emit any actions"
        );
    }

    /// Quorum must trigger exactly at the M-th agreeing vote, not before.
    #[test]
    fn quorum_boundary() {
        let me = signer(1);
        let b = signer(2);
        let c = signer(3);
        let accused = signer(9).address();
        let committee = vec![me.address(), b.address(), c.address(), accused];
        let mut v = voting_with(&me, committee, 3);
        let sm = v.slashing_manager;
        let data_hash = [0x11; 32];

        let own = signed_vote(&me, sm, &v.e3_id, [0u8; 32], data_hash, NOW + VALIDITY);
        let id = insert_pending(&mut v, &me, accused, data_hash, NOW + VALIDITY, own);
        v.pending.get_mut(&id).unwrap().votes_for[0].accusation_id = id;

        // 2nd vote — below threshold of 3, no quorum.
        let vote_b = signed_vote(&b, sm, &v.e3_id, id, data_hash, NOW + VALIDITY);
        let actions = v.on_vote_received(vote_b, &ctx());
        assert!(
            actions.is_empty(),
            "no quorum before reaching threshold M=3"
        );
        assert!(v.pending.contains_key(&id));

        // 3rd vote — reaches threshold, quorum fires.
        let vote_c = signed_vote(&c, sm, &v.e3_id, id, data_hash, NOW + VALIDITY);
        let actions = v.on_vote_received(vote_c, &ctx());
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, VoteAction::PublishQuorum { .. })),
            "quorum must fire at the M-th vote"
        );
    }

    /// Agreeing votes that disagree on data_hash at quorum yield Equivocation.
    #[test]
    fn equivocation_when_hashes_differ_at_quorum() {
        let me = signer(1);
        let b = signer(2);
        let accused = signer(9).address();
        let committee = vec![me.address(), b.address(), accused];
        let mut v = voting_with(&me, committee, 2);
        let sm = v.slashing_manager;
        let data_hash_a = [0x11; 32];
        let data_hash_b = [0x22; 32];

        let own = signed_vote(&me, sm, &v.e3_id, [0u8; 32], data_hash_a, NOW + VALIDITY);
        let id = insert_pending(&mut v, &me, accused, data_hash_a, NOW + VALIDITY, own);
        v.pending.get_mut(&id).unwrap().votes_for[0].accusation_id = id;

        // Voter b agrees but reports a different data_hash → equivocation.
        let vote_b = signed_vote(&b, sm, &v.e3_id, id, data_hash_b, NOW + VALIDITY);
        let actions = v.on_vote_received(vote_b, &ctx());
        let outcome = actions.iter().find_map(|a| match a {
            VoteAction::PublishQuorum { quorum, .. } => Some(quorum.outcome.clone()),
            _ => None,
        });
        assert_eq!(
            outcome,
            Some(AccusationOutcome::Equivocation),
            "differing data hashes at quorum must yield Equivocation"
        );
    }

    /// Timeout below threshold yields Inconclusive; at/above threshold yields
    /// AccusedFaulted.
    #[test]
    fn timeout_outcome_depends_on_vote_count() {
        let me = signer(1);
        let accused = signer(9).address();
        let committee = vec![me.address(), signer(2).address(), accused];
        let mut v = voting_with(&me, committee, 2);
        let sm = v.slashing_manager;
        let data_hash = [0x11; 32];

        let own = signed_vote(&me, sm, &v.e3_id, [0u8; 32], data_hash, NOW + VALIDITY);
        let id = insert_pending(&mut v, &me, accused, data_hash, NOW + VALIDITY, own);

        // Only one agreeing vote, threshold is 2 → Inconclusive.
        let (quorum, _ec) = v.on_vote_timeout(id).expect("timeout emits a decision");
        assert_eq!(quorum.outcome, AccusationOutcome::Inconclusive);
        assert!(v.on_vote_timeout(id).is_none(), "second timeout is a no-op");
    }

    /// After a slash shrinks the live roster, ZK re-verification must still use the
    /// canonical circuit committee size cached at construction.
    #[test]
    fn committee_size_unchanged_after_slash() {
        let me = signer(1);
        // Micro committee (T=4, N=9) — canonical pair in `from_threshold`.
        let committee: Vec<Address> = (1..=9u8).map(|b| signer(b).address()).collect();
        let mut v = voting_with(&me, committee.clone(), 4);

        let slashed = committee[8];
        v.on_slash_executed(SlashExecuted {
            e3_id: v.e3_id.clone(),
            proposal_id: 1,
            operator: slashed,
            reason: [0u8; 32],
            ticket_amount: 0,
            license_amount: 0,
        });
        assert_eq!(v.committee.len(), 8);
        assert_eq!(v.committee_n, 9);
        // Shrunken roster must not drive circuit resolution.
        assert!(
            CiphernodesCommitteeSize::from_threshold(v.threshold_m, v.committee.len()).is_err()
        );
        assert_eq!(
            CiphernodesCommitteeSize::from_threshold(v.threshold_m, v.committee_n).unwrap(),
            CiphernodesCommitteeSize::Micro
        );
    }
}
