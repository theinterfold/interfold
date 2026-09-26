// SPDX-License-Identifier: LGPL-3.0-only

//! Workflow construction, EIP-712 digests, deadlines, and verification cache.

use super::*;

impl AccusationVoting {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        e3_id: E3id,
        signer: PrivateKeySigner,
        slashing_manager: Address,
        committee: Vec<Address>,
        circuit_threshold_t: usize,
        vote_quorum_h: usize,
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
            circuit_threshold_t,
            vote_quorum_h,
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
    pub(super) fn compute_vote_window(&self) -> (u64, u64) {
        let issued_at = self.clock.unix_now_secs();
        (issued_at, issued_at.saturating_add(self.vote_validity_secs))
    }

    /// Validate a peer-provided accusation deadline against this node's local
    /// vote-validity policy and wall clock.
    pub(crate) fn is_peer_deadline_acceptable(
        issued_at: u64,
        deadline: u64,
        now: u64,
        vote_validity_secs: u64,
        skew_secs: u64,
    ) -> bool {
        if vote_validity_secs == 0 {
            return false;
        }
        issued_at <= now.saturating_add(skew_secs)
            && deadline >= issued_at
            && deadline.saturating_sub(issued_at) <= vote_validity_secs
            && deadline > now
    }

    // ─── Accusation ID computation ───────────────────────────────────────

    /// Compute a deterministic ID for an accusation based on its key fields.
    ///
    /// Instance zero preserves the legacy four-field ID. Other instances append `proofInstance`.
    pub(crate) fn accusation_id(accusation: &ProofFailureAccusation) -> [u8; 32] {
        let e3_id_u256: U256 = accusation
            .e3_id
            .clone()
            .try_into()
            .expect("E3id should be valid U256");
        let msg = if accusation.proof_instance == 0 {
            (
                U256::from(accusation.e3_id.chain_id()),
                e3_id_u256,
                accusation.accused,
                U256::from(accusation.proof_type as u8),
            )
                .abi_encode_packed()
        } else {
            (
                U256::from(accusation.e3_id.chain_id()),
                e3_id_u256,
                accusation.accused,
                U256::from(accusation.proof_type as u8),
                U256::from(accusation.proof_instance),
            )
                .abi_encode_packed()
        };
        keccak256(&msg).into()
    }

    // ─── Signing / Verification ──────────────────────────────────────────

    pub(super) fn sign_accusation_digest(
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
        let encoded = if accusation.proof_instance == 0 {
            let typehash: [u8; 32] = keccak256(
                "ProofFailureAccusation(uint256 chainId,uint256 e3Id,address accuser,address accused,uint256 proofType,bytes32 dataHash,uint256 issuedAt,uint256 deadline)"
            ).into();
            (
                typehash,
                U256::from(accusation.e3_id.chain_id()),
                e3_id_u256,
                accusation.accuser,
                accusation.accused,
                U256::from(accusation.proof_type as u8),
                accusation.data_hash,
                U256::from(accusation.issued_at),
                U256::from(accusation.deadline),
            )
                .abi_encode()
        } else {
            let typehash: [u8; 32] = keccak256(
                "ProofFailureAccusationV2(uint256 chainId,uint256 e3Id,address accuser,address accused,uint256 proofType,uint256 proofInstance,bytes32 dataHash,uint256 issuedAt,uint256 deadline)"
            ).into();
            (
                typehash,
                U256::from(accusation.e3_id.chain_id()),
                e3_id_u256,
                accusation.accuser,
                accusation.accused,
                U256::from(accusation.proof_type as u8),
                U256::from(accusation.proof_instance),
                accusation.data_hash,
                U256::from(accusation.issued_at),
                U256::from(accusation.deadline),
            )
                .abi_encode()
        };
        keccak256(&encoded).into()
    }

    pub(super) fn verify_accusation_signature(&self, accusation: &ProofFailureAccusation) -> bool {
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

    pub(crate) fn sign_vote_digest(
        &self,
        vote: &AccusationVote,
    ) -> Result<Vec<u8>, alloy::signers::Error> {
        let digest = Self::vote_digest(vote, self.slashing_manager);
        // `sign_hash_sync` signs the raw 32-byte hash without EIP-191 wrapping,
        // which is what EIP-712 requires.
        let sig = self.signer.sign_hash_sync(&digest.into())?;
        Ok(sig.as_bytes().to_vec())
    }

    /// Canonical EIP-712 domain separator for vote signatures.
    ///
    /// Must match `SlashingManager`'s domain construction exactly.
    pub(super) fn vote_domain_separator(chain_id: u64, verifying_contract: Address) -> [u8; 32] {
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
                U256::from(vote.issued_at),
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

    pub(crate) fn verify_vote_signature(&self, vote: &AccusationVote) -> bool {
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
    pub(super) fn compute_payload_hash(payload: &SignedProofPayload) -> [u8; 32] {
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
        proof_instance: u32,
        data_hash: [u8; 32],
        passed: bool,
        evidence: Bytes,
    ) {
        self.received_data.insert(
            (
                accused,
                ProofIdentity {
                    proof_type,
                    instance: proof_instance,
                },
            ),
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
        let Ok(instance) = data.proof_type.instance_from_public_signals(
            &data.public_signals,
            e3_fhe_params::lbfv_row_count(self.params_preset),
        ) else {
            warn!("Ignoring passed proof with an invalid proof instance");
            return;
        };
        self.received_data.insert(
            (
                data.address,
                ProofIdentity {
                    proof_type: data.proof_type,
                    instance,
                },
            ),
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
    pub(crate) fn rollback_initiation(&mut self, dedup_key: &(Address, ProofIdentity)) {
        self.accused_proofs.remove(dedup_key);
    }

    /// Discard a pending ZK re-verification whose dispatch failed.
    pub(crate) fn discard_reverification(&mut self, correlation_id: &CorrelationId) {
        self.pending_reverifications.remove(correlation_id);
    }
}
