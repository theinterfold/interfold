// SPDX-License-Identifier: LGPL-3.0-only

//! Verification inputs, pending state, and pure decision types.

use super::*;

/// Trait for party types whose signed proofs can be ECDSA-validated and ZK-verified.
pub(crate) trait VerifiableParty: Clone + PartialEq {
    fn party_id(&self) -> u64;
    fn signed_proofs(&self) -> Vec<SignedProofPayload>;
}

impl VerifiableParty for PartyProofsToVerify {
    fn party_id(&self) -> u64 {
        self.sender_party_id
    }
    fn signed_proofs(&self) -> Vec<SignedProofPayload> {
        self.signed_proofs.clone()
    }
}

impl VerifiableParty for PartyShareDecryptionProofsToVerify {
    fn party_id(&self) -> u64 {
        self.sender_party_id
    }
    fn signed_proofs(&self) -> Vec<SignedProofPayload> {
        std::iter::once(self.signed_sk_decryption_proof.clone())
            .chain(self.signed_e_sm_decryption_proofs.iter().cloned())
            .collect()
    }
}

/// ECDSA validation result for a single party.
pub(crate) struct EcdsaPartyResult {
    pub(crate) passed: bool,
    /// The pair (signed_payload, recovered_address) of the first failing proof, if any.
    pub(crate) failed_payload: Option<(SignedProofPayload, Option<Address>)>,
}

/// A single ECDSA failure to be attributed (emitted) by the actor.
pub(crate) struct EcdsaFailure {
    pub(crate) party_id: u64,
    pub(crate) signed: SignedProofPayload,
    pub(crate) recovered: Option<Address>,
}

/// Outcome of validating + preparing a batch of party proofs for the
/// consistency-check + ZK phases. Pure data; the actor performs the I/O.
pub(crate) struct EcdsaValidationOutcome<P> {
    pub(crate) ecdsa_dishonest: HashSet<u64>,
    /// Failures to emit, in party iteration order.
    pub(crate) failures: Vec<EcdsaFailure>,
    pub(crate) ecdsa_passed_parties: Vec<P>,
    pub(crate) party_addresses: HashMap<u64, Address>,
    pub(crate) party_proof_hashes: HashMap<u64, Vec<(ProofType, [u8; 32])>>,
    pub(crate) party_public_signals: HashMap<u64, Vec<(ProofType, ArcBytes)>>,
    pub(crate) party_proof_data: HashMap<u64, Vec<(ProofType, ArcBytes)>>,
    /// Assembled per-party data for the consistency-check request.
    pub(crate) consistency_party_data: Vec<PartyProofData>,
}

/// Pending verification state — stored while ZK verification is in flight.
pub(crate) struct PendingVerification {
    pub(crate) e3_id: E3id,
    pub(crate) kind: VerificationKind,
    pub(crate) ec: EventContext<Sequenced>,
    /// Parties that failed ECDSA (dishonest before ZK runs).
    pub(crate) ecdsa_dishonest: HashSet<u64>,
    /// Pre-dishonest parties from the dispatch (missing/incomplete proofs).
    pub(crate) pre_dishonest: BTreeSet<u64>,
    /// Party IDs dispatched for ZK verification (for cross-checking results).
    pub(crate) dispatched_party_ids: HashSet<u64>,
    /// Recovered address for each party (from ECDSA step).
    pub(crate) party_addresses: HashMap<u64, Address>,
    /// Cached (proof_type, data_hash) per party — for emitting ProofVerificationPassed.
    pub(crate) party_proof_hashes: HashMap<u64, Vec<(ProofType, [u8; 32])>>,
    /// Cached (proof_type, public_signals) per party — for commitment consistency checking.
    pub(crate) party_public_signals: HashMap<u64, Vec<(ProofType, ArcBytes)>>,
    /// Parallel to `party_public_signals` — raw `proof.data` per (party, proof_type).
    pub(crate) party_proof_data: HashMap<u64, Vec<(ProofType, ArcBytes)>>,
    /// BFV preset for circuit artifact resolution.
    #[allow(dead_code)]
    pub(crate) params_preset: e3_fhe_params::BfvPreset,
    /// Committee size for per-committee circuit artifact resolution.
    #[allow(dead_code)]
    pub(crate) committee_size: CiphernodesCommitteeSize,
}

/// Pending consistency check — stored between ECDSA pass and ZK dispatch.
pub(crate) struct PendingConsistencyCheck {
    pub(crate) e3_id: E3id,
    pub(crate) kind: VerificationKind,
    pub(crate) ec: EventContext<Sequenced>,
    /// Parties that failed ECDSA (dishonest before consistency runs).
    pub(crate) ecdsa_dishonest: HashSet<u64>,
    /// Pre-dishonest parties from the dispatch (missing/incomplete proofs).
    pub(crate) pre_dishonest: BTreeSet<u64>,
    /// Recovered address per ECDSA-passed party.
    pub(crate) party_addresses: HashMap<u64, Address>,
    /// (proof_type, data_hash) per party — for ProofVerificationPassed after ZK.
    pub(crate) party_proof_hashes: HashMap<u64, Vec<(ProofType, [u8; 32])>>,
    /// (proof_type, public_signals) per party — for consistency & ZK.
    pub(crate) party_public_signals: HashMap<u64, Vec<(ProofType, ArcBytes)>>,
    /// Parallel to `party_public_signals` — raw `proof.data` per (party, proof_type).
    pub(crate) party_proof_data: HashMap<u64, Vec<(ProofType, ArcBytes)>>,
    /// Original ECDSA-passed share proofs for ZK dispatch.
    pub(crate) ecdsa_passed_share_proofs: Vec<PartyProofsToVerify>,
    /// Original ECDSA-passed decryption proofs for ZK dispatch.
    pub(crate) ecdsa_passed_decryption_proofs: Vec<PartyShareDecryptionProofsToVerify>,
    /// BFV preset for circuit artifact resolution.
    pub(crate) params_preset: e3_fhe_params::BfvPreset,
    /// Committee size for per-committee circuit artifact resolution.
    pub(crate) committee_size: CiphernodesCommitteeSize,
}
/// Per-party emission decision produced when tallying ZK verification results.
pub(crate) enum ZkPartyEmission {
    /// Party failed ZK — attribute fault using the signed payload.
    Failed {
        party_id: u64,
        signed: SignedProofPayload,
    },
    /// Party passed ZK — emit `ProofVerificationPassed` for each cached proof.
    Passed { party_id: u64 },
}

/// Outcome of tallying ZK verification results: the accumulated dishonest set
/// and the ordered emission decisions.
pub(crate) struct ZkTallyOutcome {
    pub(crate) dishonest: BTreeSet<u64>,
    pub(crate) emissions: Vec<ZkPartyEmission>,
}

/// Human-readable label for a verification kind (used in log lines).
pub(crate) fn label_for(kind: &VerificationKind) -> &'static str {
    match kind {
        VerificationKind::ShareProofs => "C2/C3",
        VerificationKind::ThresholdDecryptionProofs => "C6",
        VerificationKind::PkGenerationProofs => "C1",
        VerificationKind::DecryptionProofs => "C4",
    }
}

/// Stateless service holding all pure share-verification business logic.
pub(crate) struct ShareVerifier;
