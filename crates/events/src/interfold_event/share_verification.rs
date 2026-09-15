// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Events for share, decryption, and l-BFV proof verification flows.
//!
//! `ShareVerificationDispatched` is published by [`ThresholdKeyshare`] when
//! proof verification is needed. [`ShareVerificationActor`] subscribes and
//! orchestrates ECDSA validation + ZK verification via multithread.
//!
//! `ShareVerificationComplete` is published by [`ShareVerificationActor`]
//! when verification finishes, carrying the set of dishonest party IDs.

use crate::{E3id, PartyProofsToVerify, PartyShareDecryptionProofsToVerify, ProofType};
use alloy::primitives::B256;
use e3_committee_hash::LbfvProofDomainContext;
use e3_zk_helpers::CiphernodesCommitteeSize;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Which verification phase this request/result refers to.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VerificationKind {
    /// C2/C3 share proof verification (after AllThresholdSharesCollected).
    ShareProofs,
    /// C4 share decryption proof verification (after AllDecryptionKeySharesCollected).
    DecryptionProofs,
    /// C6 threshold decryption proof verification (after all DecryptionshareCreated collected).
    ThresholdDecryptionProofs,
    /// C1 PK generation proof verification (after all KeyshareCreated collected).
    PkGenerationProofs,
    /// C1 followed by five public-key and five RLK generation row proofs from one party.
    LbfvGenerationProofs,
    /// Five public-key and five RLK aggregation row proofs from one aggregator.
    LbfvAggregationProofs,
}

/// Versioned authoritative context for an l-BFV verification dispatch.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LbfvVerificationContext {
    V1(LbfvVerificationContextV1),
}

/// Authoritative l-BFV proof domain and optional aggregation binding.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LbfvVerificationContextV1 {
    pub proof_domain: LbfvProofDomainContext,
    /// Present only for `LbfvAggregationProofs`.
    pub aggregation: Option<LbfvAggregationVerificationContext>,
}

/// Canonical accepted set and proof-backed generation commitments.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LbfvAggregationVerificationContext {
    /// Exactly H records in strictly ascending `party_id` order.
    pub accepted_parties: Vec<LbfvAcceptedPartyCommitments>,
}

/// Generation commitments for one accepted party, indexed by gadget row.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LbfvAcceptedPartyCommitments {
    pub party_id: u32,
    pub pk_generation_commitments: [B256; ProofType::LBFV_ROW_INSTANCES as usize],
    pub rlk_d0_commitments: [B256; ProofType::LBFV_ROW_INSTANCES as usize],
    pub rlk_d2_commitments: [B256; ProofType::LBFV_ROW_INSTANCES as usize],
}

/// ThresholdKeyshare → ShareVerificationActor: verify party proofs.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShareVerificationDispatched {
    pub e3_id: E3id,
    pub kind: VerificationKind,
    /// C2/C3 party proofs (when kind == ShareProofs).
    pub share_proofs: Vec<PartyProofsToVerify>,
    /// C4 party proofs (when kind == DecryptionProofs).
    pub decryption_proofs: Vec<PartyShareDecryptionProofsToVerify>,
    /// Parties already identified as dishonest before verification
    /// (e.g., missing/incomplete proofs). Merged into the final result.
    pub pre_dishonest: BTreeSet<u64>,
    /// BFV preset for circuit artifact resolution.
    pub params_preset: e3_fhe_params::BfvPreset,
    /// Committee size for per-committee circuit artifact resolution.
    pub committee_size: CiphernodesCommitteeSize,
    /// Authoritative l-BFV context. Legacy verification kinds require `None`.
    pub lbfv_context: Option<LbfvVerificationContext>,
    /// Stable l-BFV candidate-set identity. Legacy verification kinds require `None`.
    pub verification_id: Option<B256>,
}

/// ShareVerificationActor → ThresholdKeyshare: verification results.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShareVerificationComplete {
    pub e3_id: E3id,
    pub kind: VerificationKind,
    /// Stable l-BFV candidate-set identity. Legacy verification kinds use `None`.
    pub verification_id: Option<B256>,
    /// All dishonest parties (pre-dishonest + ECDSA-failed + ZK-failed).
    pub dishonest_parties: BTreeSet<u64>,
}
