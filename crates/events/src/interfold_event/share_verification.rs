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
    V2(LbfvVerificationContextV2),
}

/// Original fixed-five-row l-BFV verification context.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LbfvVerificationContextV1 {
    pub proof_domain: LbfvProofDomainContext,
    /// Present only for `LbfvAggregationProofs`.
    pub aggregation: Option<LbfvAggregationVerificationContextV1>,
}

/// Original fixed-five-row aggregation binding.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LbfvAggregationVerificationContextV1 {
    /// Exactly H records in strictly ascending `party_id` order.
    pub accepted_parties: Vec<LbfvAcceptedPartyCommitmentsV1>,
}

/// Original generation commitments for one accepted party.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LbfvAcceptedPartyCommitmentsV1 {
    pub party_id: u32,
    pub pk_generation_commitments: [B256; ProofType::LBFV_ROW_INSTANCES as usize],
    pub rlk_d0_commitments: [B256; ProofType::LBFV_ROW_INSTANCES as usize],
    pub rlk_d2_commitments: [B256; ProofType::LBFV_ROW_INSTANCES as usize],
}

/// Authoritative l-BFV proof domain and dynamic aggregation binding.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LbfvVerificationContextV2 {
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
    pub pk_generation_commitments: Vec<B256>,
    pub rlk_d0_commitments: Vec<B256>,
    pub rlk_d2_commitments: Vec<B256>,
}

impl LbfvVerificationContext {
    /// Convert a replayed fixed-row context to the current dynamic-row representation.
    pub fn into_latest(self) -> Self {
        match self {
            Self::V1(context) => Self::V2(LbfvVerificationContextV2 {
                proof_domain: context.proof_domain,
                aggregation: context.aggregation.map(Into::into),
            }),
            current @ Self::V2(_) => current,
        }
    }
}

impl From<LbfvAggregationVerificationContextV1> for LbfvAggregationVerificationContext {
    fn from(value: LbfvAggregationVerificationContextV1) -> Self {
        Self {
            accepted_parties: value.accepted_parties.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<LbfvAcceptedPartyCommitmentsV1> for LbfvAcceptedPartyCommitments {
    fn from(value: LbfvAcceptedPartyCommitmentsV1) -> Self {
        Self {
            party_id: value.party_id,
            pk_generation_commitments: value.pk_generation_commitments.into(),
            rlk_d0_commitments: value.rlk_d0_commitments.into(),
            rlk_d2_commitments: value.rlk_d2_commitments.into(),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, U256};

    const LEGACY_DISPATCH: &[u8] =
        include_bytes!("fixtures/share_verification_dispatched_lbfv_v1.bincode");

    fn legacy_dispatch() -> ShareVerificationDispatched {
        ShareVerificationDispatched {
            e3_id: E3id::new("7", 1),
            kind: VerificationKind::LbfvAggregationProofs,
            share_proofs: Vec::new(),
            decryption_proofs: Vec::new(),
            pre_dishonest: BTreeSet::new(),
            params_preset: e3_fhe_params::BfvPreset::SecureThreshold16384,
            committee_size: CiphernodesCommitteeSize::Minimum,
            lbfv_context: Some(LbfvVerificationContext::V1(LbfvVerificationContextV1 {
                proof_domain: LbfvProofDomainContext {
                    protocol_version: 4,
                    chain_id: 1,
                    interfold_address: Address::repeat_byte(0x11),
                    e3_id: U256::from(7),
                    crypto_config_id: B256::repeat_byte(0x22),
                    finalized_committee_hash: B256::repeat_byte(0x33),
                    lbfv_constants_version: 1,
                    ciphertext_level: 0,
                    key_level: 0,
                },
                aggregation: Some(LbfvAggregationVerificationContextV1 {
                    accepted_parties: vec![LbfvAcceptedPartyCommitmentsV1 {
                        party_id: 2,
                        pk_generation_commitments: [B256::repeat_byte(0x44); 5],
                        rlk_d0_commitments: [B256::repeat_byte(0x55); 5],
                        rlk_d2_commitments: [B256::repeat_byte(0x66); 5],
                    }],
                }),
            })),
            verification_id: Some(B256::repeat_byte(0x77)),
        }
    }

    #[test]
    fn legacy_lbfv_dispatch_fixture_decodes_and_normalizes() {
        assert_eq!(
            bincode::serialize(&legacy_dispatch()).unwrap(),
            LEGACY_DISPATCH
        );

        let restored: ShareVerificationDispatched = bincode::deserialize(LEGACY_DISPATCH).unwrap();
        let LbfvVerificationContext::V2(context) = restored.lbfv_context.unwrap().into_latest()
        else {
            panic!("legacy context did not normalize to V2")
        };
        let accepted = context.aggregation.unwrap().accepted_parties;
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].party_id, 2);
        assert_eq!(accepted[0].pk_generation_commitments.len(), 5);
        assert_eq!(accepted[0].rlk_d0_commitments.len(), 5);
        assert_eq!(accepted[0].rlk_d2_commitments.len(), 5);
    }
}
