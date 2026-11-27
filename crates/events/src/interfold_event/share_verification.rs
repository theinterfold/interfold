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

use crate::{E3id, PartyProofsToVerify, PartyShareDecryptionProofsToVerify};
use alloy::primitives::B256;
use e3_committee::CiphernodesCommitteeSize;
use e3_committee_hash::LbfvProofDomainContext;
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
    /// One public-key generation proof per row, then one RLK generation proof per row, from one
    /// party. The row count is the E3 preset's CRT modulus count.
    LbfvGenerationProofs,
    /// One public-key aggregation proof per row, then one RLK aggregation proof per row for `d0`
    /// and one per row for `d2`, from one aggregator.
    LbfvAggregationProofs,
}

/// Authoritative context for an l-BFV verification dispatch.
///
/// Bincode encodes variants by order. Append new versions and do not reorder existing variants.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LbfvVerificationContext {
    V2(LbfvVerificationContextV2),
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

/// ThresholdKeyshare → ShareVerificationActor: verify party proofs.
///
/// The persisted and wire layout of this event is the trBFV one and must not change. The l-BFV
/// verification kinds, which need an authoritative context and a candidate-set identity, use
/// [`LbfvShareVerificationDispatched`].
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
    /// Request-time profile for proof shape and circuit artifact resolution.
    pub params_profile: e3_fhe_params::BfvProfile,
    /// Committee size for per-committee circuit artifact resolution.
    pub committee_size: CiphernodesCommitteeSize,
}

/// ShareVerificationActor → ThresholdKeyshare: verification results.
///
/// The persisted and wire layout of this event is the trBFV one and must not change. A result
/// that carries an l-BFV candidate-set identity is [`LbfvShareVerificationComplete`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShareVerificationComplete {
    pub e3_id: E3id,
    pub kind: VerificationKind,
    /// All dishonest parties (pre-dishonest + ECDSA-failed + ZK-failed).
    pub dishonest_parties: BTreeSet<u64>,
}

/// [`ShareVerificationDispatched`] with the l-BFV fields. Verification of the l-BFV kinds is
/// dispatched in this form; every other dispatch keeps the trBFV form.
///
/// The verification workflow runs on this form. [`Self::into_event_data`] gives the trBFV form
/// whenever it can represent the dispatch.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LbfvShareVerificationDispatched {
    pub e3_id: E3id,
    pub kind: VerificationKind,
    /// C2/C3 party proofs (when kind == ShareProofs).
    pub share_proofs: Vec<PartyProofsToVerify>,
    /// C4 party proofs (when kind == DecryptionProofs).
    pub decryption_proofs: Vec<PartyShareDecryptionProofsToVerify>,
    /// Parties already identified as dishonest before verification.
    pub pre_dishonest: BTreeSet<u64>,
    /// Request-time profile for proof shape and circuit artifact resolution.
    pub params_profile: e3_fhe_params::BfvProfile,
    /// Committee size for per-committee circuit artifact resolution.
    pub committee_size: CiphernodesCommitteeSize,
    /// Authoritative l-BFV context. Legacy verification kinds require `None`.
    pub lbfv_context: Option<LbfvVerificationContext>,
    /// Stable l-BFV candidate-set identity. Legacy verification kinds require `None`.
    pub verification_id: Option<B256>,
}

/// [`ShareVerificationComplete`] with the l-BFV candidate-set identity. The result of an l-BFV
/// kind is published in this form; every other result keeps the trBFV form.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LbfvShareVerificationComplete {
    pub e3_id: E3id,
    pub kind: VerificationKind,
    /// Stable l-BFV candidate-set identity. Legacy verification kinds use `None`.
    pub verification_id: Option<B256>,
    /// All dishonest parties (pre-dishonest + ECDSA-failed + ZK-failed).
    pub dishonest_parties: BTreeSet<u64>,
}

impl VerificationKind {
    /// Whether this kind exists only on the l-BFV path.
    pub fn is_lbfv(&self) -> bool {
        matches!(
            self,
            Self::LbfvGenerationProofs | Self::LbfvAggregationProofs
        )
    }
}

impl From<ShareVerificationDispatched> for LbfvShareVerificationDispatched {
    fn from(dispatch: ShareVerificationDispatched) -> Self {
        Self {
            e3_id: dispatch.e3_id,
            kind: dispatch.kind,
            share_proofs: dispatch.share_proofs,
            decryption_proofs: dispatch.decryption_proofs,
            pre_dishonest: dispatch.pre_dishonest,
            params_profile: dispatch.params_profile,
            committee_size: dispatch.committee_size,
            lbfv_context: None,
            verification_id: None,
        }
    }
}

impl LbfvShareVerificationDispatched {
    /// Whether the trBFV form can represent this dispatch.
    pub fn has_trbfv_form(&self) -> bool {
        !self.kind.is_lbfv() && self.lbfv_context.is_none() && self.verification_id.is_none()
    }

    /// The event to publish: the trBFV form when it can represent this dispatch, so that trBFV
    /// bytes stay as they were.
    pub fn into_event_data(self) -> crate::InterfoldEventData {
        if self.has_trbfv_form() {
            ShareVerificationDispatched {
                e3_id: self.e3_id,
                kind: self.kind,
                share_proofs: self.share_proofs,
                decryption_proofs: self.decryption_proofs,
                pre_dishonest: self.pre_dishonest,
                params_profile: self.params_profile,
                committee_size: self.committee_size,
            }
            .into()
        } else {
            self.into()
        }
    }
}

impl From<ShareVerificationComplete> for LbfvShareVerificationComplete {
    fn from(result: ShareVerificationComplete) -> Self {
        Self {
            e3_id: result.e3_id,
            kind: result.kind,
            verification_id: None,
            dishonest_parties: result.dishonest_parties,
        }
    }
}

impl LbfvShareVerificationComplete {
    /// Whether the trBFV form can represent this result.
    pub fn has_trbfv_form(&self) -> bool {
        !self.kind.is_lbfv() && self.verification_id.is_none()
    }

    /// The event to publish: the trBFV form when it can represent this result.
    pub fn into_event_data(self) -> crate::InterfoldEventData {
        if self.has_trbfv_form() {
            ShareVerificationComplete {
                e3_id: self.e3_id,
                kind: self.kind,
                dishonest_parties: self.dishonest_parties,
            }
            .into()
        } else {
            self.into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trbfv_dispatch() -> ShareVerificationDispatched {
        ShareVerificationDispatched {
            e3_id: E3id::new("7", 1),
            kind: VerificationKind::ShareProofs,
            share_proofs: Vec::new(),
            decryption_proofs: Vec::new(),
            pre_dishonest: BTreeSet::from([1]),
            params_profile: e3_fhe_params::BfvProfile::SsInsecure64,
            committee_size: CiphernodesCommitteeSize::Minimum,
        }
    }

    /// The bincode bytes of the trBFV events, written out by field type: little-endian
    /// fixed-width integers, `u64` length prefixes and `u32` variant indexes. A field that is
    /// added, reordered or retyped fails here.
    #[test]
    fn trbfv_verification_events_keep_their_encoded_layout() {
        let e3_id = [&1u64.to_le_bytes()[..], b"7", &1u64.to_le_bytes()].concat();
        let share_proofs_kind = 0u32.to_le_bytes();
        let empty_vec = 0u64.to_le_bytes();

        assert_eq!(
            bincode::serialize(&trbfv_dispatch()).unwrap(),
            [
                &e3_id[..],
                &share_proofs_kind,
                &empty_vec,
                &empty_vec,
                // `pre_dishonest`: one element, party 1.
                &1u64.to_le_bytes(),
                &1u64.to_le_bytes(),
                // `params_profile` SsInsecure64 and `committee_size` Minimum.
                &0u32.to_le_bytes(),
                &0u32.to_le_bytes(),
            ]
            .concat()
        );

        let result = ShareVerificationComplete {
            e3_id: E3id::new("7", 1),
            kind: VerificationKind::ShareProofs,
            dishonest_parties: BTreeSet::from([2]),
        };
        assert_eq!(
            bincode::serialize(&result).unwrap(),
            [
                &e3_id[..],
                &share_proofs_kind,
                // `dishonest_parties`: one element, party 2.
                &1u64.to_le_bytes(),
                &2u64.to_le_bytes(),
            ]
            .concat()
        );
    }

    #[test]
    fn the_trbfv_form_is_published_whenever_it_can_represent_the_event() {
        let trbfv = trbfv_dispatch();
        let lbfv = LbfvShareVerificationDispatched::from(trbfv.clone());
        assert!(lbfv.has_trbfv_form());
        assert_eq!(
            lbfv.clone().into_event_data(),
            crate::InterfoldEventData::from(trbfv.clone())
        );

        // An l-BFV kind, a context or a candidate-set identity needs the l-BFV form.
        for needs_lbfv in [
            LbfvShareVerificationDispatched {
                kind: VerificationKind::LbfvGenerationProofs,
                ..lbfv.clone()
            },
            LbfvShareVerificationDispatched {
                verification_id: Some(B256::repeat_byte(1)),
                ..lbfv.clone()
            },
        ] {
            assert!(!needs_lbfv.has_trbfv_form());
            assert_eq!(
                needs_lbfv.clone().into_event_data(),
                crate::InterfoldEventData::from(needs_lbfv)
            );
        }

        let result = LbfvShareVerificationComplete {
            e3_id: E3id::new("7", 1),
            kind: VerificationKind::ShareProofs,
            verification_id: None,
            dishonest_parties: BTreeSet::new(),
        };
        assert!(matches!(
            result.clone().into_event_data(),
            crate::InterfoldEventData::ShareVerificationComplete(_)
        ));
        let with_id = LbfvShareVerificationComplete {
            verification_id: Some(B256::repeat_byte(1)),
            ..result
        };
        assert!(matches!(
            with_id.into_event_data(),
            crate::InterfoldEventData::LbfvShareVerificationComplete(_)
        ));
    }
}
