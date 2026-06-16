// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Events for C2/C3/C4 share proof verification flow.
//!
//! `ShareVerificationDispatched` is published by [`ThresholdKeyshare`] when
//! proof verification is needed. [`ShareVerificationActor`] subscribes and
//! orchestrates ECDSA validation + ZK verification via multithread.
//!
//! `ShareVerificationComplete` is published by [`ShareVerificationActor`]
//! when verification finishes, carrying the set of dishonest party IDs.

use crate::{E3id, PartyProofsToVerify, PartyShareDecryptionProofsToVerify};
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
}

/// ShareVerificationActor → ThresholdKeyshare: verification results.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShareVerificationComplete {
    pub e3_id: E3id,
    pub kind: VerificationKind,
    /// All dishonest parties (pre-dishonest + ECDSA-failed + ZK-failed).
    pub dishonest_parties: BTreeSet<u64>,
}
