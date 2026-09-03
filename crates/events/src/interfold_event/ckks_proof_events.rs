// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS-specific proof events: C1-CKKS (pk share) and C8-CKKS (hybrid
//! relin ceremony round 1).
//!
//! The pending events are LOCAL (keyshare shell -> ProofRequestActor),
//! mirroring `ShareDecryptionProofPending`. `RelinCeremonyProofSigned` is
//! the durable, gossiped bundle of one party's signed C8 digit proofs; it
//! travels NEXT TO the party's `RelinCeremonyShare` chunks (whose shape is
//! unchanged) and every receiver verifies it BEFORE aggregating that
//! party's round-1 contribution.

use crate::{E3id, PkGenerationCkksProofRequest, RelinRound1CkksProofRequest, SignedProofPayload};
use actix::Message;
use e3_utils::utility_types::ArcBytes;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// ThresholdKeyshare (CKKS) -> ProofRequestActor: generate + sign the
/// C1-CKKS proof, then publish `KeyshareCreated` carrying it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PkGenerationCkksProofPending {
    pub e3_id: E3id,
    /// 0-based committee slot of this node.
    pub party_id: u64,
    pub node: String,
    /// The pk share bytes `KeyshareCreated.pubkey` will carry.
    pub pk_share: ArcBytes,
    pub proof_request: PkGenerationCkksProofRequest,
}

/// ThresholdKeyshare (CKKS) -> ProofRequestActor: generate + sign the
/// per-digit C8 proofs for this party's hybrid round-1 share, then publish
/// `RelinCeremonyProofSigned`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RelinRound1ProofPending {
    pub e3_id: E3id,
    /// 1-based Shamir id (the base `RelinCeremonyShare.party_id` uses).
    pub party_id: u64,
    pub node: String,
    /// Ceremony slot the share belongs to (`HYBRID_RELIN_LEVEL` sentinel).
    pub level: u32,
    pub proof_request: RelinRound1CkksProofRequest,
}

/// One party's signed C8-CKKS digit proofs for its hybrid round-1 share.
/// Durable + gossiped (like `DecryptionshareCreated`); receivers verify
/// every digit proof and its bindings before that party's R1 share is
/// aggregated.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct RelinCeremonyProofSigned {
    pub e3_id: E3id,
    /// 1-based Shamir id of the prover (matches `RelinCeremonyShare`).
    pub party_id: u64,
    pub node: String,
    /// Ceremony round the proofs cover (round 1 only today).
    pub round: u8,
    /// Ceremony slot (`HYBRID_RELIN_LEVEL` for the hybrid plan).
    pub level: u32,
    /// `signed_proofs[j]` proves gadget digit `j`.
    pub signed_proofs: Vec<SignedProofPayload>,
    /// Whether this was received from the network.
    pub external: bool,
}

impl Display for RelinCeremonyProofSigned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RelinCeremonyProofSigned(e3_id: {}, party: {}, round: {}, level: {}, digits: {})",
            self.e3_id,
            self.party_id,
            self.round,
            self.level,
            self.signed_proofs.len()
        )
    }
}
