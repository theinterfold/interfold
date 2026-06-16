// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{E3id, ProofType, SignedProofPayload};
use actix::Message;
use alloy::primitives::Address;
use e3_utils::ArcBytes;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// Broadcast via gossip: a committee member claims another node's proof failed verification.
///
/// This is the accusation that starts the off-chain quorum protocol. Other committee
/// members receive this, independently check their own verification result for the same
/// proof, and respond with an [`AccusationVote`].
///
/// For C3a/C3b proofs (per-recipient encryption), the accuser includes the
/// [`SignedProofPayload`] so other nodes can re-verify a proof they never received directly.
#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct ProofFailureAccusation {
    pub e3_id: E3id,
    /// Ethereum address of the accusing node.
    pub accuser: Address,
    /// Ethereum address of the accused node.
    pub accused: Address,
    /// Party ID of the accused node.
    pub accused_party_id: u64,
    /// Which proof type allegedly failed.
    pub proof_type: ProofType,
    /// keccak256 hash of (data + proof) as received by the accuser.
    pub data_hash: [u8; 32],
    /// Unix-seconds deadline after which votes signed for this accusation must be
    /// rejected on-chain (`SlashingManager._verifyAttestationEvidence` enforces
    /// `block.timestamp <= deadline`). Set by the accuser; every voter signs the
    /// same value so the aggregated evidence carries one shared deadline.
    pub deadline: u64,
    /// For C3a/C3b: the signed proof payload so other nodes can re-verify.
    /// `None` for proofs that all nodes already received.
    pub signed_payload: Option<SignedProofPayload>,
    /// ECDSA signature of the accuser over the accusation fields.
    pub signature: ArcBytes,
}

impl Display for ProofFailureAccusation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProofFailureAccusation {{ e3_id: {}, accuser: {}, accused: {}, proof_type: {:?} }}",
            self.e3_id, self.accuser, self.accused, self.proof_type
        )
    }
}
