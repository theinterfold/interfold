// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{E3id, ProofType, SignedProofPayload};
use actix::Message;
use alloy::primitives::Address;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// Emitted locally when a node detects that another node's ZK proof failed verification.
///
/// This triggers the [`AccusationManager`] to broadcast a [`ProofFailureAccusation`]
/// and start the off-chain quorum protocol.
///
/// Emitted by:
/// - [`ProofVerificationActor`] — for C0 (BFV public key) failures
/// - [`ShareVerificationActor`] — for C1–C4/C6 failures
#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct ProofVerificationFailed {
    pub e3_id: E3id,
    /// Party ID of the node whose proof failed.
    pub accused_party_id: u64,
    /// Recovered Ethereum address of the accused node.
    pub accused_address: Address,
    /// Which proof type failed.
    pub proof_type: ProofType,
    /// keccak256 hash of the received data + proof bytes — used for equivocation detection.
    pub data_hash: [u8; 32],
    /// The signed proof payload that failed — preserved for C3a/C3b forwarding.
    pub signed_payload: SignedProofPayload,
}

impl Display for ProofVerificationFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProofVerificationFailed {{ e3_id: {}, accused: {}, proof_type: {:?} }}",
            self.e3_id, self.accused_address, self.proof_type
        )
    }
}
