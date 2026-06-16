// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{E3id, ProofType};
use actix::Message;
use alloy::primitives::Address;
use e3_utils::utility_types::ArcBytes;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// Emitted locally when a node successfully verifies another node's ZK proof.
///
/// This allows the [`AccusationManager`] to cache successful verification results
/// so it can vote DISAGREE on false accusations from other nodes, and the
/// [`CommitmentConsistencyChecker`] to cross-check commitment values across circuits.
///
/// Emitted by:
/// - [`ProofVerificationActor`] — for C0 (BFV public key) successes
/// - [`ShareVerificationActor`] — for C1–C4/C6 successes
#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct ProofVerificationPassed {
    pub e3_id: E3id,
    /// Party ID of the node whose proof passed.
    pub party_id: u64,
    /// Recovered Ethereum address of the verified node.
    pub address: Address,
    /// Which proof type passed.
    pub proof_type: ProofType,
    /// keccak256 hash of the received data + proof bytes — for equivocation detection.
    pub data_hash: [u8; 32],
    /// Raw public signals from the verified proof — for commitment consistency checks.
    pub public_signals: ArcBytes,
    /// Raw proof bytes — needed only by paths that may later turn this proof into
    /// slashing evidence (so the on-chain contract can recompute and verify the
    /// dataHash bound in voter signatures). Empty when the emitter did not have
    /// the raw bytes available; downstream consumers that need it will fail
    /// gracefully if so.
    pub proof_data: ArcBytes,
}

impl Display for ProofVerificationPassed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProofVerificationPassed {{ e3_id: {}, party: {}, address: {}, proof_type: {:?} }}",
            self.e3_id, self.party_id, self.address, self.proof_type
        )
    }
}
