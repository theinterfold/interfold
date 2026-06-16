// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{AccusationVote, E3id, ProofType};
use actix::Message;
use alloy::primitives::{Address, Bytes};
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// The outcome of an accusation quorum vote.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccusationOutcome {
    /// >= M nodes agree the proof is bad → slash the accused.
    AccusedFaulted,
    /// data_hashes differ between voters → accused sent different data to different nodes.
    Equivocation,
    /// Vote timeout expired or not enough votes → proceed with E3 timeout.
    Inconclusive,
}

impl Display for AccusationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccusationOutcome::AccusedFaulted => write!(f, "AccusedFaulted"),
            AccusationOutcome::Equivocation => write!(f, "Equivocation"),
            AccusationOutcome::Inconclusive => write!(f, "Inconclusive"),
        }
    }
}

/// Emitted locally when the accusation quorum protocol reaches a decision.
///
/// Consumed by aggregator actors to exclude faulted nodes and by the on-chain
/// submission logic to submit `E3FaultEvidence`.
#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct AccusationQuorumReached {
    pub e3_id: E3id,
    /// Address of the node that originally accused.
    pub accuser: Address,
    /// Address of the accused node.
    pub accused: Address,
    /// Which proof type was disputed.
    pub proof_type: ProofType,
    /// Votes from nodes that agreed the proof is bad.
    ///
    /// There is no `votes_against` companion: the gossip protocol no longer
    /// carries disagreement signatures, so silence is the only signal of
    /// disagreement. See the `AccusationVote` docstring for the rationale.
    pub votes_for: Vec<AccusationVote>,
    /// The quorum decision.
    pub outcome: AccusationOutcome,
    /// Raw `abi.encode(proof.data, public_signals)` — preimage of every voter's
    /// `data_hash`.
    ///
    /// Consumed by Lane A slash submission: on-chain verifier checks
    /// `keccak256(evidence) == sharedDataHash`.
    /// Empty when this node didn't have raw bytes locally (e.g.
    /// consistency-violation path), in which case submitter should skip
    /// submission because on-chain binding cannot be proven.
    pub evidence: Bytes,
}

impl Display for AccusationQuorumReached {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AccusationQuorumReached {{ e3_id: {}, accused: {}, proof_type: {:?}, outcome: {} }}",
            self.e3_id, self.accused, self.proof_type, self.outcome
        )
    }
}
