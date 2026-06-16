// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::E3id;
use actix::Message;
use alloy::primitives::Address;
use e3_utils::ArcBytes;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// EIP-712 domain `name` for accusation vote signatures.
///
/// MUST byte-equal the literal passed to `EIP712(...)` in
/// `packages/interfold-contracts/contracts/slashing/SlashingManager.sol`
/// (`EIP712_DOMAIN_NAME` constant there). Off-chain signers and the on-chain
/// verifier share this one string — diverging here silently breaks
/// `ECDSA.recover` on every slashing submission.
pub const VOTE_DOMAIN_NAME: &str = "InterfoldSlashing";

/// EIP-712 domain `version` for accusation vote signatures. Same alignment
/// rule as [`VOTE_DOMAIN_NAME`].
pub const VOTE_DOMAIN_VERSION: &str = "1";

/// EIP-712 struct typehash string for [`AccusationVote`].
///
/// MUST byte-equal `SlashingManager.VOTE_TYPEHASH`'s source string. Reordering
/// or renaming fields here without updating Solidity (or vice versa) silently
/// breaks signature recovery on chain.
pub const VOTE_TYPEHASH_STR: &str =
    "AccusationVote(uint256 e3Id,bytes32 accusationId,address voter,bytes32 dataHash,uint256 deadline)";

/// Broadcast via gossip: a committee member's vote agreeing with an accusation.
///
/// A node broadcasts an `AccusationVote` only when its own local verification
/// of the disputed proof also failed. There is no "disagree" vote on the
/// wire — a peer who finds the proof passes simply stays silent. This matches
/// the on-chain `SlashingManager._verifyAttestationEvidence`, which consumes
/// only agreeing signatures and treats every submitted vote as an
/// affirmative attestation; carrying an explicit `agrees` flag here would be
/// dead bytes off-chain and unverifiable gossip metadata (a malicious peer
/// could flip the flag in transit without invalidating the EIP-712 signature
/// over the on-chain digest).
///
/// **Loss of fast-fail.** Off-chain quorum protocols sometimes track explicit
/// "no" votes so an accusation that clearly cannot reach quorum exits the
/// pending pool early. We trade that optimization for protocol simplicity and
/// soundness: an unanswerable accusation now runs to `vote_timeout` (default 5 min)
/// before being declared inconclusive. Other committee members' silence is the
/// signal; no separate signed message is required.
#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct AccusationVote {
    pub e3_id: E3id,
    /// keccak256 of the `ProofFailureAccusation` this vote responds to.
    pub accusation_id: [u8; 32],
    /// Ethereum address of the voter.
    pub voter: Address,
    /// keccak256 hash of the data as this node received it — for equivocation detection.
    pub data_hash: [u8; 32],
    /// Unix-seconds deadline shared across all voters for this accusation.
    /// Bound into the EIP-712 vote digest and re-checked on-chain by
    /// `SlashingManager._verifyAttestationEvidence` via `block.timestamp <= deadline`.
    pub deadline: u64,
    /// ECDSA signature of the voter over the EIP-712 vote digest.
    pub signature: ArcBytes,
}

impl Display for AccusationVote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AccusationVote {{ e3_id: {}, voter: {} }}",
            self.e3_id, self.voter
        )
    }
}
