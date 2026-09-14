// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Signed DKG roster proposal.
//!
//! The DKG continues when up to `N - H` committee members are absent. Every member must
//! then build its C4 decryption-key share from the same `H` contributions. The epoch leader
//! proposes that roster. The proposal is a liveness message only: the DKG aggregator
//! circuit rejects any set of C4 proofs that were not built over one roster, and the
//! registry accepts one committee publication.

use crate::E3id;
use actix::Message;
use alloy::primitives::{keccak256, Address, Signature, U256};
use alloy::signers::{local::PrivateKeySigner, SignerSync};
use alloy::sol_types::SolValue;
use e3_utils::ArcBytes;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// Type string hashed into the signing digest. Off-chain only.
const ROSTER_TYPEHASH_STR: &str =
    "DkgRosterProposed(uint256 chainId,uint256 e3Id,uint32 epoch,uint256 proposerPartyId,bytes32 rosterHash)";

/// Broadcast via gossip: the epoch leader's proposed `H`-member DKG roster.
#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct DkgRosterProposed {
    pub e3_id: E3id,
    /// Roster epoch. Epoch `e` is proposed by `eligible[e mod |eligible|]`.
    pub epoch: u32,
    /// Strictly ascending party ids, exactly `H` entries.
    pub roster: Vec<u64>,
    /// Party id of the proposer.
    pub proposer_party_id: u64,
    /// Registered address of the proposer.
    pub proposer: Address,
    /// ECDSA signature of the proposer over [`DkgRosterProposed::digest`].
    pub signature: ArcBytes,
}

impl DkgRosterProposed {
    /// Hash of the ascending roster, used in the signing digest.
    pub fn roster_hash(roster: &[u64]) -> [u8; 32] {
        let ids: Vec<U256> = roster.iter().map(|id| U256::from(*id)).collect();
        keccak256(ids.abi_encode()).into()
    }

    /// Structured digest for ECDSA signing. Off-chain only.
    pub fn digest(&self) -> [u8; 32] {
        let e3_id_u256: U256 = self
            .e3_id
            .clone()
            .try_into()
            .expect("E3id should be valid U256");
        let typehash: [u8; 32] = keccak256(ROSTER_TYPEHASH_STR).into();
        let encoded = (
            typehash,
            U256::from(self.e3_id.chain_id()),
            e3_id_u256,
            U256::from(self.epoch),
            U256::from(self.proposer_party_id),
            Self::roster_hash(&self.roster),
        )
            .abi_encode();
        keccak256(&encoded).into()
    }

    /// Build and sign a proposal.
    pub fn sign(
        e3_id: E3id,
        epoch: u32,
        roster: Vec<u64>,
        proposer_party_id: u64,
        signer: &PrivateKeySigner,
    ) -> anyhow::Result<Self> {
        let mut proposal = Self {
            e3_id,
            epoch,
            roster,
            proposer_party_id,
            proposer: signer.address(),
            signature: ArcBytes::from_bytes(&[]),
        };
        let sig = signer.sign_message_sync(&proposal.digest())?;
        proposal.signature = ArcBytes::from_bytes(&sig.as_bytes());
        Ok(proposal)
    }

    /// True when the signature recovers to `proposer`.
    pub fn verify_signature(&self) -> bool {
        let Ok(sig) = Signature::try_from(self.signature.extract_bytes().as_ref()) else {
            return false;
        };
        sig.recover_address_from_msg(self.digest())
            .is_ok_and(|address| address == self.proposer)
    }

    /// True when the roster is strictly ascending, has exactly `h` entries, and every id is
    /// below `n`.
    pub fn roster_is_well_formed(&self, n: usize, h: usize) -> bool {
        self.roster.len() == h
            && self.roster.iter().all(|id| (*id as usize) < n)
            && self.roster.windows(2).all(|w| w[0] < w[1])
    }
}

impl Display for DkgRosterProposed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DkgRosterProposed {{ e3_id: {}, epoch: {}, proposer_party_id: {}, roster: {:?} }}",
            self.e3_id, self.epoch, self.proposer_party_id, self.roster
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_proposal_verifies_and_rejects_tampering() {
        let signer = PrivateKeySigner::random();
        let proposal =
            DkgRosterProposed::sign(E3id::new("7", 1), 0, vec![0, 2], 0, &signer).unwrap();
        assert!(proposal.verify_signature());

        let mut reordered = proposal.clone();
        reordered.roster = vec![0, 1];
        assert!(!reordered.verify_signature());

        let mut other_epoch = proposal.clone();
        other_epoch.epoch = 1;
        assert!(!other_epoch.verify_signature());

        let mut other_signer = proposal.clone();
        other_signer.proposer = PrivateKeySigner::random().address();
        assert!(!other_signer.verify_signature());
    }

    #[test]
    fn roster_shape_is_checked() {
        let signer = PrivateKeySigner::random();
        let ok = DkgRosterProposed::sign(E3id::new("7", 1), 0, vec![0, 2], 0, &signer).unwrap();
        assert!(ok.roster_is_well_formed(3, 2));
        assert!(!ok.roster_is_well_formed(3, 3));

        let descending =
            DkgRosterProposed::sign(E3id::new("7", 1), 0, vec![2, 0], 0, &signer).unwrap();
        assert!(!descending.roster_is_well_formed(3, 2));

        let out_of_range =
            DkgRosterProposed::sign(E3id::new("7", 1), 0, vec![0, 3], 0, &signer).unwrap();
        assert!(!out_of_range.roster_is_well_formed(3, 2));
    }
}
