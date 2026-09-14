// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::E3id;
use actix::Message;
use alloy::primitives::{keccak256, Address, Signature, U256};
use alloy::signers::{local::PrivateKeySigner, SignerSync};
use alloy::sol_types::SolValue;
use anyhow::{anyhow, Result};
use e3_utils::utility_types::ArcBytes;
use serde::{Deserialize, Serialize};

/// Identifies one dealer's exact public key and C2 proof pair.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DkgDealer {
    pub party_id: u64,
    pub contribution_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DkgCoordinationKind {
    /// This party has verified and stored the listed dealer contributions.
    Ready,
    /// The named leader proposes the exact H dealer contributions for C4.
    Roster { view: u64 },
}

/// Authenticated, E3-scoped DKG readiness or roster message.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct DkgCoordination {
    pub e3_id: E3id,
    pub interfold_address: Address,
    pub party_id: u64,
    pub kind: DkgCoordinationKind,
    /// Sorted by full-committee party ID; each entry names exact public inputs.
    pub dealers: Vec<DkgDealer>,
    pub signature: ArcBytes,
}

impl DkgCoordination {
    pub fn sign(
        e3_id: E3id,
        interfold_address: Address,
        party_id: u64,
        kind: DkgCoordinationKind,
        dealers: Vec<DkgDealer>,
        signer: &PrivateKeySigner,
    ) -> Result<Self> {
        let mut message = Self {
            e3_id,
            interfold_address,
            party_id,
            kind,
            dealers,
            signature: ArcBytes::from_bytes(&[]),
        };
        let digest = message.digest()?;
        let signature = signer
            .sign_hash_sync(&digest.into())
            .map_err(|error| anyhow!("failed to sign DKG coordination message: {error}"))?;
        message.signature = ArcBytes::from_bytes(&signature.as_bytes());
        Ok(message)
    }

    pub fn digest(&self) -> Result<[u8; 32]> {
        let e3_id: U256 = self
            .e3_id
            .clone()
            .try_into()
            .map_err(|_| anyhow!("invalid E3 ID in DKG coordination message"))?;
        let (kind, view) = match self.kind {
            DkgCoordinationKind::Ready => (0u64, 0u64),
            DkgCoordinationKind::Roster { view } => (1u64, view),
        };
        let ids: Vec<U256> = self
            .dealers
            .iter()
            .map(|dealer| U256::from(dealer.party_id))
            .collect();
        let hashes: Vec<[u8; 32]> = self
            .dealers
            .iter()
            .map(|dealer| dealer.contribution_hash)
            .collect();
        let dealers_hash = keccak256((ids, hashes).abi_encode());
        let encoded = (
            keccak256("InterfoldDkgCoordination(uint256 chainId,address interfold,uint256 e3Id,uint256 partyId,uint256 kind,uint256 view,bytes32 dealersHash)"),
            U256::from(self.e3_id.chain_id()),
            self.interfold_address,
            e3_id,
            U256::from(self.party_id),
            U256::from(kind),
            U256::from(view),
            dealers_hash,
        )
            .abi_encode();
        Ok(keccak256(encoded).into())
    }

    pub fn recover_address(&self) -> Result<Address> {
        let signature = Signature::try_from(&self.signature[..])
            .map_err(|error| anyhow!("invalid DKG coordination signature: {error}"))?;
        let digest = self.digest()?;
        signature
            .recover_address_from_prehash(&digest.into())
            .map_err(|error| anyhow!("failed to recover DKG coordination signer: {error}"))
    }

    pub fn has_canonical_dealers(&self, committee_n: usize) -> bool {
        self.dealers
            .windows(2)
            .all(|pair| pair[0].party_id < pair[1].party_id)
            && self
                .dealers
                .last()
                .is_none_or(|dealer| dealer.party_id < committee_n as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_binds_roster_and_deployment() {
        let signer = PrivateKeySigner::random();
        let message = DkgCoordination::sign(
            E3id::new("7", 11155111),
            Address::repeat_byte(0x11),
            2,
            DkgCoordinationKind::Roster { view: 2 },
            vec![DkgDealer {
                party_id: 2,
                contribution_hash: [0x42; 32],
            }],
            &signer,
        )
        .unwrap();
        assert_eq!(message.recover_address().unwrap(), signer.address());
        let mut tampered = message.clone();
        tampered.dealers[0].contribution_hash[0] ^= 1;
        assert_ne!(tampered.recover_address().unwrap(), signer.address());
        tampered = message;
        tampered.interfold_address = Address::repeat_byte(0x12);
        assert_ne!(tampered.recover_address().unwrap(), signer.address());
    }

    #[test]
    fn dealer_ids_must_be_sorted_and_in_range() {
        let signer = PrivateKeySigner::random();
        let message = DkgCoordination::sign(
            E3id::new("7", 11155111),
            Address::repeat_byte(0x11),
            2,
            DkgCoordinationKind::Ready,
            vec![
                DkgDealer {
                    party_id: 1,
                    contribution_hash: [1; 32],
                },
                DkgDealer {
                    party_id: 3,
                    contribution_hash: [3; 32],
                },
            ],
            &signer,
        )
        .unwrap();
        assert!(message.has_canonical_dealers(4));
        assert!(!message.has_canonical_dealers(3));
        let mut reversed = message;
        reversed.dealers.reverse();
        assert!(!reversed.has_canonical_dealers(4));
    }
}
