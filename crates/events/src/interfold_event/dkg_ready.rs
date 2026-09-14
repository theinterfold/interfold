// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Signed DKG readiness report.
//!
//! After C2/C3 verification a committee member reports the set of senders whose complete,
//! verified share bundle it holds. The epoch leader chooses the DKG roster from these
//! reports. A report is a liveness message only. A member that reports a sender it does
//! not hold cannot produce its own C4 proof over that roster, and the epoch times out.

use crate::E3id;
use actix::Message;
use alloy::primitives::{keccak256, Address, Signature, U256};
use alloy::signers::{local::PrivateKeySigner, SignerSync};
use alloy::sol_types::SolValue;
use e3_utils::ArcBytes;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt::{self, Display};

/// Type string hashed into the signing digest. Off-chain only.
const READY_TYPEHASH_STR: &str =
    "DkgReady(uint256 chainId,uint256 e3Id,uint256 partyId,bytes32 readyHash)";

/// Broadcast via gossip: the senders whose verified share bundle this member holds.
#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct DkgReady {
    pub e3_id: E3id,
    /// Party id of the reporting member.
    pub party_id: u64,
    /// Registered address of the reporting member.
    pub node: Address,
    /// Sender party ids whose bundle passed C2/C3 verification here. Ascending, excludes
    /// `party_id`.
    pub ready: Vec<u64>,
    /// ECDSA signature of the member over [`DkgReady::digest`].
    pub signature: ArcBytes,
}

impl DkgReady {
    /// Structured digest for ECDSA signing. Off-chain only.
    pub fn digest(&self) -> [u8; 32] {
        let e3_id_u256: U256 = self
            .e3_id
            .clone()
            .try_into()
            .expect("E3id should be valid U256");
        let ids: Vec<U256> = self.ready.iter().map(|id| U256::from(*id)).collect();
        let ready_hash: [u8; 32] = keccak256(ids.abi_encode()).into();
        let typehash: [u8; 32] = keccak256(READY_TYPEHASH_STR).into();
        let encoded = (
            typehash,
            U256::from(self.e3_id.chain_id()),
            e3_id_u256,
            U256::from(self.party_id),
            ready_hash,
        )
            .abi_encode();
        keccak256(&encoded).into()
    }

    /// Build and sign a report. `ready` is normalized to ascending order without `party_id`.
    pub fn sign(
        e3_id: E3id,
        party_id: u64,
        ready: impl IntoIterator<Item = u64>,
        signer: &PrivateKeySigner,
    ) -> anyhow::Result<Self> {
        let ready: BTreeSet<u64> = ready.into_iter().filter(|id| *id != party_id).collect();
        let mut report = Self {
            e3_id,
            party_id,
            node: signer.address(),
            ready: ready.into_iter().collect(),
            signature: ArcBytes::from_bytes(&[]),
        };
        let sig = signer.sign_message_sync(&report.digest())?;
        report.signature = ArcBytes::from_bytes(&sig.as_bytes());
        Ok(report)
    }

    /// True when the signature recovers to `node`.
    pub fn verify_signature(&self) -> bool {
        let Ok(sig) = Signature::try_from(self.signature.extract_bytes().as_ref()) else {
            return false;
        };
        sig.recover_address_from_msg(self.digest())
            .is_ok_and(|address| address == self.node)
    }

    /// The ready set as a set, always including the reporter itself.
    pub fn ready_with_self(&self) -> BTreeSet<u64> {
        let mut set: BTreeSet<u64> = self.ready.iter().copied().collect();
        set.insert(self.party_id);
        set
    }
}

impl Display for DkgReady {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DkgReady {{ e3_id: {}, party_id: {}, ready: {:?} }}",
            self.e3_id, self.party_id, self.ready
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_report_verifies_and_is_normalized() {
        let signer = PrivateKeySigner::random();
        let report = DkgReady::sign(E3id::new("7", 1), 1, [2, 0, 1], &signer).unwrap();
        assert_eq!(
            report.ready,
            vec![0, 2],
            "self is removed, order is ascending"
        );
        assert!(report.verify_signature());
        assert_eq!(report.ready_with_self(), BTreeSet::from([0, 1, 2]));

        let mut tampered = report.clone();
        tampered.ready = vec![0];
        assert!(!tampered.verify_signature());
    }
}
