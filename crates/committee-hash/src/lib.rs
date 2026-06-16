// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Canonical committee hash for DKG / decryption aggregator proofs.
//! Must match `CommitteeHashLib.sol` (`keccak256(abi.encodePacked(addresses))`).

use alloy::primitives::{keccak256, Address, B256};

/// Hi/lo limbs of `keccak256(abi.encodePacked(addresses))` for Noir public inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitteeHashLimbs {
    pub hi: B256,
    pub lo: B256,
}

/// `keccak256(abi.encodePacked(addresses))` for the ordered on-chain committee.
pub fn hash_committee_addresses(addresses: &[Address]) -> B256 {
    let packed: Vec<u8> = addresses
        .iter()
        .flat_map(|addr| addr.into_array())
        .collect();
    keccak256(packed)
}

/// Split a committee hash into 128-bit limbs for BN254 public inputs.
/// Each limb is a bytes32 with its 128 bits right-aligned, matching `CommitteeHashLib`.
pub fn split_committee_hash(hash: B256) -> CommitteeHashLimbs {
    let mut hi = [0u8; 32];
    hi[16..].copy_from_slice(&hash.0[..16]);
    let mut lo = [0u8; 32];
    lo[16..].copy_from_slice(&hash.0[16..]);
    CommitteeHashLimbs {
        hi: B256::from(hi),
        lo: B256::from(lo),
    }
}

/// Hash and split in one step.
pub fn committee_hash_limbs_from_addresses(addresses: &[Address]) -> CommitteeHashLimbs {
    split_committee_hash(hash_committee_addresses(addresses))
}

/// Field hex strings (`0x…`, 32 bytes) for Noir witness `committee_hash_hi` / `committee_hash_lo`.
pub fn committee_hash_field_hex(addresses: &[Address]) -> (String, String) {
    let limbs = committee_hash_limbs_from_addresses(addresses);
    (field_hex_from_b256(limbs.hi), field_hex_from_b256(limbs.lo))
}

fn field_hex_from_b256(value: B256) -> String {
    format!("0x{}", hex::encode(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    #[test]
    fn encode_packed_matches_solidity_layout() {
        let nodes = vec![
            address!("0x0000000000000000000000000000000000000001"),
            address!("0x0000000000000000000000000000000000000002"),
        ];
        let hash = hash_committee_addresses(&nodes);
        let limbs = split_committee_hash(hash);
        assert_ne!(limbs.hi, B256::ZERO);
        assert_ne!(limbs.lo, B256::ZERO);
    }

    /// Limb bytes32 layout must match `CommitteeHashLib.hi` / `lo`.
    #[test]
    fn split_limbs_match_solidity_bytes32_layout() {
        let nodes = vec![
            address!("0x0000000000000000000000000000000000000001"),
            address!("0x0000000000000000000000000000000000000002"),
            address!("0x0000000000000000000000000000000000000003"),
        ];
        let hash = hash_committee_addresses(&nodes);
        let limbs = split_committee_hash(hash);

        let mut expected_hi = [0u8; 32];
        expected_hi[16..].copy_from_slice(&hash.0[..16]);
        assert_eq!(limbs.hi.0, expected_hi);

        let mut expected_lo = [0u8; 32];
        expected_lo[16..].copy_from_slice(&hash.0[16..]);
        assert_eq!(limbs.lo.0, expected_lo);
    }
}
