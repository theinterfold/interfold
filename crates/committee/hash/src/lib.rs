// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Canonical EVM hashes for DKG / decryption aggregator proofs.
//! Committee hashing must match `CommitteeHashLib.sol`
//! (`keccak256` over ordered raw 20-byte addresses). Decryption-domain hashing
//! must match `InterfoldPricing.decryptionDomain`.

use alloy::{
    primitives::{keccak256, Address, B256, U256},
    sol_types::SolValue,
};
use serde::{Deserialize, Serialize};

/// Hi/lo limbs of the canonical ordered-address hash for Noir public inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitteeHashLimbs {
    pub hi: B256,
    pub lo: B256,
}

/// Stable, non-secret context needed to bind a C6 decryption-share proof to
/// the E3 that authorized it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DecryptionDomainContext {
    pub interfold_address: Address,
    pub committee_hash: B256,
    pub committee_public_key: B256,
}

/// Hi/lo 128-bit limbs of the decryption-domain hash for Noir public inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecryptionDomainLimbs {
    pub hi: u128,
    pub lo: u128,
}

/// `keccak256` over the ordered committee's raw 20-byte addresses.
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

/// Compute the E3 decryption domain:
///
/// `keccak256(abi.encode(chainId, interfold, e3Id, committeeHash,
/// ciphertextOutputHash, committeePublicKey))`.
///
/// The Interfold address prevents cross-deployment replay. The remaining
/// fields prevent replay across chains, E3s, committees, ciphertexts, or DKG
/// keys within one deployment.
pub fn hash_decryption_domain(
    chain_id: u64,
    e3_id: U256,
    context: DecryptionDomainContext,
    ciphertext_output_hash: B256,
) -> B256 {
    keccak256(
        (
            U256::from(chain_id),
            context.interfold_address,
            e3_id,
            context.committee_hash,
            ciphertext_output_hash,
            context.committee_public_key,
        )
            .abi_encode(),
    )
}

/// Split a decryption-domain hash into two 128-bit Noir field elements.
pub fn split_decryption_domain(hash: B256) -> DecryptionDomainLimbs {
    DecryptionDomainLimbs {
        hi: u128::from_be_bytes(hash[..16].try_into().expect("16-byte high limb")),
        lo: u128::from_be_bytes(hash[16..].try_into().expect("16-byte low limb")),
    }
}

/// Hash and split the E3 decryption domain in one step.
pub fn decryption_domain_limbs(
    chain_id: u64,
    e3_id: U256,
    context: DecryptionDomainContext,
    ciphertext_output_hash: B256,
) -> DecryptionDomainLimbs {
    split_decryption_domain(hash_decryption_domain(
        chain_id,
        e3_id,
        context,
        ciphertext_output_hash,
    ))
}

fn field_hex_from_b256(value: B256) -> String {
    format!("0x{}", hex::encode(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    #[test]
    fn committee_hash_matches_cross_language_vector() {
        let nodes = vec![
            address!("0x0000000000000000000000001234567890abcdef"),
            address!("0x1111111111111111111111111234567890abcdef"),
            address!("0xabcdefabcdefabcdefabcdef0123456789abcdef"),
        ];
        let expected = "0x47416ae429c0010f46c2f61a7fff4ed80384e64a6b1709b84416f27790ec5f20"
            .parse::<B256>()
            .expect("valid hash");

        assert_eq!(hash_committee_addresses(&nodes), expected);
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

    #[test]
    fn decryption_domain_matches_solidity_abi_layout() {
        let context = DecryptionDomainContext {
            interfold_address: address!("0x1111111111111111111111111111111111111111"),
            committee_hash: B256::repeat_byte(0x22),
            committee_public_key: B256::repeat_byte(0x44),
        };
        let ciphertext_hash = B256::repeat_byte(0x33);
        let chain_id = 31_337u64;
        let e3_id = U256::from(7);

        let mut encoded = [0u8; 32 * 6];
        U256::from(chain_id)
            .to_be_bytes_vec()
            .iter()
            .enumerate()
            .for_each(|(index, byte)| encoded[index] = *byte);
        encoded[32 + 12..64].copy_from_slice(context.interfold_address.as_slice());
        e3_id
            .to_be_bytes_vec()
            .iter()
            .enumerate()
            .for_each(|(index, byte)| encoded[64 + index] = *byte);
        encoded[96..128].copy_from_slice(context.committee_hash.as_slice());
        encoded[128..160].copy_from_slice(ciphertext_hash.as_slice());
        encoded[160..192].copy_from_slice(context.committee_public_key.as_slice());

        let expected = keccak256(encoded);
        assert_eq!(
            hash_decryption_domain(chain_id, e3_id, context, ciphertext_hash),
            expected
        );

        let limbs = split_decryption_domain(expected);
        assert_eq!(
            limbs.hi,
            u128::from_be_bytes(expected[..16].try_into().unwrap())
        );
        assert_eq!(
            limbs.lo,
            u128::from_be_bytes(expected[16..].try_into().unwrap())
        );
    }
}
