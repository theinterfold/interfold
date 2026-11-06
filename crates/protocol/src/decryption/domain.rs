// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::E3Id;
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::SolValue;

/// Keccak-256 over the committee's raw 20-byte addresses in order, as `CommitteeHashLib` hashes
/// the registry's committee.
pub fn committee_hash(committee: &[Address]) -> B256 {
    keccak256(
        committee
            .iter()
            .flat_map(|member| member.into_array())
            .collect::<Vec<u8>>(),
    )
}

/// The decryption domain that every C6 proof and the final decryption proof bind, as
/// `InterfoldLifecycle.verifyPlaintext` recomputes it: `keccak256(abi.encode(chainId,
/// interfold, e3Id, committeeHash, ciphertextHash, committeePublicKey))`.
pub fn decryption_domain(
    e3: E3Id,
    interfold: Address,
    committee_hash: B256,
    ciphertext_hash: B256,
    key_commitment: B256,
) -> B256 {
    keccak256(
        (
            U256::from(e3.chain_id),
            interfold,
            e3.number,
            committee_hash,
            ciphertext_hash,
            key_commitment,
        )
            .abi_encode(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_committee_hash_matches_the_cross_language_vector() {
        let committee = [
            "0x0000000000000000000000001234567890abcdef",
            "0x1111111111111111111111111234567890abcdef",
            "0xabcdefabcdefabcdefabcdef0123456789abcdef",
        ]
        .map(|member| member.parse::<Address>().unwrap());
        let expected: B256 = "0x47416ae429c0010f46c2f61a7fff4ed80384e64a6b1709b84416f27790ec5f20"
            .parse()
            .unwrap();
        assert_eq!(committee_hash(&committee), expected);
    }

    #[test]
    fn the_decryption_domain_hashes_the_solidity_abi_layout() {
        let e3 = E3Id {
            chain_id: 31_337,
            number: U256::from(7),
        };
        let interfold = Address::repeat_byte(0x11);
        let mut encoded = [0u8; 32 * 6];
        encoded[24..32].copy_from_slice(&e3.chain_id.to_be_bytes());
        encoded[44..64].copy_from_slice(interfold.as_slice());
        encoded[95] = 7;
        encoded[96..128].copy_from_slice(&[0x22; 32]);
        encoded[128..160].copy_from_slice(&[0x33; 32]);
        encoded[160..192].copy_from_slice(&[0x44; 32]);
        let domain = decryption_domain(
            e3,
            interfold,
            B256::repeat_byte(0x22),
            B256::repeat_byte(0x33),
            B256::repeat_byte(0x44),
        );
        assert_eq!(domain, keccak256(encoded));
    }
}
