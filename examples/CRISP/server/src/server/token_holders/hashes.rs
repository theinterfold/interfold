// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use ark_bn254::Fr;
use ark_ff::{BigInt, BigInteger, PrimeField};
use eyre::Result;
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;
use std::str::FromStr;

use crate::server::models::TokenHolder;

/// Hex-encoded Poseidon(address, balance) leaf for each holder.
///
/// The address must fit the field (a 20-byte address always does). The balance is a decimal
/// string of any size, reduced modulo the field order.
pub fn compute_token_holder_hashes(token_holders: &[TokenHolder]) -> Result<Vec<String>> {
    token_holders
        .iter()
        .map(|holder| {
            let address_hex = holder.address.trim_start_matches("0x");
            let address_bigint = BigUint::parse_bytes(address_hex.as_bytes(), 16)
                .ok_or_else(|| eyre::eyre!("Invalid address format"))?;
            let address_fr = Fr::from_str(&address_bigint.to_string())
                .map_err(|_| eyre::eyre!("Failed to convert address to field element"))?;

            let balance = BigUint::from_str(&holder.balance)
                .map_err(|e| eyre::eyre!("Invalid balance format: {}", e))?;
            let balance_fr = Fr::from_be_bytes_mod_order(&balance.to_bytes_be());

            let mut poseidon = Poseidon::<Fr>::new_circom(2)?;
            let hash: BigInt<4> = poseidon.hash(&[address_fr, balance_fr])?.into();
            Ok(hex::encode(hash.to_bytes_be()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDRESS: &str = "0x1234567890123456789012345678901234567890";
    const BN254_MODULUS: &str =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617";

    fn holder(address: &str, balance: &str) -> TokenHolder {
        TokenHolder {
            address: address.to_string(),
            balance: balance.to_string(),
        }
    }

    fn hash_of(address: &str, balance: &str) -> String {
        compute_token_holder_hashes(&[holder(address, balance)])
            .expect("hash")
            .remove(0)
    }

    #[test]
    fn leaves_match_the_pinned_vectors() {
        let hashes = compute_token_holder_hashes(&[
            holder(ADDRESS, "1000"),
            holder("0x2345678901234567890123456789012345678901", "500"),
        ])
        .expect("Should compute hashes successfully");

        assert_eq!(
            hashes,
            [
                "0cb36cd64fcc99d7f742ae77954eda75236e182d7c10de1660f62f56c582b518",
                "0793d785764e7afa3343e9ef2f1b1ad6d367a93622ddaaec328686a402a1d085",
            ]
        );
        // The `0x` prefix is optional.
        assert_eq!(hash_of(ADDRESS.trim_start_matches("0x"), "1000"), hashes[0]);
    }

    #[test]
    fn balances_are_reduced_modulo_the_field_order() {
        let one = hash_of(ADDRESS, "1");
        let modulus = BigUint::from_str(BN254_MODULUS).unwrap();

        assert_eq!(hash_of(ADDRESS, &(&modulus + 1u8).to_string()), one);
        // Wider than 32 bytes: the value still reduces instead of overflowing a fixed buffer.
        assert_eq!(
            hash_of(ADDRESS, &((&modulus << 256usize) + 1u8).to_string()),
            one
        );
    }

    #[test]
    fn malformed_holders_are_errors() {
        for (address, balance, message) in [
            ("invalid_address", "1000", "Invalid address format"),
            (ADDRESS, "not_a_number", "Invalid balance format"),
        ] {
            let error = compute_token_holder_hashes(&[holder(address, balance)]).unwrap_err();
            assert!(error.to_string().contains(message), "{error}");
        }
    }
}
