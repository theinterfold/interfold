// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use ark_bn254::Fr;
use ark_ff::{BigInt, BigInteger, PrimeField};
use eyre::Result;
use lean_imt::LeanIMT;
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;

/// Builds a LeanIMT over hex-encoded Poseidon hashes.
///
/// Every leaf must be 32 bytes and below the BN254 modulus: a larger value would be reduced and
/// collide with a smaller one, and Poseidon outputs are always inside the field.
pub fn build_tree(poseidon_hashes: Vec<String>) -> Result<LeanIMT> {
    for (i, h) in poseidon_hashes.iter().enumerate() {
        let bytes =
            hex::decode(h).map_err(|_| eyre::eyre!("Invalid hex at index {}: '{}'", i, h))?;
        if bytes.len() != 32 {
            return Err(eyre::eyre!(
                "Invalid leaf length at index {}: expected 32 bytes, got {}",
                i,
                bytes.len()
            ));
        }
        if field_element(h).is_none() {
            return Err(eyre::eyre!(
                "Leaf at index {} is not below the BN254 modulus: '{}'",
                i,
                h
            ));
        }
    }

    let mut tree = LeanIMT::new(poseidon_hash);

    // An empty batch would leave the tree without a root to report.
    if !poseidon_hashes.is_empty() {
        tree.insert_many(poseidon_hashes)
            .map_err(|e| eyre::eyre!("Failed to insert hashes into tree: {}", e))?;
    }

    Ok(tree)
}

/// Reads a hex string as a canonical field element; `None` at or above the modulus, which
/// `Fr` would otherwise silently reduce.
fn field_element(hex: &str) -> Option<Fr> {
    let value = BigUint::parse_bytes(hex.as_bytes(), 16)?;
    (value < BigUint::from_bytes_be(&Fr::MODULUS.to_bytes_be()))
        .then(|| Fr::from_be_bytes_mod_order(&value.to_bytes_be()))
}

/// LeanIMT node hasher: Poseidon over two hex-encoded field elements.
fn poseidon_hash(nodes: Vec<String>) -> String {
    const VALIDATED: &str =
        "`build_tree` validated the leaves and Poseidon outputs are in the field";
    let inputs: Vec<Fr> = nodes
        .iter()
        .map(|node| field_element(node).expect(VALIDATED))
        .collect();
    let mut poseidon = Poseidon::<Fr>::new_circom(2).expect(VALIDATED);
    let result: BigInt<4> = poseidon.hash(&inputs).expect(VALIDATED).into();

    hex::encode(result.to_bytes_be())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_root_of_known_leaves_is_pinned() {
        let tree = build_tree(vec![
            "1234567890123456789012345678901234567890123456789012345678901234".to_string(),
            "2345678901234567890123456789012345678901234567890123456789012345".to_string(),
        ])
        .expect("Failed to build LeanIMT");

        assert_eq!(
            tree.root().expect("Failed to get tree root"),
            "2fe696cef38a7749071ccd4ae33faf09ebdc9df31eca68dd113ac674b8dd6a70"
        );
    }

    #[test]
    fn a_leaf_at_or_above_the_field_modulus_is_an_error() {
        // 0xff..ff is above the BN254 modulus.
        let result = build_tree(vec!["01".repeat(32), "ff".repeat(32)]);
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("not below the BN254 modulus"));
    }
}
