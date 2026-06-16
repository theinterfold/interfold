// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use ark_bn254::Fr;
use ark_ff::{BigInt, BigInteger};
use eyre::Result;
use lean_imt::LeanIMT;
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;
use std::str::FromStr;

/// Builds a LeanIMT from a vector of Poseidon hashes.
///
/// # Arguments
/// * `poseidon_hashes` - A vector of hex-encoded Poseidon hashes to use as leaves.
///
/// # Returns
/// A Result containing either a LeanIMT instance with the provided hashes as leaves,
/// or an error if construction fails.
pub fn build_tree(poseidon_hashes: Vec<String>) -> Result<LeanIMT> {
    // Pre‑validate leaves (must be 32‑byte hex).
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
    }

    let mut tree = LeanIMT::new(poseidon_hash);

    // Only insert if we have hashes to avoid empty tree issues.
    if !poseidon_hashes.is_empty() {
        tree.insert_many(poseidon_hashes)
            .map_err(|e| eyre::eyre!("Failed to insert hashes into tree: {}", e))?;
    }

    Ok(tree)
}

/// Poseidon hash function for LeanIMT internal nodes.
///
/// # Arguments
/// * `nodes` - A vector of hex-encoded hash strings to hash together.
///
/// # Returns
/// A hex-encoded hash string representing the combined hash.
fn poseidon_hash(nodes: Vec<String>) -> String {
    let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
    let mut field_elements = Vec::new();

    for node in nodes {
        let bigint = BigUint::parse_bytes(node.as_bytes(), 16).unwrap();
        let field_repr = Fr::from_str(&bigint.to_string()).unwrap();

        field_elements.push(field_repr);
    }

    let result_hash: BigInt<4> = poseidon.hash(&field_elements).unwrap().into();

    hex::encode(result_hash.to_bytes_be())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_lean_imt() {
        let hashes = vec![
            "1234567890123456789012345678901234567890123456789012345678901234".to_string(),
            "2345678901234567890123456789012345678901234567890123456789012345".to_string(),
        ];

        let tree = build_tree(hashes).expect("Failed to build LeanIMT");
        let root = tree.root().expect("Failed to get tree root");

        assert!(!root.is_empty());
        assert!(root.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_build_lean_imt_empty() {
        let hashes = vec![];
        let _tree = build_tree(hashes).expect("Failed to build empty LeanIMT");

        // For empty tree, we expect it to be valid but may not have a root.
        // Building with no leaves must not panic.
    }
}
