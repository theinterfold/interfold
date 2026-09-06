// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Issuer snapshot → Poseidon Merkle tree: the round opener attests every applicant's feature
//! vector by publishing ONE root on-chain; each applicant proves in-circuit that
//! `poseidon([address, x_0, .., x_7])` is a leaf and that the encrypted coefficients are exactly
//! those features (masked). The tree is `e3_zk_helpers::threshold::ckks_credit_validity::FeatureTree`
//! — the implementation the circuit's witness builder and the on-chain fixtures were produced with.

use crate::server::models::{Applicant, FeatureProofResponse};
use ckks_credit_program::FEATURES;
use e3_zk_helpers::threshold::ckks_credit_validity::{feature_leaf, FeatureTree};
use eyre::{eyre, Result};
use num_bigint::BigUint;

fn parse_applicant(a: &Applicant, cap: u64) -> Result<(BigUint, [u32; FEATURES])> {
    let address_hex = a.address.trim_start_matches("0x");
    if address_hex.len() != 40 {
        return Err(eyre!("Invalid address format: {}", a.address));
    }
    let address = BigUint::parse_bytes(address_hex.as_bytes(), 16)
        .ok_or_else(|| eyre!("Invalid address format: {}", a.address))?;
    for (j, x) in a.features.iter().enumerate() {
        if u64::from(*x) > cap {
            return Err(eyre!("{}: feature {j} = {x} exceeds cap {cap}", a.address));
        }
    }
    Ok((address, a.features))
}

/// Poseidon leaf hashes, hex, in snapshot order.
pub fn compute_leaf_hashes(snapshot: &[Applicant], cap: u64) -> Result<Vec<String>> {
    snapshot
        .iter()
        .map(|a| {
            let (address, features) = parse_applicant(a, cap)?;
            Ok(format!("{:064x}", feature_leaf(&address, &features)))
        })
        .collect()
}

/// A built snapshot tree plus the parsed leaves it was built from.
pub struct IssuerTree {
    tree: FeatureTree,
    leaves: Vec<(BigUint, [u32; FEATURES])>,
    applicants: Vec<Applicant>,
    cap: u64,
}

impl IssuerTree {
    /// `0x`-prefixed 32-byte root, as `setIssuerRoot` takes it.
    pub fn root_hex(&self) -> String {
        format!("0x{:064x}", self.tree.root())
    }

    pub fn root_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        let be = self.tree.root().to_bytes_be();
        out[32 - be.len()..].copy_from_slice(&be);
        out
    }

    /// The opening for `address`, or `None` when it is not in the snapshot.
    pub fn proof_for(&self, address: &str) -> Option<FeatureProofResponse> {
        let wanted = address.trim_start_matches("0x").to_lowercase();
        let index = self
            .applicants
            .iter()
            .position(|a| a.address.trim_start_matches("0x").to_lowercase() == wanted)?;
        let (addr, features) = &self.leaves[index];
        let proof = self.tree.proof(index, addr, *features);
        Some(FeatureProofResponse {
            address: self.applicants[index].address.clone(),
            index: index as u32,
            features: *features,
            cap: self.cap,
            merkle_root: self.root_hex(),
            depth: proof.depth,
            indices: proof.indices,
            siblings: proof.siblings.iter().map(|s| s.to_string()).collect(),
        })
    }
}

/// Builds the round's issuer tree (every feature must be `<= cap`).
pub fn build_tree(snapshot: &[Applicant], cap: u64) -> Result<IssuerTree> {
    if snapshot.is_empty() {
        return Err(eyre!("issuer snapshot needs at least one applicant"));
    }
    let leaves = snapshot
        .iter()
        .map(|a| parse_applicant(a, cap))
        .collect::<Result<Vec<_>>>()?;
    let tree = FeatureTree::new(&leaves).map_err(|e| eyre!("{e}"))?;
    Ok(IssuerTree {
        tree,
        leaves,
        applicants: snapshot.to_vec(),
        cap,
    })
}

/// The default dev snapshot: anvil accounts 6–9 + 0 (the applicant wallets the client offers and
/// `scripts/e2e.mjs` uses; 1–5 are the ciphernodes), features over cap 1000.
pub fn get_mock_applicants() -> Vec<Applicant> {
    [
        (
            "0x976EA74026E726554dB657fA54763abd0C3a0aa9",
            [520, 130, 350, 999, 0, 1, 777, 42],
        ),
        (
            "0x14dC79964da2C08b23698B3D3cc7Ca32193d9955",
            [900, 850, 700, 120, 300, 640, 210, 980],
        ),
        (
            "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f",
            [100, 200, 300, 400, 500, 600, 700, 800],
        ),
        (
            "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720",
            [1000, 1000, 1000, 1000, 0, 0, 0, 0],
        ),
        (
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            [250, 750, 125, 875, 333, 666, 999, 1],
        ),
    ]
    .into_iter()
    .map(|(a, f)| Applicant {
        address: a.to_string(),
        features: f,
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned against `packages/interfold-contracts/test/fixtures/ckks_credit_ps4` (Alice + Bob
    /// two-leaf tree the on-chain gate accepted a real proof under).
    #[test]
    fn fixture_root_matches_circuit_fixture() {
        let snapshot = vec![
            Applicant {
                address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
                features: [520, 130, 350, 999, 0, 1, 777, 42],
            },
            Applicant {
                address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".into(),
                features: [1, 2, 3, 4, 5, 6, 7, 8],
            },
        ];
        let tree = build_tree(&snapshot, 1000).unwrap();
        let fixture: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../packages/interfold-contracts/test/fixtures/ckks_credit_ps4/verified_input.json"
            ))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            tree.root_hex(),
            fixture["extra"]["merkleRoot"].as_str().unwrap()
        );
        let proof = tree
            .proof_for("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")
            .unwrap();
        assert_eq!(proof.depth, 1);
        assert_eq!(proof.features[3], 999);
        assert!(tree
            .proof_for("0x0000000000000000000000000000000000000001")
            .is_none());
    }

    #[test]
    fn rejects_bad_input() {
        assert!(build_tree(&[], 1000).is_err());
        assert!(build_tree(
            &[Applicant {
                address: "nope".into(),
                features: [0; 8]
            }],
            1000
        )
        .is_err());
        let mut over = get_mock_applicants();
        over[0].features[3] = 1001;
        assert!(build_tree(&over, 1000).is_err());
        assert!(build_tree(&get_mock_applicants(), 1000).is_ok());
    }
}
