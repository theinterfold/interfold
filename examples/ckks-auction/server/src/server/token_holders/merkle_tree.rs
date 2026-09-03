// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::server::models::{BalanceProofResponse, TokenHolder};
use e3_zk_helpers::threshold::ckks_app_validity::{balance_leaf, BalanceTree};
use eyre::{eyre, Result};
use num_bigint::BigUint;

/// Parses a snapshot entry into the `(address, balance)` the tree hashes.
fn parse_holder(holder: &TokenHolder) -> Result<(BigUint, u64)> {
    let address_hex = holder.address.trim_start_matches("0x");
    if address_hex.len() != 40 {
        return Err(eyre!("Invalid address format: {}", holder.address));
    }
    let address = BigUint::parse_bytes(address_hex.as_bytes(), 16)
        .ok_or_else(|| eyre!("Invalid address format: {}", holder.address))?;
    let balance: u64 = holder
        .balance
        .trim()
        .parse()
        .map_err(|e| eyre!("Invalid balance format '{}': {e}", holder.balance))?;
    Ok((address, balance))
}

/// Poseidon leaf hashes (`poseidon([address, balance])`), hex, in snapshot order.
pub fn compute_token_holder_hashes(token_holders: &[TokenHolder]) -> Result<Vec<String>> {
    token_holders
        .iter()
        .map(|h| {
            let (address, balance) = parse_holder(h)?;
            Ok(format!("{:064x}", balance_leaf(&address, balance)))
        })
        .collect()
}

/// A built snapshot tree plus the parsed leaves it was built from.
pub struct BalanceSnapshotTree {
    tree: BalanceTree,
    leaves: Vec<(BigUint, u64)>,
    holders: Vec<TokenHolder>,
}

impl BalanceSnapshotTree {
    /// `0x`-prefixed 32-byte root, as `setBalanceRoot` takes it.
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
    pub fn proof_for(&self, address: &str) -> Option<BalanceProofResponse> {
        let wanted = address.trim_start_matches("0x").to_lowercase();
        let index = self
            .holders
            .iter()
            .position(|h| h.address.trim_start_matches("0x").to_lowercase() == wanted)?;
        let (addr, balance) = &self.leaves[index];
        let proof = self.tree.proof(index, addr, *balance);
        Some(BalanceProofResponse {
            address: self.holders[index].address.clone(),
            balance: balance.to_string(),
            merkle_root: self.root_hex(),
            depth: proof.depth,
            indices: proof.indices,
            siblings: proof.siblings.iter().map(|s| s.to_string()).collect(),
        })
    }
}

/// Builds the round's balance tree.
pub fn build_tree(token_holders: &[TokenHolder]) -> Result<BalanceSnapshotTree> {
    if token_holders.is_empty() {
        return Err(eyre!("balance snapshot needs at least one holder"));
    }
    let leaves = token_holders
        .iter()
        .map(parse_holder)
        .collect::<Result<Vec<_>>>()?;
    let tree = BalanceTree::new(&leaves).map_err(|e| eyre!("{e}"))?;
    Ok(BalanceSnapshotTree {
        tree,
        leaves,
        holders: token_holders.to_vec(),
    })
}

/// The default dev snapshot: anvil accounts 6–9 + 0 (the bidder wallets the client offers and
/// `scripts/e2e.mjs` uses; 1–5 are the ciphernodes), balances 100 / 500 / 1000 / 1000 / 1000
/// under bid bound 1000.
pub fn get_mock_token_holders() -> Vec<TokenHolder> {
    [
        ("0x976EA74026E726554dB657fA54763abd0C3a0aa9", "100"),
        ("0x14dC79964da2C08b23698B3D3cc7Ca32193d9955", "500"),
        ("0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f", "1000"),
        ("0xa0Ee7A142d267C1f36714E4a8F75612F20a79720", "1000"),
        ("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "1000"),
    ]
    .into_iter()
    .map(|(a, b)| TokenHolder {
        address: a.to_string(),
        balance: b.to_string(),
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned against `packages/interfold-contracts/test/fixtures/ckks_auction_ps2` (the root the
    /// on-chain gate accepted a real proof under) and the sdk's `balanceTree.test.ts`.
    #[test]
    fn fixture_root_matches_circuit_and_client() {
        let holders = vec![
            TokenHolder {
                address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
                balance: "800".into(),
            },
            TokenHolder {
                address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".into(),
                balance: "300".into(),
            },
        ];
        let tree = build_tree(&holders).unwrap();
        assert_eq!(
            tree.root_hex(),
            "0x2ae63b169ba05aec6ff47eddae2294da69ee64ed900fd79c4116178450b4db47"
        );
        let proof = tree
            .proof_for("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")
            .unwrap();
        assert_eq!(proof.depth, 1);
        assert_eq!(proof.balance, "800");
        assert_eq!(
            proof.siblings[0],
            "18385459649577497665220684845508695793320800046942131834489884290641637195370"
        );
        assert!(tree
            .proof_for("0x0000000000000000000000000000000000000001")
            .is_none());
    }

    #[test]
    fn rejects_bad_input() {
        assert!(build_tree(&[]).is_err());
        assert!(compute_token_holder_hashes(&[TokenHolder {
            address: "nope".into(),
            balance: "1".into()
        }])
        .is_err());
        assert!(compute_token_holder_hashes(&[TokenHolder {
            address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
            balance: "x".into()
        }])
        .is_err());
    }
}
