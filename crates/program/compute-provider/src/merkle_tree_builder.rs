// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::compute_input::ComputeError;
use ark_bn254::Fr;
use ark_ff::{BigInt, BigInteger};
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;
use num_traits::Num;
use std::str::FromStr;
use zk_kit_imt::imt::IMT;

/// How the per-input ciphertext commitments are computed.
///
/// This chooses the schedule of one pure function over independent inputs. It does not change
/// which inputs are consumed, the leaf order, or the root: [`Batching::Parallel`] and
/// [`Batching::Sequential`] produce identical output for identical input, and the
/// `batching_does_not_change_the_root` test holds them to it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Batching {
    /// One input at a time, in order. What the zkVM guest uses.
    #[default]
    Sequential,
    /// Chunks of `batch_size` inputs across a thread pool.
    ///
    /// For hosts with cores to spare. Needs the `parallel` feature; without it this falls back to
    /// [`Batching::Sequential`] rather than failing, because the result is the same either way.
    Parallel { batch_size: usize },
}

pub struct MerkleTreeBuilder {
    pub leaf_hashes: Vec<String>,
    pub arity: usize,
    pub zero_value: String,
    pub depth: usize,
}

impl MerkleTreeBuilder {
    pub fn new(num_leaves: usize) -> Self {
        Self {
            leaf_hashes: Vec::new(),
            arity: 2,
            zero_value: "0".to_string(),
            depth: ((num_leaves as f64).log2().ceil() as usize).max(1),
        }
    }

    /// Sets the leaves directly, for tests that need a known tree.
    ///
    /// Never use this to build a tree the journal publishes. A Secure Process must derive its
    /// leaves from the ciphertexts it consumed, as [`crate::SecureProcess`] does. Leaves that arrive
    /// as a separate value can disagree with those ciphertexts.
    #[cfg(test)]
    pub fn with_leaf_hashes(mut self, leaf_hashes: Vec<String>) -> Self {
        self.leaf_hashes = leaf_hashes;
        self
    }

    fn poseidon_hash(nodes: Vec<String>) -> String {
        let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
        let mut field_elements = Vec::new();

        for node in nodes {
            let sanitized_node = node.trim_start_matches("0x");
            let numeric_str = BigUint::from_str_radix(sanitized_node, 16)
                .unwrap()
                .to_string();
            let field_repr = Fr::from_str(&numeric_str).unwrap();
            field_elements.push(field_repr);
        }

        let result_hash: BigInt<4> = poseidon.hash(&field_elements).unwrap().into();
        hex::encode(result_hash.to_bytes_be())
    }

    pub fn build_tree(&self) -> Result<IMT, ComputeError> {
        let mut tree = IMT::new(
            Self::poseidon_hash,
            self.depth,
            self.zero_value.clone(),
            self.arity,
            vec![],
        )
        .map_err(|e| ComputeError::MerkleTree(e.to_string()))?;

        for leaf in &self.leaf_hashes {
            tree.insert(leaf.clone())
                .map_err(|e| ComputeError::MerkleTree(e.to_string()))?;
        }

        Ok(tree)
    }
}

#[cfg(test)]
mod tests {
    use super::MerkleTreeBuilder;

    #[test]
    fn test_depth_computation() {
        assert_eq!(MerkleTreeBuilder::new(0).depth, 1);
        assert_eq!(MerkleTreeBuilder::new(1).depth, 1);
        assert_eq!(MerkleTreeBuilder::new(2).depth, 1);
        assert_eq!(MerkleTreeBuilder::new(3).depth, 2);
        assert_eq!(MerkleTreeBuilder::new(4).depth, 2);
        assert_eq!(MerkleTreeBuilder::new(5).depth, 3);
        assert_eq!(MerkleTreeBuilder::new(8).depth, 3);
        assert_eq!(MerkleTreeBuilder::new(9).depth, 4);
        assert_eq!(MerkleTreeBuilder::new(16).depth, 4);
        assert_eq!(MerkleTreeBuilder::new(17).depth, 5);
    }

    #[test]
    fn one_zero_leaf_matches_solidity_lazy_imt() {
        let root = MerkleTreeBuilder::new(1)
            .with_leaf_hashes(vec!["0".to_string()])
            .build_tree()
            .unwrap()
            .root()
            .unwrap();

        assert_eq!(
            root,
            "2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864"
        );
    }
}
