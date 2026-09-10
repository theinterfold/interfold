// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::compute_input::{ComputeError, FHEInputs, PublishedData};
use crate::policy::{InputPolicy, PublishedInput};
use ark_bn254::Fr;
use ark_ff::{BigInt, BigInteger};
use e3_bfv_client::client::compute_ct_commitment_with_params;
use fhe::bfv::BfvParameters;
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;
use num_traits::Num;
use std::str::FromStr;
use std::sync::Arc;
use zk_kit_imt::imt::IMT;

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
    /// leaves from the ciphertexts it consumed, with [`Self::compute_leaf_hashes`]. Leaves that
    /// arrive as a separate value can disagree with those ciphertexts.
    #[cfg(test)]
    pub fn with_leaf_hashes(mut self, leaf_hashes: Vec<String>) -> Self {
        self.leaf_hashes = leaf_hashes;
        self
    }

    /// Derives one leaf per published input and returns the ciphertexts the policy selected.
    ///
    /// Two guarantees hold whatever the policy does, because they are applied here rather than
    /// delegated:
    ///
    /// - **every input contributes a leaf**, so the root covers the whole published set and a
    ///   policy cannot make the result unpublishable by omitting one;
    /// - **leaves are derived from the ciphertexts given**, never accepted alongside them.
    pub fn compute_leaf_hashes(
        &mut self,
        inputs: &FHEInputs,
        published: &[PublishedData],
        params: &Arc<BfvParameters>,
        policy: InputPolicy,
    ) -> Result<Vec<(Vec<u8>, u64)>, ComputeError> {
        let empty = PublishedData::default();

        let entries: Vec<PublishedInput> = inputs
            .ciphertexts
            .iter()
            .enumerate()
            .map(|(index, (ciphertext, _))| {
                let entry = published.get(index).unwrap_or(&empty);
                PublishedInput {
                    index,
                    ciphertext,
                    commitment: entry.commitment.as_ref(),
                    metadata: &entry.metadata,
                    // Recomputed here rather than by the policy: it is the one value that ties the
                    // published bytes back to what the E3 program proved, and it needs the BFV
                    // parameters. A ciphertext that does not deserialize yields `None`, which is an
                    // unusable input rather than a failure — the bytes are untrusted.
                    recomputed: compute_ct_commitment_with_params(ciphertext, params).ok(),
                }
            })
            .collect();

        for entry in &entries {
            self.leaf_hashes.push((policy.leaf)(entry)?);
        }

        let mut selected = (policy.select)(&entries);
        selected.sort_unstable();
        selected.dedup();

        selected
            .into_iter()
            .map(|index| {
                inputs.ciphertexts.get(index).cloned().ok_or_else(|| {
                    ComputeError::MerkleTree(format!("selected index {index} is out of range"))
                })
            })
            .collect()
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
