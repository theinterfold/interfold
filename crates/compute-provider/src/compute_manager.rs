// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::ciphertext_output::ComputeProvider;
use crate::compute_input::{ComputeInput, FHEInputs};
use crate::merkle_tree_builder::MerkleTreeBuilder;
use crate::FHEProcessor;
use rayon::prelude::*;
use sha3::{Digest, Keccak256};
use std::sync::Arc;

pub struct ComputeManager<P>
where
    P: ComputeProvider + Send + Sync,
{
    input: ComputeInput,
    provider: P,
    processor: FHEProcessor,
    use_parallel: bool,
    batch_size: Option<usize>,
}

impl<P> ComputeManager<P>
where
    P: ComputeProvider + Send + Sync,
{
    pub fn new(
        provider: P,
        fhe_inputs: FHEInputs,
        fhe_processor: FHEProcessor,
        use_parallel: bool,
        batch_size: Option<usize>,
    ) -> Self {
        Self {
            provider,
            input: ComputeInput {
                fhe_inputs,
                ciphertext_hash: Vec::new(),
                leaf_hashes: Vec::new(),
            },
            processor: fhe_processor,
            use_parallel,
            batch_size,
        }
    }

    pub fn start(&mut self) -> (P::Output, Vec<u8>) {
        if self.use_parallel {
            self.start_parallel()
        } else {
            self.start_sequential()
        }
    }

    fn start_sequential(&mut self) -> (P::Output, Vec<u8>) {
        let num_leaves = self.input.fhe_inputs.ciphertexts.len();
        let mut tree_builder = MerkleTreeBuilder::new(num_leaves);

        tree_builder.compute_leaf_hashes(
            &self.input.fhe_inputs.ciphertexts,
            &self.input.fhe_inputs.params,
        );
        self.input.leaf_hashes = tree_builder.leaf_hashes.clone();

        // Compute the ciphertext
        let ciphertext = (self.processor)(&self.input.fhe_inputs);

        // Compute the hash of the ciphertext
        self.input.ciphertext_hash = Keccak256::digest(&ciphertext).to_vec();

        (self.provider.prove(&self.input), ciphertext)
    }

    fn start_parallel(&self) -> (P::Output, Vec<u8>) {
        let batch_size = self.batch_size.unwrap_or(2);

        let ciphertexts = Arc::new(self.input.fhe_inputs.ciphertexts.clone());
        let params = Arc::new(self.input.fhe_inputs.params.clone());

        let chunks: Vec<Vec<(Vec<u8>, u64)>> = ciphertexts
            .chunks(batch_size)
            .map(|chunk| chunk.to_vec())
            .collect();

        let tally_results: Vec<(P::Output, Vec<u8>, String)> = chunks
            .into_par_iter()
            .map(|chunk| {
                let mut tree_builder = MerkleTreeBuilder::new(chunk.len());

                tree_builder.compute_leaf_hashes(&chunk, params.as_slice());
                let merkle_root = tree_builder.build_tree().root().unwrap();

                let fhe_inputs = FHEInputs {
                    ciphertexts: chunk.clone(),
                    params: params.to_vec(),
                };

                let ciphertext = (self.processor)(&fhe_inputs);
                let ciphertext_hash = Keccak256::digest(&ciphertext).to_vec();

                let input = ComputeInput {
                    fhe_inputs,
                    ciphertext_hash,
                    leaf_hashes: tree_builder.leaf_hashes.clone(),
                };

                (self.provider.prove(&input), ciphertext, merkle_root)
            })
            .collect();

        // The leaf hashes are the hashes of the merkle roots of the parallel trees
        let leaf_hashes: Vec<String> = tally_results
            .iter()
            .map(|result| result.2.clone())
            .collect();

        let fhe_inputs = FHEInputs {
            ciphertexts: tally_results
                .iter()
                .map(|result| (result.1.clone(), 0u64)) // The index is not used for the final computation in the parallel case
                .collect(),
            params: params.to_vec(),
        };

        let ciphertext = (self.processor)(&fhe_inputs);
        let ciphertext_hash = Keccak256::digest(&ciphertext).to_vec();

        let final_input = ComputeInput {
            fhe_inputs,
            ciphertext_hash,
            leaf_hashes: leaf_hashes.clone(),
        };

        (self.provider.prove(&final_input), ciphertext)
    }
}
