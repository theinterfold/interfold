// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::ciphertext_output::ComputeResult;
use crate::merkle_tree_builder::MerkleTreeBuilder;
use crate::policy::InputPolicy;
#[cfg(test)]
use e3_bfv_client::client::compute_ct_commitment;
use e3_bfv_client::client::compute_ct_commitment_with_params;
use e3_fhe_params::decode_bfv_params_arc;
use fhe::bfv::BfvParameters;
use sha3::{Digest, Keccak256};
use std::sync::Arc;

pub type FHEProcessor = for<'a> fn(&FHEProcessorInput<'a>) -> Vec<u8>;

/// Inputs passed to an E3 program's homomorphic processor.
///
/// The secure process builds BFV parameters once and shares them with the processor. Building the
/// secure parameter tables is expensive inside a zkVM, and decoding the same immutable bytes twice
/// adds no verification.
pub struct FHEProcessorInput<'a> {
    pub ciphertexts: &'a [(Vec<u8>, u64)],
    pub params: &'a Arc<BfvParameters>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FHEInputs {
    /// The serialized ciphertexts to compute over, each paired with its on-chain index.
    ///
    /// The index is not the authority on order — a leaf's position in the tree is its position in
    /// this vector. **A caller assembling this from chain events must sort by the index**, because
    /// event delivery is not ordered, and getting it wrong produces a root the E3 program rejects.
    pub ciphertexts: Vec<(Vec<u8>, u64)>,
    pub params: Vec<u8>,
}

/// What an E3 program published alongside a ciphertext, in the same order as `ciphertexts`.
///
/// Separate from `FHEInputs` because a Secure Process never computes over it: it decides leaves and
/// selection, which is the [`InputPolicy`]'s business, not the processor's.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct PublishedData {
    /// The commitment the E3 program stored for this input, when it stores one.
    pub commitment: Option<[u8; 32]>,
    /// Anything else the program published per input. Opaque here; CRISP carries its slot address.
    #[serde(default)]
    pub metadata: Vec<u8>,
}

/// The full input to the Secure Process.
///
/// This type holds only the values the Secure Process computes over. Every field the journal
/// publishes is derived from these values inside the compute environment. A prover cannot supply
/// the input Merkle root or the output hash as separate values, because a separate value can
/// disagree with the ciphertexts the Secure Process actually consumed.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ComputeInput {
    pub fhe_inputs: FHEInputs,
    /// One entry per ciphertext, in the same order. Empty when the E3 program publishes nothing
    /// beyond the ciphertexts, which is what [`InputPolicy::default`] expects.
    #[serde(default)]
    pub published: Vec<PublishedData>,
}

/// A failure inside the Secure Process.
///
/// These arise from malformed inputs, which a Secure Process cannot assume away: an E3 program
/// accepts inputs from untrusted parties, and a single unusable one reaches the compute environment
/// like any other. Returning the reason lets a compute provider report which input was bad rather
/// than aborting the process with a panic.
#[derive(Debug, thiserror::Error)]
pub enum ComputeError {
    #[error("failed to decode BFV parameters: {0}")]
    DecodeParams(String),

    #[error("failed to compute the commitment of ciphertext {index}: {reason}")]
    LeafCommitment { index: usize, reason: String },

    #[error("failed to compute the commitment of the output ciphertext: {0}")]
    OutputCommitment(String),

    #[error("failed to build the input Merkle tree: {0}")]
    MerkleTree(String),
}

impl ComputeInput {
    /// Runs the Secure Process under the E3 program's [`InputPolicy`].
    ///
    /// The policy decides the leaf layout and which inputs are computed over. What it cannot do is
    /// supply a root or drop an input from the tree — leaves are derived here, from the ciphertexts
    /// actually consumed, and every published input contributes one.
    pub fn process(
        &self,
        fhe_processor: FHEProcessor,
        policy: InputPolicy,
    ) -> Result<ComputeResult, ComputeError> {
        self.run(fhe_processor, policy).map(|(result, _)| result)
    }

    /// As [`Self::process`], and also returns the output ciphertext.
    ///
    /// A caller that publishes the ciphertext must take it from here rather than running the
    /// processor itself. The two are not interchangeable once a policy excludes anything: an E3
    /// program hashes the published bytes into the digest it rebuilds, so a ciphertext computed
    /// over a different input set makes the receipt unverifiable and the round unpublishable.
    pub fn run(
        &self,
        fhe_processor: FHEProcessor,
        policy: InputPolicy,
    ) -> Result<(ComputeResult, Vec<u8>), ComputeError> {
        let params = decode_bfv_params_arc(&self.fhe_inputs.params)
            .map_err(|e| ComputeError::DecodeParams(e.to_string()))?;

        if !self.published.is_empty() && self.published.len() != self.fhe_inputs.ciphertexts.len() {
            return Err(ComputeError::MerkleTree(format!(
                "{} ciphertexts but {} published entries",
                self.fhe_inputs.ciphertexts.len(),
                self.published.len()
            )));
        }

        let mut tree_builder = MerkleTreeBuilder::new(self.fhe_inputs.ciphertexts.len());
        let selected =
            tree_builder.compute_leaf_hashes(&self.fhe_inputs, &self.published, &params, policy)?;
        let merkle_root = tree_builder
            .build_tree()
            .map_err(|e| ComputeError::MerkleTree(e.to_string()))?
            .root()
            .ok_or_else(|| ComputeError::MerkleTree("the tree has no root".into()))?;

        // The processor sees only what the policy selected. Both the root above and this set are
        // functions of values the root binds, so any prover over the same published inputs reaches
        // the same result.
        let processed_ciphertext = (fhe_processor)(&FHEProcessorInput {
            ciphertexts: &selected,
            params: &params,
        });
        let processed_hash = Keccak256::digest(&processed_ciphertext).to_vec();
        let ciphertext_commitment =
            compute_ct_commitment_with_params(&processed_ciphertext, &params)
                .map_err(|e| ComputeError::OutputCommitment(e.to_string()))?
                .to_vec();
        let params_hash = Keccak256::digest(&self.fhe_inputs.params).to_vec();

        Ok((
            ComputeResult {
                ciphertext_hash: processed_hash,
                ciphertext_commitment,
                params_hash,
                merkle_root: hex::decode(merkle_root)
                    .map_err(|e| ComputeError::MerkleTree(e.to_string()))?,
            },
            processed_ciphertext,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{all_inputs, commitment_leaf, PublishedInput};
    use e3_fhe_params::{build_pair_for_preset, encode_bfv_params, BfvPreset};
    use fhe::bfv::{Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
    use fhe_traits::{FheEncoder, FheEncrypter, Serialize as FheSerialize};
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    fn sum_processor(inputs: &FHEProcessorInput<'_>) -> Vec<u8> {
        let mut sum = Ciphertext::zero(inputs.params);
        for (bytes, _) in inputs.ciphertexts {
            use fhe_traits::DeserializeParametrized;
            sum += &Ciphertext::from_bytes(bytes, inputs.params).unwrap();
        }
        sum.to_bytes()
    }

    fn encrypted_inputs(values: &[u64]) -> FHEInputs {
        let (params, _) = build_pair_for_preset(BfvPreset::InsecureThreshold512).unwrap();
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let secret_key = SecretKey::random(&params, &mut rng);
        let public_key = PublicKey::new(&secret_key, &mut rng);

        let ciphertexts = values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let plaintext =
                    Plaintext::try_encode(&[*value], Encoding::poly(), &params).unwrap();
                let ciphertext = public_key.try_encrypt(&plaintext, &mut rng).unwrap();
                (ciphertext.to_bytes(), index as u64)
            })
            .collect();

        FHEInputs {
            ciphertexts,
            params: encode_bfv_params(&params),
        }
    }

    fn process(inputs: FHEInputs, policy: InputPolicy) -> Result<ComputeResult, ComputeError> {
        ComputeInput {
            fhe_inputs: inputs,
            published: Vec::new(),
        }
        .process(sum_processor, policy)
    }

    /// The journal's input root must be a function of the ciphertexts consumed. Before this, the
    /// root arrived as a separate field, so a prover could publish a tally over one input set while
    /// proving the root of another.
    #[test]
    fn the_root_is_derived_from_the_processed_ciphertexts() {
        let inputs = encrypted_inputs(&[1, 1, 1]);
        let params = decode_bfv_params_arc(&inputs.params).unwrap();

        let result = process(inputs.clone(), InputPolicy::default()).unwrap();

        let mut builder = MerkleTreeBuilder::new(3);
        builder
            .compute_leaf_hashes(&inputs, &[], &params, InputPolicy::default())
            .unwrap();
        let expected = hex::decode(builder.build_tree().unwrap().root().unwrap()).unwrap();

        assert_eq!(result.merkle_root, expected);
    }

    /// Changing the consumed ciphertexts must change the published root, so an E3 program's
    /// comparison rejects a substituted set.
    #[test]
    fn substituted_ciphertexts_produce_a_different_root() {
        let honest = encrypted_inputs(&[1, 1, 1]);
        let mut forged = honest.clone();
        forged.ciphertexts[2] = encrypted_inputs(&[9]).ciphertexts[0].clone();

        assert_ne!(
            process(honest, InputPolicy::default()).unwrap().merkle_root,
            process(forged, InputPolicy::default()).unwrap().merkle_root
        );
    }

    /// The default policy is what every E3 program had before policies existed.
    #[test]
    fn the_default_policy_uses_the_ciphertext_commitment_and_keeps_every_input() {
        let inputs = encrypted_inputs(&[4, 5]);
        let params = decode_bfv_params_arc(&inputs.params).unwrap();

        let mut builder = MerkleTreeBuilder::new(2);
        let selected = builder
            .compute_leaf_hashes(&inputs, &[], &params, InputPolicy::default())
            .unwrap();

        assert_eq!(selected.len(), 2, "every input is computed over");
        let commitment = compute_ct_commitment(
            inputs.ciphertexts[0].0.clone(),
            params.degree(),
            params.plaintext(),
            params.moduli().to_vec(),
        )
        .unwrap();
        assert_eq!(builder.leaf_hashes[0], hex::encode(commitment));
    }

    /// A policy chooses what is computed over; it cannot shrink the tree. Dropping a leaf would
    /// change the root and make the result unpublishable, so the crate applies this rather than
    /// trusting each program to.
    #[test]
    fn a_policy_cannot_drop_an_input_from_the_tree() {
        fn select_nothing(_: &[PublishedInput]) -> Vec<usize> {
            Vec::new()
        }
        let inputs = encrypted_inputs(&[1, 2, 3]);
        let params = decode_bfv_params_arc(&inputs.params).unwrap();

        let mut builder = MerkleTreeBuilder::new(3);
        let selected = builder
            .compute_leaf_hashes(
                &inputs,
                &[],
                &params,
                InputPolicy {
                    leaf: commitment_leaf,
                    select: select_nothing,
                },
            )
            .unwrap();

        assert!(selected.is_empty(), "the policy selected nothing");
        assert_eq!(
            builder.leaf_hashes.len(),
            3,
            "every leaf is still in the tree"
        );
    }

    /// A policy returning an index that does not exist is a bug in the program, not a silent skip.
    #[test]
    fn an_out_of_range_selection_is_rejected() {
        fn select_beyond_the_end(_: &[PublishedInput]) -> Vec<usize> {
            vec![99]
        }
        let inputs = encrypted_inputs(&[1]);
        let params = decode_bfv_params_arc(&inputs.params).unwrap();

        let error = MerkleTreeBuilder::new(1)
            .compute_leaf_hashes(
                &inputs,
                &[],
                &params,
                InputPolicy {
                    leaf: commitment_leaf,
                    select: select_beyond_the_end,
                },
            )
            .unwrap_err();

        assert!(
            matches!(error, ComputeError::MerkleTree(_)),
            "got {error:?}"
        );
    }

    /// Published data of the wrong length would silently mis-pair inputs with their commitments.
    #[test]
    fn mismatched_published_data_is_rejected() {
        let error = ComputeInput {
            fhe_inputs: encrypted_inputs(&[1, 2]),
            published: vec![PublishedData::default()],
        }
        .process(sum_processor, InputPolicy::default())
        .unwrap_err();

        assert!(
            matches!(error, ComputeError::MerkleTree(_)),
            "got {error:?}"
        );
    }

    /// Under the default policy an undecodable ciphertext names the index that failed, rather than
    /// aborting the process.
    #[test]
    fn the_default_policy_reports_the_index_of_an_undecodable_input() {
        let mut inputs = encrypted_inputs(&[1, 1]);
        inputs.ciphertexts[1].0 = vec![0xff; 8];
        let params = decode_bfv_params_arc(&inputs.params).unwrap();

        let error = MerkleTreeBuilder::new(2)
            .compute_leaf_hashes(&inputs, &[], &params, InputPolicy::default())
            .unwrap_err();

        assert!(
            matches!(error, ComputeError::LeafCommitment { index: 1, .. }),
            "got {error:?}"
        );
    }

    /// `matches_commitment` is what a policy uses to spot a published ciphertext that disagrees
    /// with what the E3 program proved.
    #[test]
    fn matches_commitment_reports_the_three_cases() {
        let bytes = vec![1u8, 2, 3];
        let commitment = [7u8; 32];

        let agreeing = PublishedInput {
            index: 0,
            ciphertext: &bytes,
            commitment: Some(&commitment),
            metadata: &[],
            recomputed: Some(commitment),
        };
        let disagreeing = PublishedInput {
            recomputed: Some([8u8; 32]),
            ..agreeing
        };
        let undecodable = PublishedInput {
            recomputed: None,
            ..agreeing
        };
        let unpublished = PublishedInput {
            commitment: None,
            recomputed: None,
            ..agreeing
        };

        assert!(agreeing.matches_commitment());
        assert!(!disagreeing.matches_commitment());
        assert!(
            !undecodable.matches_commitment(),
            "an undecodable input cannot match"
        );
        assert!(
            unpublished.matches_commitment(),
            "with no commitment published there is nothing to contradict"
        );
    }

    #[test]
    fn all_inputs_selects_everything() {
        let bytes = vec![0u8];
        let entries: Vec<PublishedInput> = (0..3)
            .map(|index| PublishedInput {
                index,
                ciphertext: &bytes,
                commitment: None,
                metadata: &[],
                recomputed: None,
            })
            .collect();
        assert_eq!(all_inputs(&entries), vec![0, 1, 2]);
    }

    /// The ciphertext a caller publishes must be the one the journal describes.
    ///
    /// An E3 program hashes the published bytes into the digest it rebuilds, so if the two are
    /// computed over different input sets the receipt never verifies. That is exactly what happens
    /// when a policy excludes anything and the caller runs the processor itself.
    #[test]
    fn the_returned_ciphertext_is_the_one_the_journal_describes() {
        fn drop_the_first(inputs: &[PublishedInput]) -> Vec<usize> {
            (1..inputs.len()).collect()
        }

        let inputs = encrypted_inputs(&[1, 2, 3]);
        let policy = InputPolicy {
            leaf: commitment_leaf,
            select: drop_the_first,
        };

        let (result, ciphertext) = ComputeInput {
            fhe_inputs: inputs.clone(),
            published: Vec::new(),
        }
        .run(sum_processor, policy)
        .unwrap();

        assert_eq!(
            result.ciphertext_hash,
            Keccak256::digest(&ciphertext).to_vec(),
            "the journal must describe the ciphertext the caller publishes"
        );

        // And it is genuinely the selected subset, not the whole set.
        let params = decode_bfv_params_arc(&inputs.params).unwrap();
        let over_everything = sum_processor(&FHEProcessorInput {
            ciphertexts: &inputs.ciphertexts,
            params: &params,
        });
        assert_ne!(
            ciphertext, over_everything,
            "the excluded input must not be in the published ciphertext"
        );
    }
}
