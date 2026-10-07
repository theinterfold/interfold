// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::ciphertext_output::ComputeResult;
use crate::merkle_tree_builder::Batching;
use crate::policy::InputPolicy;
use crate::secure_process::{absorb_all, SecureProcess};
use fhe::bfv::BfvParameters;
use std::sync::Arc;

pub type FHEProcessor = for<'a> fn(FHEProcessorInput<'a>) -> Vec<u8>;

/// Inputs passed to an E3 program's homomorphic processor.
///
/// The secure process builds BFV parameters once and shares them with the processor. Building the
/// secure parameter tables is expensive inside a zkVM, and decoding the same immutable bytes twice
/// adds no verification.
pub struct FHEProcessorInput<'a> {
    /// The selected ciphertexts in index order, each paired with its on-chain index.
    ///
    /// Read one at a time: inside the zkVM each is read from the input stream and checked only when
    /// the processor asks for it, so a round never has to fit in memory at once. The processor must
    /// read every item.
    ///
    /// The on-chain index is what the caller supplied. No leaf, root or journal word binds it, so the
    /// output must not depend on it; the ciphertext's position in the round is what the root binds.
    pub ciphertexts: &'a mut dyn Iterator<Item = (Vec<u8>, u64)>,
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

    #[error("the round has {expected} inputs, but {actual} were read")]
    InputCount { expected: usize, actual: usize },

    #[error("input {index} differs from the ciphertext read in the first pass")]
    InputChanged { index: usize },

    #[error("the processor returned before reading {remaining} selected inputs")]
    Unread { remaining: usize },
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
        self.run_batched(fhe_processor, policy, Batching::Sequential)
    }

    /// As [`Self::run`], choosing how the per-input commitments are scheduled.
    ///
    /// The schedule is not part of the result. Every value the journal publishes is derived from
    /// the same inputs in the same order whichever variant is given, so a host may batch while the
    /// guest does not, and the two still agree on the root.
    pub fn run_batched(
        &self,
        fhe_processor: FHEProcessor,
        policy: InputPolicy,
        batching: Batching,
    ) -> Result<(ComputeResult, Vec<u8>), ComputeError> {
        self.run_selected(fhe_processor, policy, batching)
            .map(|(result, ciphertext, _)| (result, ciphertext))
    }

    /// As [`Self::run_batched`], and also returns the indices the policy selected.
    ///
    /// Runs the same [`SecureProcess`] a zkVM guest runs over a streamed round, so the result is
    /// the journal the guest proves. The selection names the ciphertexts the guest reads in its
    /// second pass.
    pub fn run_selected(
        &self,
        fhe_processor: FHEProcessor,
        policy: InputPolicy,
        batching: Batching,
    ) -> Result<(ComputeResult, Vec<u8>, Vec<usize>), ComputeError> {
        let ciphertexts = &self.fhe_inputs.ciphertexts;
        let mut process = SecureProcess::new(
            &self.fhe_inputs.params,
            ciphertexts.iter().map(|(_, index)| *index).collect(),
            self.published.clone(),
            policy,
        )?;
        absorb_all(&mut process, ciphertexts, batching)?;

        let selected = process.select()?;
        let indices = selected.indices().to_vec();
        // The processor sees only what the policy selected. Both the root and this set are
        // functions of values the root binds, so any prover over the same published inputs reaches
        // the same result.
        let (result, ciphertext) =
            selected.finish(fhe_processor, |index| Ok(ciphertexts[index].0.clone()))?;
        Ok((result, ciphertext, indices))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_tree_builder::MerkleTreeBuilder;
    use crate::policy::{all_inputs, commitment_leaf, InputRecord, PublishedInput};
    use e3_bfv_client::client::compute_ct_commitment;
    use e3_fhe_params::{
        build_pair_for_preset, decode_bfv_params_arc, encode_bfv_params, BfvPreset,
    };
    use fhe::bfv::{Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
    use fhe_traits::{FheEncoder, FheEncrypter, Serialize as FheSerialize};
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use sha3::{Digest, Keccak256};

    fn sum_processor(inputs: FHEProcessorInput<'_>) -> Vec<u8> {
        use fhe_traits::DeserializeParametrized;
        let mut sum = Ciphertext::zero(inputs.params);
        for (bytes, _) in inputs.ciphertexts {
            sum += &Ciphertext::from_bytes(&bytes, inputs.params).unwrap();
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

    fn input(inputs: FHEInputs) -> ComputeInput {
        ComputeInput {
            fhe_inputs: inputs,
            published: Vec::new(),
        }
    }

    fn process(inputs: FHEInputs, policy: InputPolicy) -> Result<ComputeResult, ComputeError> {
        input(inputs).process(sum_processor, policy)
    }

    /// The root of a tree whose leaves are each input's own commitment, built independently of the
    /// Secure Process.
    fn commitment_root(inputs: &FHEInputs) -> Vec<u8> {
        let params = decode_bfv_params_arc(&inputs.params).unwrap();
        let leaves = inputs
            .ciphertexts
            .iter()
            .map(|(bytes, _)| {
                hex::encode(
                    compute_ct_commitment(
                        bytes.clone(),
                        params.degree(),
                        params.plaintext(),
                        params.moduli().to_vec(),
                    )
                    .unwrap(),
                )
            })
            .collect();
        let root = MerkleTreeBuilder::new(inputs.ciphertexts.len())
            .with_leaf_hashes(leaves)
            .build_tree()
            .unwrap()
            .root()
            .unwrap();
        hex::decode(root).unwrap()
    }

    /// The journal's input root must be a function of the ciphertexts consumed. Before this, the
    /// root arrived as a separate field, so a prover could publish a tally over one input set while
    /// proving the root of another.
    #[test]
    fn the_root_is_derived_from_the_processed_ciphertexts() {
        let inputs = encrypted_inputs(&[1, 1, 1]);

        let result = process(inputs.clone(), InputPolicy::default()).unwrap();

        assert_eq!(result.merkle_root, commitment_root(&inputs));
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

        let (result, _, selected) = input(inputs.clone())
            .run_selected(sum_processor, InputPolicy::default(), Batching::Sequential)
            .unwrap();

        assert_eq!(selected, vec![0, 1], "every input is computed over");
        assert_eq!(result.merkle_root, commitment_root(&inputs));
    }

    /// A policy chooses what is computed over; it cannot shrink the tree. Dropping a leaf would
    /// change the root and make the result unpublishable, so the crate applies this rather than
    /// trusting each program to.
    #[test]
    fn a_policy_cannot_drop_an_input_from_the_tree() {
        fn select_the_first(_: &[InputRecord]) -> Vec<usize> {
            vec![0]
        }
        let inputs = encrypted_inputs(&[1, 2, 3]);

        let (result, _, selected) = input(inputs.clone())
            .run_selected(
                sum_processor,
                InputPolicy {
                    leaf: commitment_leaf,
                    select: select_the_first,
                },
                Batching::Sequential,
            )
            .unwrap();

        assert_eq!(selected, vec![0], "the policy selected one input");
        assert_eq!(
            result.merkle_root,
            commitment_root(&inputs),
            "every leaf is still in the tree"
        );
    }

    /// A policy returning an index that does not exist is a bug in the program, not a silent skip.
    #[test]
    fn an_out_of_range_selection_is_rejected() {
        fn select_beyond_the_end(_: &[InputRecord]) -> Vec<usize> {
            vec![99]
        }

        let error = process(
            encrypted_inputs(&[1]),
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

        let error = process(inputs, InputPolicy::default()).unwrap_err();

        assert!(
            matches!(error, ComputeError::LeafCommitment { index: 1, .. }),
            "got {error:?}"
        );
    }

    /// Batching is a schedule, not a change of meaning. Every batch size must give the same root,
    /// the same selection and the same ciphertext as the sequential path.
    ///
    /// This is the property the removed `start_parallel` did not have. That version chunked the
    /// round itself and rebuilt a tally over chunk results with a hardcoded index of zero, so the
    /// leaves stopped binding an input to its position. Batching only the per-input commitments
    /// cannot drift, and this test is what keeps it that way.
    #[test]
    fn batching_does_not_change_the_root() {
        let inputs = encrypted_inputs(&[3, 1, 4, 1, 5, 9, 2, 6]);
        let policy = InputPolicy::default();
        let input = input(inputs);

        let (sequential, sequential_ciphertext) = input.run(sum_processor, policy).unwrap();

        // 1 is the degenerate chunk, 3 does not divide the input count, and 8 is the whole set:
        // between them they cover every boundary a chunked schedule can get wrong.
        for batch_size in [1, 2, 3, 8, 64] {
            let (batched, batched_ciphertext) = input
                .run_batched(sum_processor, policy, Batching::Parallel { batch_size })
                .unwrap();

            assert_eq!(
                batched.merkle_root, sequential.merkle_root,
                "batch size {batch_size} changed the input root"
            );
            assert_eq!(
                batched.ciphertext_hash, sequential.ciphertext_hash,
                "batch size {batch_size} changed the tally"
            );
            assert_eq!(
                batched_ciphertext, sequential_ciphertext,
                "batch size {batch_size} changed the published ciphertext"
            );
        }
    }

    /// A batched run must report a bad input the same way a sequential one does, naming the index
    /// that failed. Recomputing commitments away from the entry loop is where that could be lost.
    #[test]
    fn batching_preserves_the_index_of_an_undecodable_input() {
        let mut inputs = encrypted_inputs(&[1, 1, 1, 1, 1]);
        inputs.ciphertexts[3].0 = vec![0xff; 8];

        let error = input(inputs)
            .run_batched(
                sum_processor,
                InputPolicy::default(),
                Batching::Parallel { batch_size: 2 },
            )
            .unwrap_err();

        assert!(
            matches!(error, ComputeError::LeafCommitment { index: 3, .. }),
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
            ciphertext_hash: [0; 32],
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
        let entries: Vec<InputRecord> = (0..3)
            .map(|index| InputRecord {
                index,
                ciphertext_hash: [0; 32],
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
        fn drop_the_first(inputs: &[InputRecord]) -> Vec<usize> {
            (1..inputs.len()).collect()
        }

        let inputs = encrypted_inputs(&[1, 2, 3]);
        let policy = InputPolicy {
            leaf: commitment_leaf,
            select: drop_the_first,
        };

        let (result, ciphertext) = input(inputs.clone()).run(sum_processor, policy).unwrap();

        assert_eq!(
            result.ciphertext_hash,
            Keccak256::digest(&ciphertext).to_vec(),
            "the journal must describe the ciphertext the caller publishes"
        );

        // And it is genuinely the selected subset, not the whole set.
        let params = decode_bfv_params_arc(&inputs.params).unwrap();
        let over_everything = sum_processor(FHEProcessorInput {
            ciphertexts: &mut inputs.ciphertexts.iter().cloned(),
            params: &params,
        });
        assert_ne!(
            ciphertext, over_everything,
            "the excluded input must not be in the published ciphertext"
        );
    }
}
