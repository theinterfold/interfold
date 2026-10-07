// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The Secure Process over a round that arrives one ciphertext at a time.
//!
//! A round is read twice. The first pass reads every ciphertext in index order and keeps only what
//! the tree and the policy need: the leaf, the recomputed commitment and the hash of the bytes.
//! Selection then runs over those records. The second pass reads the selected ciphertexts again, in
//! index order, and refuses any whose hash differs from the first pass before the processor sees
//! it.
//!
//! Only one ciphertext is held at a time, so a round can be larger than the zkVM guest's memory.
//! A host runs the same code over ciphertexts it already holds (see
//! [`crate::ComputeInput::run_selected`]) to predict the journal the guest proves. The guest build
//! swaps in accelerated hashing and packing, so the two agree only while those match the reference
//! code the host runs; unit tests and the CI guest-parity check compare them.

use crate::ciphertext_output::ComputeResult;
use crate::compute_input::{ComputeError, FHEProcessor, FHEProcessorInput, PublishedData};
use crate::hashing::keccak256;
use crate::merkle_tree_builder::{Batching, MerkleTreeBuilder};
use crate::policy::{InputPolicy, InputRecord, PublishedInput};
use e3_bfv_client::client::compute_ct_commitment_with_params;
use e3_fhe_params::decode_bfv_params_arc;
use fhe::bfv::BfvParameters;
use std::sync::Arc;

/// What the first pass keeps of one input once its bytes are gone.
struct Absorbed {
    ciphertext_hash: [u8; 32],
    recomputed: Option<[u8; 32]>,
}

/// The first pass: every input of the round, in index order.
pub struct SecureProcess {
    params: Arc<BfvParameters>,
    params_hash: [u8; 32],
    policy: InputPolicy,
    indices: Vec<u64>,
    published: Vec<PublishedData>,
    absorbed: Vec<Absorbed>,
    tree: MerkleTreeBuilder,
}

impl SecureProcess {
    /// Starts a round of `indices.len()` inputs.
    ///
    /// `indices` holds each input's on-chain index, which the processor receives beside the
    /// ciphertext. `published` is empty, or has one entry per input in the same order.
    pub fn new(
        params: &[u8],
        indices: Vec<u64>,
        published: Vec<PublishedData>,
        policy: InputPolicy,
    ) -> Result<Self, ComputeError> {
        let decoded =
            decode_bfv_params_arc(params).map_err(|e| ComputeError::DecodeParams(e.to_string()))?;
        if !published.is_empty() && published.len() != indices.len() {
            return Err(ComputeError::MerkleTree(format!(
                "{} ciphertexts but {} published entries",
                indices.len(),
                published.len()
            )));
        }

        Ok(Self {
            params: decoded,
            params_hash: keccak256(params),
            policy,
            absorbed: Vec::with_capacity(indices.len()),
            tree: MerkleTreeBuilder::new(indices.len()),
            indices,
            published,
        })
    }

    /// The decoded BFV parameters.
    pub fn params(&self) -> &Arc<BfvParameters> {
        &self.params
    }

    /// Reads the next input, in index order.
    ///
    /// A ciphertext that does not deserialize is recorded as such rather than refused: the bytes
    /// are untrusted, and the policy decides what an unusable input means.
    pub fn absorb(&mut self, ciphertext: &[u8]) -> Result<(), ComputeError> {
        let recomputed = compute_ct_commitment_with_params(ciphertext, &self.params).ok();
        self.absorb_recomputed(ciphertext, recomputed)
    }

    /// As [`Self::absorb`], with the commitment of these bytes already recomputed.
    ///
    /// For a host that recomputes commitments on a thread pool. Not public, because the caller is
    /// trusted to pass the commitment of exactly these bytes.
    fn absorb_recomputed(
        &mut self,
        ciphertext: &[u8],
        recomputed: Option<[u8; 32]>,
    ) -> Result<(), ComputeError> {
        let index = self.absorbed.len();
        if index == self.indices.len() {
            return Err(ComputeError::InputCount {
                expected: self.indices.len(),
                actual: index + 1,
            });
        }

        let ciphertext_hash = keccak256(ciphertext);
        let entry = self.published.get(index);
        let leaf = (self.policy.leaf)(&PublishedInput {
            index,
            ciphertext,
            ciphertext_hash,
            commitment: entry.and_then(|entry| entry.commitment.as_ref()),
            metadata: entry.map_or(&[][..], |entry| entry.metadata.as_slice()),
            recomputed,
        })?;

        self.tree.leaf_hashes.push(leaf);
        self.absorbed.push(Absorbed {
            ciphertext_hash,
            recomputed,
        });
        Ok(())
    }

    /// Ends the first pass: builds the input tree and applies the policy's selection.
    pub fn select(self) -> Result<Selected, ComputeError> {
        if self.absorbed.len() != self.indices.len() {
            return Err(ComputeError::InputCount {
                expected: self.indices.len(),
                actual: self.absorbed.len(),
            });
        }

        let records: Vec<InputRecord> = self
            .absorbed
            .iter()
            .enumerate()
            .map(|(index, absorbed)| {
                let entry = self.published.get(index);
                InputRecord {
                    index,
                    ciphertext_hash: absorbed.ciphertext_hash,
                    commitment: entry.and_then(|entry| entry.commitment.as_ref()),
                    metadata: entry.map_or(&[][..], |entry| entry.metadata.as_slice()),
                    recomputed: absorbed.recomputed,
                }
            })
            .collect();
        let mut selected = (self.policy.select)(&records);
        drop(records);
        selected.sort_unstable();
        selected.dedup();
        if let Some(&index) = selected.last() {
            if index >= self.indices.len() {
                return Err(ComputeError::MerkleTree(format!(
                    "selected index {index} is out of range"
                )));
            }
        }

        // Every input contributed a leaf above, whatever the policy selected. Dropping one would
        // change the root and make the result unpublishable.
        let root = self
            .tree
            .build_tree()?
            .root()
            .ok_or_else(|| ComputeError::MerkleTree("the tree has no root".into()))?;
        let merkle_root = hex::decode(root).map_err(|e| ComputeError::MerkleTree(e.to_string()))?;

        Ok(Selected {
            params: self.params,
            params_hash: self.params_hash,
            merkle_root,
            indices: self.indices,
            hashes: self
                .absorbed
                .into_iter()
                .map(|absorbed| absorbed.ciphertext_hash)
                .collect(),
            selected,
        })
    }
}

/// The second pass: the selected inputs, in index order.
pub struct Selected {
    params: Arc<BfvParameters>,
    params_hash: [u8; 32],
    merkle_root: Vec<u8>,
    indices: Vec<u64>,
    hashes: Vec<[u8; 32]>,
    selected: Vec<usize>,
}

impl Selected {
    /// The inputs the processor runs over, ascending. The second pass reads exactly these, in this
    /// order.
    pub fn indices(&self) -> &[usize] {
        &self.selected
    }

    /// Runs the processor over the selected inputs and returns the result and the output
    /// ciphertext.
    ///
    /// `read` returns the ciphertext at the given index. Each is refused unless its hash matches
    /// the first pass, so whoever supplies the second pass cannot choose what is computed over.
    /// The processor must read every selected input.
    pub fn finish(
        self,
        processor: FHEProcessor,
        read: impl FnMut(usize) -> Result<Vec<u8>, ComputeError>,
    ) -> Result<(ComputeResult, Vec<u8>), ComputeError> {
        let mut ciphertexts = Checked {
            selected: self.selected.iter(),
            hashes: &self.hashes,
            indices: &self.indices,
            read,
            failure: None,
        };
        let output = processor(FHEProcessorInput {
            ciphertexts: &mut ciphertexts,
            params: &self.params,
        });
        if let Some(error) = ciphertexts.failure {
            return Err(error);
        }
        let unread = ciphertexts.selected.len();
        if unread > 0 {
            return Err(ComputeError::Unread { remaining: unread });
        }

        let ciphertext_commitment = compute_ct_commitment_with_params(&output, &self.params)
            .map_err(|e| ComputeError::OutputCommitment(e.to_string()))?
            .to_vec();

        Ok((
            ComputeResult {
                ciphertext_hash: keccak256(&output).to_vec(),
                ciphertext_commitment,
                params_hash: self.params_hash.to_vec(),
                merkle_root: self.merkle_root,
            },
            output,
        ))
    }
}

/// The selected ciphertexts as the processor reads them, each checked against the first pass.
struct Checked<'a, R> {
    selected: std::slice::Iter<'a, usize>,
    hashes: &'a [[u8; 32]],
    indices: &'a [u64],
    read: R,
    failure: Option<ComputeError>,
}

impl<R> Iterator for Checked<'_, R>
where
    R: FnMut(usize) -> Result<Vec<u8>, ComputeError>,
{
    type Item = (Vec<u8>, u64);

    fn next(&mut self) -> Option<Self::Item> {
        if self.failure.is_some() {
            return None;
        }
        let index = *self.selected.next()?;
        match (self.read)(index) {
            Ok(bytes) if keccak256(&bytes) == self.hashes[index] => {
                Some((bytes, self.indices[index]))
            }
            Ok(_) => {
                self.failure = Some(ComputeError::InputChanged { index });
                None
            }
            Err(error) => {
                self.failure = Some(error);
                None
            }
        }
    }
}

/// Recomputes every input's ciphertext commitment, in index order.
///
/// The one expensive step per input, and pure: it reads the ciphertext bytes and the shared
/// parameters, and nothing else. That is what makes it safe to schedule freely.
#[cfg(feature = "parallel")]
pub(crate) fn recompute_commitments(
    ciphertexts: &[(Vec<u8>, u64)],
    params: &Arc<BfvParameters>,
    batching: Batching,
) -> Vec<Option<[u8; 32]>> {
    use rayon::prelude::*;

    let batch_size = match batching {
        Batching::Sequential => 0,
        Batching::Parallel { batch_size } => batch_size,
    };

    // A zero or one chunk is the sequential schedule. Taking that path explicitly keeps a
    // misconfigured batch size from panicking inside `chunks`.
    if batch_size <= 1 {
        return ciphertexts
            .iter()
            .map(|(bytes, _)| compute_ct_commitment_with_params(bytes, params).ok())
            .collect();
    }

    // `flat_map` over ordered chunks, not `par_iter` over inputs: rayon preserves the order of an
    // indexed parallel iterator, so the output stays in index order, and chunking bounds how many
    // of the large intermediate values are live at once.
    ciphertexts
        .par_chunks(batch_size)
        .flat_map(|chunk| {
            chunk
                .iter()
                .map(|(bytes, _)| compute_ct_commitment_with_params(bytes, params).ok())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The sequential schedule, used when the `parallel` feature is off.
///
/// [`Batching::Parallel`] is accepted and ignored here. A caller that asks for batching without
/// the feature gets the same commitments, so failing would serve nothing.
#[cfg(not(feature = "parallel"))]
pub(crate) fn recompute_commitments(
    ciphertexts: &[(Vec<u8>, u64)],
    params: &Arc<BfvParameters>,
    _batching: Batching,
) -> Vec<Option<[u8; 32]>> {
    ciphertexts
        .iter()
        .map(|(bytes, _)| compute_ct_commitment_with_params(bytes, params).ok())
        .collect()
}

/// Runs the first pass over ciphertexts the caller already holds.
pub(crate) fn absorb_all(
    process: &mut SecureProcess,
    ciphertexts: &[(Vec<u8>, u64)],
    batching: Batching,
) -> Result<(), ComputeError> {
    let recomputed = recompute_commitments(ciphertexts, process.params(), batching);
    for ((bytes, _), recomputed) in ciphertexts.iter().zip(recomputed) {
        process.absorb_recomputed(bytes, recomputed)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute_input::{ComputeInput, FHEInputs};
    use crate::policy::leaf_from_digest;
    use e3_fhe_params::{build_pair_for_preset, encode_bfv_params, BfvPreset};
    use fhe::bfv::{Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
    use fhe_traits::{DeserializeParametrized, FheEncoder, FheEncrypter, Serialize};
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    fn sum(input: FHEProcessorInput<'_>) -> Vec<u8> {
        let mut sum = Ciphertext::zero(input.params);
        for (bytes, _) in input.ciphertexts {
            sum += &Ciphertext::from_bytes(&bytes, input.params).unwrap();
        }
        sum.to_bytes()
    }

    fn first_only(input: FHEProcessorInput<'_>) -> Vec<u8> {
        let (bytes, _) = input.ciphertexts.next().unwrap();
        Ciphertext::from_bytes(&bytes, input.params)
            .unwrap()
            .to_bytes()
    }

    /// Binds the bytes and accepts an undecodable input, so a round can contain one.
    fn hash_leaf(input: &PublishedInput) -> Result<String, ComputeError> {
        let mut digest = input.ciphertext_hash.to_vec();
        digest.extend_from_slice(&input.recomputed.unwrap_or_default());
        Ok(leaf_from_digest(&crate::hashing::keccak256(&digest)))
    }

    /// Every usable input at an even index.
    fn usable_even(inputs: &[InputRecord]) -> Vec<usize> {
        inputs
            .iter()
            .filter(|input| input.index % 2 == 0 && input.matches_commitment())
            .map(|input| input.index)
            .collect()
    }

    const POLICY: InputPolicy = InputPolicy {
        leaf: hash_leaf,
        select: usable_even,
    };

    /// Seven inputs. Input 4 does not deserialize and input 2's published commitment is wrong, so
    /// the policy drops both along with every odd index.
    fn round() -> ComputeInput {
        let (params, _) = build_pair_for_preset(BfvPreset::InsecureThreshold512).unwrap();
        let mut rng = ChaCha8Rng::seed_from_u64(11);
        let secret_key = SecretKey::random(&params, &mut rng);
        let public_key = PublicKey::new(&secret_key, &mut rng);

        let mut ciphertexts: Vec<(Vec<u8>, u64)> = (0..7u64)
            .map(|value| {
                let plaintext = Plaintext::try_encode(&[value], Encoding::poly(), &params).unwrap();
                let ciphertext = public_key.try_encrypt(&plaintext, &mut rng).unwrap();
                (ciphertext.to_bytes(), 100 + value)
            })
            .collect();
        ciphertexts[4].0 = vec![0xff; 16];

        let mut published: Vec<PublishedData> = ciphertexts
            .iter()
            .map(|(bytes, _)| PublishedData {
                commitment: Some(
                    compute_ct_commitment_with_params(bytes, &params).unwrap_or_default(),
                ),
                metadata: vec![7; 3],
            })
            .collect();
        published[2].commitment = Some([9; 32]);

        ComputeInput {
            fhe_inputs: FHEInputs {
                ciphertexts,
                params: encode_bfv_params(&params),
            },
            published,
        }
    }

    fn streamed(input: &ComputeInput) -> SecureProcess {
        let mut process = SecureProcess::new(
            &input.fhe_inputs.params,
            input
                .fhe_inputs
                .ciphertexts
                .iter()
                .map(|(_, index)| *index)
                .collect(),
            input.published.clone(),
            POLICY,
        )
        .unwrap();
        for (bytes, _) in &input.fhe_inputs.ciphertexts {
            process.absorb(bytes).unwrap();
        }
        process
    }

    /// The guest reads the round one ciphertext at a time and the host holds all of it. Both must
    /// reach the same root, selection, output and journal values, or the host predicts a journal
    /// the guest never proves.
    #[test]
    fn a_streamed_round_matches_a_held_round() {
        let input = round();
        let (held, held_output, held_selection) = input
            .run_selected(sum, POLICY, Batching::Parallel { batch_size: 3 })
            .unwrap();
        assert_eq!(held_selection, vec![0, 6], "inputs 2 and 4 are unusable");

        let selected = streamed(&input).select().unwrap();
        assert_eq!(selected.indices(), held_selection.as_slice());
        let (streamed, streamed_output) = selected
            .finish(sum, |index| {
                Ok(input.fhe_inputs.ciphertexts[index].0.clone())
            })
            .unwrap();

        assert_eq!(streamed.merkle_root, held.merkle_root);
        assert_eq!(streamed.ciphertext_hash, held.ciphertext_hash);
        assert_eq!(streamed.ciphertext_commitment, held.ciphertext_commitment);
        assert_eq!(streamed.params_hash, held.params_hash);
        assert_eq!(streamed_output, held_output);
    }

    /// Whoever supplies the second pass must not choose what is computed over. A ciphertext that
    /// differs from the one hashed in the first pass is refused, even a valid one.
    #[test]
    fn a_changed_ciphertext_in_the_second_pass_is_refused() {
        let input = round();
        let error = streamed(&input)
            .select()
            .unwrap()
            .finish(sum, |index| {
                let substitute = if index == 6 { 0 } else { index };
                Ok(input.fhe_inputs.ciphertexts[substitute].0.clone())
            })
            .unwrap_err();

        assert!(
            matches!(error, ComputeError::InputChanged { index: 6 }),
            "got {error:?}"
        );
    }

    /// A second pass that runs out reports why, rather than computing over what arrived.
    #[test]
    fn a_failed_second_pass_read_is_reported() {
        let input = round();
        let error = streamed(&input)
            .select()
            .unwrap()
            .finish(sum, |index| {
                if index == 0 {
                    Ok(input.fhe_inputs.ciphertexts[0].0.clone())
                } else {
                    Err(ComputeError::InputCount {
                        expected: 2,
                        actual: 1,
                    })
                }
            })
            .unwrap_err();

        assert!(
            matches!(error, ComputeError::InputCount { .. }),
            "got {error:?}"
        );
    }

    /// The first pass reads every input exactly once. A round with an input missing or added would
    /// build a different tree from the one the E3 program stored.
    #[test]
    fn the_first_pass_reads_every_input_once() {
        let input = round();

        let mut short = SecureProcess::new(
            &input.fhe_inputs.params,
            vec![0; 7],
            input.published.clone(),
            POLICY,
        )
        .unwrap();
        for (bytes, _) in &input.fhe_inputs.ciphertexts[..6] {
            short.absorb(bytes).unwrap();
        }
        assert!(matches!(
            short.select(),
            Err(ComputeError::InputCount {
                expected: 7,
                actual: 6
            })
        ));

        let mut long = streamed(&input);
        assert!(matches!(
            long.absorb(&input.fhe_inputs.ciphertexts[0].0),
            Err(ComputeError::InputCount {
                expected: 7,
                actual: 8
            })
        ));
    }

    /// The journal describes a computation over the whole selection. A processor that stops early
    /// would publish a result over fewer inputs.
    #[test]
    fn the_processor_must_read_every_selected_input() {
        let input = round();
        let error = streamed(&input)
            .select()
            .unwrap()
            .finish(first_only, |index| {
                Ok(input.fhe_inputs.ciphertexts[index].0.clone())
            })
            .unwrap_err();

        assert!(
            matches!(error, ComputeError::Unread { remaining: 1 }),
            "got {error:?}"
        );
    }
}
