// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_compute_provider::FHEProcessorInput;
use fhe::bfv::Ciphertext;
use fhe_traits::{DeserializeParametrized, Serialize};

/// The input policy this E3 program requires.
///
/// Every E3 program exports one beside its processor, so the guest and the dev runner do not need
/// to know which program they are running.
pub fn policy() -> e3_compute_provider::InputPolicy {
    policy::crisp()
}

/// CRISP Implementation of the CiphertextProcessor function
pub fn fhe_processor(fhe_inputs: &FHEProcessorInput<'_>) -> Vec<u8> {
    let mut sum = Ciphertext::zero(fhe_inputs.params);
    for ciphertext_bytes in fhe_inputs.ciphertexts {
        let ciphertext = Ciphertext::from_bytes(&ciphertext_bytes.0, fhe_inputs.params).unwrap();

        sum += &ciphertext;
    }

    sum.to_bytes()
}

/// CRISP's answers to how an input becomes a leaf and which inputs are tallied.
///
/// Both are specific to this program and its contract. They live here, beside the `CRISPProgram`
/// they must agree with, rather than in `e3-compute-provider`, which every E3 program shares.
pub mod policy {
    use e3_compute_provider::policy::{leaf_from_digest, PublishedInput};
    use e3_compute_provider::{ComputeError, InputPolicy};
    use sha2::{Digest, Sha256};
    use sha3::Keccak256;
    use std::collections::BTreeMap;

    /// The metadata `CRISPProgram` publishes with each input: 20-byte slot, then a 5-byte parent.
    const METADATA_LEN: usize = 25;

    /// What `CRISPProgram` publishes alongside one ciphertext.
    struct Metadata {
        slot: [u8; 20],
        /// The tree index of the entry this input extends, or `None` when it extends nothing.
        parent: Option<u64>,
    }

    /// Splits the published metadata, which is `slot || parentIndexPlusOne` as
    /// `abi.encodePacked(address, uint40)` lays it out.
    fn metadata_of(input: &PublishedInput) -> Result<Metadata, ComputeError> {
        if input.metadata.len() != METADATA_LEN {
            return Err(ComputeError::LeafCommitment {
                index: input.index,
                reason: format!(
                    "expected {METADATA_LEN} bytes of slot and parent, got {}",
                    input.metadata.len()
                ),
            });
        }

        let mut slot = [0u8; 20];
        slot.copy_from_slice(&input.metadata[..20]);

        let mut parent_plus_one: u64 = 0;
        for byte in &input.metadata[20..] {
            parent_plus_one = (parent_plus_one << 8) | u64::from(*byte);
        }

        Ok(Metadata {
            slot,
            parent: parent_plus_one.checked_sub(1),
        })
    }

    /// `sha256(keccak256(ciphertext) || commitment || slot || parent) mod SNARK_SCALAR_FIELD`.
    ///
    /// Must stay byte-identical to `CRISPProgram.inputLeaf`, or no root will ever match. It binds
    /// four things: the bytes, because the Noir proof constrains only the commitment and never sees
    /// the serialized ciphertext; the commitment, so no commitment can be paired with any
    /// ciphertext; the slot, because selection is per slot and an unbound slot would let a prover
    /// re-group entries; and the parent, because selection walks the slot's chain by it.
    pub fn leaf(input: &PublishedInput) -> Result<String, ComputeError> {
        let commitment = input
            .commitment
            .ok_or_else(|| ComputeError::LeafCommitment {
                index: input.index,
                reason: "CRISP publishes a commitment with every input".to_string(),
            })?;
        // Hashed as published rather than as parsed, so the leaf cannot drift from the contract's
        // `abi.encodePacked` layout. Parsed first only to refuse the wrong length.
        metadata_of(input)?;

        let mut outer = Sha256::new();
        outer.update(Keccak256::digest(input.ciphertext));
        outer.update(commitment);
        outer.update(input.metadata);
        Ok(leaf_from_digest(&outer.finalize()))
    }

    /// The end of each slot's chain of usable entries.
    ///
    /// CRISP's input tree is append-only: anyone may write to any census member's slot, since the
    /// mask path checks no signature. Overwriting in place would let a third party replace the
    /// bytes of a counted vote and erase it, so entries accumulate and one per slot is selected
    /// here.
    ///
    /// Each entry names the entry it extends, and an entry is taken only when two things hold:
    ///
    /// - its bytes reproduce its commitment, so it is a ciphertext anyone can read; and
    /// - the entry it names is the one currently selected for that slot.
    ///
    /// The first rule is what stops a submitter poisoning a slot with bytes that decode to nothing.
    /// The second is what stops one reaching back past a vote: an entry built on a superseded
    /// ciphertext would put that older ciphertext back in the slot, erasing the vote in between.
    ///
    /// Together they also keep a slot writable. `CRISPProgram` cannot check the first rule — only
    /// this runs late enough to — so anyone can leave an entry nobody else can open. Because such
    /// an entry is never selected, it is never a valid parent either, and the next honest input
    /// names the same parent it did and is taken in its place. Without that, a slot could be frozen
    /// against masking, and a slot that cannot be masked is one where every later input is provably
    /// its owner voting again — a receipt, which is what masks exist to prevent.
    ///
    /// A slot whose entries are all unusable contributes nothing — it never held a good vote.
    pub fn chain_head_per_slot(inputs: &[PublishedInput]) -> Vec<usize> {
        let mut head: BTreeMap<[u8; 20], u64> = BTreeMap::new();
        let mut selected_for_slot: BTreeMap<[u8; 20], usize> = BTreeMap::new();

        // In index order, which is the order the tree was built in, so a chain is only ever
        // extended forwards.
        for input in inputs {
            if !input.matches_commitment() {
                continue;
            }

            let Ok(metadata) = metadata_of(input) else {
                continue;
            };

            if metadata.parent != head.get(&metadata.slot).copied() {
                continue;
            }

            head.insert(metadata.slot, input.index as u64);
            selected_for_slot.insert(metadata.slot, input.index);
        }

        let mut selected: Vec<usize> = selected_for_slot.into_values().collect();
        selected.sort_unstable();
        selected
    }

    /// The policy `CRISPProgram` requires.
    pub fn crisp() -> InputPolicy {
        InputPolicy {
            leaf,
            select: chain_head_per_slot,
        }
    }
}
