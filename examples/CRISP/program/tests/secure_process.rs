// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Runs the CRISP Secure Process natively, outside the RISC Zero zkVM.
//!
//! The guest is one line — `input.input.process(fhe_processor, crisp())` — so calling that here
//! exercises the same code the zkVM runs, with the real CRISP processor and the real CRISP policy.
//! Everything except proof generation is covered, which matters because a guest failure inside the
//! zkVM surfaces only as a missing proof and a requester-billed compute timeout.

use e3_compute_provider::{
    ComputeError, ComputeInput, ComputeResult, FHEInputs, FHEProcessorInput, PublishedData,
};
use e3_fhe_params::{build_pair_for_preset, encode_bfv_params, BfvPreset};
use e3_user_program::fhe_processor;
use e3_user_program::policy::crisp;
use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe_traits::{
    DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter,
    Serialize as FheSerialize,
};
use rand::{rngs::StdRng, SeedableRng};
use std::sync::Arc;

const PRESET: BfvPreset = BfvPreset::InsecureThreshold512;

struct Round {
    params: Arc<BfvParameters>,
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl Round {
    fn new() -> Self {
        let (params, _) = build_pair_for_preset(PRESET).unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let secret_key = SecretKey::random(&params, &mut rng);
        let public_key = PublicKey::new(&secret_key, &mut rng);
        Self {
            params,
            secret_key,
            public_key,
        }
    }

    fn slot(tag: u8) -> [u8; 20] {
        let mut address = [0u8; 20];
        address[19] = tag;
        address
    }

    /// Encrypts one ballot the way a voter's client would.
    fn ballot(&self, votes: &[u64], nonce: u64) -> Vec<u8> {
        let mut rng = StdRng::seed_from_u64(1_000 + nonce);
        let plaintext = Plaintext::try_encode(votes, Encoding::poly(), &self.params).unwrap();
        let ciphertext: Ciphertext = self.public_key.try_encrypt(&plaintext, &mut rng).unwrap();
        ciphertext.to_bytes()
    }

    /// The commitment `CRISPProgram` stores for a ciphertext.
    fn commitment(&self, bytes: &[u8]) -> [u8; 32] {
        e3_bfv_client::client::compute_ct_commitment(
            bytes.to_vec(),
            self.params.degree(),
            self.params.plaintext(),
            self.params.moduli().to_vec(),
        )
        .unwrap()
    }

    /// One ballot per slot, which is the ordinary case.
    fn round_input(&self, ballots: Vec<Vec<u8>>) -> ComputeInput {
        let slots = (0..ballots.len()).map(|i| Self::slot(i as u8)).collect();
        self.round_input_at(ballots, slots)
    }

    /// `abi.encodePacked(address, uint40)`, which is what `CRISPProgram` publishes per input.
    ///
    /// `parent` is the tree index of the entry this one extends, or `None` for the first entry of a
    /// slot's chain.
    fn metadata(slot: [u8; 20], parent: Option<usize>) -> Vec<u8> {
        let parent_plus_one = parent.map_or(0u64, |index| index as u64 + 1);

        let mut bytes = slot.to_vec();
        bytes.extend_from_slice(&parent_plus_one.to_be_bytes()[3..]);
        bytes
    }

    /// Ballots published to the given slots, in order, each opening its slot's chain.
    fn round_input_at(&self, ballots: Vec<Vec<u8>>, slots: Vec<[u8; 20]>) -> ComputeInput {
        let published = ballots
            .iter()
            .zip(slots.iter())
            .map(|(bytes, slot)| PublishedData {
                commitment: Some(self.commitment(bytes)),
                metadata: Self::metadata(*slot, None),
            })
            .collect();

        ComputeInput {
            fhe_inputs: FHEInputs {
                ciphertexts: ballots
                    .into_iter()
                    .enumerate()
                    .map(|(i, b)| (b, i as u64))
                    .collect(),
                params: encode_bfv_params(&self.params),
            },
            published,
        }
    }

    fn run(&self, input: ComputeInput) -> Result<ComputeResult, ComputeError> {
        input.process(fhe_processor, crisp())
    }

    fn aggregate(&self, inputs: &FHEInputs) -> Vec<u8> {
        fhe_processor(&FHEProcessorInput {
            ciphertexts: &inputs.ciphertexts,
            params: &self.params,
        })
    }

    /// Decrypts a tally ciphertext, as the ciphernode committee would.
    ///
    /// Against `self.params`, not a re-decoded copy: fhe.rs compares parameters by `Arc` identity,
    /// so a structurally identical clone is rejected as incompatible.
    fn decrypt_tally(&self, ciphertext_bytes: &[u8], options: usize) -> Vec<u64> {
        let ciphertext = Ciphertext::from_bytes(ciphertext_bytes, &self.params).unwrap();
        let plaintext = self.secret_key.try_decrypt(&ciphertext).unwrap();
        Vec::<u64>::try_decode(&plaintext, Encoding::poly()).unwrap()[..options].to_vec()
    }
}

/// The honest path: every input is well formed and the tally is their homomorphic sum.
#[test]
fn the_secure_process_tallies_well_formed_ballots() {
    let round = Round::new();
    let input = round.round_input(vec![
        round.ballot(&[3, 0], 1),
        round.ballot(&[0, 5], 2),
        round.ballot(&[2, 0], 3),
    ]);
    let all = input.fhe_inputs.clone();

    let result = round.run(input).expect("an honest round must process");

    assert_eq!(round.decrypt_tally(&round.aggregate(&all), 2), vec![5, 5]);
    assert_eq!(result.merkle_root.len(), 32);
}

/// An input whose published bytes are not the ciphertext that was proven is dropped from the tally,
/// and the round still completes.
///
/// This is the case that used to abort the guest: `fhe_processor` deserializes with `unwrap`, so a
/// bad blob panicked before any error path could run. The policy keeps it away from the processor.
#[test]
fn a_contradicting_input_is_dropped_and_the_round_survives() {
    let round = Round::new();
    let honest = vec![
        round.ballot(&[3, 0], 1),
        round.ballot(&[0, 5], 2),
        round.ballot(&[2, 0], 3),
    ];

    let mut attacked = round.round_input(honest.clone());
    // A real, proven commitment beside bytes that are not its ciphertext — what an E3 program
    // cannot detect on chain.
    attacked.fhe_inputs.ciphertexts[1].0 = round.ballot(&[0, 99], 9);

    let result = round
        .run(attacked)
        .expect("a contradicting input must not abort the Secure Process");

    let survivors = round.round_input_at(
        vec![honest[0].clone(), honest[2].clone()],
        vec![Round::slot(0), Round::slot(2)],
    );
    let survivor_inputs = survivors.fhe_inputs.clone();
    let reference = round.run(survivors).unwrap();

    assert_eq!(
        result.ciphertext_hash, reference.ciphertext_hash,
        "the substituted ballot must not reach the tally"
    );
    assert_eq!(
        round.decrypt_tally(&round.aggregate(&survivor_inputs), 2),
        vec![5, 0]
    );
}

/// Undecodable bytes reach the same outcome. Without the binding this is the cheapest way to kill a
/// round: one input of garbage and the guest aborts.
#[test]
fn garbage_bytes_do_not_abort_the_secure_process() {
    let round = Round::new();
    let mut input = round.round_input(vec![round.ballot(&[4, 0], 1), round.ballot(&[0, 1], 2)]);
    input.fhe_inputs.ciphertexts[0].0 = vec![0xff; 32];

    let result = round
        .run(input)
        .expect("garbage must not abort the Secure Process");

    let survivor = round.round_input_at(vec![round.ballot(&[0, 1], 2)], vec![Round::slot(1)]);
    let survivor_inputs = survivor.fhe_inputs.clone();
    let reference = round.run(survivor).unwrap();

    assert_eq!(result.ciphertext_hash, reference.ciphertext_hash);
    assert_eq!(
        round.decrypt_tally(&round.aggregate(&survivor_inputs), 2),
        vec![0, 1]
    );
}

/// Two provers over the same published data must agree, or the selected set would be something a
/// prover chooses rather than something the inputs determine.
#[test]
fn the_result_is_deterministic_across_runs() {
    let round = Round::new();
    let mut input = round.round_input(vec![round.ballot(&[1, 0], 1), round.ballot(&[0, 2], 2)]);
    input.fhe_inputs.ciphertexts[0].0 = vec![0x00; 24];

    let first = round.run(input.clone()).unwrap();
    let second = round.run(input).unwrap();

    assert_eq!(first.merkle_root, second.merkle_root);
    assert_eq!(first.ciphertext_hash, second.ciphertext_hash);
    assert_eq!(first.ciphertext_commitment, second.ciphertext_commitment);
}

/// Reordering the inputs changes the root, which is why the indexer must sort by the on-chain index
/// before handing them over.
#[test]
fn input_order_changes_the_root() {
    let round = Round::new();
    let ballots = vec![round.ballot(&[1, 0], 1), round.ballot(&[0, 2], 2)];

    let ordered = round.run(round.round_input(ballots.clone())).unwrap();
    let swapped = round
        .run(round.round_input(vec![ballots[1].clone(), ballots[0].clone()]))
        .unwrap();

    assert_ne!(ordered.merkle_root, swapped.merkle_root);
}

/// A round where every entry is unusable degenerates into one with nothing to tally. The processor
/// returns an empty ciphertext, which does not deserialize, so the output commitment fails with a
/// typed error rather than a panic. Only reachable when no honest input exists.
#[test]
fn an_all_unusable_round_fails_cleanly() {
    let round = Round::new();
    let mut input = round.round_input(vec![round.ballot(&[1, 0], 1)]);
    input.fhe_inputs.ciphertexts[0].0 = vec![0xab; 16];

    let error = round.run(input).unwrap_err();

    assert!(
        matches!(error, ComputeError::OutputCommitment(_)),
        "expected a typed error, got {error:?}"
    );
}

/// The mask-poisoning case, through the real Secure Process.
///
/// A third party appends to a slot that already holds a counted vote, with a real commitment and
/// bytes that are not its ciphertext. Append-only means the earlier entry is still in the tree, so
/// the victim's vote survives instead of being erased.
#[test]
fn a_poisoned_append_does_not_erase_the_vote_already_in_the_slot() {
    let round = Round::new();
    let victim = Round::slot(7);
    let honest_ballot = round.ballot(&[6, 0], 1);

    let mut input = round.round_input_at(vec![honest_ballot.clone()], vec![victim]);
    // The attacker's entry reuses the victim's commitment beside unrelated bytes.
    let reused_commitment = input.published[0].commitment;
    input
        .fhe_inputs
        .ciphertexts
        .push((round.ballot(&[0, 9], 5), 1));
    input.published.push(PublishedData {
        commitment: reused_commitment,
        metadata: Round::metadata(victim, Some(0)),
    });

    let result = round
        .run(input)
        .expect("a poisoned append must not stop the round");

    let reference_input = round.round_input_at(vec![honest_ballot], vec![victim]);
    let reference_fhe = reference_input.fhe_inputs.clone();
    assert_eq!(
        round.decrypt_tally(&round.aggregate(&reference_fhe), 2),
        vec![6, 0]
    );
    assert_eq!(
        result.ciphertext_hash,
        round.run(reference_input).unwrap().ciphertext_hash,
        "the poisoned append must not change the tally"
    );
}

/// An honest re-vote still replaces the earlier ballot, so append-only does not freeze a voter into
/// their first choice.
#[test]
fn an_honest_re_vote_replaces_the_earlier_ballot() {
    let round = Round::new();
    let voter = Round::slot(2);
    let first = round.ballot(&[1, 0], 1);
    let second = round.ballot(&[0, 7], 2);

    let mut input = round.round_input_at(vec![first], vec![voter]);
    input.fhe_inputs.ciphertexts.push((second.clone(), 1));
    input.published.push(PublishedData {
        commitment: Some(round.commitment(&second)),
        metadata: Round::metadata(voter, Some(0)),
    });

    let result = round.run(input).unwrap();

    let reference_input = round.round_input_at(vec![second], vec![voter]);
    let reference_fhe = reference_input.fhe_inputs.clone();
    assert_eq!(
        round.decrypt_tally(&round.aggregate(&reference_fhe), 2),
        vec![0, 7]
    );
    assert_eq!(
        result.ciphertext_hash,
        round.run(reference_input).unwrap().ciphertext_hash
    );
}
