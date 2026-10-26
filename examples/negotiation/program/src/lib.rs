// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The FHE program of the negotiation example: a sealed price negotiation between a seller and a
//! buyer. `DESIGN.md` explains the construction. `README.md` ("Contracts") describes the interface.
//!
//! Input 0 of a round is its configuration, [`config_input`]. It is not a ciphertext.
//! `NegotiationProgram.validate` inserts its leaf, so the compute proof binds the configuration
//! through the input root.
//!
//! Each party sends one offer: [`OFFER_CIPHERTEXTS`] ciphertexts of 128 SIMD slots each. The offer of
//! the role `r` is `X0, X1, M` (lane tensor for the lanes 0..7, lane tensor for the lanes 8..15, mask).
//! The program computes, slot by slot:
//!
//! ```text
//! out = X0 * Y0 + X1 * Y1 + M_seller + M_buyer
//! ```
//!
//! `X` is the seller and `Y` the buyer. The sum is symmetric, so the program does not need to know
//! which offer is the seller's. After the decryption, the public sums the 8 groups of each level
//! (see [`layout::read_output`]). The sum is the one-hot vector of the agreed level, or zero for no
//! match.
//!
//! Two products of depth 1 are added before the relinearization, so the program relinearizes once.
//!
//! The offer needs three leaves, one for each ciphertext. The metadata of a leaf names the party, the
//! role and the index of the ciphertext in the offer. The contract cannot check that published bytes
//! open a commitment, so any submitter can publish an offer that does not. [`select_offers`] leaves
//! such an offer out of the computation, and the negotiation has no output.
//!
//! The slot layout lives in [`layout`] only. `NegotiationOutput` (Solidity) and `sdk/src/layout.ts`
//! decode the same layout, and their tests check it against these functions.

use e3_compute_provider::policy::{InputRecord, leaf_from_digest};
use e3_compute_provider::{ComputeError, FHEProcessorInput, InputPolicy, PublishedInput};
use fhe::bfv::Ciphertext;
use fhe::trlbfv::LBFVRelinearizationKey;
use fhe_traits::{DeserializeParametrized, Serialize};
#[cfg(feature = "openvm-hashes")]
use openvm_sha2::Sha256;
#[cfg(not(all(feature = "openvm-hashes", target_os = "zkvm")))]
use sha2::Digest;
#[cfg(not(feature = "openvm-hashes"))]
use sha2::Sha256;

/// The slot layout of an offer and of the output. The single place of this language.
pub mod layout {
    /// The most price levels of a negotiation: the slots of one group.
    pub const LEVELS: usize = 16;

    /// The groups of 16 slots in a plaintext.
    pub const GROUPS: usize = 8;

    /// The bits of the random share of a party.
    pub const SHARE_BITS: usize = 4;

    /// The lanes of the lane tensor: one for each value of the share.
    pub const LANES: usize = 1 << SHARE_BITS;

    /// The number of slots of the plaintext (the degree of the insecure-simd preset).
    pub const SLOTS: usize = LEVELS * GROUPS;

    /// The ciphertexts of one offer: lanes 0..7, lanes 8..15 and the mask.
    pub const OFFER_CIPHERTEXTS: usize = 3;

    /// The plaintext modulus of the insecure-simd preset.
    pub const PLAINTEXT_MODULUS: u64 = 257;

    /// The two parties. The values are the `uint8` that the contract uses.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(u8)]
    pub enum Role {
        Seller = 0,
        Buyer = 1,
    }

    impl Role {
        /// The role of a `uint8`, or `None`.
        pub fn from_byte(byte: u8) -> Option<Self> {
            match byte {
                0 => Some(Self::Seller),
                1 => Some(Self::Buyer),
                _ => None,
            }
        }
    }

    fn bit(value: usize, k: usize) -> usize {
        (value >> k) & 1
    }

    /// The largest level below `i` that beats `i` when the pointer bit `k` is 0 and `i` has the bit
    /// `k`: `i` with the bit `k` cleared and every lower bit set.
    pub fn left_reach(i: usize, k: usize) -> usize {
        ((i >> (k + 1)) << (k + 1)) | ((1 << k) - 1)
    }

    /// The smallest level above `i` that beats `i` when the pointer bit `k` is 1 and `i` has not the
    /// bit `k`: `i` with the bit `k` set and every lower bit cleared.
    pub fn right_reach(i: usize, k: usize) -> usize {
        ((i >> (k + 1)) << (k + 1)) | (1 << k)
    }

    /// The tensor entry of `role` for the lane `theta` (0..16) at the level `i`.
    ///
    /// The sum over `theta` of `seller(theta) * buyer(theta)` is 1 if `i` is the agreed level and 0
    /// otherwise (`DESIGN.md`).
    pub fn tensor_entry(role: Role, theta: usize, i: usize, step: usize, share: usize) -> u64 {
        let seller = role == Role::Seller;
        if if seller { step > i } else { step < i } {
            return 0;
        }
        for k in 0..SHARE_BITS {
            let own = (bit(i, k) == 1) == seller;
            if own {
                let reach = if seller {
                    step <= left_reach(i, k)
                } else {
                    step >= right_reach(i, k)
                };
                let pointer_bit = bit(share, k) ^ bit(theta, k);
                let killed = reach && (pointer_bit == usize::from(!seller));
                if killed {
                    return 0;
                }
            } else if bit(share, k) != bit(theta, k) {
                return 0;
            }
        }
        1
    }

    /// The slots of the two lane ciphertexts of an offer.
    ///
    /// # Panics
    ///
    /// If `step >= LEVELS` or `share >= LANES`.
    pub fn lane_slots(role: Role, step: usize, share: usize) -> [Vec<u64>; 2] {
        assert!(step < LEVELS, "the step {step} is not below {LEVELS}");
        assert!(share < LANES, "the share {share} is not below {LANES}");
        let mut half = [vec![0u64; SLOTS], vec![0u64; SLOTS]];
        for theta in 0..LANES {
            for i in 0..LEVELS {
                half[theta >> 3][(theta & 7) * LEVELS + i] = tensor_entry(role, theta, i, step, share);
            }
        }
        half
    }

    /// A mask: slots below `t` whose sum over the 8 groups of each level is 0 mod `t`. `random`
    /// returns a uniform value in `[0, t)`.
    pub fn mask_slots(mut random: impl FnMut() -> u64) -> Vec<u64> {
        let mut slots = vec![0u64; SLOTS];
        for i in 0..LEVELS {
            let mut sum = 0;
            for g in 0..GROUPS - 1 {
                let value = random();
                assert!(value < PLAINTEXT_MODULUS, "the mask value {value} is not below t");
                slots[g * LEVELS + i] = value;
                sum += value;
            }
            slots[(GROUPS - 1) * LEVELS + i] = (PLAINTEXT_MODULUS - sum % PLAINTEXT_MODULUS) % PLAINTEXT_MODULUS;
        }
        slots
    }

    /// The three plaintexts of an offer, in the order of the ciphertexts.
    pub fn offer_slots(role: Role, step: usize, share: usize, mask: Vec<u64>) -> [Vec<u64>; 3] {
        let [low, high] = lane_slots(role, step, share);
        [low, high, mask]
    }

    /// `sum over g of slots[g * 16 + i] mod t` for each level `i`. `None` unless there are
    /// [`SLOTS`] slots.
    pub fn level_sums(slots: &[u64]) -> Option<[u64; LEVELS]> {
        if slots.len() != SLOTS {
            return None;
        }
        let mut sums = [0u64; LEVELS];
        for (i, sum) in sums.iter_mut().enumerate() {
            *sum = (0..GROUPS).map(|g| slots[g * LEVELS + i]).sum::<u64>() % PLAINTEXT_MODULUS;
        }
        Some(sums)
    }

    /// The outcome of a negotiation: the agreed level, or `None` for no match.
    pub type Outcome = Option<usize>;

    /// Reads the decrypted slots. `None` if the level sums are neither the one-hot vector of one
    /// level nor the zero vector. `Some(None)` is no match.
    pub fn read_output(slots: &[u64]) -> Option<Outcome> {
        let mut step = None;
        for (level, sum) in level_sums(slots)?.into_iter().enumerate() {
            match sum {
                0 => {}
                1 if step.is_none() => step = Some(level),
                _ => return None,
            }
        }
        Some(step)
    }

    /// The exact law of the agreed level for the private steps `[s, b]`, in sixteenths: entry `p` is
    /// the number of the 16 pointers `u` for which the level `p` wins. All zero if `s > b`.
    pub fn law(seller_step: usize, buyer_step: usize) -> [u32; LEVELS] {
        let mut counts = [0u32; LEVELS];
        for pointer in 0..LANES {
            if let Some(level) = expected_outcome(seller_step, buyer_step, pointer, 0) {
                counts[level] += 1;
            }
        }
        counts
    }

    /// The agreed level of the private steps and shares: the level of the least `i xor u` in
    /// `[s, b]`, with `u = seller_share xor buyer_share`. `None` if `s > b`.
    pub fn expected_outcome(
        seller_step: usize,
        buyer_step: usize,
        seller_share: usize,
        buyer_share: usize,
    ) -> Outcome {
        let pointer = seller_share ^ buyer_share;
        (seller_step..=buyer_step).min_by_key(|level| level ^ pointer)
    }
}

pub use layout::{GROUPS, LANES, LEVELS, OFFER_CIPHERTEXTS, Role, SLOTS};

/// The configuration input of a round. `NegotiationProgram.CONFIG_DOMAIN` is the same bytes.
pub const CONFIG_DOMAIN: &[u8] = b"interfold-negotiation-config-v1";

/// Input 0 of a round.
pub fn config_input() -> Vec<u8> {
    CONFIG_DOMAIN.to_vec()
}

/// The metadata `NegotiationProgram` publishes with each offer ciphertext: the 20-byte party, then
/// the 5-byte `uint40(role * 256 + index)`, as the program runner packs a slot and a parent.
/// So the bytes 20..23 are 0, byte 23 is the role and byte 24 is the index of the ciphertext.
///
/// The configuration at index 0 gets a zero commitment and zero metadata; its leaf ignores them.
const METADATA_LEN: usize = 25;

/// The party, the role and the index of the ciphertext in the offer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Tag<'a> {
    party: &'a [u8],
    role: Role,
    index: u8,
}

impl<'a> Tag<'a> {
    /// The tag in `metadata`, or `None` if it has the wrong length, a non-zero padding, a role
    /// that is not 0 or 1, or an index that is not below [`OFFER_CIPHERTEXTS`].
    fn parse(metadata: &'a [u8]) -> Option<Self> {
        if metadata.len() != METADATA_LEN || metadata[20..23] != [0, 0, 0] {
            return None;
        }
        let index = metadata[24];
        if usize::from(index) >= OFFER_CIPHERTEXTS {
            return None;
        }
        Some(Self {
            party: &metadata[..20],
            role: Role::from_byte(metadata[23])?,
            index,
        })
    }
}

/// The input policy this E3 program requires: [`offer_leaf`] and [`select_offers`].
pub fn policy() -> InputPolicy {
    InputPolicy {
        leaf: offer_leaf,
        select: select_offers,
    }
}

/// The leaf of input `index`.
///
/// The leaf of input 0, the configuration, is `keccak256(config) mod BN254`, which
/// `NegotiationProgram.validate` inserts. The leaf of every other input is
/// `sha256(keccak256(ciphertext) || commitment || party || uint40(role * 256 + index)) mod BN254`. It
/// must stay byte-identical to `NegotiationProgram.inputLeaf`, or no root will ever match. It binds
/// the bytes, because the offer proof constrains only the commitment and never sees the serialized
/// ciphertext; the commitment, so no commitment can be paired with any ciphertext; and the party,
/// the role and the index, because the selection groups the leaves by them.
///
/// The leaf does not check that the bytes open the commitment. A ciphertext that does not open it
/// still gets a leaf, since every published input must; [`select_offers`] leaves it out of the
/// computation.
pub fn offer_leaf(input: &PublishedInput) -> Result<String, ComputeError> {
    if input.index == 0 {
        return Ok(leaf_from_digest(&input.ciphertext_hash));
    }
    let commitment = input
        .commitment
        .ok_or_else(|| ComputeError::LeafCommitment {
            index: input.index,
            reason: "the negotiation publishes a commitment with every offer ciphertext".to_string(),
        })?;
    Tag::parse(input.metadata).ok_or_else(|| ComputeError::LeafCommitment {
        index: input.index,
        reason: format!(
            "expected {METADATA_LEN} bytes of party, role and index ({OFFER_CIPHERTEXTS} indices, 2 roles), got {}",
            input.metadata.len()
        ),
    })?;

    // `ciphertext_hash` is `keccak256(input.ciphertext)`, computed once by the Secure Process.
    let mut outer = Sha256::new();
    outer.update(input.ciphertext_hash.as_slice());
    outer.update(commitment);
    outer.update(input.metadata);
    Ok(leaf_from_digest(&outer.finalize()))
}

/// Which inputs the computation runs over: the configuration, and for each role one complete offer
/// whose bytes all open their commitments.
///
/// `NegotiationProgram.publishInput` inserts an offer as three consecutive leaves, with the indices
/// 0, 1, 2 of the same party and role. A run is such a group. It is complete if it has exactly the
/// three indices in order and every record has a commitment that its bytes reproduce. A run is never
/// taken in part, because an offer with a missing ciphertext is no offer. The first complete run of
/// a role is taken; the contract accepts one offer for each role, so a role has one run.
///
/// If a role has no complete run, only the configuration is selected, and the round has no output:
/// [`fhe_processor`] panics, which the server treats as a skipped round. The result is ascending by
/// index: the configuration, then the runs in leaf order.
pub fn select_offers(inputs: &[InputRecord]) -> Vec<usize> {
    let Some((_, offers)) = inputs.split_first() else {
        return Vec::new();
    };

    let mut chosen: [Option<&[InputRecord]>; 2] = [None, None];
    // A run starts at every index 0, and at every change of party or role.
    for run in offers.chunk_by(|a, b| match (Tag::parse(a.metadata), Tag::parse(b.metadata)) {
        (Some(a), Some(b)) => b.index != 0 && a.party == b.party && a.role == b.role,
        _ => false,
    }) {
        let tags: Vec<Option<Tag>> = run.iter().map(|r| Tag::parse(r.metadata)).collect();
        let complete = tags.len() == OFFER_CIPHERTEXTS
            && tags
                .iter()
                .enumerate()
                .all(|(position, tag)| tag.is_some_and(|tag| usize::from(tag.index) == position))
            && run
                .iter()
                .all(|record| record.commitment.is_some() && record.matches_commitment());
        if !complete {
            continue;
        }
        let role = tags[0].expect("a complete run is tagged").role as usize;
        chosen[role].get_or_insert(run);
    }

    let mut selected = vec![0];
    selected.extend(
        chosen
            .into_iter()
            .flatten()
            .flat_map(|run| run.iter().map(|record| record.index)),
    );
    selected.sort_unstable();
    selected
}

/// The product of two ciphertexts, before the relinearization.
fn product(a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
    a * b
}

/// The processor. See the module documentation for the formula.
///
/// Input 0 is the configuration. Then come the two offers selected by [`select_offers`], three
/// ciphertexts each, in leaf order. The role of an offer does not matter, because
/// `X0 * Y0 + X1 * Y1 + M + M'` is symmetric.
///
/// # Panics
///
/// If input 0 is not the configuration, if the number of ciphertexts is not
/// [`2 * OFFER_CIPHERTEXTS`](OFFER_CIPHERTEXTS) (a negotiation with a missing or invalid offer has no
/// output), if a ciphertext does not deserialize, or if the l-BFV relinearization key is missing.
/// A malformed round has no meaningful result, so there is nothing to recover to.
pub fn fhe_processor(inputs: FHEProcessorInput<'_>) -> Vec<u8> {
    let relinearization_key: &LBFVRelinearizationKey = inputs
        .relinearization_key
        .expect("the negotiation program requires the l-BFV relinearization key");

    let params = inputs.params;
    let (config, _) = inputs
        .ciphertexts
        .next()
        .expect("input 0 must be the negotiation configuration");
    assert_eq!(
        config, CONFIG_DOMAIN,
        "input 0 must be the negotiation configuration"
    );

    let offers: Vec<Ciphertext> = inputs
        .ciphertexts
        .map(|(bytes, _)| Ciphertext::from_bytes(&bytes, params).expect("an offer ciphertext deserializes"))
        .collect();
    assert_eq!(
        offers.len(),
        2 * OFFER_CIPHERTEXTS,
        "a negotiation needs one complete offer of each role: {} ciphertexts",
        2 * OFFER_CIPHERTEXTS
    );
    let (first, second) = offers.split_at(OFFER_CIPHERTEXTS);

    let mut tensor = &product(&first[0], &second[0]) + &product(&first[1], &second[1]);
    relinearization_key
        .relinearizes(&mut tensor)
        .expect("a sum of ct*ct products has three components");
    let masks = &first[2] + &second[2];
    (&tensor + &masks).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::layout::*;
    use super::*;
    use anyhow::Result;
    use e3_bfv_client::client::compute_ct_commitment_with_params;
    use e3_fhe_params::{BfvPreset, build_pair_for_preset, lbfv_crs_seed, lbfv_urs_seed};
    use fhe::aggregate::AggregateIter;
    use fhe::bfv::{BfvParameters, CommonRandomPolyVec, Encoding, Plaintext, SecretKey};
    use fhe::trlbfv::{
        LBFVPublicKey, PublicKeyShare, RelinKeyShare, aggregate_relinearization_key,
    };
    use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
    use serde::Deserialize;
    use std::sync::Arc;

    const PRESET: BfvPreset = BfvPreset::InsecureThresholdSimd;

    struct Fixture {
        params: Arc<BfvParameters>,
        secret_key: SecretKey,
        public_key: LBFVPublicKey,
        rlk: LBFVRelinearizationKey,
    }

    /// A single-party committee: the same key-generation path the real committee runs.
    fn fixture() -> Result<Fixture> {
        let mut rng = rand::rng();
        let (params, _) = build_pair_for_preset(PRESET)?;
        let crs = CommonRandomPolyVec::from_seed(&params, lbfv_crs_seed(PRESET).unwrap())?;
        let urs = CommonRandomPolyVec::from_seed(&params, lbfv_urs_seed(PRESET).unwrap())?;
        let secret_key = SecretKey::random(&params, &mut rng);
        let public_key_share = PublicKeyShare::contribute_with_crp(&secret_key, &crs, &mut rng)?;
        let public_key: LBFVPublicKey = [public_key_share].into_iter().aggregate()?;
        let rlk_share =
            RelinKeyShare::contribution_with_crp(&secret_key, &urs, &crs, 0, 0, &mut rng)?;
        let rlk = aggregate_relinearization_key(&[rlk_share], &public_key)?;
        Ok(Fixture {
            params,
            secret_key,
            public_key,
            rlk,
        })
    }

    fn encrypt(fixture: &Fixture, slots: &[u64]) -> Result<Vec<u8>> {
        let plaintext = Plaintext::try_encode(slots, Encoding::simd(), &fixture.params)?;
        let ciphertext: Ciphertext = fixture
            .public_key
            .try_encrypt(&plaintext, &mut rand::rng())?;
        Ok(ciphertext.to_bytes())
    }

    fn encrypt_offer(fixture: &Fixture, slots: &[Vec<u64>]) -> Result<Vec<Vec<u8>>> {
        slots.iter().map(|s| encrypt(fixture, s)).collect()
    }

    fn decrypt(fixture: &Fixture, bytes: &[u8]) -> Result<Vec<u64>> {
        let decrypted = fixture
            .secret_key
            .try_decrypt(&Ciphertext::from_bytes(bytes, &fixture.params)?)?;
        Ok(Vec::<u64>::try_decode(&decrypted, Encoding::simd())?)
    }

    /// Runs the processor over `config` and then `cts`.
    fn run(fixture: &Fixture, config: Vec<u8>, cts: Vec<Vec<u8>>) -> Vec<u8> {
        let inputs = std::iter::once(config)
            .chain(cts)
            .enumerate()
            .map(|(index, bytes)| (bytes, index as u64));
        fhe_processor(FHEProcessorInput {
            ciphertexts: &mut inputs.into_iter(),
            params: &fixture.params,
            relinearization_key: Some(&fixture.rlk),
        })
    }

    fn negotiate(fixture: &Fixture, first: &[Vec<u64>], second: &[Vec<u64>]) -> Result<Vec<u64>> {
        let cts = [encrypt_offer(fixture, first)?, encrypt_offer(fixture, second)?].concat();
        decrypt(fixture, &run(fixture, config_input(), cts))
    }

    #[derive(Deserialize)]
    struct Vectors {
        cases: Vec<Case>,
    }

    #[derive(Deserialize)]
    struct Case {
        #[serde(rename = "sellerStep")]
        seller_step: usize,
        #[serde(rename = "sellerShare")]
        seller_share: usize,
        #[serde(rename = "buyerStep")]
        buyer_step: usize,
        #[serde(rename = "buyerShare")]
        buyer_share: usize,
        seller: Vec<Vec<u64>>,
        buyer: Vec<Vec<u64>>,
        output: Vec<u64>,
        matched: bool,
        step: Option<usize>,
    }

    fn vectors() -> Vectors {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../sdk/test-vectors/layout.json");
        serde_json::from_str(&std::fs::read_to_string(path).expect("sdk/test-vectors/layout.json"))
            .expect("layout.json parses")
    }

    #[test]
    fn the_preset_has_the_slots_of_the_layout() -> Result<()> {
        let fixture = fixture()?;
        assert_eq!(fixture.params.degree(), SLOTS);
        assert_eq!(fixture.params.plaintext(), PLAINTEXT_MODULUS);
        Ok(())
    }

    #[test]
    fn the_tensor_entries_match_the_vectors() {
        let vectors = vectors();
        assert!(!vectors.cases.is_empty());
        for case in &vectors.cases {
            for (role, offer, step, share) in [
                (Role::Seller, &case.seller, case.seller_step, case.seller_share),
                (Role::Buyer, &case.buyer, case.buyer_step, case.buyer_share),
            ] {
                let [low, high] = lane_slots(role, step, share);
                assert_eq!(offer[0], low, "{role:?} step {step} share {share}");
                assert_eq!(offer[1], high, "{role:?} step {step} share {share}");
                assert!(level_sums(&offer[2]).unwrap().iter().all(|&s| s == 0));
            }
        }
    }

    #[test]
    fn the_tensor_sums_to_the_one_hot_of_the_agreed_level() {
        for s in 0..LEVELS {
            for b in 0..LEVELS {
                for a in 0..LANES {
                    for c in 0..LANES {
                        let winner = expected_outcome(s, b, a, c);
                        for i in 0..LEVELS {
                            let sum: u64 = (0..LANES)
                                .map(|theta| {
                                    tensor_entry(Role::Seller, theta, i, s, a)
                                        * tensor_entry(Role::Buyer, theta, i, b, c)
                                })
                                .sum();
                            assert_eq!(sum, u64::from(winner == Some(i)), "s={s} b={b} a={a} c={c} i={i}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn the_program_computes_the_vector_outputs() -> Result<()> {
        let fixture = fixture()?;
        for (n, case) in vectors().cases.iter().enumerate() {
            let slots = negotiate(&fixture, &case.seller, &case.buyer)?;
            assert_eq!(slots, case.output, "case {n}");
            let outcome = read_output(&slots).expect("a valid output");
            assert_eq!(outcome.is_some(), case.matched, "case {n}");
            assert_eq!(outcome, case.step, "case {n}");
            assert_eq!(
                outcome,
                expected_outcome(case.seller_step, case.buyer_step, case.seller_share, case.buyer_share),
                "case {n}"
            );
        }
        Ok(())
    }

    #[test]
    fn the_order_of_the_offers_does_not_matter() -> Result<()> {
        let fixture = fixture()?;
        let case = &vectors().cases[0];
        assert_eq!(
            negotiate(&fixture, &case.buyer, &case.seller)?,
            case.output
        );
        Ok(())
    }

    fn mask(seed: u64) -> Vec<u64> {
        let mut state = seed;
        mask_slots(|| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 33) % PLAINTEXT_MODULUS
        })
    }

    #[test]
    fn a_match_is_the_one_hot_and_no_match_is_zero() -> Result<()> {
        let fixture = fixture()?;
        let run = |s, b| -> Result<Option<usize>> {
            let seller = offer_slots(Role::Seller, s, 5, mask(1));
            let buyer = offer_slots(Role::Buyer, b, 9, mask(2));
            Ok(read_output(&negotiate(&fixture, &seller, &buyer)?).expect("a valid output"))
        };
        assert_eq!(run(3, 3)?, expected_outcome(3, 3, 5, 9));
        assert_eq!(run(3, 3)?, Some(3));
        assert_eq!(run(9, 4)?, None);
        assert_eq!(run(0, 15)?, expected_outcome(0, 15, 5, 9));
        Ok(())
    }

    #[test]
    fn the_masks_hide_the_groups() -> Result<()> {
        // With zero masks the output slots show the products. With a mask they are shifted, but
        // the level sums stay the same.
        let fixture = fixture()?;
        let zero = vec![0u64; SLOTS];
        let plain = negotiate(
            &fixture,
            &offer_slots(Role::Seller, 2, 1, zero.clone()),
            &offer_slots(Role::Buyer, 12, 7, zero),
        )?;
        let masked = negotiate(
            &fixture,
            &offer_slots(Role::Seller, 2, 1, mask(11)),
            &offer_slots(Role::Buyer, 12, 7, mask(12)),
        )?;
        assert_ne!(plain, masked);
        assert_eq!(level_sums(&plain), level_sums(&masked));
        Ok(())
    }

    #[test]
    #[should_panic(expected = "negotiation configuration")]
    fn rejects_a_round_without_the_configuration() {
        let fixture = fixture().unwrap();
        let offer = offer_slots(Role::Seller, 1, 0, mask(1));
        let ct = encrypt(&fixture, &offer[0]).unwrap();
        fhe_processor(FHEProcessorInput {
            ciphertexts: &mut std::iter::once((ct, 0)),
            params: &fixture.params,
            relinearization_key: Some(&fixture.rlk),
        });
    }

    #[test]
    #[should_panic(expected = "one complete offer of each role")]
    fn rejects_a_round_with_one_offer() {
        let fixture = fixture().unwrap();
        let offer = encrypt_offer(&fixture, &offer_slots(Role::Seller, 1, 0, mask(1))).unwrap();
        run(&fixture, config_input(), offer);
    }

    #[test]
    #[should_panic(expected = "one complete offer of each role")]
    fn rejects_a_round_with_no_offer() {
        let fixture = fixture().unwrap();
        run(&fixture, config_input(), vec![]);
    }

    #[test]
    #[should_panic(expected = "requires the l-BFV relinearization key")]
    fn rejects_a_round_without_the_relinearization_key() {
        fhe_processor(FHEProcessorInput {
            ciphertexts: &mut std::iter::empty(),
            params: &fixture().unwrap().params,
            relinearization_key: None,
        });
    }

    #[test]
    fn the_layout_reads_only_valid_outputs() {
        let mut slots = vec![0u64; SLOTS];
        assert_eq!(read_output(&slots), Some(None));
        slots[3 * LEVELS + 5] = 1;
        slots[5] = 256;
        slots[LEVELS + 5] = 1;
        assert_eq!(read_output(&slots), Some(Some(5)));
        slots[LEVELS + 6] = 1;
        assert_eq!(read_output(&slots), None);
        slots[LEVELS + 6] = 0;
        slots[5] = 2;
        assert_eq!(read_output(&slots), None);
        assert_eq!(read_output(&slots[..SLOTS - 1]), None);
    }

    #[test]
    fn the_configuration_leaf_is_the_reduced_hash_of_the_configuration() {
        // `NegotiationProgram.configLeaf` computes `keccak256(CONFIG_DOMAIN) mod BN254`.
        let config = config_input();
        assert_eq!(config, b"interfold-negotiation-config-v1");
        let zero = [0u8; 32];
        let leaf = (policy().leaf)(&PublishedInput {
            index: 0,
            ciphertext: &config,
            ciphertext_hash: e3_compute_provider::hashing::keccak256(&config),
            commitment: Some(&zero),
            metadata: &[0; METADATA_LEN],
            recomputed: None,
        })
        .unwrap();
        assert_eq!(
            leaf,
            leaf_from_digest(&e3_compute_provider::hashing::keccak256(
                b"interfold-negotiation-config-v1"
            ))
        );
    }

    /// `party || 0 0 0 || role || index`, as the runner packs it.
    fn metadata_of(party: u8, role: u8, index: u8) -> Vec<u8> {
        let parent = u64::from(role) * 256 + u64::from(index);
        [vec![party; 20], parent.to_be_bytes()[3..].to_vec()].concat()
    }

    /// The leaf of an offer ciphertext with the given parts.
    fn leaf_of(hash: [u8; 32], commitment: Option<&[u8; 32]>, metadata: &[u8]) -> Result<String, ComputeError> {
        (policy().leaf)(&PublishedInput {
            index: 1,
            ciphertext: b"unused",
            ciphertext_hash: hash,
            commitment,
            metadata,
            recomputed: None,
        })
    }

    #[test]
    fn the_offer_leaf_matches_the_solidity_vector() {
        // `NegotiationProgram.inputLeaf(h, c, party, role, index)`: sha256 of the 89 bytes
        // `h || c || party || uint40(role * 256 + index)`, mod BN254.
        let leaf = leaf_of([0x11; 32], Some(&[0x22; 32]), &metadata_of(0x33, 1, 2)).unwrap();
        let preimage = [vec![0x11; 32], vec![0x22; 32], vec![0x33; 20], vec![0, 0, 0, 1, 2]].concat();
        assert_eq!(preimage.len(), 89);
        assert_eq!(leaf, leaf_from_digest(&sha2::Sha256::digest(&preimage)));
        assert_eq!(
            format!("{leaf:0>64}"),
            "0eba2162cee5e04f2618586cb772d9e10e735f55391b893d5a351b5d2d94a9c6"
        );
    }

    #[test]
    fn the_offer_leaf_binds_every_part() {
        let commitment = [0x22; 32];
        let leaf = |hash, commitment: &[u8; 32], metadata: &[u8]| leaf_of(hash, Some(commitment), metadata).unwrap();
        let base = leaf([0x11; 32], &commitment, &metadata_of(5, 0, 1));
        assert_ne!(base, leaf([0x12; 32], &commitment, &metadata_of(5, 0, 1)));
        assert_ne!(base, leaf([0x11; 32], &[0x23; 32], &metadata_of(5, 0, 1)));
        assert_ne!(base, leaf([0x11; 32], &commitment, &metadata_of(6, 0, 1)));
        assert_ne!(base, leaf([0x11; 32], &commitment, &metadata_of(5, 1, 1)));
        assert_ne!(base, leaf([0x11; 32], &commitment, &metadata_of(5, 0, 2)));
    }

    #[test]
    fn the_offer_leaf_needs_a_commitment_and_well_formed_metadata() {
        let commitment = [0x22; 32];
        assert!(leaf_of([0x11; 32], None, &metadata_of(5, 0, 1)).is_err());
        assert!(leaf_of([0x11; 32], Some(&commitment), &[0; 24]).is_err());
        assert!(leaf_of([0x11; 32], Some(&commitment), &[0; 26]).is_err());
        // A role above 1, an index above 2 and a non-zero padding are not offers.
        assert!(leaf_of([0x11; 32], Some(&commitment), &metadata_of(5, 2, 0)).is_err());
        assert!(leaf_of([0x11; 32], Some(&commitment), &metadata_of(5, 0, 3)).is_err());
        let mut padded = metadata_of(5, 0, 0);
        padded[22] = 1;
        assert!(leaf_of([0x11; 32], Some(&commitment), &padded).is_err());
    }

    /// What the policy sees of one published offer ciphertext.
    struct Row {
        metadata: Vec<u8>,
        commitment: Option<[u8; 32]>,
        recomputed: Option<[u8; 32]>,
    }

    /// The 3 rows of an offer; `opens[i]` says whether ciphertext `i` opens its commitment.
    fn offer(party: u8, role: u8, opens: [bool; 3]) -> Vec<Row> {
        opens
            .iter()
            .enumerate()
            .map(|(index, &opens)| Row {
                metadata: metadata_of(party, role, index as u8),
                commitment: Some([1; 32]),
                recomputed: Some([if opens { 1 } else { 0xff }; 32]),
            })
            .collect()
    }

    const OPENS: [bool; 3] = [true; 3];

    /// The indices `select_offers` picks from the configuration followed by `rows`.
    fn selected(rows: &[Vec<Row>]) -> Vec<usize> {
        let zero = [0u8; 32];
        let config = std::iter::once(InputRecord {
            index: 0,
            ciphertext_hash: [0; 32],
            commitment: Some(&zero),
            metadata: &[0; METADATA_LEN],
            recomputed: Some(zero),
        });
        let records: Vec<InputRecord> = config
            .chain(rows.iter().flatten().enumerate().map(|(i, row)| InputRecord {
                index: i + 1,
                ciphertext_hash: [0; 32],
                commitment: row.commitment.as_ref(),
                metadata: &row.metadata,
                recomputed: row.recomputed,
            }))
            .collect();
        select_offers(&records)
    }

    #[test]
    fn a_complete_offer_of_each_role_is_selected() {
        assert_eq!(selected(&[offer(1, 0, OPENS), offer(2, 1, OPENS)]), [0, 1, 2, 3, 4, 5, 6]);
        assert_eq!(selected(&[offer(2, 1, OPENS), offer(1, 0, OPENS)]), [0, 1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn an_offer_with_one_bad_ciphertext_is_dropped_whole() {
        for bad in 0..3 {
            let mut opens = OPENS;
            opens[bad] = false;
            assert_eq!(selected(&[offer(1, 0, opens), offer(2, 1, OPENS)]), [0, 4, 5, 6]);
            assert_eq!(selected(&[offer(1, 0, OPENS), offer(2, 1, opens)]), [0, 1, 2, 3]);
        }
    }

    #[test]
    fn a_missing_role_leaves_only_the_configuration_for_that_role() {
        assert_eq!(selected(&[]), [0]);
        assert_eq!(selected(&[offer(1, 0, OPENS)]), [0, 1, 2, 3]);
        assert_eq!(selected(&[offer(2, 1, [false; 3])]), [0]);
    }

    #[test]
    fn an_incomplete_run_is_never_taken() {
        let mut short = offer(1, 0, OPENS);
        short.pop();
        assert_eq!(selected(&[short, offer(2, 1, OPENS)]), [0, 3, 4, 5]);
        // The indices are out of order.
        let mut shuffled = offer(1, 0, OPENS);
        shuffled.swap(0, 1);
        assert_eq!(selected(&[shuffled, offer(2, 1, OPENS)]), [0, 4, 5, 6]);
    }

    #[test]
    fn a_row_with_malformed_metadata_or_no_commitment_breaks_its_offer() {
        for length in [0, 24, 26] {
            let mut malformed = offer(1, 0, OPENS);
            malformed[1].metadata = vec![1; length];
            assert_eq!(selected(&[malformed, offer(2, 1, OPENS)]), [0, 4, 5, 6]);
        }
        let mut no_commitment = offer(1, 0, OPENS);
        no_commitment[2].commitment = None;
        assert_eq!(selected(&[no_commitment, offer(2, 1, OPENS)]), [0, 4, 5, 6]);
    }

    #[test]
    fn a_second_offer_of_a_role_is_ignored() {
        // The contract refuses it, but the selection must not mix the ciphertexts of two offers.
        assert_eq!(
            selected(&[offer(1, 0, OPENS), offer(1, 0, OPENS), offer(2, 1, OPENS)]),
            [0, 1, 2, 3, 7, 8, 9]
        );
        assert_eq!(
            selected(&[offer(1, 0, [false; 3]), offer(1, 0, OPENS), offer(2, 1, OPENS)]),
            [0, 4, 5, 6, 7, 8, 9]
        );
    }

    #[test]
    fn the_secure_process_runs_the_policy_and_the_products() -> Result<()> {
        // The seller's offer is published twice by an attacker with bytes that do not open the
        // commitment (a bad run at the front). The honest seller offer and the buyer offer count.
        use e3_compute_provider::{Batching, ComputeInput, FHEInputs, PublishedData};
        let fixture = fixture()?;
        let params = &fixture.params;
        let seller = encrypt_offer(&fixture, &offer_slots(Role::Seller, 2, 6, mask(3)))?;
        let buyer = encrypt_offer(&fixture, &offer_slots(Role::Buyer, 12, 10, mask(4)))?;
        let junk = encrypt_offer(&fixture, &offer_slots(Role::Seller, 14, 0, mask(5)))?;
        let open = |bytes: &[u8]| compute_ct_commitment_with_params(bytes, params);

        let mut ciphertexts = vec![(config_input(), 0)];
        let mut published = vec![PublishedData {
            commitment: Some([0; 32]),
            metadata: vec![],
        }];
        // The junk run carries the commitments of the honest seller ciphertexts.
        for (role, party, cts, commitments) in [
            (0u8, 1u8, &junk, [open(&seller[0])?, open(&seller[1])?, open(&seller[2])?]),
            (0, 1, &seller, [open(&seller[0])?, open(&seller[1])?, open(&seller[2])?]),
            (1, 2, &buyer, [open(&buyer[0])?, open(&buyer[1])?, open(&buyer[2])?]),
        ] {
            for (index, (bytes, commitment)) in cts.iter().zip(commitments).enumerate() {
                ciphertexts.push((bytes.clone(), ciphertexts.len() as u64));
                published.push(PublishedData {
                    commitment: Some(commitment),
                    metadata: metadata_of(party, role, index as u8),
                });
            }
        }
        // Both seller runs have the same party and role: only the first complete one counts.
        // `junk` does not open, so the second run is the first complete one.
        let committee_key = e3_bfv_client::encode_lbfv_key_envelope(
            &fixture.public_key.to_bytes(),
            &fixture.rlk.to_bytes(),
            PRESET.lbfv_label().expect("the preset has l-BFV keys"),
        )?;
        let (commitments, _) = e3_bfv_client::inspect_lbfv_key_envelope(
            &committee_key,
            PRESET.lbfv_label().unwrap(),
        )?;
        let input = ComputeInput {
            fhe_inputs: FHEInputs {
                ciphertexts,
                params: e3_fhe_params::encode_bfv_params(params),
                committee_key,
            },
            published,
        };
        let (_, output, selected) = input
            .run_bound_selected(
                fhe_processor,
                policy(),
                Some(commitments.envelope),
                Batching::Sequential,
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        assert_eq!(selected, [0, 4, 5, 6, 7, 8, 9]);
        let slots = decrypt(&fixture, &output)?;
        assert_eq!(read_output(&slots), Some(expected_outcome(2, 12, 6, 10)));
        Ok(())
    }
}
