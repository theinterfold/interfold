// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The FHE program of the sealed-cca example: a sealed, one-batch, uniform-price token sale.
//!
//! Input 0 of a round is its configuration, [`config_input`]: the domain bytes and the reveal mode.
//! It is not a ciphertext. `SealedCcaProgram.validate` inserts its leaf, so the compute proof binds
//! the reveal mode through the input root.
//!
//! Each bid is ONE ciphertext. The SIMD plaintext of a bid has 128 slots:
//!
//! ```text
//! slot l, l in 0..LEVELS     1 if l <= b else 0   (the thermometer of the max price step b)
//! slot COUNTED_BASE + i      the version of the bid (1..=MAX_VERSION), i the bidder index
//! every other slot           0
//! ```
//!
//! The contract assigns the bidder index `i` at the deposit of the bidder, and the bid proof binds
//! the index and the version into the plaintext, so the program needs no metadata of its own.
//!
//! `SealedCcaProgram.publishInput` inserts one leaf per bid. A bidder may bid again (an update), so
//! the tree can hold several bids of one bidder. The policy picks for each bidder its latest bid
//! whose bytes open the commitment (see [`select_bids`]). The processor then receives one
//! ciphertext per chosen bid, in leaf order, and returns their homomorphic sum. Each bidder has
//! one chosen bid, so after decryption:
//!
//! ```text
//! slot l, l in 0..LEVELS     c_l: the number of counted bidders with b >= l
//! slot COUNTED_BASE + i      the counted version of bidder i, or 0 if no bid of the bidder counts
//! ```
//!
//! The count of a slot is at most [`MAX_BIDDERS`], which is below the plaintext modulus `t = 257`,
//! so no slot wraps. The decryption is verified on chain, so the counted set needs no extra trust.
//! The program needs no key: the sum is a plain ciphertext addition.
//!
//! The slot layout lives in [`layout`] only. `SealedCcaProgram` (Solidity) and `sdk/src/layout.ts`
//! decode the same layout, and their tests check it against these functions.

use e3_compute_provider::policy::{InputRecord, leaf_from_digest};
use e3_compute_provider::{ComputeError, FHEProcessorInput, InputPolicy, PublishedInput};
use fhe::bfv::Ciphertext;
use fhe_traits::{DeserializeParametrized, Serialize};
#[cfg(feature = "openvm-hashes")]
use openvm_sha2::Sha256;
#[cfg(not(all(feature = "openvm-hashes", target_os = "zkvm")))]
use sha2::Digest;
#[cfg(not(feature = "openvm-hashes"))]
use sha2::Sha256;
use std::collections::BTreeMap;

/// The slot layout of a bid and of the output. The single place of this language.
pub mod layout {
    /// The number of price slots, which is the most price steps a sale has: `L <= LEVELS`.
    pub const LEVELS: usize = 16;

    /// The slot of the counted version of bidder 0. Bidder `i` is at `COUNTED_BASE + i`.
    pub const COUNTED_BASE: usize = LEVELS;

    /// The number of slots of the plaintext (the degree of the insecure-simd preset).
    pub const SLOTS: usize = 128;

    /// The most bidders of a sale: the slots after the price slots.
    pub const MAX_BIDDERS: usize = SLOTS - COUNTED_BASE;

    /// The most versions of one bidder (the first bid and two updates).
    pub const MAX_VERSION: u64 = 3;

    /// The slots of a bid of the step `b` for bidder `index` and bid `version`, over `slots`
    /// slots: the thermometer, and the version in the slot of the bidder.
    ///
    /// # Panics
    ///
    /// If `b >= LEVELS`, `index >= MAX_BIDDERS`, `version` is not in `1..=MAX_VERSION` or `slots`
    /// is smaller than [`SLOTS`].
    pub fn bid_slots(slots: usize, b: usize, index: usize, version: u64) -> Vec<u64> {
        assert!(b < LEVELS, "the step {b} is not below {LEVELS}");
        assert!(
            index < MAX_BIDDERS,
            "the bidder index {index} is not below {MAX_BIDDERS}"
        );
        assert!(
            (1..=MAX_VERSION).contains(&version),
            "the version {version} is not in 1..={MAX_VERSION}"
        );
        assert!(slots >= SLOTS, "a bid has {SLOTS} slots, got {slots}");
        let mut out = vec![0u64; slots];
        out[..=b].fill(1);
        out[COUNTED_BASE + index] = version;
        out
    }

    /// What the decrypted output holds.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Output {
        /// `counts[l]` is the number of counted bidders with `b >= l`.
        pub counts: [u64; LEVELS],
        /// `counted[i]` is the counted version of bidder `i`, or 0.
        pub counted: [u64; MAX_BIDDERS],
    }

    /// Reads the decrypted slots. `None` if there are fewer than [`SLOTS`] of them.
    pub fn decode_output(slots: &[u64]) -> Option<Output> {
        if slots.len() < SLOTS {
            return None;
        }
        Some(Output {
            counts: slots[..LEVELS].try_into().ok()?,
            counted: slots[COUNTED_BASE..SLOTS].try_into().ok()?,
        })
    }
}

pub use layout::{COUNTED_BASE, LEVELS, MAX_BIDDERS, MAX_VERSION, SLOTS};

/// The prefix of the configuration input. `SealedCcaProgram.CONFIG_DOMAIN` is the same bytes.
pub const CONFIG_DOMAIN: &[u8] = b"interfold-sealed-cca-config-v1";

/// What the sale reveals. The values are the `uint8` that `SealedCcaProgram` stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RevealMode {
    /// The demand curve and the counted version of each bidder.
    DemandCurve = 0,
}

impl RevealMode {
    /// The mode of a configuration input, or `None` if `input` is not one.
    pub fn from_config(input: &[u8]) -> Option<Self> {
        match input.strip_prefix(CONFIG_DOMAIN)? {
            [0] => Some(Self::DemandCurve),
            _ => None,
        }
    }
}

/// Input 0 of a round: the domain bytes followed by the reveal mode byte.
pub fn config_input(mode: RevealMode) -> Vec<u8> {
    [CONFIG_DOMAIN, &[mode as u8]].concat()
}

/// The metadata `SealedCcaProgram` publishes with each bid ciphertext: the 20-byte bidder, then the
/// 5-byte bid version, as `abi.encodePacked(address, uint40)` lays it out.
///
/// The program server builds it from `input_slots` (the bidder) and `input_parents` (the version).
/// The configuration at index 0 gets a zero commitment, a zero slot and the parent 0; its leaf
/// ignores them.
const METADATA_LEN: usize = 25;

/// The input policy this E3 program requires: [`bid_leaf`] and [`select_bids`].
pub fn policy() -> InputPolicy {
    InputPolicy {
        leaf: bid_leaf,
        select: select_bids,
    }
}

/// The leaf of input `index`.
///
/// The leaf of input 0, the configuration, is `keccak256(config) mod BN254`, which
/// `SealedCcaProgram.validate` inserts. The leaf of every other input is
/// `sha256(keccak256(ciphertext) || commitment || bidder || uint40(version)) mod BN254`. It must stay
/// byte-identical to `SealedCcaProgram.inputLeaf`, or no root will ever match. It binds the bytes,
/// because the bid proof constrains only the commitment and never sees the serialized ciphertext;
/// the commitment, so no commitment can be paired with any ciphertext; and the bidder and the
/// version, because selection groups the leaves by them.
///
/// The leaf does not check that the bytes open the commitment. A ciphertext that does not open it
/// still gets a leaf, since every published input must; [`select_bids`] leaves it out of the
/// computation.
pub fn bid_leaf(input: &PublishedInput) -> Result<String, ComputeError> {
    if input.index == 0 {
        return Ok(leaf_from_digest(&input.ciphertext_hash));
    }
    let commitment = input
        .commitment
        .ok_or_else(|| ComputeError::LeafCommitment {
            index: input.index,
            reason: "the sale publishes a commitment with every bid ciphertext".to_string(),
        })?;
    if input.metadata.len() != METADATA_LEN {
        return Err(ComputeError::LeafCommitment {
            index: input.index,
            reason: format!(
                "expected {METADATA_LEN} bytes of bidder and version, got {}",
                input.metadata.len()
            ),
        });
    }

    // `ciphertext_hash` is `keccak256(input.ciphertext)`, computed once by the Secure Process.
    let mut outer = Sha256::new();
    outer.update(input.ciphertext_hash.as_slice());
    outer.update(commitment);
    outer.update(input.metadata);
    Ok(leaf_from_digest(&outer.finalize()))
}

/// Which inputs the computation runs over: the configuration, and for each bidder its latest bid
/// whose bytes open the commitment.
///
/// A bidder may bid up to a few times; each bid has the next version and one leaf. For every bidder
/// this keeps the leaf with the highest version that has a commitment and reproduces it. A bidder
/// with no such leaf is dropped.
///
/// The contract cannot check that published bytes open a commitment, so any submitter can publish
/// a bid that does not. That bid is skipped, and an earlier valid bid of the same bidder counts. A
/// bidder can also withdraw this way, and it learns nothing from doing so.
///
/// A record whose metadata is not [`METADATA_LEN`] bytes is never taken. The result is ascending by
/// index, and the configuration (input 0) is always in it.
pub fn select_bids(inputs: &[InputRecord]) -> Vec<usize> {
    let Some((_, bids)) = inputs.split_first() else {
        return Vec::new();
    };

    // The best leaf so far of each bidder: its version bytes and its index.
    let mut latest: BTreeMap<&[u8], (&[u8], usize)> = BTreeMap::new();
    for record in bids {
        if record.metadata.len() != METADATA_LEN
            || record.commitment.is_none()
            || !record.matches_commitment()
        {
            continue;
        }
        let (bidder, version) = record.metadata.split_at(20);
        // Versions are big-endian of one fixed width, so comparing the bytes compares the numbers.
        if latest
            .get(bidder)
            .is_none_or(|(chosen, _)| *chosen < version)
        {
            latest.insert(bidder, (version, record.index));
        }
    }

    let mut selected = vec![0];
    selected.extend(latest.into_values().map(|(_, index)| index));
    selected.sort_unstable();
    selected
}

/// The processor: the homomorphic sum of the selected bid ciphertexts. See the module
/// documentation for the layout of the result.
///
/// Input 0 is the configuration, and every other input is one chosen bid, in leaf order. The bids
/// are summed in that order. The sum needs no key.
///
/// # Panics
///
/// If input 0 is not a configuration, if there is no bid (a sale with no counted bidder has no
/// output), or if there are more than [`MAX_BIDDERS`] bids. A malformed round has no meaningful
/// result, so there is nothing to recover to.
pub fn fhe_processor(inputs: FHEProcessorInput<'_>) -> Vec<u8> {
    let params = inputs.params;
    let (config, _) = inputs
        .ciphertexts
        .next()
        .expect("input 0 must be the sale configuration");
    RevealMode::from_config(&config).expect("input 0 must be the sale configuration");

    let mut sum: Option<Ciphertext> = None;
    let mut bids = 0usize;
    for (bytes, _) in inputs.ciphertexts {
        bids += 1;
        assert!(
            bids <= MAX_BIDDERS,
            "a sale has at most {MAX_BIDDERS} bidders"
        );
        let ciphertext = Ciphertext::from_bytes(&bytes, params).expect("a chosen bid deserializes");
        sum = Some(match sum {
            Some(acc) => &acc + &ciphertext,
            None => ciphertext,
        });
    }
    sum.expect("a sale needs one bid at least").to_bytes()
}

#[cfg(test)]
mod tests {
    use super::layout::*;
    use super::*;
    use anyhow::Result;
    use e3_fhe_params::{BfvPreset, build_pair_for_preset, lbfv_crs_seed};
    use fhe::aggregate::AggregateIter;
    use fhe::bfv::{BfvParameters, CommonRandomPolyVec, Encoding, Plaintext, SecretKey};
    use fhe::trlbfv::{LBFVPublicKey, PublicKeyShare};
    use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
    use std::sync::Arc;

    const PRESET: BfvPreset = BfvPreset::InsecureThresholdSimd;

    struct Fixture {
        params: Arc<BfvParameters>,
        secret_key: SecretKey,
        public_key: LBFVPublicKey,
    }

    /// A single-party committee: the same key-generation path the real committee runs. The sum
    /// needs no relinearization key.
    fn fixture() -> Result<Fixture> {
        let mut rng = rand::rng();
        let (params, _) = build_pair_for_preset(PRESET)?;
        let crs = CommonRandomPolyVec::from_seed(&params, lbfv_crs_seed(PRESET).unwrap())?;
        let secret_key = SecretKey::random(&params, &mut rng);
        let share = PublicKeyShare::contribute_with_crp(&secret_key, &crs, &mut rng)?;
        let public_key: LBFVPublicKey = [share].into_iter().aggregate()?;
        Ok(Fixture {
            params,
            secret_key,
            public_key,
        })
    }

    fn encrypt(fixture: &Fixture, slots: &[u64]) -> Result<Vec<u8>> {
        let plaintext = Plaintext::try_encode(slots, Encoding::simd(), &fixture.params)?;
        let ciphertext: Ciphertext = fixture
            .public_key
            .try_encrypt(&plaintext, &mut rand::rng())?;
        Ok(ciphertext.to_bytes())
    }

    fn decrypt(fixture: &Fixture, bytes: &[u8]) -> Result<Vec<u64>> {
        let decrypted = fixture
            .secret_key
            .try_decrypt(&Ciphertext::from_bytes(bytes, &fixture.params)?)?;
        Ok(Vec::<u64>::try_decode(&decrypted, Encoding::simd())?)
    }

    /// Runs the processor over the configuration and then `bids`.
    fn run(fixture: &Fixture, config: Vec<u8>, bids: Vec<Vec<u8>>) -> Vec<u8> {
        let inputs = std::iter::once(config)
            .chain(bids)
            .enumerate()
            .map(|(index, bytes)| (bytes, index as u64));
        fhe_processor(FHEProcessorInput {
            ciphertexts: &mut inputs.into_iter(),
            params: &fixture.params,
            relinearization_key: None,
        })
    }

    /// `(b, bidder index, version)` of each bid.
    fn sale(fixture: &Fixture, bids: &[(usize, usize, u64)]) -> Result<Vec<u64>> {
        let cts = bids
            .iter()
            .map(|&(b, index, version)| {
                encrypt(
                    fixture,
                    &bid_slots(fixture.params.degree(), b, index, version),
                )
            })
            .collect::<Result<Vec<_>>>()?;
        decrypt(
            fixture,
            &run(fixture, config_input(RevealMode::DemandCurve), cts),
        )
    }

    #[test]
    fn the_preset_has_the_slots_of_the_layout() -> Result<()> {
        assert_eq!(fixture()?.params.degree(), SLOTS);
        assert!(fixture()?.params.plaintext() > MAX_BIDDERS as u64);
        Ok(())
    }

    #[test]
    fn the_output_counts_each_step_and_holds_each_counted_version() -> Result<()> {
        let fixture = fixture()?;
        // Bidders 0, 1, 2 with the steps 5, 12, 5; bidder 1 is at version 2.
        let slots = sale(&fixture, &[(5, 0, 1), (12, 1, 2), (5, 2, 1)])?;
        let output = decode_output(&slots).unwrap();
        let expected = |l: usize| [5usize, 12, 5].iter().filter(|&&b| b >= l).count() as u64;
        for l in 0..LEVELS {
            assert_eq!(output.counts[l], expected(l), "c_{l}");
        }
        assert_eq!(output.counted[..4], [1, 2, 1, 0]);
        assert!(output.counted[3..].iter().all(|&v| v == 0));
        Ok(())
    }

    #[test]
    fn a_bidder_that_is_not_selected_leaves_zero_in_its_slot() -> Result<()> {
        let fixture = fixture()?;
        // Bidder 1 is dropped: no ciphertext of it reaches the processor.
        let slots = sale(&fixture, &[(0, 0, 1), (15, 2, 3)])?;
        let output = decode_output(&slots).unwrap();
        assert_eq!(output.counted[..3], [1, 0, 3]);
        assert_eq!(output.counts[0], 2);
        assert_eq!(output.counts[1], 1);
        assert_eq!(output.counts[15], 1);
        Ok(())
    }

    #[test]
    fn the_last_bidder_slot_and_the_most_bidders_do_not_wrap() -> Result<()> {
        let fixture = fixture()?;
        let bids: Vec<(usize, usize, u64)> = (0..MAX_BIDDERS).map(|i| (15, i, 3)).collect();
        let output = decode_output(&sale(&fixture, &bids)?).unwrap();
        assert!(output.counts.iter().all(|&c| c == MAX_BIDDERS as u64));
        assert!(output.counted.iter().all(|&v| v == 3));
        Ok(())
    }

    #[test]
    fn the_layout_places_the_thermometer_and_the_version() {
        let slots = bid_slots(SLOTS, 2, 5, 3);
        assert_eq!(slots.len(), SLOTS);
        assert_eq!(slots[..4], [1, 1, 1, 0]);
        assert_eq!(slots[COUNTED_BASE + 5], 3);
        assert_eq!(slots.iter().filter(|&&v| v != 0).count(), 4);
        let output = decode_output(&slots).unwrap();
        assert_eq!(output.counts[..4], [1, 1, 1, 0]);
        assert_eq!(output.counted[5], 3);
        assert!(decode_output(&slots[..SLOTS - 1]).is_none());
    }

    #[test]
    #[should_panic(expected = "bidder index")]
    fn a_bid_rejects_the_bidder_after_the_last() {
        bid_slots(SLOTS, 0, MAX_BIDDERS, 1);
    }

    #[test]
    #[should_panic(expected = "sale configuration")]
    fn rejects_a_round_without_the_configuration() {
        let fixture = fixture().unwrap();
        let ct = encrypt(&fixture, &bid_slots(SLOTS, 1, 0, 1)).unwrap();
        fhe_processor(FHEProcessorInput {
            ciphertexts: &mut std::iter::once((ct, 0)),
            params: &fixture.params,
            relinearization_key: None,
        });
    }

    #[test]
    #[should_panic(expected = "one bid at least")]
    fn rejects_a_round_without_a_bid() {
        let fixture = fixture().unwrap();
        run(&fixture, config_input(RevealMode::DemandCurve), vec![]);
    }

    #[test]
    fn the_configuration_names_the_reveal_mode() {
        assert_eq!(
            RevealMode::from_config(&[CONFIG_DOMAIN, &[0]].concat()),
            Some(RevealMode::DemandCurve)
        );
        assert_eq!(
            RevealMode::from_config(&[CONFIG_DOMAIN, &[1]].concat()),
            None
        );
        assert_eq!(RevealMode::from_config(&CONFIG_DOMAIN[1..]), None);
    }

    #[test]
    fn the_configuration_leaf_is_the_reduced_hash_of_the_configuration() {
        // `SealedCcaProgram.configLeaf` computes `keccak256(CONFIG_DOMAIN || mode) mod BN254`.
        let config = config_input(RevealMode::DemandCurve);
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
                b"interfold-sealed-cca-config-v1\x00"
            ))
        );
    }

    /// The leaf of a bid ciphertext with the given parts.
    fn leaf_of(
        hash: [u8; 32],
        commitment: Option<&[u8; 32]>,
        metadata: &[u8],
        recomputed: Option<[u8; 32]>,
    ) -> Result<String, ComputeError> {
        (policy().leaf)(&PublishedInput {
            index: 1,
            ciphertext: b"unused",
            ciphertext_hash: hash,
            commitment,
            metadata,
            recomputed,
        })
    }

    #[test]
    fn the_bid_leaf_matches_the_solidity_vector() {
        // `SealedCcaProgram.inputLeaf(h, c, bidder, version)` for this input is the same number.
        // The auction example computes the same function, so the vector is the same.
        let metadata = [vec![0x33; 20], 2u64.to_be_bytes()[3..].to_vec()].concat();
        let leaf = leaf_of([0x11; 32], Some(&[0x22; 32]), &metadata, None).unwrap();
        assert_eq!(
            format!("{leaf:0>64}"),
            "0b8ba63e8917dfb3f66cfcc1b0be5d3a8f8613ba8092d690a43b84daec02b94a"
        );
    }

    #[test]
    fn the_bid_leaf_binds_every_part_and_ignores_whether_the_bytes_open() {
        let commitment = [0x22; 32];
        let metadata = metadata_of(5, 1);
        let leaf = |hash, commitment: &[u8; 32], metadata: &[u8], recomputed| {
            leaf_of(hash, Some(commitment), metadata, recomputed).unwrap()
        };
        let base = leaf([0x11; 32], &commitment, &metadata, None);
        assert_eq!(
            base,
            leaf([0x11; 32], &commitment, &metadata, Some([9; 32]))
        );
        assert_ne!(base, leaf([0x12; 32], &commitment, &metadata, None));
        assert_ne!(base, leaf([0x11; 32], &[0x23; 32], &metadata, None));
        assert_ne!(
            base,
            leaf([0x11; 32], &commitment, &metadata_of(6, 1), None)
        );
        assert_ne!(
            base,
            leaf([0x11; 32], &commitment, &metadata_of(5, 2), None)
        );
    }

    #[test]
    fn the_bid_leaf_needs_a_commitment_and_25_bytes_of_metadata() {
        let commitment = [0x22; 32];
        assert!(leaf_of([0x11; 32], None, &metadata_of(5, 1), None).is_err());
        assert!(leaf_of([0x11; 32], Some(&commitment), &[0; 24], None).is_err());
        assert!(leaf_of([0x11; 32], Some(&commitment), &[0; 26], None).is_err());
    }

    /// `bidder || uint40(version)`, as the contract publishes it.
    fn metadata_of(bidder: u8, version: u64) -> Vec<u8> {
        [vec![bidder; 20], version.to_be_bytes()[3..].to_vec()].concat()
    }

    /// What the policy sees of one published bid ciphertext.
    struct Row {
        metadata: Vec<u8>,
        commitment: Option<[u8; 32]>,
        recomputed: Option<[u8; 32]>,
    }

    fn bid(bidder: u8, version: u64, opens: bool) -> Row {
        Row {
            metadata: metadata_of(bidder, version),
            commitment: Some([1; 32]),
            recomputed: Some([if opens { 1 } else { 0xff }; 32]),
        }
    }

    /// The indices `select_bids` picks from the configuration followed by `rows`.
    fn selected(rows: &[Row]) -> Vec<usize> {
        let zero = [0u8; 32];
        let config = std::iter::once(InputRecord {
            index: 0,
            ciphertext_hash: [0; 32],
            commitment: Some(&zero),
            metadata: &[0; METADATA_LEN],
            recomputed: Some(zero),
        });
        let records: Vec<InputRecord> = config
            .chain(rows.iter().enumerate().map(|(i, row)| InputRecord {
                index: i + 1,
                ciphertext_hash: [0; 32],
                commitment: row.commitment.as_ref(),
                metadata: &row.metadata,
                recomputed: row.recomputed,
            }))
            .collect();
        select_bids(&records)
    }

    #[test]
    fn the_latest_valid_version_of_a_bidder_is_selected() {
        assert_eq!(
            selected(&[bid(1, 1, true), bid(1, 2, true), bid(1, 3, true)]),
            [0, 3]
        );
    }

    #[test]
    fn a_bidder_falls_back_to_an_earlier_version_when_the_latest_does_not_open() {
        assert_eq!(selected(&[bid(1, 1, true), bid(1, 2, false)]), [0, 1]);
        // The first usable one counts, not the first one.
        assert_eq!(
            selected(&[bid(1, 1, true), bid(1, 2, true), bid(1, 3, false)]),
            [0, 2]
        );
        assert_eq!(
            selected(&[bid(1, 1, false), bid(1, 2, true), bid(1, 3, false)]),
            [0, 2]
        );
    }

    #[test]
    fn a_bidder_with_no_bid_that_opens_is_dropped() {
        assert_eq!(selected(&[bid(1, 1, false), bid(2, 1, true)]), [0, 2]);
        assert_eq!(selected(&[bid(1, 1, false), bid(1, 2, false)]), [0]);
    }

    #[test]
    fn bidders_are_ordered_by_the_leaf_of_the_selected_bid() {
        // bidder 1: leaves 1 and 3, bidder 2: leaf 2. Bidder 1 counts at its update (leaf 3).
        assert_eq!(
            selected(&[bid(1, 1, true), bid(2, 1, true), bid(1, 2, true)]),
            [0, 2, 3]
        );
    }

    #[test]
    fn the_configuration_is_always_selected() {
        assert_eq!(selected(&[]), [0]);
        assert_eq!(selected(&[bid(1, 1, false)]), [0]);
    }

    #[test]
    fn a_bid_with_malformed_metadata_or_no_commitment_is_never_selected() {
        for length in [0, 24, 26] {
            let mut malformed = bid(1, 1, true);
            malformed.metadata = vec![1; length];
            assert_eq!(selected(&[malformed, bid(2, 1, true)]), [0, 2]);
        }
        let mut no_commitment = bid(1, 1, true);
        no_commitment.commitment = None;
        assert_eq!(selected(&[no_commitment, bid(2, 1, true)]), [0, 2]);
    }

    #[test]
    fn the_secure_process_runs_the_policy_and_the_sum_over_the_selected_bids() -> Result<()> {
        // Bidder 0 bids twice, and its second ciphertext does not open its commitment: the first
        // one counts. Bidder 1 bids once. The output holds the two counted versions.
        use e3_bfv_client::client::compute_ct_commitment_with_params;
        use e3_compute_provider::{Batching, ComputeInput, FHEInputs, PublishedData};
        let fixture = fixture()?;
        let degree = fixture.params.degree();
        let cts = [
            encrypt(&fixture, &bid_slots(degree, 3, 0, 1))?,
            encrypt(&fixture, &bid_slots(degree, 9, 0, 2))?,
            encrypt(&fixture, &bid_slots(degree, 6, 1, 1))?,
        ];
        let open = |bytes: &[u8]| compute_ct_commitment_with_params(bytes, &fixture.params);
        // Leaf 2 carries the commitment of the bytes of leaf 1: its own bytes do not open it.
        let commitments = [open(&cts[0])?, open(&cts[0])?, open(&cts[2])?];
        let metadata = [metadata_of(1, 1), metadata_of(1, 2), metadata_of(2, 1)];
        let mut published = vec![PublishedData {
            commitment: Some([0; 32]),
            metadata: vec![],
        }];
        for (commitment, metadata) in commitments.into_iter().zip(metadata) {
            published.push(PublishedData {
                commitment: Some(commitment),
                metadata,
            });
        }
        let ciphertexts: Vec<(Vec<u8>, u64)> =
            std::iter::once(config_input(RevealMode::DemandCurve))
                .chain(cts.iter().cloned())
                .enumerate()
                .map(|(i, bytes)| (bytes, i as u64))
                .collect();
        let input = ComputeInput {
            fhe_inputs: FHEInputs {
                ciphertexts,
                params: e3_fhe_params::encode_bfv_params(&fixture.params),
                committee_key: vec![],
            },
            published,
        };
        let (_, output, selected) = input
            .run_selected(fhe_processor, policy(), Batching::Sequential)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        assert_eq!(selected, [0, 1, 3]);
        let output = decode_output(&decrypt(&fixture, &output)?).unwrap();
        assert_eq!(output.counted[..3], [1, 1, 0]);
        let expected = |l: usize| [3usize, 6].iter().filter(|&&b| b >= l).count() as u64;
        for l in 0..LEVELS {
            assert_eq!(output.counts[l], expected(l), "c_{l}");
        }
        Ok(())
    }
}
