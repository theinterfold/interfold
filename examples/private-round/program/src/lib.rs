// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The FHE program of the private-round example: a sealed round for at most 13 bidders that reveals
//! the clearing step and nothing else about the demand.
//!
//! Every bidder wants one lot and bids a price step `b`. The creator sells `lots` lots (`K`), has a
//! reserve step `rho` and a minimum raise of `min_lots` lots (`m`). With `c_l` the number of counted
//! bidders with `b >= l`, the round decides:
//!
//! ```text
//! gate        G   = [c_rho >= m]
//! lane l      A_l = [c_l >= K]        for l in rho..levels
//! ```
//!
//! `A_l` does not increase with `l`. If `G` is 0 the reserve is not met. If `A_rho` is 0 the round is
//! undersubscribed. Otherwise it sells out at `l* = max{ l : A_l = 1 }`. The program reveals only
//! these flags. It never reveals a count.
//!
//! # Input 0: the configuration
//!
//! Input 0 of a round is its configuration, [`config_input`]: the domain bytes, then `levels`,
//! `reserve_step`, `lots` and `min_lots` as one byte each. It is not a ciphertext.
//! `PrivateRoundProgram.validate` inserts its leaf, so the compute proof binds the parameters
//! through the input root.
//!
//! # The bid: two ciphertexts
//!
//! A bid has [`ROLES`] ciphertexts, both SIMD-encoded over 128 slots. `PrivateRoundProgram.publishInput`
//! verifies one proof for the whole bid and inserts two consecutive leaves with the same metadata.
//!
//! ```text
//! role 0 "bid"   slot g * LEVELS + l      1 if l <= b else 0    (g in 0..COPIES: six copies of the thermometer)
//!                slot GATE_BASE + k       1 if b >= rho else 0  (k in 0..GATE_COPIES)
//!                slot VERSION_BASE + i    the version of the bid, i the bidder index
//!                every other slot         0
//! role 1 "mask"  every slot               uniform in 0..t, chosen by the bidder
//! ```
//!
//! # The program
//!
//! With `C` the sum of the bid ciphertexts and `R` the sum of the masks, a lane slot of `C` holds the
//! count `c` of its lane. For each lane slot the program computes `R * prod_j (c - z_j)`, where the
//! `z_j` are the zeros of a polynomial that is zero on exactly one side of the threshold `theta` (`K` for a
//! price lane, `m` for a gate lane). With `n` counted bidders the two sides are
//!
//! ```text
//! direct       {0, ..., theta - 1}    zero  <=>  c < theta     theta factors
//! complement   {theta, ..., n}        zero  <=>  c >= theta    n + 1 - theta factors (none if theta > n)
//! ```
//!
//! The program takes the side with fewer factors ([`layout::uses_complement_side`]). Both lane kinds
//! then have at most `min(theta, n + 1 - theta) <= 7` factors for `n <= 13`. A lane with fewer
//! factors than the largest repeats its first zero, which keeps its zeros. One balanced product tree
//! over the factors and the mask has at most 8 leaves, so the depth is 3 and there are at most 7
//! ct*ct products, all relinearized with the threshold l-BFV key.
//!
//! Where the product is not zero, the slot is uniform: `R` is uniform if one bidder is honest, and a
//! nonzero factor does not change that. Where it is zero the slot is zero. So after decryption each
//! lane slot only says zero or nonzero. A lane copy is falsely zero with the probability `1 / 257`.
//! The six copies of a lane must all be zero to count: the probability is `257^-6`.
//!
//! The output also carries the counted version of each bidder in the slot `VERSION_BASE + i`,
//! copied from `C`. The contract needs it to know which bid counted.
//!
//! The slot layout lives in [`layout`] only. `PrivateRoundProgram` (Solidity) and `sdk/src/layout.ts`
//! decode the same layout, and their tests check it against these functions.

use e3_compute_provider::policy::{InputRecord, leaf_from_digest};
use e3_compute_provider::{ComputeError, FHEProcessorInput, InputPolicy, PublishedInput};
use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext};
use fhe::trlbfv::LBFVRelinearizationKey;
use fhe_traits::{DeserializeParametrized, FheEncoder, Serialize};
#[cfg(feature = "openvm-hashes")]
use openvm_sha2::Sha256;
#[cfg(not(all(feature = "openvm-hashes", target_os = "zkvm")))]
use sha2::Digest;
#[cfg(not(feature = "openvm-hashes"))]
use sha2::Sha256;
use std::collections::BTreeMap;
use std::sync::Arc;

/// The slot layout of a bid and of the output, and its decoder. The single place of this language.
pub mod layout {
    /// The number of price slots of one thermometer, which is the most price steps of a round.
    pub const LEVELS: usize = 16;

    /// The copies of every lane.
    pub const COPIES: usize = 6;

    /// The first slot of the gate lanes.
    pub const GATE_BASE: usize = COPIES * LEVELS;

    /// The number of gate lanes.
    pub const GATE_COPIES: usize = COPIES;

    /// The number of slots of the plaintext (the degree of the insecure-simd preset).
    pub const SLOTS: usize = 128;

    /// The most bidders of a round. It keeps the lane polynomial at 8 leaves: depth 3.
    pub const MAX_BIDDERS: usize = 13;

    /// The slot of the version of bidder 0. Bidder `i` is at `VERSION_BASE + i`.
    pub const VERSION_BASE: usize = SLOTS - MAX_BIDDERS;

    /// The most versions of one bidder (the first bid and two updates).
    pub const MAX_VERSION: u64 = 3;

    /// The most lots of a round.
    pub const MAX_LOTS: usize = MAX_BIDDERS - 1;

    /// The public parameters of a round.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct RoundParams {
        /// The number of price steps, 2 to [`LEVELS`].
        pub levels: usize,
        /// The reserve step, below `levels`.
        pub reserve_step: usize,
        /// The lots for sale, 1 to [`MAX_LOTS`].
        pub lots: usize,
        /// The fewest bidders at the reserve step or above, 1 to `lots`.
        pub min_lots: usize,
    }

    impl RoundParams {
        /// Why the parameters are not valid, or `None`.
        pub fn error(&self) -> Option<String> {
            if !(2..=LEVELS).contains(&self.levels) {
                return Some(format!("levels {} is not in 2..={LEVELS}", self.levels));
            }
            if self.reserve_step >= self.levels {
                return Some(format!(
                    "the reserve step {} is not below {}",
                    self.reserve_step, self.levels
                ));
            }
            if !(1..=MAX_LOTS).contains(&self.lots) {
                return Some(format!("lots {} is not in 1..={MAX_LOTS}", self.lots));
            }
            if !(1..=self.lots).contains(&self.min_lots) {
                return Some(format!(
                    "the minimum raise {} is not in 1..={}",
                    self.min_lots, self.lots
                ));
            }
            None
        }
    }

    /// The number of zeros of the lane polynomial with the threshold `theta` for `n` counted
    /// bidders: `n + 1 - theta` (at least 0) on the complement side, `theta` on the direct side.
    pub fn zero_set_size(theta: usize, n: usize, complement: bool) -> usize {
        if complement {
            (n + 1).saturating_sub(theta)
        } else {
            theta
        }
    }

    /// Whether the lane polynomial uses the complement side `{theta, ..., n}`: the side with fewer
    /// zeros, and the direct side `{0, ..., theta - 1}` if both are as big. On the complement side a
    /// zero lane means `c >= theta`, on the direct side it means `c < theta`.
    pub fn uses_complement_side(theta: usize, n: usize) -> bool {
        zero_set_size(theta, n, true) < zero_set_size(theta, n, false)
    }

    /// The zeros of the lane polynomial with the threshold `theta` for `n` counted bidders.
    pub fn zero_set(theta: usize, n: usize) -> Vec<u64> {
        let (from, to) = if uses_complement_side(theta, n) {
            (theta, n + 1)
        } else {
            (0, theta)
        };
        (from..to).map(|z| z as u64).collect()
    }

    /// The number of factors of the lane polynomial: the larger of the price lane and the gate lane.
    pub fn lane_factors(round: &RoundParams, n: usize) -> usize {
        [round.lots, round.min_lots]
            .into_iter()
            .map(|theta| zero_set_size(theta, n, uses_complement_side(theta, n)))
            .max()
            .unwrap_or(0)
    }

    /// The slots of the price lane of step `level` in copy `copy`.
    pub fn price_slot(copy: usize, level: usize) -> usize {
        copy * LEVELS + level
    }

    /// The slots of the bid ciphertext (role 0) of the step `b` for bidder `index` and bid
    /// `version`, over `slots` slots.
    ///
    /// # Panics
    ///
    /// If `b >= LEVELS`, `index >= MAX_BIDDERS`, `version` is not in `1..=MAX_VERSION` or `slots`
    /// is smaller than [`SLOTS`].
    pub fn bid_slots(
        slots: usize,
        round: &RoundParams,
        b: usize,
        index: usize,
        version: u64,
    ) -> Vec<u64> {
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
        for copy in 0..COPIES {
            out[price_slot(copy, 0)..=price_slot(copy, b)].fill(1);
        }
        if b >= round.reserve_step {
            out[GATE_BASE..GATE_BASE + GATE_COPIES].fill(1);
        }
        out[VERSION_BASE + index] = version;
        out
    }

    /// What the round decided. The values are the `uint8` that `PrivateRoundProgram` stores.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(u8)]
    pub enum Outcome {
        /// The reserve was not met.
        NotMet = 0,
        /// The reserve was met, and fewer than `lots` bidders accept the reserve price.
        Undersubscribed = 1,
        /// `lots` or more bidders accept the clearing step.
        SoldOut = 2,
        /// The output is not a valid output of the program.
        Aborted = 3,
    }

    /// What the decrypted output means.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct RoundOutput {
        /// The number of counted bidders.
        pub counted: usize,
        /// The counted version of each bidder, 0 for a bidder that did not count.
        pub versions: [u64; MAX_BIDDERS],
        pub outcome: Outcome,
        /// `l*` if sold out, the reserve step if undersubscribed.
        pub step: Option<usize>,
        /// Why the output is [`Outcome::Aborted`].
        pub reason: Option<String>,
    }

    /// Reads the decrypted slots. The rules are the ones of `decodeRound` in `sdk/src/layout.ts`
    /// and of `RoundOutput.sol`:
    ///
    /// - A price slot of a step below the reserve step or from `levels`, an unused slot, and a version
    ///   above [`MAX_VERSION`] are invalid.
    /// - The price lane tests `c_l >= lots` must not rise with the step.
    /// - A sell-out at the reserve step needs the gate.
    ///
    /// A lane is zero if all its copies are zero. With the complement side a zero lane means that its
    /// test holds; with the direct side it means that it fails.
    ///
    /// # Panics
    ///
    /// If `slots` has fewer than [`SLOTS`] values or `round` is not valid.
    pub fn decode_round(slots: &[u64], round: &RoundParams) -> RoundOutput {
        assert!(slots.len() >= SLOTS, "the output has {SLOTS} slots");
        assert!(round.error().is_none(), "the round parameters are invalid");
        let mut versions = [0u64; MAX_BIDDERS];
        let mut invalid = None;
        for (i, version) in versions.iter_mut().enumerate() {
            let slot = slots[VERSION_BASE + i];
            if slot > MAX_VERSION {
                invalid.get_or_insert(format!("the counted version of bidder {i} is {slot}"));
            } else {
                *version = slot;
            }
        }
        let n = versions.iter().filter(|&&v| v > 0).count();
        let aborted = |reason: String| RoundOutput {
            counted: n,
            versions,
            outcome: Outcome::Aborted,
            step: None,
            reason: Some(reason),
        };
        if let Some(reason) = invalid {
            return aborted(reason);
        }
        if n == 0 {
            return aborted("no bidder counted".to_string());
        }

        let is_lane = |slot: usize| {
            (slot < GATE_BASE && (round.reserve_step..round.levels).contains(&(slot % LEVELS)))
                || (GATE_BASE..GATE_BASE + GATE_COPIES).contains(&slot)
        };
        if let Some(slot) = (0..VERSION_BASE).find(|&s| !is_lane(s) && slots[s] != 0) {
            return aborted(format!("slot {slot} is not a lane and not zero"));
        }

        let price_complement = uses_complement_side(round.lots, n);
        let gate_complement = uses_complement_side(round.min_lots, n);
        let holds: Vec<bool> = (round.reserve_step..round.levels)
            .map(|l| (0..COPIES).all(|g| slots[price_slot(g, l)] == 0) == price_complement)
            .collect();
        let gate = (GATE_BASE..GATE_BASE + GATE_COPIES).all(|s| slots[s] == 0) == gate_complement;
        if let Some(j) = (1..holds.len()).find(|&j| holds[j] && !holds[j - 1]) {
            return aborted(format!(
                "the demand test rises at step {}",
                round.reserve_step + j
            ));
        }
        if holds[0] && !gate {
            return aborted("the round sells out but the reserve is not met".to_string());
        }
        let (outcome, step) = if !gate {
            (Outcome::NotMet, None)
        } else if !holds[0] {
            (Outcome::Undersubscribed, Some(round.reserve_step))
        } else {
            let last = holds.iter().rposition(|&h| h).unwrap_or(0);
            (Outcome::SoldOut, Some(round.reserve_step + last))
        };
        RoundOutput {
            counted: n,
            versions,
            outcome,
            step,
            reason: None,
        }
    }
}

use layout::{
    COPIES, GATE_BASE, GATE_COPIES, MAX_BIDDERS, RoundParams, SLOTS, VERSION_BASE, price_slot,
};

/// The prefix of the configuration input. `PrivateRoundProgram.CONFIG_DOMAIN` is the same bytes.
pub const CONFIG_DOMAIN: &[u8] = b"interfold-private-round-config-v1";

/// The ciphertexts of one bid: the bid and the mask.
pub const ROLES: usize = 2;

/// Input 0 of a round: the domain bytes, then `levels`, `reserve_step`, `lots` and `min_lots`.
///
/// # Panics
///
/// If a parameter does not fit one byte. A valid [`RoundParams`] does.
pub fn config_input(round: &RoundParams) -> Vec<u8> {
    let byte = |value: usize| u8::try_from(value).expect("a round parameter fits one byte");
    [
        CONFIG_DOMAIN,
        &[
            byte(round.levels),
            byte(round.reserve_step),
            byte(round.lots),
            byte(round.min_lots),
        ],
    ]
    .concat()
}

/// The parameters of a configuration input, or `None` if `input` is not a valid one.
pub fn parse_config(input: &[u8]) -> Option<RoundParams> {
    let [levels, reserve_step, lots, min_lots] = input.strip_prefix(CONFIG_DOMAIN)? else {
        return None;
    };
    let round = RoundParams {
        levels: usize::from(*levels),
        reserve_step: usize::from(*reserve_step),
        lots: usize::from(*lots),
        min_lots: usize::from(*min_lots),
    };
    round.error().is_none().then_some(round)
}

/// The metadata `PrivateRoundProgram` publishes with each bid ciphertext: the 20-byte bidder, then the
/// 5-byte bid version, as `abi.encodePacked(address, uint40)` lays it out.
///
/// The program server builds it from `input_slots` (the bidder) and `input_parents` (the version).
/// Both ciphertexts of a bid have the same metadata. The configuration at index 0 gets a zero
/// commitment, a zero slot and the parent 0; its leaf ignores them.
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
/// `PrivateRoundProgram.validate` inserts. The leaf of every other input is
/// `sha256(keccak256(ciphertext) || commitment || bidder || uint40(version)) mod BN254`. It must stay
/// byte-identical to `PrivateRoundProgram.inputLeaf`, or no root will ever match. It binds the bytes,
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
            reason: "the round publishes a commitment with every bid ciphertext".to_string(),
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
/// whose two ciphertexts open their commitments.
///
/// `PrivateRoundProgram.publishInput` inserts one bid as a run of [`ROLES`] consecutive leaves with
/// the same metadata. A bidder may bid up to a few times; each bid has the next version. For every
/// bidder this keeps the run with the highest version in which every record has a commitment and
/// reproduces it. A bidder with no such run is dropped whole, and a run is never taken in part,
/// because a bid with one missing role is no bid.
///
/// The contract cannot check that published bytes open a commitment, so any submitter can publish
/// a bid that does not. That bid is skipped, and an earlier valid bid of the same bidder counts. A
/// bidder can also withdraw this way, and it learns nothing from doing so.
///
/// A run whose metadata is not [`METADATA_LEN`] bytes or whose length is not [`ROLES`] is never
/// taken. The result is ascending by index, so the order of the chosen runs is the bidder position
/// in the computation.
pub fn select_bids(inputs: &[InputRecord]) -> Vec<usize> {
    let Some((_, bids)) = inputs.split_first() else {
        return Vec::new();
    };

    // The best run so far of each bidder: its version bytes and its records.
    let mut latest: BTreeMap<&[u8], (&[u8], &[InputRecord])> = BTreeMap::new();
    for run in bids.chunk_by(|a, b| a.metadata == b.metadata) {
        let metadata = run[0].metadata;
        if metadata.len() != METADATA_LEN || run.len() != ROLES {
            continue;
        }
        if !run
            .iter()
            .all(|record| record.commitment.is_some() && record.matches_commitment())
        {
            continue;
        }
        let (bidder, version) = metadata.split_at(20);
        // Versions are big-endian of one fixed width, so comparing the bytes compares the numbers.
        if latest
            .get(bidder)
            .is_none_or(|(chosen, _)| *chosen < version)
        {
            latest.insert(bidder, (version, run));
        }
    }

    let mut selected = vec![0];
    selected.extend(
        latest
            .into_values()
            .flat_map(|(_, run)| run.iter().map(|record| record.index)),
    );
    selected.sort_unstable();
    selected
}

/// A SIMD plaintext with these slot values.
fn plaintext(params: &Arc<BfvParameters>, slots: &[u64]) -> Plaintext {
    Plaintext::try_encode(slots, Encoding::simd(), params).expect("slots fit the degree")
}

/// The sum of the ciphertexts.
fn sum(cts: impl IntoIterator<Item = Ciphertext>) -> Ciphertext {
    cts.into_iter()
        .reduce(|acc, ct| &acc + &ct)
        .expect("a round has one bidder at least")
}

/// The product of two ciphertexts, relinearized.
fn multiply(
    relinearization_key: &LBFVRelinearizationKey,
    a: &Ciphertext,
    b: &Ciphertext,
) -> Ciphertext {
    let mut product = a * b;
    relinearization_key
        .relinearizes(&mut product)
        .expect("a ct*ct product has three components");
    product
}

/// The product of the ciphertexts in a balanced tree. The depth is `ceil(log2(len))`: pairs of
/// neighbours are multiplied level by level, and an odd one out moves up a level unchanged.
fn product_tree(
    relinearization_key: &LBFVRelinearizationKey,
    mut leaves: Vec<Ciphertext>,
) -> Ciphertext {
    while leaves.len() > 1 {
        leaves = leaves
            .chunks(2)
            .map(|pair| match pair {
                [a, b] => multiply(relinearization_key, a, b),
                [a] => a.clone(),
                _ => unreachable!("chunks of two"),
            })
            .collect();
    }
    leaves.pop().expect("a product has one leaf at least")
}

/// Computes the output ciphertext of a round of `n` counted bidders from the sum `bids` of their bid
/// ciphertexts and the sum `masks` of their mask ciphertexts. See the module documentation.
///
/// The depth is `ceil(log2(factors + 1))`, at most 3 for `n <= MAX_BIDDERS`.
///
/// # Panics
///
/// If the degree is not [`SLOTS`], `round` is not valid or `n` is not in `1..=MAX_BIDDERS`.
pub fn evaluate(
    params: &Arc<BfvParameters>,
    relinearization_key: &LBFVRelinearizationKey,
    round: &RoundParams,
    n: usize,
    bids: &Ciphertext,
    masks: &Ciphertext,
) -> Ciphertext {
    assert_eq!(params.degree(), SLOTS, "the program needs {SLOTS} slots");
    assert!(round.error().is_none(), "the round parameters are invalid");
    assert!(
        (1..=MAX_BIDDERS).contains(&n),
        "a round has 1 to {MAX_BIDDERS} bidders, got {n}"
    );

    // The slots that hold a lane: the price steps from the reserve to the last in every copy, and
    // the gate lanes. The mask is zero elsewhere, so every other slot of the product is zero.
    let mut lane = vec![0u64; SLOTS];
    // The zeros of each lane slot.
    let mut zeros: Vec<Vec<u64>> = vec![Vec::new(); SLOTS];
    let price_zeros = layout::zero_set(round.lots, n);
    let gate_zeros = layout::zero_set(round.min_lots, n);
    for copy in 0..COPIES {
        for level in round.reserve_step..round.levels {
            lane[price_slot(copy, level)] = 1;
            zeros[price_slot(copy, level)] = price_zeros.clone();
        }
    }
    for slot in GATE_BASE..GATE_BASE + GATE_COPIES {
        lane[slot] = 1;
        zeros[slot] = gate_zeros.clone();
    }
    let factors = price_zeros.len().max(gate_zeros.len());

    // Factor `j` of a lane slot is `c - z_j`. A lane with fewer zeros than `factors` repeats them.
    // A slot with no zero gets `n + 1`, which no count equals.
    let mut leaves: Vec<Ciphertext> = (0..factors)
        .map(|j| {
            let z: Vec<u64> = zeros
                .iter()
                .map(|set| {
                    if set.is_empty() {
                        n as u64 + 1
                    } else {
                        set[j % set.len()]
                    }
                })
                .collect();
            bids - &plaintext(params, &z)
        })
        .collect();
    leaves.push(masks * &plaintext(params, &lane));

    // The counted versions, copied from the sum of the bids.
    let mut versions = vec![0u64; SLOTS];
    versions[VERSION_BASE..].fill(1);
    let counted = bids * &plaintext(params, &versions);

    &product_tree(relinearization_key, leaves) + &counted
}

/// Runs the round over the inputs of the round.
///
/// The selected inputs arrive one at a time, in leaf order: the configuration, then the [`ROLES`]
/// ciphertexts of each chosen bid in role order (see [`select_bids`]). The on-chain index is not
/// used, only the position.
///
/// # Panics
///
/// If input 0 is not a configuration, if the number of ciphertexts is not a multiple of [`ROLES`],
/// if there are no bidders or more than [`MAX_BIDDERS`], or if the l-BFV relinearization key is
/// missing. A malformed round has no meaningful result, so there is nothing to recover to.
pub fn fhe_processor(inputs: FHEProcessorInput<'_>) -> Vec<u8> {
    let relinearization_key = inputs
        .relinearization_key
        .expect("the private round requires the l-BFV relinearization key");

    let params = inputs.params;
    let (config, _) = inputs
        .ciphertexts
        .next()
        .expect("input 0 must be the round configuration");
    let round = parse_config(&config).expect("input 0 must be the round configuration");

    let mut raw = Vec::new();
    while let Some((bytes, _)) = inputs.ciphertexts.next() {
        raw.push(bytes);
    }
    assert!(
        raw.len() % ROLES == 0,
        "the number of ciphertexts must be a multiple of {ROLES}: {ROLES} per bidder"
    );
    let n = raw.len() / ROLES;
    assert!(
        (1..=MAX_BIDDERS).contains(&n),
        "a round has 1 to {MAX_BIDDERS} bidders, got {n}"
    );

    let ciphertext = |bytes: &Vec<u8>| Ciphertext::from_bytes(bytes, params).unwrap();
    let bids = sum(raw.chunks(ROLES).map(|bidder| ciphertext(&bidder[0])));
    let masks = sum(raw.chunks(ROLES).map(|bidder| ciphertext(&bidder[1])));
    evaluate(params, relinearization_key, &round, n, &bids, &masks).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::layout::*;
    use super::*;
    use anyhow::Result;
    use e3_compute_provider::hashing::keccak256;
    use e3_fhe_params::{BfvPreset, build_pair_for_preset, lbfv_crs_seed, lbfv_urs_seed};
    use fhe::aggregate::AggregateIter;
    use fhe::bfv::{CommonRandomPolyVec, SecretKey};
    use fhe::trlbfv::{
        LBFVPublicKey, PublicKeyShare, RelinKeyShare, aggregate_relinearization_key,
    };
    use fhe_traits::{FheDecoder, FheDecrypter, FheEncrypter};
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    const PRESET: BfvPreset = BfvPreset::InsecureThresholdSimd;

    /// A committee of `parties` parties: the same key-generation path the real committee runs, with
    /// one share of the public key and of the relinearization key from each party.
    struct Fixture {
        params: Arc<BfvParameters>,
        /// The sum of the secret keys of the parties, for decryption and noise measurement.
        secret_key: SecretKey,
        public_key: LBFVPublicKey,
        rlk: LBFVRelinearizationKey,
    }

    fn fixture(parties: usize) -> Result<Fixture> {
        let mut rng = rand::rng();
        let (params, _) = build_pair_for_preset(PRESET)?;
        let crs = CommonRandomPolyVec::from_seed(&params, lbfv_crs_seed(PRESET).unwrap())?;
        let urs = CommonRandomPolyVec::from_seed(&params, lbfv_urs_seed(PRESET).unwrap())?;
        let secret_keys: Vec<SecretKey> = (0..parties)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();
        let shares = secret_keys
            .iter()
            .map(|sk| PublicKeyShare::contribute_with_crp(sk, &crs, &mut rng))
            .collect::<Result<Vec<_>, _>>()?;
        let public_key: LBFVPublicKey = shares.into_iter().aggregate()?;
        let rlk_shares = secret_keys
            .iter()
            .map(|sk| RelinKeyShare::contribution_with_crp(sk, &urs, &crs, 0, 0, &mut rng))
            .collect::<Result<Vec<_>, _>>()?;
        let rlk = aggregate_relinearization_key(&rlk_shares, &public_key)?;
        let mut sum = vec![0i64; params.degree()];
        for sk in &secret_keys {
            for (acc, c) in sum.iter_mut().zip(sk.coeffs.iter()) {
                *acc += c;
            }
        }
        Ok(Fixture {
            secret_key: SecretKey::new(sum, &params),
            params,
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

    fn decrypt_slots(fixture: &Fixture, result: &[u8]) -> Result<Vec<u64>> {
        let decrypted = fixture
            .secret_key
            .try_decrypt(&Ciphertext::from_bytes(result, &fixture.params)?)?;
        Ok(Vec::<u64>::try_decode(&decrypted, Encoding::simd())?)
    }

    /// One round: the plaintext slots of every bid and mask, and the ciphertexts.
    struct Round {
        round: RoundParams,
        /// `bids[i]` is the step of the bidder `i`.
        bids: Vec<usize>,
        bid_slots: Vec<Vec<u64>>,
        mask_slots: Vec<Vec<u64>>,
        /// The ciphertexts in leaf order after the configuration: bid, mask, bid, mask, ...
        ciphertexts: Vec<(Vec<u8>, u64)>,
    }

    fn make_round(
        fixture: &Fixture,
        round: RoundParams,
        bids: &[usize],
        seed: u64,
    ) -> Result<Round> {
        let t = fixture.params.plaintext();
        let mut rng = StdRng::seed_from_u64(seed);
        let mut out = Round {
            round,
            bids: bids.to_vec(),
            bid_slots: Vec::new(),
            mask_slots: Vec::new(),
            ciphertexts: Vec::new(),
        };
        for (i, &b) in bids.iter().enumerate() {
            let bid = bid_slots(SLOTS, &round, b, i, 1 + (i as u64 % MAX_VERSION));
            let mask: Vec<u64> = (0..SLOTS).map(|_| rng.random_range(0..t)).collect();
            for slots in [&bid, &mask] {
                let index = out.ciphertexts.len() as u64 + 1;
                out.ciphertexts.push((encrypt(fixture, slots)?, index));
            }
            out.bid_slots.push(bid);
            out.mask_slots.push(mask);
        }
        Ok(out)
    }

    /// Runs the program over the configuration of `round` and then its ciphertexts.
    fn run(fixture: &Fixture, round: &RoundParams, ciphertexts: Vec<(Vec<u8>, u64)>) -> Vec<u8> {
        let inputs = std::iter::once((config_input(round), 0)).chain(ciphertexts);
        fhe_processor(FHEProcessorInput {
            ciphertexts: &mut inputs.into_iter(),
            params: &fixture.params,
            relinearization_key: Some(&fixture.rlk),
        })
    }

    /// What the program computes, on the plaintexts: `R * prod_j (c - z_j)` in the lane slots, the
    /// counted versions in the version slots, 0 elsewhere. All mod `t`.
    fn plain_output(round: &Round, t: u64) -> Vec<u64> {
        let n = round.bids.len();
        let rp = &round.round;
        let price_zeros = zero_set(rp.lots, n);
        let gate_zeros = zero_set(rp.min_lots, n);
        let mut out = vec![0u64; SLOTS];
        let slot_sum = |slots: &[Vec<u64>], s: usize| slots.iter().map(|v| v[s]).sum::<u64>() % t;
        let factors = price_zeros.len().max(gate_zeros.len());
        let lane_value = |s: usize, zeros: &[u64]| {
            let c = slot_sum(&round.bid_slots, s);
            let r = slot_sum(&round.mask_slots, s);
            (0..factors).fold(r, |acc, j| {
                let z = if zeros.is_empty() {
                    n as u64 + 1
                } else {
                    zeros[j % zeros.len()]
                };
                acc * ((c + t - z % t) % t) % t
            })
        };
        for copy in 0..COPIES {
            for level in rp.reserve_step..rp.levels {
                let s = price_slot(copy, level);
                out[s] = lane_value(s, &price_zeros);
            }
        }
        for s in GATE_BASE..GATE_BASE + GATE_COPIES {
            out[s] = lane_value(s, &gate_zeros);
        }
        for s in VERSION_BASE..SLOTS {
            out[s] = slot_sum(&round.bid_slots, s);
        }
        out
    }

    /// The outcome on the true bids.
    fn plain_outcome(round: &RoundParams, bids: &[usize]) -> (Outcome, Option<usize>) {
        let demand = |l: usize| bids.iter().filter(|&&b| b >= l).count();
        if demand(round.reserve_step) < round.min_lots {
            return (Outcome::NotMet, None);
        }
        if demand(round.reserve_step) < round.lots {
            return (Outcome::Undersubscribed, Some(round.reserve_step));
        }
        let step = (round.reserve_step..round.levels)
            .rev()
            .find(|&l| demand(l) >= round.lots)
            .unwrap();
        (Outcome::SoldOut, Some(step))
    }

    const ROUND: RoundParams = RoundParams {
        levels: 16,
        reserve_step: 3,
        lots: 2,
        min_lots: 1,
    };

    #[test]
    fn the_slot_layout_fits_the_ring() {
        assert_eq!(GATE_BASE, 96);
        assert_eq!(GATE_BASE + GATE_COPIES, 102);
        assert_eq!(VERSION_BASE, 115);
        assert!(GATE_BASE + GATE_COPIES <= VERSION_BASE);
        assert_eq!(VERSION_BASE + MAX_BIDDERS, SLOTS);
    }

    #[test]
    fn a_bid_has_six_thermometers_the_gate_and_the_version() {
        let slots = bid_slots(SLOTS, &ROUND, 5, 3, 2);
        assert_eq!(slots.len(), SLOTS);
        for copy in 0..COPIES {
            for l in 0..LEVELS {
                assert_eq!(slots[price_slot(copy, l)], u64::from(l <= 5));
            }
        }
        assert!(
            slots[GATE_BASE..GATE_BASE + GATE_COPIES]
                .iter()
                .all(|&s| s == 1)
        );
        assert_eq!(slots[VERSION_BASE + 3], 2);
        assert_eq!(
            slots.iter().filter(|&&s| s != 0).count(),
            COPIES * 6 + 6 + 1
        );
        // Below the reserve the gate bit is 0.
        let below = bid_slots(SLOTS, &ROUND, 2, 0, 1);
        assert!(
            below[GATE_BASE..GATE_BASE + GATE_COPIES]
                .iter()
                .all(|&s| s == 0)
        );
    }

    #[test]
    #[should_panic(expected = "not below")]
    fn a_bid_rejects_a_step_out_of_range() {
        bid_slots(SLOTS, &ROUND, LEVELS, 0, 1);
    }

    #[test]
    #[should_panic(expected = "not below")]
    fn a_bid_rejects_the_fourteenth_bidder() {
        bid_slots(SLOTS, &ROUND, 0, MAX_BIDDERS, 1);
    }

    #[test]
    #[should_panic(expected = "not in 1..=")]
    fn a_bid_rejects_a_fourth_version() {
        bid_slots(SLOTS, &ROUND, 0, 0, 4);
    }

    #[test]
    fn the_lane_polynomial_has_at_most_seven_factors_for_13_bidders() {
        // The depth of a round is `ceil(log2(factors + 1))`, which is 3 at 7 factors: any `lots`
        // and `min_lots`, any number of bidders.
        for n in 1..=MAX_BIDDERS {
            for lots in 1..=MAX_LOTS {
                for min_lots in 1..=lots {
                    let round = RoundParams {
                        levels: 16,
                        reserve_step: 0,
                        lots,
                        min_lots,
                    };
                    assert!(
                        lane_factors(&round, n) <= 7,
                        "n {n}, K {lots}, m {min_lots}"
                    );
                }
            }
        }
        // The worst case is 7 lots for 13 bidders.
        let worst = RoundParams {
            levels: 16,
            reserve_step: 0,
            lots: 7,
            min_lots: 7,
        };
        assert_eq!(lane_factors(&worst, 13), 7);
    }

    #[test]
    fn the_zero_set_is_the_side_with_fewer_zeros() {
        // 13 bidders, theta 3: the direct side {0, 1, 2} has 3 zeros, the complement 11.
        assert_eq!(zero_set(3, 13), vec![0, 1, 2]);
        assert!(!uses_complement_side(3, 13));
        // theta 10: the direct side has 10 zeros, the complement {10, 11, 12, 13} 4.
        assert_eq!(zero_set(10, 13), vec![10, 11, 12, 13]);
        assert!(uses_complement_side(10, 13));
        // A threshold above `n` has an empty complement side.
        assert_eq!(zero_set(5, 3), Vec::<u64>::new());
        assert!(uses_complement_side(5, 3));
        // A tie takes the direct side: n = 5, theta = 3 has 3 and 3.
        assert!(!uses_complement_side(3, 5));
    }

    #[test]
    fn the_round_output_equals_the_formula_on_the_plaintexts() -> Result<()> {
        let fixture = fixture(1)?;
        for (round, bids, seed) in [
            (ROUND, vec![5, 9, 9, 15, 4, 3, 2], 1),
            (ROUND, vec![15], 2),
            (
                RoundParams {
                    levels: 16,
                    reserve_step: 0,
                    lots: 7,
                    min_lots: 4,
                },
                vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
                3,
            ),
            (
                RoundParams {
                    levels: 4,
                    reserve_step: 1,
                    lots: 3,
                    min_lots: 2,
                },
                vec![3, 0, 1, 2, 3, 1],
                4,
            ),
        ] {
            let built = make_round(&fixture, round, &bids, seed)?;
            let result = run(&fixture, &round, built.ciphertexts.clone());
            let slots = decrypt_slots(&fixture, &result)?;
            assert_eq!(slots, plain_output(&built, fixture.params.plaintext()));
        }
        Ok(())
    }

    #[test]
    fn the_output_decodes_to_the_outcome_on_the_true_bids() -> Result<()> {
        let fixture = fixture(1)?;
        // Not met: one bidder at or above the reserve 3, the minimum is 2.
        let not_met = RoundParams {
            levels: 16,
            reserve_step: 3,
            lots: 4,
            min_lots: 2,
        };
        // Undersubscribed: 3 bidders at or above the reserve, the lots are 4.
        // Sold out at step 6: 4 or more bidders at 6.
        for (round, bids) in [
            (not_met, vec![9, 1, 2, 0]),
            (not_met, vec![9, 5, 1]),
            (not_met, vec![9, 5, 4, 3]),
            (not_met, vec![9, 9, 9, 6, 6, 1]),
            (not_met, vec![15, 15, 15, 15]),
            (not_met, vec![3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3]),
        ] {
            let built = make_round(&fixture, round, &bids, 11)?;
            let slots = decrypt_slots(&fixture, &run(&fixture, &round, built.ciphertexts))?;
            let decoded = decode_round(&slots, &round);
            let (outcome, step) = plain_outcome(&round, &bids);
            assert_eq!(
                (decoded.outcome, decoded.step),
                (outcome, step),
                "bids {bids:?}: {:?}",
                decoded.reason
            );
            assert_eq!(decoded.counted, bids.len());
        }
        Ok(())
    }

    #[test]
    fn random_rounds_decode_to_the_outcome_on_the_true_bids() -> Result<()> {
        let fixture = fixture(1)?;
        let mut rng = StdRng::seed_from_u64(7);
        for trial in 0..60 {
            let levels = rng.random_range(2..=LEVELS);
            let lots = rng.random_range(1..=MAX_LOTS);
            let round = RoundParams {
                levels,
                reserve_step: rng.random_range(0..levels),
                lots,
                min_lots: rng.random_range(1..=lots),
            };
            let n = rng.random_range(1..=MAX_BIDDERS);
            let bids: Vec<usize> = (0..n).map(|_| rng.random_range(0..levels)).collect();
            let built = make_round(&fixture, round, &bids, 100 + trial)?;
            let slots = decrypt_slots(&fixture, &run(&fixture, &round, built.ciphertexts))?;
            let decoded = decode_round(&slots, &round);
            let (outcome, step) = plain_outcome(&round, &bids);
            assert_eq!(
                (decoded.outcome, decoded.step),
                (outcome, step),
                "{round:?} bids {bids:?}: {:?}",
                decoded.reason
            );
            assert_eq!(
                decoded.versions.iter().filter(|&&v| v > 0).count(),
                bids.len()
            );
        }
        Ok(())
    }

    #[test]
    fn the_output_shows_only_zero_and_nonzero_in_the_lanes() -> Result<()> {
        // Two rounds with the same masks and different bids that give the same outcome have the same
        // zero pattern, whatever the counts are.
        let fixture = fixture(1)?;
        let round = RoundParams {
            levels: 8,
            reserve_step: 2,
            lots: 3,
            min_lots: 2,
        };
        let pattern = |bids: &[usize]| -> Result<Vec<bool>> {
            let built = make_round(&fixture, round, bids, 5)?;
            let slots = decrypt_slots(&fixture, &run(&fixture, &round, built.ciphertexts))?;
            Ok(slots[..VERSION_BASE].iter().map(|&s| s == 0).collect())
        };
        // Both sell out at step 4 (3 or more bidders at 4, fewer than 3 at 5).
        let a = pattern(&[4, 4, 4, 1])?;
        let b = pattern(&[9, 5, 4, 4])?;
        // The lane copies of a nonzero test are nonzero with overwhelming probability in both: the
        // same pattern here is the claim, up to a chance of 257^-1 per copy.
        let differing = a.iter().zip(&b).filter(|(x, y)| x != y).count();
        assert!(differing <= 4, "{differing} lane copies differ");
        Ok(())
    }

    #[test]
    fn the_program_runs_at_depth_three_with_three_and_nine_parties() -> Result<()> {
        for parties in [3, 9] {
            let fixture = fixture(parties)?;
            // 13 bidders and 7 lots: the worst case, 7 factors and the mask.
            let round = RoundParams {
                levels: 16,
                reserve_step: 2,
                lots: 7,
                min_lots: 7,
            };
            let bids = [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
            let built = make_round(&fixture, round, &bids, 21)?;
            let result = run(&fixture, &round, built.ciphertexts);
            let ciphertext = Ciphertext::from_bytes(&result, &fixture.params)?;
            let noise = unsafe { fixture.secret_key.measure_noise(&ciphertext)? };
            let slots = decrypt_slots(&fixture, &result)?;
            let decoded = decode_round(&slots, &round);
            assert_eq!(decoded.outcome, Outcome::SoldOut, "{:?}", decoded.reason);
            // 7 bidders are at step 8 or above: sold out at step 8.
            assert_eq!(decoded.step, Some(8));
            // The noise stays far below the smudging bound (about 2^142) and the decryption limit.
            assert!(noise < 130, "{parties} parties: {noise} bits of noise");
        }
        Ok(())
    }

    #[test]
    fn decode_rejects_the_outputs_that_break_a_rule() {
        let round = RoundParams {
            levels: 8,
            reserve_step: 2,
            lots: 2,
            min_lots: 1,
        };
        // Two bidders: 2 lots, direct side {0, 1}, complement {2}: 1 zero, so the price lanes use
        // the complement side (a zero lane means the test holds). The gate (1 lot) uses the direct
        // side (a zero lane means the gate fails).
        let mut good = vec![0u64; SLOTS];
        good[VERSION_BASE] = 1;
        good[VERSION_BASE + 1] = 1;
        // Every lane is nonzero: no price test holds, the gate holds.
        for copy in 0..COPIES {
            for l in 2..8 {
                good[price_slot(copy, l)] = 5;
            }
        }
        good[GATE_BASE..GATE_BASE + GATE_COPIES].fill(5);
        let decoded = decode_round(&good, &round);
        assert_eq!(
            decoded.outcome,
            Outcome::Undersubscribed,
            "{:?}",
            decoded.reason
        );

        let broken = |edit: &dyn Fn(&mut Vec<u64>)| {
            let mut slots = good.clone();
            edit(&mut slots);
            decode_round(&slots, &round).outcome
        };
        // A price slot below the reserve step is not a lane.
        assert_eq!(broken(&|s| s[price_slot(0, 1)] = 1), Outcome::Aborted);
        // A price slot from `levels` is not a lane.
        assert_eq!(broken(&|s| s[price_slot(0, 8)] = 1), Outcome::Aborted);
        // An unused slot.
        assert_eq!(
            broken(&|s| s[GATE_BASE + GATE_COPIES] = 1),
            Outcome::Aborted
        );
        // A version above 3.
        assert_eq!(broken(&|s| s[VERSION_BASE] = 4), Outcome::Aborted);
        // No bidder counted.
        assert_eq!(broken(&|s| s[VERSION_BASE..].fill(0)), Outcome::Aborted);
        // One zero copy is not a zero lane: still undersubscribed.
        assert_eq!(
            broken(&|s| s[price_slot(0, 2)] = 0),
            Outcome::Undersubscribed
        );
        // The test holds at step 4 but not at step 3: it rises.
        assert_eq!(
            broken(&|s| (0..COPIES).for_each(|g| s[price_slot(g, 4)] = 0)),
            Outcome::Aborted
        );
        // The test holds at the reserve step but the gate does not.
        assert_eq!(
            broken(&|s| {
                (0..COPIES).for_each(|g| (2..8).for_each(|l| s[price_slot(g, l)] = 0));
                (GATE_BASE..GATE_BASE + GATE_COPIES).for_each(|k| s[k] = 0);
            }),
            Outcome::Aborted
        );
    }

    #[test]
    #[should_panic(expected = "round configuration")]
    fn rejects_a_round_without_the_configuration() {
        let fixture = fixture(1).unwrap();
        let built = make_round(&fixture, ROUND, &[5, 6], 5).unwrap();
        fhe_processor(FHEProcessorInput {
            ciphertexts: &mut built.ciphertexts.into_iter(),
            params: &fixture.params,
            relinearization_key: Some(&fixture.rlk),
        });
    }

    #[test]
    #[should_panic(expected = "multiple of 2")]
    fn rejects_a_count_that_is_not_a_multiple_of_two() {
        let fixture = fixture(1).unwrap();
        let mut built = make_round(&fixture, ROUND, &[5, 6], 5).unwrap();
        built.ciphertexts.pop();
        run(&fixture, &ROUND, built.ciphertexts);
    }

    #[test]
    #[should_panic(expected = "1 to 13 bidders")]
    fn rejects_a_fourteenth_bidder() {
        let fixture = fixture(1).unwrap();
        let mut built = make_round(&fixture, ROUND, &[1; 13], 5).unwrap();
        // The fourteenth bid and mask: copies of the first two.
        let extra = built.ciphertexts[..2].to_vec();
        built.ciphertexts.extend(extra);
        run(&fixture, &ROUND, built.ciphertexts);
    }

    #[test]
    #[should_panic(expected = "1 to 13 bidders")]
    fn rejects_a_round_without_a_bidder() {
        let fixture = fixture(1).unwrap();
        run(&fixture, &ROUND, Vec::new());
    }

    #[test]
    fn the_configuration_names_the_parameters() {
        let round = RoundParams {
            levels: 12,
            reserve_step: 3,
            lots: 5,
            min_lots: 2,
        };
        let config = config_input(&round);
        assert_eq!(&config[..CONFIG_DOMAIN.len()], CONFIG_DOMAIN);
        assert_eq!(&config[CONFIG_DOMAIN.len()..], [12, 3, 5, 2]);
        assert_eq!(parse_config(&config), Some(round));
        // Not valid: the reserve is not below the levels; the minimum is above the lots; wrong length.
        for tail in [
            [12u8, 12, 5, 2],
            [12, 3, 5, 6],
            [12, 3, 13, 2],
            [1, 0, 1, 1],
        ] {
            assert_eq!(
                parse_config(&[CONFIG_DOMAIN, &tail].concat()),
                None,
                "{tail:?}"
            );
        }
        assert_eq!(parse_config(&config[..config.len() - 1]), None);
        assert_eq!(parse_config(&[config.as_slice(), &[0]].concat()), None);
        assert_eq!(parse_config(&config[1..]), None);
    }

    #[test]
    fn the_configuration_leaf_is_the_reduced_hash_of_the_configuration() {
        // `PrivateRoundProgram.configLeaf` computes `keccak256(CONFIG_DOMAIN || levels || reserve || lots ||
        // minLots) mod BN254`. Input 0 must get that leaf, whatever commitment and metadata come with it.
        let round = RoundParams {
            levels: 12,
            reserve_step: 3,
            lots: 5,
            min_lots: 2,
        };
        let config = config_input(&round);
        let zero = [0u8; 32];
        let leaf = (policy().leaf)(&PublishedInput {
            index: 0,
            ciphertext: &config,
            ciphertext_hash: keccak256(&config),
            commitment: Some(&zero),
            metadata: &[0; METADATA_LEN],
            recomputed: None,
        })
        .unwrap();
        assert_eq!(
            leaf,
            leaf_from_digest(&keccak256(
                &[
                    b"interfold-private-round-config-v1".as_slice(),
                    &[12, 3, 5, 2]
                ]
                .concat()
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
        // `PrivateRoundProgram.inputLeaf(h, c, bidder, version)` for this input is the same number
        // (the formula is the one of the other examples).
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
        // A ciphertext that does not open its commitment still has a leaf, the same one.
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

    /// The 2 records of a bid; `opens[r]` says whether role `r` opens its commitment.
    fn bid(bidder: u8, version: u64, opens: [bool; ROLES]) -> Vec<Row> {
        opens
            .iter()
            .enumerate()
            .map(|(role, opens)| Row {
                metadata: metadata_of(bidder, version),
                commitment: Some([role as u8 + 1; 32]),
                recomputed: Some([if *opens { role as u8 + 1 } else { 0xff }; 32]),
            })
            .collect()
    }

    /// The indices `select_bids` picks from the configuration followed by `rows`.
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
            .chain(
                rows.iter()
                    .flatten()
                    .enumerate()
                    .map(|(i, row)| InputRecord {
                        index: i + 1,
                        ciphertext_hash: [0; 32],
                        commitment: row.commitment.as_ref(),
                        metadata: &row.metadata,
                        recomputed: row.recomputed,
                    }),
            )
            .collect();
        select_bids(&records)
    }

    const OPENS: [bool; ROLES] = [true; ROLES];

    #[test]
    fn the_latest_valid_version_of_a_bidder_is_selected() {
        // Leaves 1-2 are version 1, leaves 3-4 version 2, leaves 5-6 version 3.
        assert_eq!(
            selected(&[bid(1, 1, OPENS), bid(1, 2, OPENS), bid(1, 3, OPENS)]),
            [0, 5, 6]
        );
    }

    #[test]
    fn a_bidder_falls_back_to_an_earlier_version_when_the_latest_does_not_open() {
        assert_eq!(
            selected(&[bid(1, 1, OPENS), bid(1, 2, [true, false])]),
            [0, 1, 2]
        );
        // The first usable one counts, not the first one.
        assert_eq!(
            selected(&[
                bid(1, 1, OPENS),
                bid(1, 2, [false, true]),
                bid(1, 3, [true, false]),
            ]),
            [0, 1, 2]
        );
    }

    #[test]
    fn a_bidder_with_one_bad_ciphertext_in_its_only_bid_is_dropped_whole() {
        for bad in 0..ROLES {
            let mut opens = OPENS;
            opens[bad] = false;
            assert_eq!(
                selected(&[bid(1, 1, opens), bid(2, 1, OPENS)]),
                [0, 3, 4],
                "role {bad} does not open"
            );
        }
    }

    #[test]
    fn bidders_are_ordered_by_the_leaf_of_the_selected_bid() {
        // bidder 1: leaves 1-2 and 5-6, bidder 2: leaves 3-4. Bidder 1 counts at its update, so it
        // comes after bidder 2.
        assert_eq!(
            selected(&[bid(1, 1, OPENS), bid(2, 1, OPENS), bid(1, 2, OPENS)]),
            [0, 3, 4, 5, 6]
        );
    }

    #[test]
    fn the_configuration_is_always_selected() {
        assert_eq!(selected(&[]), [0]);
        assert_eq!(selected(&[bid(1, 1, [false; ROLES])]), [0]);
    }

    #[test]
    fn a_bid_with_malformed_metadata_or_no_commitment_is_never_selected() {
        for length in [0, 24, 26] {
            let mut malformed = bid(1, 1, OPENS);
            for row in &mut malformed {
                row.metadata = vec![1; length];
            }
            assert_eq!(selected(&[malformed, bid(2, 1, OPENS)]), [0, 3, 4]);
        }

        let mut no_commitment = bid(1, 1, OPENS);
        no_commitment[1].commitment = None;
        assert_eq!(selected(&[no_commitment, bid(2, 1, OPENS)]), [0, 3, 4]);
    }

    #[test]
    fn a_run_of_the_wrong_length_is_never_selected() {
        // A bid of one record, and a bid of three, with the same metadata.
        let mut one = bid(1, 1, OPENS);
        one.truncate(1);
        let mut three = bid(1, 1, OPENS);
        three.push(Row {
            metadata: metadata_of(1, 1),
            commitment: Some([3; 32]),
            recomputed: Some([3; 32]),
        });
        assert_eq!(selected(&[one, bid(2, 1, OPENS)]), [0, 2, 3]);
        assert_eq!(selected(&[three, bid(2, 1, OPENS)]), [0, 4, 5]);
    }
}
