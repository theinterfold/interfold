// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The FHE program of the auction example: sealed-bid auctions of four types. The region types
//! are first-price and second-price (Vickrey). The ratio-lane types are first-price and
//! second-price with ratio lanes.
//!
//! Input 0 of a round is its configuration, [`config_input`]: the domain bytes and the auction type.
//! It is not a ciphertext. `AuctionProgram.validate` inserts its leaf, so the compute proof binds
//! the type through the input root (see [`policy`]).
//!
//! Each bidder sends [`role_count`] ciphertexts that do not depend on the bidder's index, on the
//! number of bidders or on the other bids. `AuctionProgram.publishInput` verifies one proof for the
//! whole bid and inserts one leaf per ciphertext as consecutive leaves in role order. A bidder may
//! bid again (an update), so the tree can hold several bids of one bidder. The policy picks, for
//! each bidder, its latest bid whose bytes open their commitments (see [`select_bids`]). After the
//! configuration the processor then receives one group of ciphertexts per chosen bid, in leaf
//! order. All are SIMD-encoded; a bid is a level `b` in `0..LEVELS`:
//!
//! ```text
//! ge         slot i  [b >= i % LEVELS]
//! gt         slot i  [b >  i % LEVELS]
//! mask       slot i  uniform in 0..t
//! pair_mask  slots (2c) * LEVELS + l and (2c + 1) * LEVELS + l hold one uniform value,
//!            for c in 0..4 and l in 0..LEVELS (second-price ratio lanes only)
//! ```
//!
//! The 128 slots are `GROUPS` groups of `LEVELS` slots. In the output, a lane is the slot of one
//! level in one group.
//!
//! # Region types
//!
//! A region type has 3 ciphertexts per bidder, `[ge, gt, mask]`, and at most 4 bidders. With `n`
//! bidders there are `copies = GROUPS / n` copies of `n` regions (region `r` of copy `c` is group
//! `c * n + r`). The last `GROUPS - copies * n` groups are not used and the program zeroes them.
//!
//! Region `k` belongs to the bidder with tie priority `k` (see [`tie_priority`]). The output is a
//! test vector times `r`, the sum of the bidder masks. Where the test is non-zero the slot is
//! uniform, so the output shows only where the test is zero.
//!
//! Second-price. Slot `p` of region `k` tests whether that bidder beats every other bidder at
//! level `p`:
//!
//! ```text
//! g_k[p] = #{j != k : b_j > p} + [b_k < p] + [b_k = p] * #{j > k : b_j = p}
//! ```
//!
//! `g_k[p]` is zero exactly when no other bid is above `p`, `b_k >= p`, and no bidder of higher
//! priority ties `k` at `p`. The program outputs `g * c'(c' - 1) * r`, where `c'[p] = #{j : b_j >= p}`.
//! With `s` the second-highest bid:
//!
//! - `p < s`: two or more bids are above `p`, the slot is uniform;
//! - `p = s`: the slot is zero in the region of the winner (ties go to the higher priority) and
//!   uniform in every other region;
//! - `p > s`: at most one bid is at or above `p`, the slot is zero.
//!
//! The output is a function of the winner and `s` only. It does not show the winning bid, the
//! runner-up, any count or a tie. 4 ct*ct products (each relinearized with the threshold l-BFV key)
//! and `3n + 1` ct*pt products, at depth 3.
//!
//! First-price. Slot `p` of region `k` tests whether that bidder bids exactly `p` and wins:
//!
//! ```text
//! f_k[p] = (1 - [b_k = p]) + #{j != k : b_j > p} + #{j > k : b_j = p}
//! ```
//!
//! Each term is non-negative and `f_k[p] <= 2n - 1 < t`, so `f_k[p]` is zero exactly at the highest
//! bid `h`, in the region of the winner. The program outputs `f * r`: one zero slot per copy. The
//! output is a function of the winner and `h` only. One ct*ct product, at depth 1.
//!
//! # Ratio-lane types
//!
//! A ratio-lane type has no regions and no tie priority, and at most 8 bidders. Bidder position `k`
//! (in leaf order) has the weight `w_k = 2^k`. For `n <= 8` bidders the weights add up to
//! `2^n - 1 < t`, so a sum of weights shows exactly which bidders it contains. The top set `T` is
//! the set of bidders whose bid equals the highest bid. The program shows `T`, not one winner.
//!
//! With `C[p] = #{j : b_j >= p}`, `A[p] = #{j : b_j > p}`, `m` the sum of the masks, `R` the sum of
//! the pair masks, `Z = sum_k w_k ge_k`, `G = sum_k w_k gt_k` and `E = Z - G`, the lane of level `p`
//! has these values:
//!
//! First-price. One lane per level, in group 0 (level `p` is slot `p`), at depth 1 and with one
//! ct*ct product:
//!
//! ```text
//! out[p] = Z[p] + m[p] * A[p]
//! ```
//!
//! - `p > h`: 0, because `Z` and `A` are 0;
//! - `p = h`: the sum of `w_k` over `T`, because `A = 0`;
//! - `p < h`: uniform, because `A >= 1` and `m` is uniform.
//!
//! Second-price. A `y` lane and a `z` lane per level, in 3 copies `c`: `y` is group `2c` and `z`
//! is group `2c + 1`. The pair mask holds the same `R` in the `y` lane and the `z` lane of a level.
//! There are 6 ct*ct products, at depth 3:
//!
//! ```text
//! c = C * (C - 1)        u = A * (A - 1)        L = G + (1 - A) * E
//! y[p] = R[p] * c[p]        + m_y[p] * u[p]
//! z[p] = R[p] * c[p] * L[p] + m_z[p] * u[p]
//! ```
//!
//! With `s` the second-highest bid (the highest bid when the top bids tie):
//!
//! - `p > s`: `y` and `z` are 0, because `C <= 1` and `A <= 1`;
//! - `p = s`: `u = 0`, so `y = R * c` and `z / y = L`. `L` is the sum of `w_k` over the winner set:
//!   the one top bidder when the top bid is unique (`A = 1`), and `T` when the top bids tie (`A = 0`);
//! - `p < s`: `A >= 2` and `u != 0`, so `(y, z)` is a uniform pair.
//!
//! The decoder takes `s` as the highest level with `y != 0`. `y[s]` is 0 only if `R[s] = 0`, which
//! has the probability `1 / t` for each copy. The decoder takes the highest `s` of the copies.
//!
//! Random lane. Both types add one slot that holds `m` and is in no result lane: slot `LEVELS`
//! (group 1) for first-price and slot `2 * RATIO_COPIES * LEVELS` (group 6) for second-price. The
//! encrypted masks fix its value, and it is uniform if one bidder is honest. The winner is the
//! member of the sorted winner set at the index `random mod |set|`. Every slot that is not a result
//! lane or the random lane is zero. The output is a function of the price, the winner set and the
//! random lane only.
//!
//! See `shared/layout.ts` for the client decoder.

use e3_compute_provider::hashing::keccak256;
use e3_compute_provider::policy::{InputRecord, leaf_from_digest};
use e3_compute_provider::{ComputeError, FHEProcessorInput, InputPolicy, PublishedInput};
use fhe::bfv::{Ciphertext, Encoding, Plaintext};
use fhe::trlbfv::LBFVRelinearizationKey;
use fhe_traits::{DeserializeParametrized, FheEncoder, Serialize};
#[cfg(feature = "openvm-hashes")]
use openvm_sha2::Sha256;
#[cfg(not(all(feature = "openvm-hashes", target_os = "zkvm")))]
use sha2::Digest;
#[cfg(not(feature = "openvm-hashes"))]
use sha2::Sha256;
use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Arc;

/// The number of levels, which is the period of a bidder's thermometer. A bid is in `0..LEVELS`.
pub const LEVELS: usize = 16;

/// The number of copies of the `y` and `z` lanes of the second-price ratio-lane auction.
pub const RATIO_COPIES: usize = 3;

/// The slot of the random lane of the first-price ratio-lane auction: level 0 of group 1.
const RATIO_FIRST_RANDOM_SLOT: usize = LEVELS;

/// The slot of the random lane of the second-price ratio-lane auction: level 0 of group 6.
const RATIO_SECOND_RANDOM_SLOT: usize = 2 * RATIO_COPIES * LEVELS;

/// The prefix of the configuration input. `AuctionProgram.CONFIG_DOMAIN` is the same bytes.
pub const CONFIG_DOMAIN: &[u8] = b"interfold-auction-config-v1";

/// What the auction reveals. The values are the `uint8` that `AuctionProgram` stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuctionType {
    /// The winner and the highest bid.
    FirstPrice = 0,
    /// The winner and the second-highest bid.
    SecondPrice = 1,
    /// The highest bid and the set of bidders that bid it, with a random value that picks the winner.
    RatioFirstPrice = 2,
    /// The second-highest bid (the highest if the top bids tie) and the winner set, with a random
    /// value that picks the winner.
    RatioSecondPrice = 3,
}

impl AuctionType {
    /// The type of a configuration input, or `None` if `input` is not one.
    pub fn from_config(input: &[u8]) -> Option<Self> {
        match input.strip_prefix(CONFIG_DOMAIN)? {
            [0] => Some(Self::FirstPrice),
            [1] => Some(Self::SecondPrice),
            [2] => Some(Self::RatioFirstPrice),
            [3] => Some(Self::RatioSecondPrice),
            _ => None,
        }
    }

    /// Whether the type is a ratio-lane type.
    pub fn is_ratio(self) -> bool {
        matches!(self, Self::RatioFirstPrice | Self::RatioSecondPrice)
    }
}

/// The number of ciphertexts one bidder sends: `[ge, gt, mask]`, and for the second-price
/// ratio-lane type also the pair mask.
pub fn role_count(auction_type: AuctionType) -> usize {
    match auction_type {
        AuctionType::RatioSecondPrice => 4,
        _ => 3,
    }
}

/// The most bidders of a type. The smallest number is two. The region types are limited by the
/// regions that fit the ring, the ratio-lane types by the weights `2^k` that must stay below `t`.
pub fn max_bidders(auction_type: AuctionType) -> usize {
    if auction_type.is_ratio() { 8 } else { 4 }
}

/// Input 0 of a round: the domain bytes followed by the type byte.
pub fn config_input(auction_type: AuctionType) -> Vec<u8> {
    [CONFIG_DOMAIN, &[auction_type as u8]].concat()
}

/// The metadata `AuctionProgram` publishes with each bid ciphertext: the 20-byte bidder, then the
/// 5-byte bid version, as `abi.encodePacked(address, uint40)` lays it out.
///
/// The program server builds it from `input_slots` (the bidder) and `input_parents` (the version).
/// The auction reads the 5-byte field as the bid version, not as a parent. The configuration at
/// index 0 gets a zero commitment, a zero slot and the parent 0; its leaf ignores them.
const METADATA_LEN: usize = 25;

/// The input policy this E3 program requires: [`auction_leaf`] and [`select_bids`].
pub fn policy() -> InputPolicy {
    InputPolicy {
        leaf: auction_leaf,
        select: select_bids,
    }
}

/// The leaf of input `index`.
///
/// The leaf of input 0, the configuration, is `keccak256(config) mod BN254`, which
/// `AuctionProgram.validate` inserts. The leaf of every other input is
/// `sha256(keccak256(ciphertext) || commitment || bidder || uint40(version)) mod BN254`. It must stay
/// byte-identical to `AuctionProgram.inputLeaf`, or no root will ever match. It binds the bytes,
/// because the bid proof constrains only the commitment and never sees the serialized ciphertext;
/// the commitment, so no commitment can be paired with any ciphertext; and the bidder and the
/// version, because selection groups the leaves by them.
///
/// The leaf does not check that the bytes open the commitment. A ciphertext that does not open it
/// still gets a leaf, since every published input must; [`select_bids`] leaves it out of the
/// computation.
pub fn auction_leaf(input: &PublishedInput) -> Result<String, ComputeError> {
    if input.index == 0 {
        return Ok(leaf_from_digest(&input.ciphertext_hash));
    }
    let commitment = input
        .commitment
        .ok_or_else(|| ComputeError::LeafCommitment {
            index: input.index,
            reason: "the auction publishes a commitment with every bid ciphertext".to_string(),
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
/// whose bytes all open their commitments.
///
/// `AuctionProgram.publishInput` inserts one bid as a run of consecutive leaves with the same
/// metadata, so a run of records with identical metadata is one bid. A bidder may bid up to a few
/// times; each bid has the next version. For every bidder this keeps the run with the highest
/// version in which every record has a commitment and reproduces it. A bidder with no such run
/// is dropped whole, and a run is never taken in part, because a bid with one missing role is
/// no bid.
///
/// The contract cannot check that published bytes open a commitment, so any submitter can publish
/// a bid that does not. That bid is skipped, and an earlier valid bid of the same bidder counts. A
/// bidder can also withdraw this way, and it learns nothing from doing so.
///
/// A run whose metadata is not [`METADATA_LEN`] bytes is never taken. The result is ascending
/// by index, so the order of the chosen runs is the bidder position in the computation.
pub fn select_bids(inputs: &[InputRecord]) -> Vec<usize> {
    let Some((_, bids)) = inputs.split_first() else {
        return Vec::new();
    };

    // The best run so far of each bidder: its version bytes and its records.
    let mut latest: BTreeMap<&[u8], (&[u8], &[InputRecord])> = BTreeMap::new();
    for run in bids.chunk_by(|a, b| a.metadata == b.metadata) {
        let metadata = run[0].metadata;
        if metadata.len() != METADATA_LEN {
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

/// The tie priority of each bidder position: `priority[j]` is the region of bidder position `j`.
/// Only the region types use it.
///
/// `seed = keccak256(ge_0 || ge_1 || ...)`, the concatenation of the ge-ciphertext bytes of all
/// bidders in iteration order. The priority of position `j` is its rank when the positions are
/// sorted ascending by `keccak256(seed || u32_be(j))`, so the position with the highest hash has
/// priority `n - 1`. The client recomputes this from the published ciphertexts. It is fixed only
/// once every ge ciphertext is in, so the last bidder can re-encrypt to grind it; that only matters
/// when the top bids tie.
pub fn tie_priority(ge_ciphertexts: &[&[u8]]) -> Vec<usize> {
    let seed = keccak256(&ge_ciphertexts.concat());
    let hashes: Vec<[u8; 32]> = (0..ge_ciphertexts.len() as u32)
        .map(|j| {
            let mut preimage = [0u8; 36];
            preimage[..32].copy_from_slice(&seed);
            preimage[32..].copy_from_slice(&j.to_be_bytes());
            keccak256(&preimage)
        })
        .collect();
    let mut order: Vec<usize> = (0..hashes.len()).collect();
    order.sort_by(|&a, &b| hashes[a].cmp(&hashes[b]).then(a.cmp(&b)));
    let mut priority = vec![0; order.len()];
    for (rank, &position) in order.iter().enumerate() {
        priority[position] = rank;
    }
    priority
}

/// The number of copies of the `n` regions that fit the ring.
pub fn copies(degree: usize, bidders: usize) -> usize {
    degree / LEVELS / bidders
}

/// The first slot of `region` in `copy`, with `bidders` regions per copy.
fn slot(bidders: usize, copy: usize, region: usize) -> usize {
    (copy * bidders + region) * LEVELS
}

/// A SIMD plaintext with 1 in the slots of `ranges` and 0 elsewhere.
fn ones_in(
    params: &Arc<fhe::bfv::BfvParameters>,
    ranges: impl IntoIterator<Item = Range<usize>>,
) -> Plaintext {
    let mut slots = vec![0u64; params.degree()];
    for range in ranges {
        slots[range].fill(1);
    }
    Plaintext::try_encode(&slots, Encoding::simd(), params).expect("slots fit the degree")
}

/// A SIMD plaintext with every slot equal to `value`.
fn constant_slots(params: &Arc<fhe::bfv::BfvParameters>, value: u64) -> Plaintext {
    Plaintext::try_encode(&vec![value; params.degree()], Encoding::simd(), params)
        .expect("slots fit the degree")
}

fn sum(cts: impl IntoIterator<Item = Ciphertext>) -> Ciphertext {
    cts.into_iter()
        .reduce(|acc, ct| &acc + &ct)
        .expect("a round has two or more bidders")
}

/// `sum_k 2^k * cts[k]`: the weights of the ratio-lane types, by bidder position.
fn weighted_sum<'a>(
    params: &Arc<fhe::bfv::BfvParameters>,
    cts: impl IntoIterator<Item = &'a Ciphertext>,
) -> Ciphertext {
    sum(cts
        .into_iter()
        .enumerate()
        .map(|(k, ct)| ct * &constant_slots(params, 1 << k)))
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

/// Computes the test vector of a region type under the masks. See the module documentation.
///
/// `bids[j]` is `([b_j >= p], [b_j > p])`, `masks` is the sum of the bidder masks and `priority[j]`
/// is the region of bidder position `j`. Every ct*ct product is relinearized.
fn tests_under_mask(
    auction_type: AuctionType,
    params: &Arc<fhe::bfv::BfvParameters>,
    relinearization_key: &LBFVRelinearizationKey,
    bids: &[(Ciphertext, Ciphertext)],
    masks: &Ciphertext,
    priority: &[usize],
) -> Ciphertext {
    let n = bids.len();
    let copies = 0..copies(params.degree(), n);
    let mul = |a: &Ciphertext, b: &Ciphertext| multiply(relinearization_key, a, b);

    // Region r: its own slots, and the slots of the regions below it (r wins a tie there).
    let own = |r: usize| {
        ones_in(
            params,
            copies
                .clone()
                .map(|c| slot(n, c, r)..slot(n, c, r + 1)),
        )
    };
    let lower = |r: usize| {
        ones_in(
            params,
            copies
                .clone()
                .map(|c| slot(n, c, 0)..slot(n, c, r)),
        )
    };
    // The slots of the regions that exist. The groups beyond the last copy hold the thermometers
    // and the masks like every other group, and are zeroed here so that the output shows only
    // used regions. Applying it to the masks costs the least noise.
    let used = ones_in(
        params,
        copies.clone().map(|c| slot(n, c, 0)..slot(n, c + 1, 0)),
    );

    let second_price = auction_type == AuctionType::SecondPrice;
    let (mut own_at_least, mut own_above, mut ties_above) = (vec![], vec![], vec![]);
    for (j, (at_least, above)) in bids.iter().enumerate() {
        let region = priority[j];
        let selector = own(region);
        own_at_least.push(at_least * &selector);
        if second_price {
            own_above.push(above * &selector);
        }
        ties_above.push(&(at_least - above) * &lower(region));
    }
    let own_at_least = sum(own_at_least);
    // #{j > k : b_j = p} in region k.
    let ties_above = sum(ties_above);
    let above = sum(bids.iter().map(|b| b.1.clone()));
    let one = constant_slots(params, 1);
    let masks = masks * &used;

    match auction_type {
        AuctionType::FirstPrice => {
            // (1 - [b_k = p]) + #{j != k : b_j > p} + #{j > k : b_j = p}. The own `[b_k > p]` in
            // `above` and in `1 - [b_k >= p]` cancel to `1 - [b_k = p]`.
            let wins = &(&(&above + &one) - &own_at_least) + &ties_above;
            mul(&wins, &masks)
        }
        AuctionType::SecondPrice => {
            let own_above = sum(own_above);
            let at_least = sum(bids.iter().map(|b| b.0.clone()));
            // [b_k = p] * #{j > k : b_j = p} in region k.
            let ties = mul(&(&own_at_least - &own_above), &ties_above);
            // #{j != k : b_j > p} + [b_k < p] + ties.
            let others_above = &above - &own_above;
            let beaten = &(&(&others_above + &one) - &own_at_least) + &ties;
            let two_at_least = mul(&at_least, &(&at_least - &one));
            let tests = mul(&beaten, &two_at_least);
            mul(&tests, &masks)
        }
        AuctionType::RatioFirstPrice | AuctionType::RatioSecondPrice => {
            unreachable!("the ratio-lane types have their own lanes")
        }
    }
}

/// Computes the lanes of the first-price ratio-lane type: `out = S0 * Z + (S0 * m) * A + S_random * m`
/// with `S0` the slots of group 0 and `S_random` the random slot. One ct*ct product, at depth 1.
/// See the module documentation.
fn ratio_first_price(
    params: &Arc<fhe::bfv::BfvParameters>,
    relinearization_key: &LBFVRelinearizationKey,
    bids: &[(Ciphertext, Ciphertext)],
    masks: &Ciphertext,
) -> Ciphertext {
    let lanes = ones_in(params, [0..LEVELS]);
    let random = ones_in(params, [RATIO_FIRST_RANDOM_SLOT..RATIO_FIRST_RANDOM_SLOT + 1]);
    let weights_at_least = weighted_sum(params, bids.iter().map(|b| &b.0));
    let above = sum(bids.iter().map(|b| b.1.clone()));
    let hidden = multiply(relinearization_key, &(masks * &lanes), &above);
    &(&(&weights_at_least * &lanes) + &hidden) + &(masks * &random)
}

/// Computes the lanes of the second-price ratio-lane type. `L' = S_y + S_z * (G + (1 - A) * E)`
/// selects the `y` or the `z` weight of each lane, and
/// `out = (R * c) * L' + (S_lanes * m) * u + S_random * m`. 6 ct*ct products, at depth 3. See the
/// module documentation.
fn ratio_second_price(
    params: &Arc<fhe::bfv::BfvParameters>,
    relinearization_key: &LBFVRelinearizationKey,
    bids: &[(Ciphertext, Ciphertext)],
    masks: &Ciphertext,
    pair_masks: &Ciphertext,
) -> Ciphertext {
    let one = constant_slots(params, 1);
    let group = |g: usize| g * LEVELS..(g + 1) * LEVELS;
    let y_lanes = ones_in(params, (0..RATIO_COPIES).map(|c| group(2 * c)));
    let z_lanes = ones_in(params, (0..RATIO_COPIES).map(|c| group(2 * c + 1)));
    let lanes = ones_in(params, [0..2 * RATIO_COPIES * LEVELS]);
    let random = ones_in(params, [RATIO_SECOND_RANDOM_SLOT..RATIO_SECOND_RANDOM_SLOT + 1]);

    let at_least = sum(bids.iter().map(|b| b.0.clone()));
    let above = sum(bids.iter().map(|b| b.1.clone()));
    let weights_at_least = weighted_sum(params, bids.iter().map(|b| &b.0));
    let weights_above = weighted_sum(params, bids.iter().map(|b| &b.1));
    let weights_equal = &weights_at_least - &weights_above;

    // c = C (C - 1) and u = A (A - 1) at depth 1.
    let two_at_least = multiply(relinearization_key, &at_least, &(&at_least - &one));
    let two_above = multiply(relinearization_key, &above, &(&above - &one));
    // L' = S_y + S_z G + (1 - A) S_z E. The selector multiplies the fresh sums, which costs the
    // least noise.
    let equal_z = &weights_equal * &z_lanes;
    let winners = &(&(&(&weights_above * &z_lanes) + &equal_z)
        - &multiply(relinearization_key, &above, &equal_z))
        + &y_lanes;
    // R * c at depth 2, and then (R * c) * L' at depth 3.
    let shown = multiply(
        relinearization_key,
        &multiply(relinearization_key, pair_masks, &two_at_least),
        &winners,
    );
    let hidden = multiply(relinearization_key, &(masks * &lanes), &two_above);
    &(&shown + &hidden) + &(masks * &random)
}

/// Runs the auction over the inputs of the round.
///
/// The selected inputs arrive one at a time, in leaf order: the configuration, then the
/// [`role_count`] ciphertexts of each chosen bid in role order (see [`select_bids`]). The on-chain
/// index is not used, only the position.
///
/// # Panics
///
/// If input 0 is not a configuration, if the number of ciphertexts is not a multiple of the role
/// count, if there are fewer than two or more than [`max_bidders`] bidders, or if the l-BFV
/// relinearization key is missing. A malformed round has no meaningful result, so there is nothing
/// to recover to.
pub fn fhe_processor(inputs: FHEProcessorInput<'_>) -> Vec<u8> {
    let relinearization_key = inputs
        .relinearization_key
        .expect("the auction program requires the l-BFV relinearization key");

    let params = inputs.params;
    let (config, _) = inputs
        .ciphertexts
        .next()
        .expect("input 0 must be the auction configuration");
    let auction_type =
        AuctionType::from_config(&config).expect("input 0 must be the auction configuration");

    let mut raw = Vec::new();
    while let Some((bytes, _)) = inputs.ciphertexts.next() {
        raw.push(bytes);
    }
    let roles = role_count(auction_type);
    assert!(
        raw.len() % roles == 0,
        "the number of ciphertexts must be a multiple of {roles}: {roles} per bidder"
    );
    let n = raw.len() / roles;
    let max = max_bidders(auction_type);
    assert!(
        (2..=max).contains(&n),
        "an auction needs 2 to {max} bidders, got {n}"
    );
    assert!(
        !auction_type.is_ratio() || (1u64 << n) - 1 < params.plaintext(),
        "the weights of {n} bidders do not fit the plaintext modulus"
    );

    let ciphertext = |bytes: &Vec<u8>| Ciphertext::from_bytes(bytes, params).unwrap();
    let bids: Vec<(Ciphertext, Ciphertext)> = raw
        .chunks(roles)
        .map(|bidder| (ciphertext(&bidder[0]), ciphertext(&bidder[1])))
        .collect();
    let masks = sum(raw.chunks(roles).map(|bidder| ciphertext(&bidder[2])));

    let result = match auction_type {
        AuctionType::FirstPrice | AuctionType::SecondPrice => {
            let priority = tie_priority(
                &raw.chunks(roles)
                    .map(|bidder| bidder[0].as_slice())
                    .collect::<Vec<_>>(),
            );
            tests_under_mask(
                auction_type,
                params,
                relinearization_key,
                &bids,
                &masks,
                &priority,
            )
        }
        AuctionType::RatioFirstPrice => {
            ratio_first_price(params, relinearization_key, &bids, &masks)
        }
        AuctionType::RatioSecondPrice => {
            let pair_masks = sum(raw.chunks(roles).map(|bidder| ciphertext(&bidder[3])));
            ratio_second_price(params, relinearization_key, &bids, &masks, &pair_masks)
        }
    };
    result.to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use e3_fhe_params::{BfvPreset, build_pair_for_preset, lbfv_crs_seed, lbfv_urs_seed};
    use fhe::aggregate::AggregateIter;
    use fhe::bfv::{BfvParameters, CommonRandomPolyVec, SecretKey};
    use fhe::trlbfv::{
        LBFVPublicKey, PublicKeyShare, RelinKeyShare, aggregate_relinearization_key,
    };
    use fhe_traits::{FheDecoder, FheDecrypter, FheEncrypter};
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use std::sync::Arc;

    const PRESET: BfvPreset = BfvPreset::InsecureThresholdSimd;
    const REGION_TYPES: [AuctionType; 2] = [AuctionType::FirstPrice, AuctionType::SecondPrice];
    const RATIO_TYPES: [AuctionType; 2] =
        [AuctionType::RatioFirstPrice, AuctionType::RatioSecondPrice];

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

    /// The slots of every ciphertext of every bid, `[bidder][role]`, over all slots of the ring. The
    /// masks come from `seed`, which makes the plaintexts reproducible.
    fn plaintexts(
        fixture: &Fixture,
        auction_type: AuctionType,
        bids: &[usize],
        seed: u64,
    ) -> Vec<Vec<Vec<u64>>> {
        let degree = fixture.params.degree();
        let t = fixture.params.plaintext();
        let mut rng = StdRng::seed_from_u64(seed);
        bids.iter()
            .map(|&bid| {
                let thermometer = |inclusive: bool| -> Vec<u64> {
                    (0..degree)
                        .map(|i| {
                            let level = i % LEVELS;
                            u64::from(bid > level || (inclusive && bid == level))
                        })
                        .collect()
                };
                let mut roles = vec![
                    thermometer(true),
                    thermometer(false),
                    (0..degree).map(|_| rng.random_range(0..t)).collect(),
                ];
                if role_count(auction_type) == 4 {
                    // One free value for the slot `l` of the groups `2c` and `2c + 1`.
                    let mut pair_mask = vec![0; degree];
                    for pair in 0..degree / LEVELS / 2 {
                        for level in 0..LEVELS {
                            let value = rng.random_range(0..t);
                            pair_mask[2 * pair * LEVELS + level] = value;
                            pair_mask[(2 * pair + 1) * LEVELS + level] = value;
                        }
                    }
                    roles.push(pair_mask);
                }
                roles
            })
            .collect()
    }

    /// Encrypts the bids with the masks of `plaintexts(.., seed)`.
    fn encrypt_bids(
        fixture: &Fixture,
        auction_type: AuctionType,
        bids: &[usize],
        seed: u64,
    ) -> Result<Vec<(Vec<u8>, u64)>> {
        let mut ciphertexts = Vec::new();
        for slots in plaintexts(fixture, auction_type, bids, seed).iter().flatten() {
            let plaintext = Plaintext::try_encode(slots, Encoding::simd(), &fixture.params)?;
            let ciphertext: Ciphertext = fixture
                .public_key
                .try_encrypt(&plaintext, &mut rand::rng())?;
            let index = ciphertexts.len() as u64;
            ciphertexts.push((ciphertext.to_bytes(), index));
        }
        Ok(ciphertexts)
    }

    /// Runs the program over the configuration of `auction_type` and then `ciphertexts`.
    fn run(
        fixture: &Fixture,
        auction_type: AuctionType,
        ciphertexts: Vec<(Vec<u8>, u64)>,
    ) -> Vec<u8> {
        let inputs = std::iter::once((config_input(auction_type), 0)).chain(ciphertexts);
        fhe_processor(FHEProcessorInput {
            ciphertexts: &mut inputs.into_iter(),
            params: &fixture.params,
            relinearization_key: Some(&fixture.rlk),
        })
    }

    /// Encrypts the bids, runs a region type over them, and decrypts the result.
    fn auction(
        fixture: &Fixture,
        auction_type: AuctionType,
        bids: &[usize],
        seed: u64,
    ) -> Result<(Vec<u64>, Vec<usize>)> {
        let ciphertexts = encrypt_bids(fixture, auction_type, bids, seed)?;
        let priority = priority_of(&ciphertexts);
        let slots = decrypt_slots(fixture, &run(fixture, auction_type, ciphertexts))?;
        Ok((slots, priority))
    }

    /// Encrypts the bids, runs a ratio-lane type over them, and decrypts the result.
    fn ratio_auction(
        fixture: &Fixture,
        auction_type: AuctionType,
        bids: &[usize],
        seed: u64,
    ) -> Result<Vec<u64>> {
        let ciphertexts = encrypt_bids(fixture, auction_type, bids, seed)?;
        decrypt_slots(fixture, &run(fixture, auction_type, ciphertexts))
    }

    fn decrypt_slots(fixture: &Fixture, result: &[u8]) -> Result<Vec<u64>> {
        let decrypted = fixture
            .secret_key
            .try_decrypt(&Ciphertext::from_bytes(result, &fixture.params)?)?;
        Ok(Vec::<u64>::try_decode(&decrypted, Encoding::simd())?)
    }

    /// Whether `level` of `region` is non-zero in one or more copies.
    fn is_set(slots: &[u64], n: usize, region: usize, level: usize) -> bool {
        (0..copies(slots.len(), n)).any(|copy| slots[slot(n, copy, region) + level] != 0)
    }

    /// `(winner position, price)` as the client reads them off the slots.
    fn decode(
        auction_type: AuctionType,
        slots: &[u64],
        n: usize,
        priority: &[usize],
    ) -> Option<(usize, usize)> {
        let (region, price) = match auction_type {
            AuctionType::FirstPrice => {
                let clear: Vec<(usize, usize)> = (0..n)
                    .flat_map(|region| (0..LEVELS).map(move |level| (region, level)))
                    .filter(|&(region, level)| !is_set(slots, n, region, level))
                    .collect();
                let [only] = clear[..] else { return None };
                only
            }
            AuctionType::SecondPrice => {
                let last = |region| (0..LEVELS).rev().find(|&level| is_set(slots, n, region, level));
                let price = (0..n).filter_map(last).max()?;
                let winners: Vec<usize> = (0..n)
                    .filter(|&region| !is_set(slots, n, region, price))
                    .collect();
                let [region] = winners[..] else { return None };
                (region, price)
            }
            _ => unreachable!("a region type"),
        };
        Some((priority.iter().position(|&r| r == region)?, price))
    }

    /// The priority the program derives, from the ge ciphertexts of the round.
    fn priority_of(ciphertexts: &[(Vec<u8>, u64)]) -> Vec<usize> {
        tie_priority(
            &ciphertexts
                .chunks(3)
                .map(|t| t[0].0.as_slice())
                .collect::<Vec<_>>(),
        )
    }

    /// The winner and the price on the plaintext bids: the highest bid wins (ties go to the higher
    /// priority) and pays the highest (first-price) or the second-highest bid (second-price).
    fn expected(auction_type: AuctionType, bids: &[usize], priority: &[usize]) -> (usize, usize) {
        let mut order: Vec<usize> = (0..bids.len()).collect();
        order.sort_by(|&a, &b| (bids[b], priority[b]).cmp(&(bids[a], priority[a])));
        let paid = match auction_type {
            AuctionType::FirstPrice => order[0],
            AuctionType::SecondPrice => order[1],
            _ => unreachable!("a region type"),
        };
        (order[0], bids[paid])
    }

    #[test]
    fn the_priority_is_a_permutation_of_the_positions() {
        for n in 2..=max_bidders(AuctionType::FirstPrice) {
            let ciphertexts: Vec<Vec<u8>> = (0..n).map(|j| vec![j as u8; 7]).collect();
            let refs: Vec<&[u8]> = ciphertexts.iter().map(Vec::as_slice).collect();
            let mut priority = tie_priority(&refs);
            priority.sort_unstable();
            assert_eq!(priority, (0..n).collect::<Vec<_>>());
        }
    }

    #[test]
    fn the_priority_ranks_positions_by_the_hash_of_the_seed_and_position() {
        let ciphertexts = [vec![1u8, 2, 3], vec![4, 5], vec![6]];
        let refs: Vec<&[u8]> = ciphertexts.iter().map(Vec::as_slice).collect();
        let seed = keccak256(&ciphertexts.concat());
        let hash = |j: u32| keccak256(&[seed.as_slice(), &j.to_be_bytes()].concat());
        let priority = tie_priority(&refs);
        for a in 0..3 {
            for b in 0..3 {
                assert_eq!(
                    priority[a] < priority[b],
                    hash(a as u32) < hash(b as u32),
                    "positions {a} and {b}"
                );
            }
        }
    }

    #[test]
    fn finds_the_winner_and_the_price() -> Result<()> {
        let fixture = fixture()?;
        let bids = [5, 12, 9];
        for (auction_type, price) in [(AuctionType::FirstPrice, 12), (AuctionType::SecondPrice, 9)] {
            let (slots, priority) = auction(&fixture, auction_type, &bids, 1)?;
            assert_eq!(
                decode(auction_type, &slots, bids.len(), &priority),
                Some((1, price)),
                "{auction_type:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_tie_at_the_top_goes_to_the_higher_priority() -> Result<()> {
        let fixture = fixture()?;
        let bids = [7, 3, 7];
        for auction_type in REGION_TYPES {
            let (slots, priority) = auction(&fixture, auction_type, &bids, 2)?;
            let (winner, price) = expected(auction_type, &bids, &priority);
            assert_eq!(price, 7);
            assert_eq!(winner, if priority[0] > priority[2] { 0 } else { 2 });
            assert_eq!(
                decode(auction_type, &slots, bids.len(), &priority),
                Some((winner, 7)),
                "{auction_type:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn handles_the_extreme_bids() -> Result<()> {
        let fixture = fixture()?;
        for auction_type in REGION_TYPES {
            for (seed, bids) in [[0, 0, 0], [15, 0, 0], [15, 15, 15], [0, 15, 14]]
                .into_iter()
                .enumerate()
            {
                let (slots, priority) = auction(&fixture, auction_type, &bids, 10 + seed as u64)?;
                assert_eq!(
                    decode(auction_type, &slots, bids.len(), &priority),
                    Some(expected(auction_type, &bids, &priority)),
                    "{auction_type:?}, bids {bids:?}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn works_for_two_to_four_bidders() -> Result<()> {
        let fixture = fixture()?;
        let rounds: [&[usize]; 3] = [&[3, 8], &[1, 14, 6, 14], &[0, 2, 15, 15]];
        for auction_type in REGION_TYPES {
            for (seed, bids) in rounds.into_iter().enumerate() {
                let (slots, priority) = auction(&fixture, auction_type, bids, 20 + seed as u64)?;
                assert_eq!(
                    decode(auction_type, &slots, bids.len(), &priority),
                    Some(expected(auction_type, bids, &priority)),
                    "{auction_type:?}, bids {bids:?}"
                );
            }
        }
        Ok(())
    }

    /// The non-zero pattern of the output, over copies, for each region and level, and whether the
    /// unused groups are zero.
    fn pattern(slots: &[u64], n: usize) -> (Vec<Vec<bool>>, bool) {
        let used = copies(slots.len(), n) * n * LEVELS;
        (
            (0..n)
                .map(|region| (0..LEVELS).map(|level| is_set(slots, n, region, level)).collect())
                .collect(),
            slots[used..].iter().all(|&s| s == 0),
        )
    }

    #[test]
    fn the_output_depends_only_on_the_winner_and_the_price() -> Result<()> {
        let fixture = fixture()?;
        for auction_type in REGION_TYPES {
            for n in 2..=max_bidders(auction_type) {
                // Every set below is compared with the pattern the winner and the price predict,
                // and with every other set that has the same price and the same winner region.
                let mut by_result = std::collections::HashMap::new();
                for (seed, bids) in sets(auction_type, n).into_iter().enumerate() {
                    let (slots, priority) =
                        auction(&fixture, auction_type, &bids, 100 + seed as u64)?;
                    let (regions, unused_zero) = pattern(&slots, n);
                    assert!(unused_zero, "unused groups must be zero, bids {bids:?}");
                    // Re-key the pattern by position so that sets with different priorities compare.
                    let by_position: Vec<Vec<bool>> =
                        (0..n).map(|j| regions[priority[j]].clone()).collect();
                    let (winner, price) = expected(auction_type, &bids, &priority);
                    for (j, row) in by_position.iter().enumerate() {
                        for (level, &set) in row.iter().enumerate() {
                            let expected_set = match auction_type {
                                // Every slot is non-zero but the winner's at the price.
                                AuctionType::FirstPrice => j != winner || level != price,
                                // The winner's region is non-zero below the price, the others up
                                // to the price.
                                AuctionType::SecondPrice if j == winner => level < price,
                                _ => level <= price,
                            };
                            assert_eq!(
                                set, expected_set,
                                "{auction_type:?}, bids {bids:?}, position {j}, level {level}"
                            );
                        }
                    }
                    let key = (priority[winner], price);
                    match by_result.get(&key) {
                        Some(previous) => assert_eq!(previous, &regions, "bids {bids:?}"),
                        None => {
                            by_result.insert(key, regions);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Bid sets for `n` bidders: several share the price (the highest bid for first-price, the
    /// second-highest for second-price) and the winner's region, with other bids that differ.
    fn sets(auction_type: AuctionType, n: usize) -> Vec<Vec<usize>> {
        let shapes = match auction_type {
            AuctionType::FirstPrice => [(9, 4, 0), (9, 8, 3), (9, 1, 1), (15, 4, 3)],
            _ => [(9, 4, 0), (15, 4, 3), (9, 4, 4), (12, 4, 1)],
        };
        let mut sets = Vec::new();
        for (top, second, rest) in shapes {
            let mut bids = vec![rest; n];
            bids[0] = top;
            bids[1] = second;
            sets.push(bids.clone());
            bids.swap(0, n - 1);
            sets.push(bids);
        }
        sets
    }

    /// What the client reads from the lanes of a ratio-lane type.
    #[derive(Debug, PartialEq, Eq)]
    struct Lanes {
        price: usize,
        tie_set: Vec<usize>,
        random: u64,
    }

    /// The value of a lane: the `y` lane of `copy` at `level`, or its `z` lane.
    fn lane(auction_type: AuctionType, slots: &[u64], copy: usize, level: usize, z: bool) -> u64 {
        let group = match auction_type {
            AuctionType::RatioFirstPrice => 0,
            _ => 2 * copy + usize::from(z),
        };
        slots[group * LEVELS + level]
    }

    fn inverse(value: u64, t: u64) -> u64 {
        (0..t - 2).fold(1, |acc, _| acc * value % t)
    }

    /// Reads the price, the tie set and the random value off the slots, as `shared/layout.ts` does.
    /// `None` if the slots show no price, if the copies disagree or if a value is no set of bidders.
    fn decode_ratio(
        auction_type: AuctionType,
        slots: &[u64],
        n: usize,
        t: u64,
    ) -> Option<Lanes> {
        let copies = if auction_type == AuctionType::RatioFirstPrice { 1 } else { RATIO_COPIES };
        let highest = |copy| {
            (0..LEVELS)
                .rev()
                .find(|&level| lane(auction_type, slots, copy, level, false) != 0)
        };
        let price = (0..copies).filter_map(highest).max()?;
        let mut weights = Vec::new();
        for copy in 0..copies {
            let y = lane(auction_type, slots, copy, price, false);
            let z = lane(auction_type, slots, copy, price, true);
            match auction_type {
                AuctionType::RatioFirstPrice => weights.push(y),
                _ if y != 0 => weights.push(z * inverse(y, t) % t),
                _ if z != 0 => return None,
                _ => {}
            }
        }
        let weight = *weights.first()?;
        if weights.iter().any(|&w| w != weight) || weight >> n != 0 {
            return None;
        }
        let random_slot = match auction_type {
            AuctionType::RatioFirstPrice => RATIO_FIRST_RANDOM_SLOT,
            _ => RATIO_SECOND_RANDOM_SLOT,
        };
        Some(Lanes {
            price,
            tie_set: (0..n).filter(|k| weight >> k & 1 == 1).collect(),
            random: slots[random_slot],
        })
    }

    /// The price and the tie set on the plaintext bids. The tie set holds the bidders whose bid
    /// equals the price. A unique top bid of the second-price type pays the second-highest bid.
    fn expected_lanes(auction_type: AuctionType, bids: &[usize]) -> (usize, Vec<usize>) {
        let top = *bids.iter().max().unwrap();
        let tie_set: Vec<usize> = (0..bids.len()).filter(|&k| bids[k] == top).collect();
        if auction_type == AuctionType::RatioSecondPrice && tie_set.len() == 1 {
            let second = (0..bids.len()).filter(|&k| k != tie_set[0]).map(|k| bids[k]).max();
            return (second.unwrap(), tie_set);
        }
        (top, tie_set)
    }

    /// The bid sets of the ratio-lane tests: unique and tied tops, ties for second place, the
    /// extreme bids, two bidders and eight bidders.
    fn ratio_rounds() -> Vec<Vec<usize>> {
        vec![
            vec![5, 12, 9],
            vec![7, 7],
            vec![0, 0],
            vec![15, 0, 15],
            vec![3, 9, 9, 2],
            vec![4, 11, 4, 11, 1],
            vec![0, 15, 14],
            vec![15, 15, 15, 15, 15, 15, 15, 15],
            vec![2, 8, 6, 8, 1, 8, 0, 3],
            vec![1, 2, 3, 4, 5, 6, 7, 15],
            vec![9, 14, 14, 3, 3, 0, 5, 1],
        ]
    }

    #[test]
    fn a_ratio_auction_shows_the_price_and_the_tie_set() -> Result<()> {
        let fixture = fixture()?;
        let t = fixture.params.plaintext();
        for auction_type in RATIO_TYPES {
            for (seed, bids) in ratio_rounds().into_iter().enumerate() {
                let slots = ratio_auction(&fixture, auction_type, &bids, 200 + seed as u64)?;
                let (price, tie_set) = expected_lanes(auction_type, &bids);
                let lanes = decode_ratio(auction_type, &slots, bids.len(), t)
                    .unwrap_or_else(|| panic!("{auction_type:?}, bids {bids:?}: no readable result"));
                assert_eq!((lanes.price, lanes.tie_set), (price, tie_set), "{auction_type:?}, bids {bids:?}");
            }
        }
        Ok(())
    }

    #[test]
    fn the_random_lane_is_the_sum_of_the_masks_and_picks_the_winner_from_the_tie_set() -> Result<()> {
        let fixture = fixture()?;
        let t = fixture.params.plaintext();
        let bids = [7, 7, 3, 7];
        for auction_type in RATIO_TYPES {
            let masks = plaintexts(&fixture, auction_type, &bids, 300);
            let slots = ratio_auction(&fixture, auction_type, &bids, 300)?;
            let lanes = decode_ratio(auction_type, &slots, bids.len(), t).unwrap();
            let random_slot = match auction_type {
                AuctionType::RatioFirstPrice => RATIO_FIRST_RANDOM_SLOT,
                _ => RATIO_SECOND_RANDOM_SLOT,
            };
            let expected_random = masks.iter().map(|bidder| bidder[2][random_slot]).sum::<u64>() % t;
            assert_eq!(lanes.random, expected_random, "{auction_type:?}");
            assert_eq!((lanes.price, &lanes.tie_set[..]), (7, &[0, 1, 3][..]), "{auction_type:?}");
            let winner = lanes.tie_set[(lanes.random % lanes.tie_set.len() as u64) as usize];
            assert_eq!(winner, [0, 1, 3][(expected_random % 3) as usize], "{auction_type:?}");
        }
        Ok(())
    }

    /// The output slots on the plaintext slots of the bids: the formulas of the module
    /// documentation, with every mask.
    fn ratio_reference(
        auction_type: AuctionType,
        t: u64,
        plaintexts: &[Vec<Vec<u64>>],
    ) -> Vec<u64> {
        let degree = plaintexts[0][0].len();
        (0..degree)
            .map(|s| {
                let (group, mut weights_at_least, mut weights_above) = (s / LEVELS, 0, 0);
                let (mut at_least, mut above, mut masks, mut pair_masks) = (0, 0, 0, 0);
                for (k, bidder) in plaintexts.iter().enumerate() {
                    at_least += bidder[0][s];
                    above += bidder[1][s];
                    weights_at_least += bidder[0][s] << k;
                    weights_above += bidder[1][s] << k;
                    masks += bidder[2][s];
                    pair_masks += bidder.get(3).map_or(0, |pair| pair[s]);
                }
                let (masks, pair_masks) = (masks % t, pair_masks % t);
                let weights_equal = (weights_at_least + t - weights_above % t) % t;
                match auction_type {
                    AuctionType::RatioFirstPrice => match s {
                        0..LEVELS => (weights_at_least + masks * above) % t,
                        RATIO_FIRST_RANDOM_SLOT => masks,
                        _ => 0,
                    },
                    _ if s == RATIO_SECOND_RANDOM_SLOT => masks,
                    _ if group < 2 * RATIO_COPIES => {
                        let c = at_least * (at_least + t - 1) % t;
                        let u = above * (above + t - 1) % t;
                        let winners = (weights_above + (1 + t - above) % t * weights_equal) % t;
                        let shown = if group % 2 == 0 { pair_masks * c % t } else { pair_masks * c % t * winners % t };
                        (shown + masks * u) % t
                    }
                    _ => 0,
                }
            })
            .collect()
    }

    #[test]
    fn the_ratio_output_equals_the_formulas_on_the_plaintexts() -> Result<()> {
        let fixture = fixture()?;
        let t = fixture.params.plaintext();
        for auction_type in RATIO_TYPES {
            for (seed, bids) in ratio_rounds().into_iter().enumerate() {
                let seed = 400 + seed as u64;
                let slots = ratio_auction(&fixture, auction_type, &bids, seed)?;
                let reference =
                    ratio_reference(auction_type, t, &plaintexts(&fixture, auction_type, &bids, seed));
                assert_eq!(slots, reference, "{auction_type:?}, bids {bids:?}");
            }
        }
        Ok(())
    }

    /// The groups that hold result lanes: group 0, or the `y` and `z` groups of every copy.
    fn lane_groups(auction_type: AuctionType) -> usize {
        match auction_type {
            AuctionType::RatioFirstPrice => 1,
            _ => 2 * RATIO_COPIES,
        }
    }

    #[test]
    fn the_ratio_output_is_zero_above_the_price_and_outside_the_lanes() -> Result<()> {
        let fixture = fixture()?;
        for auction_type in RATIO_TYPES {
            let random_slot = match auction_type {
                AuctionType::RatioFirstPrice => RATIO_FIRST_RANDOM_SLOT,
                _ => RATIO_SECOND_RANDOM_SLOT,
            };
            for (seed, bids) in ratio_rounds().into_iter().enumerate() {
                let slots = ratio_auction(&fixture, auction_type, &bids, 500 + seed as u64)?;
                let (price, _) = expected_lanes(auction_type, &bids);
                for (slot, &value) in slots.iter().enumerate() {
                    let in_lanes = slot / LEVELS < lane_groups(auction_type);
                    let must_be_zero = if in_lanes {
                        slot % LEVELS > price
                    } else {
                        slot != random_slot
                    };
                    assert!(
                        !must_be_zero || value == 0,
                        "{auction_type:?}, bids {bids:?}, slot {slot} (price {price})"
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn the_ratio_output_depends_only_on_the_price_the_tie_set_and_the_random_lane() -> Result<()> {
        let fixture = fixture()?;
        let t = fixture.params.plaintext();
        // Bid sets of 4 bidders with the same price and the same tie set in each group, and
        // different other bids. The same masks give the same random lane. `[9, 4, 4, 4]` has the
        // most bids at the second-highest level, and `[3, 9, 9, 1]` and `[0, 9, 9, 8]` tie at
        // the top.
        let groups: [(AuctionType, &[&[usize]]); 4] = [
            (AuctionType::RatioFirstPrice, &[&[9, 4, 0, 2], &[9, 8, 3, 1], &[9, 1, 1, 0]]),
            (AuctionType::RatioFirstPrice, &[&[3, 9, 9, 1], &[0, 9, 9, 8]]),
            (AuctionType::RatioSecondPrice, &[&[9, 4, 0, 2], &[9, 4, 4, 4], &[9, 4, 1, 3]]),
            (AuctionType::RatioSecondPrice, &[&[3, 9, 9, 1], &[0, 9, 9, 8]]),
        ];
        for (auction_type, sets) in groups {
            let expected = expected_lanes(auction_type, sets[0]);
            let mut first: Option<Lanes> = None;
            for bids in sets {
                assert_eq!(expected_lanes(auction_type, bids), expected, "bid set {bids:?}");
                let slots = ratio_auction(&fixture, auction_type, bids, 600)?;
                let lanes = decode_ratio(auction_type, &slots, bids.len(), t)
                    .unwrap_or_else(|| panic!("{auction_type:?}, bids {bids:?}: no readable result"));
                assert_eq!(
                    first.get_or_insert_with(|| Lanes { price: lanes.price, tie_set: lanes.tie_set.clone(), random: lanes.random }),
                    &lanes,
                    "{auction_type:?}, bids {bids:?}"
                );
            }
        }
        Ok(())
    }

    #[test]
    #[should_panic(expected = "multiple of 3")]
    fn rejects_a_count_that_is_not_a_multiple_of_three() {
        let fixture = fixture().unwrap();
        let mut ciphertexts = encrypt_bids(&fixture, AuctionType::SecondPrice, &[1, 2], 3).unwrap();
        ciphertexts.pop();
        run(&fixture, AuctionType::SecondPrice, ciphertexts);
    }

    #[test]
    #[should_panic(expected = "multiple of 4")]
    fn rejects_a_count_that_is_not_a_multiple_of_four_for_the_second_price_ratio_type() {
        let fixture = fixture().unwrap();
        let mut ciphertexts =
            encrypt_bids(&fixture, AuctionType::RatioSecondPrice, &[1, 2], 3).unwrap();
        ciphertexts.pop();
        run(&fixture, AuctionType::RatioSecondPrice, ciphertexts);
    }

    #[test]
    #[should_panic(expected = "2 to 4 bidders")]
    fn rejects_a_single_bidder() {
        let fixture = fixture().unwrap();
        let ciphertexts = encrypt_bids(&fixture, AuctionType::FirstPrice, &[5], 4).unwrap();
        run(&fixture, AuctionType::FirstPrice, ciphertexts);
    }

    #[test]
    #[should_panic(expected = "2 to 4 bidders")]
    fn rejects_a_fifth_bidder_of_a_region_type() {
        let fixture = fixture().unwrap();
        let ciphertexts =
            encrypt_bids(&fixture, AuctionType::SecondPrice, &[1, 2, 3, 4, 5], 4).unwrap();
        run(&fixture, AuctionType::SecondPrice, ciphertexts);
    }

    #[test]
    #[should_panic(expected = "2 to 8 bidders")]
    fn rejects_a_ninth_bidder_of_a_ratio_type() {
        let fixture = fixture().unwrap();
        let ciphertexts = encrypt_bids(
            &fixture,
            AuctionType::RatioFirstPrice,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9],
            4,
        )
        .unwrap();
        run(&fixture, AuctionType::RatioFirstPrice, ciphertexts);
    }

    #[test]
    #[should_panic(expected = "auction configuration")]
    fn rejects_a_round_without_the_configuration() {
        let fixture = fixture().unwrap();
        let ciphertexts = encrypt_bids(&fixture, AuctionType::FirstPrice, &[5, 6], 5).unwrap();
        fhe_processor(FHEProcessorInput {
            ciphertexts: &mut ciphertexts.into_iter(),
            params: &fixture.params,
            relinearization_key: Some(&fixture.rlk),
        });
    }

    #[test]
    fn the_configuration_type_byte_names_the_type() {
        // `AuctionProgram.AUCTION_*` stores the same numbers.
        let from_byte = |byte: u8| AuctionType::from_config(&[CONFIG_DOMAIN, &[byte]].concat());
        assert_eq!(from_byte(0), Some(AuctionType::FirstPrice));
        assert_eq!(from_byte(1), Some(AuctionType::SecondPrice));
        assert_eq!(from_byte(2), Some(AuctionType::RatioFirstPrice));
        assert_eq!(from_byte(3), Some(AuctionType::RatioSecondPrice));
        assert_eq!(from_byte(4), None);
        assert_eq!(AuctionType::from_config(&CONFIG_DOMAIN[1..]), None);
    }

    #[test]
    fn the_configuration_leaf_is_the_reduced_hash_of_the_configuration() {
        // `AuctionProgram.configLeaf` computes `keccak256(CONFIG_DOMAIN || type) mod BN254`. Input 0
        // must get that leaf, whatever commitment and metadata come with it.
        let config = config_input(AuctionType::SecondPrice);
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
            leaf_from_digest(&keccak256(b"interfold-auction-config-v1\x01"))
        );
    }

    /// The leaf of a bid ciphertext with the given parts.
    fn bid_leaf(
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
        // `AuctionProgram.inputLeaf(h, c, bidder, version)` for this input is the same number.
        let metadata = [vec![0x33; 20], 2u64.to_be_bytes()[3..].to_vec()].concat();
        let leaf = bid_leaf([0x11; 32], Some(&[0x22; 32]), &metadata, None).unwrap();
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
            bid_leaf(hash, Some(commitment), metadata, recomputed).unwrap()
        };
        let base = leaf([0x11; 32], &commitment, &metadata, None);
        // A ciphertext that does not open its commitment still has a leaf, the same one.
        assert_eq!(base, leaf([0x11; 32], &commitment, &metadata, Some([9; 32])));
        assert_ne!(base, leaf([0x12; 32], &commitment, &metadata, None));
        assert_ne!(base, leaf([0x11; 32], &[0x23; 32], &metadata, None));
        assert_ne!(base, leaf([0x11; 32], &commitment, &metadata_of(6, 1), None));
        assert_ne!(base, leaf([0x11; 32], &commitment, &metadata_of(5, 2), None));
    }

    #[test]
    fn the_bid_leaf_needs_a_commitment_and_25_bytes_of_metadata() {
        let commitment = [0x22; 32];
        assert!(bid_leaf([0x11; 32], None, &metadata_of(5, 1), None).is_err());
        assert!(bid_leaf([0x11; 32], Some(&commitment), &[0; 24], None).is_err());
        assert!(bid_leaf([0x11; 32], Some(&commitment), &[0; 26], None).is_err());
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

    /// The 3 records of a bid; `opens[r]` says whether role `r` opens its commitment.
    fn bid(bidder: u8, version: u64, opens: [bool; 3]) -> Vec<Row> {
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
            .chain(rows.iter().flatten().enumerate().map(|(i, row)| InputRecord {
                index: i + 1,
                ciphertext_hash: [0; 32],
                commitment: row.commitment.as_ref(),
                metadata: &row.metadata,
                recomputed: row.recomputed,
            }))
            .collect();
        select_bids(&records)
    }

    const OPENS: [bool; 3] = [true; 3];

    #[test]
    fn the_latest_valid_version_of_a_bidder_is_selected() {
        // Leaves 1-3 are version 1, leaves 4-6 version 2, leaves 7-9 version 3.
        assert_eq!(
            selected(&[bid(1, 1, OPENS), bid(1, 2, OPENS), bid(1, 3, OPENS)]),
            [0, 7, 8, 9]
        );
    }

    #[test]
    fn a_bidder_falls_back_to_an_earlier_version_when_the_latest_does_not_open() {
        assert_eq!(
            selected(&[bid(1, 1, OPENS), bid(1, 2, [true, false, true])]),
            [0, 1, 2, 3]
        );
        // The first usable one counts, not the first one.
        assert_eq!(
            selected(&[
                bid(1, 1, OPENS),
                bid(1, 2, [false, true, true]),
                bid(1, 3, [true, true, false]),
            ]),
            [0, 1, 2, 3]
        );
    }

    #[test]
    fn a_bidder_with_one_bad_ciphertext_in_its_only_bid_is_dropped_whole() {
        for bad in 0..3 {
            let mut opens = OPENS;
            opens[bad] = false;
            assert_eq!(
                selected(&[bid(1, 1, opens), bid(2, 1, OPENS)]),
                [0, 4, 5, 6],
                "role {bad} does not open"
            );
        }
    }

    #[test]
    fn bidders_are_ordered_by_the_leaf_of_the_selected_bid() {
        // bidder 1: leaves 1-3 and 7-9, bidder 2: leaves 4-6. Bidder 1 counts at its update, so
        // it comes after bidder 2.
        assert_eq!(
            selected(&[bid(1, 1, OPENS), bid(2, 1, OPENS), bid(1, 2, OPENS)]),
            [0, 4, 5, 6, 7, 8, 9]
        );
    }

    #[test]
    fn the_configuration_is_always_selected() {
        assert_eq!(selected(&[]), [0]);
        assert_eq!(selected(&[bid(1, 1, [false; 3])]), [0]);
    }

    #[test]
    fn a_bid_with_malformed_metadata_or_no_commitment_is_never_selected() {
        for length in [0, 24, 26] {
            let mut malformed = bid(1, 1, OPENS);
            for row in &mut malformed {
                row.metadata = vec![1; length];
            }
            assert_eq!(selected(&[malformed, bid(2, 1, OPENS)]), [0, 4, 5, 6]);
        }

        let mut no_commitment = bid(1, 1, OPENS);
        no_commitment[1].commitment = None;
        assert_eq!(selected(&[no_commitment, bid(2, 1, OPENS)]), [0, 4, 5, 6]);
    }
}
