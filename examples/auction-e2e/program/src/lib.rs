// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The FHE program of the auction example: sealed-bid auctions of three types. The first-price type
//! (priority-expanded first price, PE-FP) shows the winner and the highest bid. The mask-provider
//! type is second-price with masks that independent providers send. The no-provider type is
//! second-price with random shares that the bidders send. None of the three can fail to show its
//! result.
//!
//! Input 0 of a round is its configuration, [`config_input`]: the domain bytes, the auction type
//! and, for the mask-provider type, the 20-byte addresses of the mask providers. It is not a
//! ciphertext. `AuctionProgram.validate` inserts its leaf, so the compute proof binds the type and
//! the providers through the input root (see [`policy`]).
//!
//! Each bidder sends [`role_count`] ciphertexts that do not depend on the bidder's index, on the
//! number of bidders or on the other bids. `AuctionProgram.publishInput` verifies one proof for the
//! whole bid and inserts one leaf per ciphertext as consecutive leaves in role order. A bidder may
//! bid again (an update), so the tree can hold several bids of one bidder. The policy picks, for
//! each bidder, its latest bid whose bytes open their commitments (see [`select_bids`]). After the
//! configuration the processor then receives one group of ciphertexts per chosen bid, in leaf
//! order. The bidder position is the place of the chosen bid in that order. The position does not
//! depend on the ciphertext bytes. A bidder that updates is placed where its update is published, so
//! an update loses the place of the earlier bid. If the top bids tie, the tied bidder with the
//! lowest position (the one whose chosen bid was published first) wins. All ciphertexts are
//! SIMD-encoded; a bid is a level `b` in `0..LEVELS`:
//!
//! ```text
//! ge     slot i  [b >= i % LEVELS]
//! gt     slot i  [b >  i % LEVELS]
//! mask   slot i  uniform in 0..t (the first-price type only)
//! share  slot i  uniform in 0..t (the no-provider type only)
//! ```
//!
//! # Lanes
//!
//! The 128 slots are `GROUPS` groups of `LEVELS` slots. With `n` bidders (2 to [`MAX_BIDDERS`]),
//! lane `j` is the slots `16 j .. 16 j + 15` and belongs to the bidder at position `j`: level `p`
//! of lane `j` is slot `16 j + p`. `used` is 1 on the slots `0 .. 16 n` and 0 elsewhere, so the
//! slots of the lanes that do not exist are zero in every output.
//!
//! # First-price type
//!
//! The first-price type ([`AuctionType::FirstPrice`]) has 3 ciphertexts per bidder, `[ge, gt, mask]`.
//! With `G[p] = sum_j gt_j[p]` (the bids above `p`, the same in every lane),
//! `E_j[p] = sum_{k < j} (ge_k[p] - gt_k[p])` (the earlier bidders that bid exactly `p`) and
//! `m = (sum_j mask_j) * used`, lane `j` holds
//!
//! ```text
//! out_j[p] = ge_j[p] + m[p] * (G[p] + E_j[p])
//! ```
//!
//! One ct*ct product, at depth 1, and `3 n` ct*pt products. With `h` the highest bid and `w` the
//! winner (the first bidder that bid `h`):
//!
//! - `p > h`: every lane is 0, because `ge`, `G` and `E` are 0;
//! - `p = h`: lane `j < w` is 0, because `ge_j = 0` and `G + E_j = 0`; lane `w` is exactly 1, because
//!   `ge_w = 1` and `G + E_w = 0`; a lane after `w` is `1 + m * E` or `m * E` and means nothing;
//! - `p < h`: `G >= 1`, so the mask hides the slot.
//!
//! The decoder reads the price as the highest level where some lane is non-zero, and the winner as
//! the first lane that is non-zero there. That lane must be exactly 1. The mask only touches slots
//! where `G + E >= 1`, which the decoder never needs, so the result is read whatever the masks
//! hold (a mask sum of 0 in any slot included). If one bidder is honest, `m` is uniform, and so
//! every masked slot is uniform: the output shows only the winner and the price.
//!
//! # Second-price types
//!
//! The second-price types have one copy of the lanes. `tests` is the second-price test vector.
//! Slot `p` of lane `k` tests whether that bidder beats every other bidder at level `p`:
//!
//! ```text
//! g_k[p] = #{j != k : b_j > p} + [b_k < p] + [b_k = p] * #{j < k : b_j = p}
//! ```
//!
//! `g_k[p]` is zero exactly when no other bid is above `p`, `b_k >= p`, and no earlier bidder ties
//! `k` at `p`. The program computes `tests = g * c'(c' - 1)`, where `c'[p] = #{j : b_j >= p}`. With
//! `s` the second-highest bid:
//!
//! - `p < s`: two or more bids are above `p`, the slot is non-zero;
//! - `p = s`: the slot is zero in the lane of the winner (a tie goes to the lowest position) and
//!   non-zero in every other lane;
//! - `p > s`: at most one bid is at or above `p`, the slot is zero.
//!
//! Every non-zero `g` is a whole number in `1 ..= n`, and every non-zero `c'(c' - 1)` is one in
//! `2 ..= n (n - 1)`. Both are below `t`, and `t` is prime, so `tests` is non-zero mod `t` exactly
//! where it is non-zero as a whole number. The output is `tests * r`, with a factor `r` that is
//! never zero in a slot of a lane that exists, so the output is zero exactly where `tests` is
//! zero, and the result is read with no failure. It is a function of the winner and `s` only: it
//! does not show the winning bid, the runner-up, any count or a tie. The 3 ct*ct products of
//! `tests` are at depth 2.
//!
//! # Mask-provider type
//!
//! The mask-provider type ([`AuctionType::ProviderSecondPrice`]) has no bidder masks. A bidder sends
//! only `[ge, gt]`. The configuration names `k` mask providers (1 to [`MAX_PROVIDERS`]). Each
//! provider sends one mask ciphertext `M_i` whose 128 slots are all non-zero (`AuctionProgram`
//! checks a proof of that). The masks come right after the configuration, one per provider in
//! submission order, with the bid version [`MASK_VERSION`]. The bids follow, and so with `n` bidders
//! (2 to 8) the processor receives `1 + k + 2n` inputs. The output is
//!
//! ```text
//! out = tests * r        r = (M_1 * used) * M_2 * ... * M_k   (a product tree, depth 2)
//! ```
//!
//! Every mask slot is non-zero, so a non-zero test never becomes zero. If one provider is honest, `r`
//! is uniform in `1 .. t` in every slot, so each non-zero output slot is uniform and the output
//! shows only where it is zero: a function of the winner and the price. `tests` is at depth 2 and
//! `r` is at depth 2, so the output is at depth 3. There are `k + 3` ct*ct products: 3 for `tests`,
//! `k - 1` for `r` and the last one.
//!
//! # No-provider type
//!
//! The no-provider type ([`AuctionType::QnrSecondPrice`]) has the result and the layout of the
//! mask-provider type, with no mask providers. A bidder sends `[ge, gt, s1, s2]`: the two
//! thermometers and two shares, which are SIMD plaintexts with every slot uniform in `0..t` (the
//! plaintext of a mask). The configuration names no provider. With `n` bidders (2 to 8) the
//! processor receives `1 + 4 n` inputs.
//!
//! With `S1 = sum_j s1_j` and `S2 = sum_j s2_j` over the chosen bids, the output is
//!
//! ```text
//! out = tests * r        r = ((S1 * S1 - 3) * used) * (S2 * S2 - 3)
//! ```
//!
//! 3 is not a square mod `t = 257` (an exhaustive check; also for 65537), so `S^2 - 3` is non-zero
//! for every `S`, whatever the bidders send. `S^2 - 3` is not uniform, because it takes only
//! `(t + 1) / 2` values. If one bidder is honest, `S1` and `S2` are uniform, `r` is close to
//! uniform in `1 .. t`, and the non-zero slots of the output show a small statistical hint about
//! the counts of the tests. The squares are at depth 1, `r` at depth 2, `tests` at depth 2 and the
//! output at depth 3. There are 7 ct*ct products: 3 for `tests`, 2 squares, one for `r` and the
//! last one.
//!
//! See `decodeResult` in each design package under `sdk/` for the client decoder.

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

/// The most mask providers of a mask-provider auction.
pub const MAX_PROVIDERS: usize = 4;

/// The bid version of a mask. It is `uint32` max, so the metadata of a mask is
/// `provider || 00 FF FF FF FF`. `AuctionProgram.MASK_VERSION` is the same number. A bid never has
/// this version.
pub const MASK_VERSION: u32 = u32::MAX;

/// The prefix of the configuration input. `AuctionProgram.CONFIG_DOMAIN` is the same bytes.
pub const CONFIG_DOMAIN: &[u8] = b"interfold-auction-config-v1";

/// What the auction reveals. The values are the `uint8` that `AuctionProgram` stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuctionType {
    /// The winner and the highest bid, with random masks from the bidders. The tied bidder with the
    /// lowest position wins.
    FirstPrice = 0,
    /// The winner and the second-highest bid, with masks from 1 to [`MAX_PROVIDERS`] providers.
    /// The tied bidder with the lowest position wins.
    ProviderSecondPrice = 1,
    /// The winner and the second-highest bid, with random shares from the bidders and no
    /// providers. The tied bidder with the lowest position wins.
    QnrSecondPrice = 2,
}

/// The address of a mask provider.
pub type Provider = [u8; 20];

/// What input 0 holds: the type and, for the mask-provider type, the providers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuctionConfig {
    pub auction_type: AuctionType,
    /// Empty for every type but [`AuctionType::ProviderSecondPrice`], which has 1 to
    /// [`MAX_PROVIDERS`].
    pub providers: Vec<Provider>,
}

impl AuctionConfig {
    /// The configuration of an input, or `None` if `input` is not one: the domain bytes, the type
    /// byte and then the providers (20 raw bytes each). The mask-provider type needs 1 to
    /// [`MAX_PROVIDERS`] of them, and every other type has none.
    pub fn from_input(input: &[u8]) -> Option<Self> {
        let (&type_byte, providers) = input.strip_prefix(CONFIG_DOMAIN)?.split_first()?;
        let auction_type = match type_byte {
            0 => AuctionType::FirstPrice,
            1 => AuctionType::ProviderSecondPrice,
            2 => AuctionType::QnrSecondPrice,
            _ => return None,
        };
        let (providers, rest) = providers.as_chunks::<20>();
        let count_fits = if auction_type == AuctionType::ProviderSecondPrice {
            (1..=MAX_PROVIDERS).contains(&providers.len())
        } else {
            providers.is_empty()
        };
        (rest.is_empty() && count_fits).then(|| Self {
            auction_type,
            providers: providers.to_vec(),
        })
    }
}

/// The number of ciphertexts one bidder sends: `[ge, gt, mask]` for the first-price type, `[ge, gt]`
/// for the mask-provider type and `[ge, gt, s1, s2]` for the no-provider type.
pub fn role_count(auction_type: AuctionType) -> usize {
    match auction_type {
        AuctionType::FirstPrice => 3,
        AuctionType::ProviderSecondPrice => 2,
        AuctionType::QnrSecondPrice => 4,
    }
}

/// The most bidders of every type, which is the groups that fit the ring. The smallest number is two.
pub const MAX_BIDDERS: usize = 8;

/// Input 0 of a round: the domain bytes, the type byte and the 20-byte `providers`.
pub fn config_input(auction_type: AuctionType, providers: &[Provider]) -> Vec<u8> {
    [CONFIG_DOMAIN, &[auction_type as u8], providers.as_flattened()].concat()
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

/// Whether the metadata of `record` is that of a mask: [`METADATA_LEN`] bytes with the version
/// [`MASK_VERSION`].
fn is_mask(record: &InputRecord) -> bool {
    match record.metadata {
        [.., 0, a, b, c, d] if record.metadata.len() == METADATA_LEN => {
            u32::from_be_bytes([*a, *b, *c, *d]) == MASK_VERSION
        }
        _ => false,
    }
}

/// Which inputs the computation runs over: the configuration, the masks of a mask-provider
/// auction, and for each bidder its latest bid whose bytes all open their commitments.
///
/// The masks are the maximal run of records right after the configuration whose version is
/// [`MASK_VERSION`] (`AuctionProgram` inserts them first and gives no bid that version). A mask
/// that has no commitment or does not open it cannot be replaced, and the auction cannot run
/// without every mask: then only the configuration is selected, and the processor panics. If
/// every mask opens, all of them are selected. A record with the mask version anywhere else is
/// never a bid.
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
    let Some((_, records)) = inputs.split_first() else {
        return Vec::new();
    };
    let mask_count = records.iter().take_while(|record| is_mask(record)).count();
    let (masks, bids) = records.split_at(mask_count);
    if !masks
        .iter()
        .all(|record| record.commitment.is_some() && record.matches_commitment())
    {
        return vec![0];
    }

    // The best run so far of each bidder: its version bytes and its records.
    let mut latest: BTreeMap<&[u8], (&[u8], &[InputRecord])> = BTreeMap::new();
    for run in bids.chunk_by(|a, b| a.metadata == b.metadata) {
        let metadata = run[0].metadata;
        if metadata.len() != METADATA_LEN || is_mask(&run[0]) {
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
    selected.extend(masks.iter().map(|record| record.index));
    selected.extend(
        latest
            .into_values()
            .flat_map(|(_, run)| run.iter().map(|record| record.index)),
    );
    selected.sort_unstable();
    selected
}

/// The slots of lane `j`: level `p` is slot `16 j + p`.
fn lane(j: usize) -> Range<usize> {
    j * LEVELS..(j + 1) * LEVELS
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

/// The product of `factors`, as a balanced tree of ct*ct products: the depth is `ceil(log2(len))`.
fn product_tree(
    relinearization_key: &LBFVRelinearizationKey,
    mut factors: Vec<Ciphertext>,
) -> Ciphertext {
    assert!(!factors.is_empty(), "a product needs a factor");
    while factors.len() > 1 {
        factors = factors
            .chunks(2)
            .map(|pair| match pair {
                [a, b] => multiply(relinearization_key, a, b),
                [a] => a.clone(),
                _ => unreachable!("chunks of 2"),
            })
            .collect();
    }
    factors.swap_remove(0)
}

/// Computes the output of the first-price type: `ge_j + m * (G + E_j)` in lane `j`, with
/// `m = (sum of the bidder masks) * used`. One ct*ct product, at depth 1. See the module
/// documentation.
///
/// `bids[j]` is `([b_j >= p], [b_j > p])` of bidder position `j`. `used` goes on the fresh sum of the
/// masks, which costs the least noise.
fn first_price(
    params: &Arc<fhe::bfv::BfvParameters>,
    relinearization_key: &LBFVRelinearizationKey,
    bids: &[(Ciphertext, Ciphertext)],
    masks: &Ciphertext,
) -> Ciphertext {
    let end = bids.len() * LEVELS;
    let (mut own_at_least, mut equal_before) = (vec![], vec![]);
    for (j, (at_least, above)) in bids.iter().enumerate() {
        own_at_least.push(at_least * &ones_in(params, [lane(j)]));
        // #{k < j : b_k = p} in lane j: the lanes after bidder `j` get its `[b_j = p]`.
        equal_before.push(&(at_least - above) * &ones_in(params, [lane(j + 1).start..end]));
    }
    let blockers = &sum(bids.iter().map(|b| b.1.clone())) + &sum(equal_before);
    let hidden = multiply(
        relinearization_key,
        &(masks * &ones_in(params, [0..end])),
        &blockers,
    );
    &sum(own_at_least) + &hidden
}

/// Computes the second-price test vector `tests` under the masks. See the module documentation.
///
/// `bids[j]` is `([b_j >= p], [b_j > p])` of bidder position `j`, and lane `j` is its lane. `mask`
/// is the factor the tests are multiplied by: it gets `used`, the slots of the lanes that exist, and
/// applies it to the masks. Every ct*ct product is relinearized.
fn tests_under_mask(
    params: &Arc<fhe::bfv::BfvParameters>,
    relinearization_key: &LBFVRelinearizationKey,
    bids: &[(Ciphertext, Ciphertext)],
    mask: impl FnOnce(&Plaintext) -> Ciphertext,
) -> Ciphertext {
    let end = bids.len() * LEVELS;
    let mul = |a: &Ciphertext, b: &Ciphertext| multiply(relinearization_key, a, b);

    // The slots of the lanes that exist. The groups beyond them hold the thermometers and the
    // masks like every other group, and are zeroed here so that the output shows only used lanes.
    // Applying it to the masks costs the least noise.
    let used = ones_in(params, [0..end]);
    let (mut own_at_least, mut own_above, mut ties_before) = (vec![], vec![], vec![]);
    for (j, (at_least, above)) in bids.iter().enumerate() {
        // Lane j: its own slots, and the slots of the lanes after it (lane j wins a tie there).
        let selector = ones_in(params, [lane(j)]);
        own_at_least.push(at_least * &selector);
        own_above.push(above * &selector);
        ties_before.push(&(at_least - above) * &ones_in(params, [lane(j + 1).start..end]));
    }
    let own_at_least = sum(own_at_least);
    let own_above = sum(own_above);
    // #{j < k : b_j = p} in lane k.
    let ties_before = sum(ties_before);
    let above = sum(bids.iter().map(|b| b.1.clone()));
    let at_least = sum(bids.iter().map(|b| b.0.clone()));
    let one = constant_slots(params, 1);
    let masks = mask(&used);

    // [b_k = p] * #{j < k : b_j = p} in lane k.
    let ties = mul(&(&own_at_least - &own_above), &ties_before);
    // #{j != k : b_j > p} + [b_k < p] + ties.
    let others_above = &above - &own_above;
    let beaten = &(&(&others_above + &one) - &own_at_least) + &ties;
    let two_at_least = mul(&at_least, &(&at_least - &one));
    let tests = mul(&beaten, &two_at_least);
    mul(&tests, &masks)
}

/// Runs the auction over the inputs of the round.
///
/// The selected inputs arrive one at a time, in leaf order: the configuration, for the
/// mask-provider type one mask per provider of the configuration, then the [`role_count`]
/// ciphertexts of each chosen bid in role order (see [`select_bids`]). The on-chain index is not
/// used, only the position.
///
/// # Panics
///
/// If input 0 is not a configuration, if a mask-provider round lacks a mask, if the number of bid
/// ciphertexts is not a multiple of the role count, if there are fewer than two or more than
/// [`MAX_BIDDERS`] bidders, or if the l-BFV relinearization key is missing. A malformed round has
/// no meaningful result, so there is nothing to recover to.
pub fn fhe_processor(inputs: FHEProcessorInput<'_>) -> Vec<u8> {
    let relinearization_key = inputs
        .relinearization_key
        .expect("the auction program requires the l-BFV relinearization key");

    let params = inputs.params;
    let (config, _) = inputs
        .ciphertexts
        .next()
        .expect("input 0 must be the auction configuration");
    let AuctionConfig {
        auction_type,
        providers,
    } = AuctionConfig::from_input(&config).expect("input 0 must be the auction configuration");

    let mut raw = Vec::new();
    while let Some((bytes, _)) = inputs.ciphertexts.next() {
        raw.push(bytes);
    }
    assert!(
        raw.len() >= providers.len(),
        "the auction needs the {} masks of its providers, got {} inputs",
        providers.len(),
        raw.len()
    );
    let (mask_bytes, raw) = raw.split_at(providers.len());
    let roles = role_count(auction_type);
    assert!(
        raw.len() % roles == 0,
        "the number of ciphertexts must be a multiple of {roles}: {roles} per bidder"
    );
    let n = raw.len() / roles;
    assert!(
        (2..=MAX_BIDDERS).contains(&n),
        "an auction needs 2 to {MAX_BIDDERS} bidders, got {n}"
    );

    let ciphertext = |bytes: &Vec<u8>| Ciphertext::from_bytes(bytes, params).unwrap();
    let bids: Vec<(Ciphertext, Ciphertext)> = raw
        .chunks(roles)
        .map(|bidder| (ciphertext(&bidder[0]), ciphertext(&bidder[1])))
        .collect();

    let result = match auction_type {
        AuctionType::FirstPrice => {
            let masks = sum(raw.chunks(roles).map(|bidder| ciphertext(&bidder[2])));
            first_price(params, relinearization_key, &bids, &masks)
        }
        AuctionType::ProviderSecondPrice => {
            // r = (M_1 * used) * M_2 * ... * M_k. `used` goes on the fresh M_1, which costs the
            // least noise, and the product tree has the depth `ceil(log2 k)`.
            let mut masks = mask_bytes.iter().map(ciphertext);
            let first = masks.next().expect("a mask-provider round has a provider");
            tests_under_mask(params, relinearization_key, &bids, |used| {
                let factors = std::iter::once(&first * used).chain(masks).collect();
                product_tree(relinearization_key, factors)
            })
        }
        AuctionType::QnrSecondPrice => {
            // r = ((S1 * S1 - 3) * used) * (S2 * S2 - 3). `used` goes on the first factor, which
            // is at depth 1, and the output is at depth 3.
            let share_sum = |role: usize| sum(raw.chunks(roles).map(|bidder| ciphertext(&bidder[role])));
            let (first, second) = (share_sum(2), share_sum(3));
            let three = constant_slots(params, 3);
            let square_less_three =
                |share: &Ciphertext| &multiply(relinearization_key, share, share) - &three;
            tests_under_mask(params, relinearization_key, &bids, |used| {
                multiply(
                    relinearization_key,
                    &(&square_less_three(&first) * used),
                    &square_less_three(&second),
                )
            })
        }
    };
    result.to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_compute_provider::hashing::keccak256;
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
                let mut roles = vec![thermometer(true), thermometer(false)];
                // The masks and the shares: one uniform ciphertext for each role after the
                // thermometers (none for the mask-provider type).
                for _ in 2..role_count(auction_type) {
                    roles.push((0..degree).map(|_| rng.random_range(0..t)).collect());
                }
                roles
            })
            .collect()
    }

    /// The bytes of the encryption of `slots` under the committee key.
    fn encrypt_slots(fixture: &Fixture, slots: &[u64]) -> Result<Vec<u8>> {
        let plaintext = Plaintext::try_encode(slots, Encoding::simd(), &fixture.params)?;
        let ciphertext: Ciphertext = fixture
            .public_key
            .try_encrypt(&plaintext, &mut rand::rng())?;
        Ok(ciphertext.to_bytes())
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
            let index = ciphertexts.len() as u64;
            ciphertexts.push((encrypt_slots(fixture, slots)?, index));
        }
        Ok(ciphertexts)
    }

    /// Runs the program over the configuration of `auction_type` with `providers`, and then
    /// `ciphertexts`.
    fn run_with_providers(
        fixture: &Fixture,
        auction_type: AuctionType,
        providers: &[Provider],
        ciphertexts: Vec<(Vec<u8>, u64)>,
    ) -> Vec<u8> {
        let inputs =
            std::iter::once((config_input(auction_type, providers), 0)).chain(ciphertexts);
        fhe_processor(FHEProcessorInput {
            ciphertexts: &mut inputs.into_iter(),
            params: &fixture.params,
            relinearization_key: Some(&fixture.rlk),
        })
    }

    /// Runs the program over the configuration of `auction_type` and then `ciphertexts`.
    fn run(
        fixture: &Fixture,
        auction_type: AuctionType,
        ciphertexts: Vec<(Vec<u8>, u64)>,
    ) -> Vec<u8> {
        run_with_providers(fixture, auction_type, &[], ciphertexts)
    }

    /// The output of `auction_type` over the plaintext slots `[bidder][role]`, as bytes.
    fn output(
        fixture: &Fixture,
        auction_type: AuctionType,
        plaintexts: &[Vec<Vec<u64>>],
    ) -> Result<Vec<u8>> {
        let mut ciphertexts = Vec::new();
        for slots in plaintexts.iter().flatten() {
            let index = ciphertexts.len() as u64 + 1;
            ciphertexts.push((encrypt_slots(fixture, slots)?, index));
        }
        Ok(run(fixture, auction_type, ciphertexts))
    }

    /// The noise of `output` in bits, and the budget that remains: the output stops decrypting
    /// exactly at a budget of 0.
    fn noise_budget(fixture: &Fixture, output: &Ciphertext) -> Result<(f64, f64)> {
        // SAFETY: `measure_noise` has a variable-time path that depends on the noise. The test
        // holds the secret key and only reads the budget.
        let noise = unsafe { fixture.secret_key.measure_noise(output) }? as f64;
        let log2_q: f64 = fixture.params.moduli().iter().map(|&q| (q as f64).log2()).sum();
        let t = fixture.params.plaintext() as f64;
        Ok((noise, log2_q - t.log2() - 1.0 - noise))
    }

    fn decrypt_slots(fixture: &Fixture, result: &[u8]) -> Result<Vec<u64>> {
        let decrypted = fixture
            .secret_key
            .try_decrypt(&Ciphertext::from_bytes(result, &fixture.params)?)?;
        Ok(Vec::<u64>::try_decode(&decrypted, Encoding::simd())?)
    }

    /// `(winner position, price)` as the client reads the slots of the first-price type: the slots
    /// beyond the `n` lanes are zero, the price is the highest level where some lane is non-zero,
    /// and the winner is the first lane that is non-zero there, which must hold exactly 1.
    fn decode_first_price(slots: &[u64], n: usize) -> Option<(usize, usize)> {
        let at = |lane: usize, level: usize| slots[lane * LEVELS + level];
        if slots[n * LEVELS..].iter().any(|&s| s != 0) {
            return None;
        }
        let price = (0..LEVELS)
            .rev()
            .find(|&level| (0..n).any(|lane| at(lane, level) != 0))?;
        let winner = (0..n).find(|&lane| at(lane, price) != 0)?;
        (at(winner, price) == 1).then_some((winner, price))
    }

    /// The winner and the price on the plaintext bids: the highest bid wins (a tie goes to the
    /// lowest position) and pays the highest (first-price) or the second-highest bid
    /// (second-price).
    fn expected(auction_type: AuctionType, bids: &[usize]) -> (usize, usize) {
        let mut order: Vec<usize> = (0..bids.len()).collect();
        // The sort is stable, so the lowest position of equal bids comes first.
        order.sort_by_key(|&j| std::cmp::Reverse(bids[j]));
        let paid = match auction_type {
            AuctionType::FirstPrice => order[0],
            AuctionType::ProviderSecondPrice | AuctionType::QnrSecondPrice => order[1],
        };
        (order[0], bids[paid])
    }

    /// Bid sets of 2 to 8 bidders with the winner position: unique tops at every position, and
    /// tops that tie (some of them with a bidder between or before the tied bidders).
    const TIE_ROUNDS: [(&[usize], usize); 11] = [
        (&[12, 5, 9], 0),
        (&[5, 12, 9], 1),
        (&[5, 9, 12], 2),
        (&[7, 3, 7], 0),
        (&[3, 7, 7], 1),
        (&[7, 7, 7], 0),
        (&[5, 9, 2, 9], 1),
        (&[4, 4], 0),
        (&[2, 3, 9, 1, 9, 9, 0, 9], 2),
        (&[15, 15, 15, 15, 15, 15, 15, 15], 0),
        (&[0, 0, 0, 0, 0, 0, 15, 15], 6),
    ];

    /// The output slots of the first-price type on the plaintext slots `[bidder][role]`, from the
    /// formulas of the module documentation, with every operation mod `t`. It does not use the
    /// ciphertext code, so it checks the formulas, the zero failure and the decoder on their own.
    fn first_price_model(t: u64, plaintexts: &[Vec<Vec<u64>>]) -> Vec<u64> {
        let n = plaintexts.len();
        (0..plaintexts[0][0].len())
            .map(|slot| {
                let lane = slot / LEVELS;
                if lane >= n {
                    return 0;
                }
                let sum = |role: usize| -> u64 { plaintexts.iter().map(|bidder| bidder[role][slot]).sum() };
                let (above, masks) = (sum(1), sum(2) % t);
                // The earlier bidders that bid exactly the level of the slot.
                let equal_before: u64 = plaintexts[..lane]
                    .iter()
                    .map(|bidder| bidder[0][slot] - bidder[1][slot])
                    .sum();
                (plaintexts[lane][0][slot] + masks * ((above + equal_before) % t)) % t
            })
            .collect()
    }

    /// Checks that the slots of the first-price type show the expected winner and price.
    fn check_first_price(slots: &[u64], bids: &[usize], context: &str) {
        assert_eq!(
            decode_first_price(slots, bids.len()),
            Some(expected(AuctionType::FirstPrice, bids)),
            "{context}, bids {bids:?}"
        );
    }

    /// Bid sets of `n` bidders for the first-price type: the sets of the provider tests, and sets
    /// that tie a lot (every bid in the top two levels, or in the bottom two levels).
    fn first_price_bid_sets(n: usize, rng: &mut StdRng) -> Vec<Vec<usize>> {
        let mut sets = provider_bid_sets(n, rng);
        for _ in 0..40 {
            sets.push((0..n).map(|_| rng.random_range(LEVELS - 2..LEVELS)).collect());
            sets.push((0..n).map(|_| rng.random_range(0..2)).collect());
        }
        sets
    }

    /// The mask sums `sum_j mask_j` that the bidders can force when they collude: zero in chosen
    /// slots (every slot, the slots of the price level, of the winner's lane, of the levels up to
    /// the price, or a random half) and random elsewhere, and two constants.
    fn first_price_mask_sums(
        bids: &[usize],
        degree: usize,
        t: u64,
        rng: &mut StdRng,
    ) -> Vec<(&'static str, Vec<u64>)> {
        let (winner, price) = expected(AuctionType::FirstPrice, bids);
        let half: Vec<bool> = (0..degree).map(|_| rng.random_bool(0.5)).collect();
        let mut zero_where = |zero: &dyn Fn(usize) -> bool| -> Vec<u64> {
            (0..degree)
                .map(|slot| if zero(slot) { 0 } else { rng.random_range(0..t) })
                .collect()
        };
        vec![
            ("zero in every slot", vec![0; degree]),
            ("zero at the price level", zero_where(&|slot| slot % LEVELS == price)),
            ("zero in the lane of the winner", zero_where(&|slot| slot / LEVELS == winner)),
            ("zero up to the price level", zero_where(&|slot| slot % LEVELS <= price)),
            ("zero in a random half", zero_where(&|slot| half[slot])),
            ("every slot 1", vec![1; degree]),
            ("every slot t - 1", vec![t - 1; degree]),
        ]
    }

    #[test]
    fn the_first_price_formulas_are_exact_for_every_bid_set_of_two_and_three_bidders() -> Result<()> {
        let fixture = fixture()?;
        let t = fixture.params.plaintext();
        let mut seed = 0;
        let mut sets = 0;
        for n in 2..=3u32 {
            for code in 0..LEVELS.pow(n) {
                let bids: Vec<usize> = (0..n).map(|j| code / LEVELS.pow(j) % LEVELS).collect();
                seed += 1;
                let inputs = plaintexts(&fixture, AuctionType::FirstPrice, &bids, seed);
                check_first_price(&first_price_model(t, &inputs), &bids, &format!("n = {n}"));
                sets += 1;
            }
        }
        assert_eq!(sets, 16 * 16 + 16 * 16 * 16);
        Ok(())
    }

    #[test]
    fn the_first_price_formulas_are_exact_for_random_and_tie_heavy_sets_up_to_eight_bidders() -> Result<()> {
        let fixture = fixture()?;
        let t = fixture.params.plaintext();
        let mut rng = StdRng::seed_from_u64(61);
        let mut seed = 10_000;
        for n in 2..=8 {
            let mut sets = first_price_bid_sets(n, &mut rng);
            for _ in 0..200 {
                sets.push((0..n).map(|_| rng.random_range(0..LEVELS)).collect());
            }
            for bids in sets {
                seed += 1;
                let inputs = plaintexts(&fixture, AuctionType::FirstPrice, &bids, seed);
                check_first_price(&first_price_model(t, &inputs), &bids, &format!("n = {n}"));
            }
        }
        Ok(())
    }

    #[test]
    fn the_first_price_formulas_are_exact_under_adversarial_masks() -> Result<()> {
        let fixture = fixture()?;
        let (degree, t) = (fixture.params.degree(), fixture.params.plaintext());
        let mut rng = StdRng::seed_from_u64(62);
        let mut seed = 20_000;
        for n in 2..=8 {
            for bids in first_price_bid_sets(n, &mut rng) {
                for (name, target) in first_price_mask_sums(&bids, degree, t, &mut rng) {
                    seed += 1;
                    let mut inputs = plaintexts(&fixture, AuctionType::FirstPrice, &bids, seed);
                    set_share_sum(&mut inputs, 2, &target, t);
                    check_first_price(
                        &first_price_model(t, &inputs),
                        &bids,
                        &format!("n = {n}, mask sum: {name}"),
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn the_first_price_type_matches_the_formulas_and_keeps_a_noise_budget_for_two_to_eight_bidders() -> Result<()> {
        let fixture = fixture()?;
        let t = fixture.params.plaintext();
        let mut rng = StdRng::seed_from_u64(63);
        for n in 2..=8 {
            let (mut most_noise, mut least_budget) = (0.0f64, f64::MAX);
            // Random bids, equal bids, ties at the top (first and last, or the last two), only
            // zero bids, only the highest bids and one bid above zero bids.
            for (seed, bids) in provider_bid_sets(n, &mut rng).into_iter().enumerate() {
                let inputs = plaintexts(&fixture, AuctionType::FirstPrice, &bids, 1500 + seed as u64);
                let bytes = output(&fixture, AuctionType::FirstPrice, &inputs)?;
                let (noise, budget) =
                    noise_budget(&fixture, &Ciphertext::from_bytes(&bytes, &fixture.params)?)?;
                (most_noise, least_budget) = (most_noise.max(noise), least_budget.min(budget));
                let slots = decrypt_slots(&fixture, &bytes)?;
                assert_eq!(slots, first_price_model(t, &inputs), "n = {n}, bids {bids:?}");
                check_first_price(&slots, &bids, &format!("n = {n}"));
            }
            eprintln!("type 0, n = {n}: noise {most_noise:.0} bits at most, budget {least_budget:.1} bits at least");
            // The output stops decrypting exactly at 0.
            assert!(least_budget > 30.0, "n = {n}: the budget is {least_budget} bits");
        }
        Ok(())
    }

    #[test]
    fn the_first_price_type_gives_a_tie_at_the_top_to_the_earliest_position() -> Result<()> {
        let fixture = fixture()?;
        for (seed, (bids, winner)) in TIE_ROUNDS.into_iter().enumerate() {
            let inputs = plaintexts(&fixture, AuctionType::FirstPrice, bids, 1600 + seed as u64);
            let slots = decrypt_slots(&fixture, &output(&fixture, AuctionType::FirstPrice, &inputs)?)?;
            let (expected_winner, price) = expected(AuctionType::FirstPrice, bids);
            assert_eq!(expected_winner, winner, "bids {bids:?}");
            assert_eq!(decode_first_price(&slots, bids.len()), Some((winner, price)), "bids {bids:?}");
        }
        Ok(())
    }

    #[test]
    fn the_first_price_type_decodes_exactly_under_adversarial_masks() -> Result<()> {
        let fixture = fixture()?;
        let (degree, t) = (fixture.params.degree(), fixture.params.plaintext());
        let mut rng = StdRng::seed_from_u64(64);
        for n in [2, 3, 5, 8] {
            let sets = provider_bid_sets(n, &mut rng);
            // A random set, a top tie and the zero bids.
            for bids in [&sets[0], &sets[3], &sets[5]] {
                for (name, target) in first_price_mask_sums(bids, degree, t, &mut rng) {
                    let mut inputs = plaintexts(&fixture, AuctionType::FirstPrice, bids, 1700);
                    set_share_sum(&mut inputs, 2, &target, t);
                    let slots =
                        decrypt_slots(&fixture, &output(&fixture, AuctionType::FirstPrice, &inputs)?)?;
                    assert_eq!(slots, first_price_model(t, &inputs), "n = {n}, mask sum: {name}");
                    check_first_price(&slots, bids, &format!("n = {n}, mask sum: {name}"));
                }
            }
        }
        Ok(())
    }

    #[test]
    #[should_panic(expected = "multiple of 3")]
    fn rejects_a_first_price_count_that_is_not_a_multiple_of_three() {
        let fixture = fixture().unwrap();
        let mut ciphertexts = encrypt_bids(&fixture, AuctionType::FirstPrice, &[1, 2], 3).unwrap();
        ciphertexts.pop();
        run(&fixture, AuctionType::FirstPrice, ciphertexts);
    }

    #[test]
    #[should_panic(expected = "2 to 8 bidders")]
    fn rejects_a_single_bidder() {
        let fixture = fixture().unwrap();
        let ciphertexts = encrypt_bids(&fixture, AuctionType::FirstPrice, &[5], 4).unwrap();
        run(&fixture, AuctionType::FirstPrice, ciphertexts);
    }

    #[test]
    #[should_panic(expected = "2 to 8 bidders")]
    fn rejects_a_ninth_bidder_of_the_first_price_type() {
        let fixture = fixture().unwrap();
        let ciphertexts = encrypt_bids(
            &fixture,
            AuctionType::FirstPrice,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9],
            4,
        )
        .unwrap();
        run(&fixture, AuctionType::FirstPrice, ciphertexts);
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
        let from_byte = |byte: u8| {
            AuctionConfig::from_input(&[CONFIG_DOMAIN, &[byte]].concat())
                .map(|config| config.auction_type)
        };
        assert_eq!(from_byte(0), Some(AuctionType::FirstPrice));
        // The provider type needs 1 to 4 providers, so its bare byte is no configuration.
        assert_eq!(from_byte(1), None);
        assert_eq!(
            AuctionConfig::from_input(&[CONFIG_DOMAIN, &[1], &[0x11; 20]].concat())
                .map(|config| config.auction_type),
            Some(AuctionType::ProviderSecondPrice)
        );
        assert_eq!(from_byte(2), Some(AuctionType::QnrSecondPrice));
        assert_eq!(from_byte(3), None);
        assert_eq!(from_byte(4), None);
        assert_eq!(from_byte(5), None);
        assert_eq!(from_byte(255), None);
        assert_eq!(AuctionConfig::from_input(&CONFIG_DOMAIN[1..]), None);
        assert_eq!(AuctionConfig::from_input(CONFIG_DOMAIN), None);
    }

    #[test]
    fn the_configuration_of_the_provider_type_lists_one_to_four_providers() {
        let providers = [[0x11; 20], [0x22; 20], [0x33; 20], [0x44; 20], [0x55; 20]];
        let parse = |auction_type, count: usize| {
            AuctionConfig::from_input(&config_input(auction_type, &providers[..count]))
        };
        for count in 1..=MAX_PROVIDERS {
            assert_eq!(
                parse(AuctionType::ProviderSecondPrice, count),
                Some(AuctionConfig {
                    auction_type: AuctionType::ProviderSecondPrice,
                    providers: providers[..count].to_vec(),
                })
            );
        }
        assert_eq!(parse(AuctionType::ProviderSecondPrice, 0), None);
        assert_eq!(parse(AuctionType::ProviderSecondPrice, MAX_PROVIDERS + 1), None);
        // The other types have no providers.
        for auction_type in [AuctionType::FirstPrice, AuctionType::QnrSecondPrice] {
            assert_eq!(parse(auction_type, 0).map(|c| c.providers.len()), Some(0));
            assert_eq!(parse(auction_type, 1), None);
        }
        // A provider is 20 raw bytes, not a padded word and not a part of one.
        let config = config_input(AuctionType::ProviderSecondPrice, &providers[..2]);
        assert_eq!(config.len(), CONFIG_DOMAIN.len() + 1 + 40);
        assert_eq!(AuctionConfig::from_input(&config[..config.len() - 1]), None);
        assert_eq!(AuctionConfig::from_input(&[config, vec![0]].concat()), None);
    }

    #[test]
    fn the_configuration_leaf_is_the_reduced_hash_of_the_configuration() {
        // `AuctionProgram.configLeaf` computes `keccak256(CONFIG_DOMAIN || type || providers) mod
        // BN254`. Input 0 must get that leaf, whatever commitment and metadata come with it.
        let zero = [0u8; 32];
        let leaf_of = |config: &[u8]| {
            (policy().leaf)(&PublishedInput {
                index: 0,
                ciphertext: config,
                ciphertext_hash: keccak256(config),
                commitment: Some(&zero),
                metadata: &[0; METADATA_LEN],
                recomputed: None,
            })
            .unwrap()
        };
        assert_eq!(
            leaf_of(&config_input(AuctionType::FirstPrice, &[])),
            leaf_from_digest(&keccak256(b"interfold-auction-config-v1\x00"))
        );
        assert_eq!(
            leaf_of(&config_input(AuctionType::QnrSecondPrice, &[])),
            leaf_from_digest(&keccak256(b"interfold-auction-config-v1\x02"))
        );
        let providers = [[0x11; 20], [0x22; 20]];
        let config = config_input(AuctionType::ProviderSecondPrice, &providers);
        assert_eq!(
            config,
            [
                &b"interfold-auction-config-v1\x01"[..],
                &[0x11; 20][..],
                &[0x22; 20][..]
            ]
            .concat()
        );
        assert_eq!(leaf_of(&config), leaf_from_digest(&keccak256(&config)));
        // The values `AuctionProgram.configInput` and `configLeaf` give for these providers.
        let digest: String = keccak256(&config).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(digest, "c35ec886d8a9aa1b8ee8253c137ea4da5393c43cd7a1e2cd1e7adf4e08af0746");
        assert_eq!(
            format!("{:0>64}", leaf_of(&config)),
            "01cd8ebb53e32974ada70e620d794365b2c4231af0bc20880ef308fe48af0742"
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

    /// The records of one run with the same metadata; `opens[r]` says whether record `r` opens its
    /// commitment.
    fn run_of(bidder: u8, version: u64, opens: &[bool]) -> Vec<Row> {
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

    /// The 3 records of a bid; `opens[r]` says whether role `r` opens its commitment.
    fn bid(bidder: u8, version: u64, opens: [bool; 3]) -> Vec<Row> {
        run_of(bidder, version, &opens)
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

    /// The 2 records of a mask-provider bid.
    fn bid2(bidder: u8, version: u64) -> Vec<Row> {
        run_of(bidder, version, &[true, true])
    }

    /// The record of the mask of provider `provider`.
    fn mask(provider: u8, opens: bool) -> Vec<Row> {
        run_of(provider, MASK_VERSION.into(), &[opens])
    }

    #[test]
    fn the_masks_lead_and_the_bids_follow_by_the_usual_rule() {
        // Leaves 1 and 2 are the masks, 3-4 the bid of bidder 1, 5-6 its update, 7-8 bidder 2.
        assert_eq!(
            selected(&[
                mask(0xa0, true),
                mask(0xa1, true),
                bid2(1, 1),
                bid2(1, 2),
                bid2(2, 1)
            ]),
            [0, 1, 2, 5, 6, 7, 8]
        );
        // An update that does not open falls back to the first bid, which keeps its place.
        let mut bad_update = bid2(1, 2);
        bad_update[1].recomputed = Some([0xff; 32]);
        assert_eq!(
            selected(&[mask(0xa0, true), bid2(1, 1), bad_update, bid2(2, 1)]),
            [0, 1, 2, 3, 6, 7]
        );
        // A bidder whose only bid does not open is dropped, and the masks stay.
        let mut bad = bid2(1, 1);
        bad[0].recomputed = Some([0xff; 32]);
        assert_eq!(selected(&[mask(0xa0, true), bad, bid2(2, 1)]), [0, 1, 4, 5]);
    }

    #[test]
    fn a_mask_that_does_not_open_leaves_only_the_configuration() {
        for bad in 0..3 {
            let masks: Vec<Vec<Row>> = (0..3).map(|i| mask(0xa0 + i, i as usize != bad)).collect();
            let mut rows = masks;
            rows.push(bid2(1, 1));
            rows.push(bid2(2, 1));
            assert_eq!(selected(&rows), [0], "mask {bad} does not open");
        }
        // A mask with no commitment does not open either.
        let mut no_commitment = mask(0xa1, true);
        no_commitment[0].commitment = None;
        assert_eq!(
            selected(&[mask(0xa0, true), no_commitment, bid2(1, 1), bid2(2, 1)]),
            [0]
        );
    }

    #[test]
    fn a_record_with_the_mask_version_after_a_bid_is_ignored() {
        // The leading run ends at the first bid. A later mask record is no mask and no bid, and it
        // does not matter whether it opens.
        for opens in [true, false] {
            assert_eq!(
                selected(&[mask(0xa0, true), bid2(1, 1), mask(0xa1, opens), bid2(2, 1)]),
                [0, 1, 2, 3, 5, 6]
            );
        }
        // Without a mask at the front, a mask-version record is never a bid either.
        assert_eq!(selected(&[bid2(1, 1), mask(0xa1, true)]), [0, 1, 2]);
    }

    #[test]
    fn the_mask_version_is_the_last_uint32_in_the_metadata() {
        // `provider || 00 FF FF FF FF`; a bid of version 1 to 3 is no mask, and a version one
        // below the mask version is a bid.
        let almost = u64::from(MASK_VERSION) - 1;
        assert_eq!(selected(&[bid2(1, almost), bid2(2, 1)]), [0, 1, 2, 3, 4]);
        assert_eq!(metadata_of(7, MASK_VERSION.into())[20..], [0, 0xff, 0xff, 0xff, 0xff]);
    }

    /// Slots of a mask-provider round: `t - 1` values `1..t`.
    fn mask_slots(rng: &mut StdRng, degree: usize, t: u64) -> Vec<u64> {
        (0..degree).map(|_| rng.random_range(1..t)).collect()
    }

    /// The masks of `k` providers that the adversarial tests use. Every slot is non-zero.
    fn mask_sets(k: usize, degree: usize, t: u64, rng: &mut StdRng) -> Vec<(&'static str, Vec<Vec<u64>>)> {
        let constant = |values: &[u64]| -> Vec<Vec<u64>> {
            values[..k].iter().map(|&v| vec![v; degree]).collect()
        };
        // A slot-dependent ramp that covers `1..t` with a different offset for each provider.
        let ramp: Vec<Vec<u64>> = (0..k)
            .map(|p| (0..degree).map(|s| (s as u64 * (p as u64 + 1)) % (t - 1) + 1).collect())
            .collect();
        vec![
            ("random", (0..k).map(|_| mask_slots(rng, degree, t)).collect()),
            ("every slot 1", constant(&[1; 4])),
            ("every slot t - 1", constant(&[t - 1; 4])),
            // 2 * 129 = 1 mod 257: the product of the pair is 1 in every slot.
            ("a different constant per provider", constant(&[1, t - 1, 2, 129])),
            ("a ramp per provider", ramp),
        ]
    }

    /// The output of the mask-provider type: the `masks` (slots of each provider), then the bids.
    fn provider_output(
        fixture: &Fixture,
        bids: &[usize],
        masks: &[Vec<u64>],
        seed: u64,
    ) -> Result<Vec<u8>> {
        let mut ciphertexts = Vec::new();
        for slots in masks {
            let index = ciphertexts.len() as u64 + 1;
            ciphertexts.push((encrypt_slots(fixture, slots)?, index));
        }
        ciphertexts.extend(encrypt_bids(fixture, AuctionType::ProviderSecondPrice, bids, seed)?);
        let providers: Vec<Provider> = (0..masks.len()).map(|i| [0xa0 + i as u8; 20]).collect();
        Ok(run_with_providers(
            fixture,
            AuctionType::ProviderSecondPrice,
            &providers,
            ciphertexts,
        ))
    }

    /// `(winner position, price)` as the client reads the slots of the mask-provider type, with
    /// the strict pattern: the unused slots are zero, no slot above the price is non-zero, exactly
    /// one region is zero at the price, and every slot below the price is non-zero.
    fn decode_provider(slots: &[u64], n: usize) -> Option<(usize, usize)> {
        let at = |region: usize, level: usize| slots[region * LEVELS + level];
        if slots[n * LEVELS..].iter().any(|&s| s != 0) {
            return None;
        }
        let price = (0..LEVELS)
            .rev()
            .find(|&level| (0..n).any(|region| at(region, level) != 0))?;
        let winners: Vec<usize> = (0..n).filter(|&region| at(region, price) == 0).collect();
        let below_set = (0..n).all(|region| (0..price).all(|level| at(region, level) != 0));
        match (&winners[..], below_set) {
            ([winner], true) => Some((*winner, price)),
            _ => None,
        }
    }

    /// Whether each slot of the output is non-zero, on the plaintext bids.
    fn provider_pattern(bids: &[usize], degree: usize) -> Vec<bool> {
        let (winner, price) = expected(AuctionType::ProviderSecondPrice, bids);
        (0..degree)
            .map(|slot| {
                let (region, level) = (slot / LEVELS, slot % LEVELS);
                region < bids.len() && (level < price || (level == price && region != winner))
            })
            .collect()
    }

    /// Checks the output against the expected winner and price and against the exact pattern.
    fn check_provider(slots: &[u64], bids: &[usize], context: &str) {
        let pattern: Vec<bool> = slots.iter().map(|&s| s != 0).collect();
        assert_eq!(
            pattern,
            provider_pattern(bids, slots.len()),
            "{context}, bids {bids:?}: the zero pattern is not the one of the winner and the price"
        );
        assert_eq!(
            decode_provider(slots, bids.len()),
            Some(expected(AuctionType::ProviderSecondPrice, bids)),
            "{context}, bids {bids:?}"
        );
    }

    /// Bid sets of `n` bidders: random bids, equal bids, ties at the top, only zero bids, and one
    /// bid above zero bids.
    fn provider_bid_sets(n: usize, rng: &mut StdRng) -> Vec<Vec<usize>> {
        let random = |rng: &mut StdRng| -> Vec<usize> {
            (0..n).map(|_| rng.random_range(0..LEVELS)).collect()
        };
        let (mut top_tie, mut late_tie, mut one_above) = (random(rng), random(rng), vec![0; n]);
        top_tie[0] = LEVELS - 1;
        top_tie[n - 1] = LEVELS - 1;
        late_tie.iter_mut().for_each(|bid| *bid = (*bid).min(LEVELS - 2));
        late_tie[n - 1] = LEVELS - 1;
        late_tie[n - 2] = LEVELS - 1;
        one_above[n - 1] = 5;
        vec![
            random(rng),
            random(rng),
            vec![9; n],
            top_tie,
            late_tie,
            vec![0; n],
            vec![LEVELS - 1; n],
            one_above,
        ]
    }

    #[test]
    fn the_provider_type_decodes_exactly_for_every_bidder_and_provider_count() -> Result<()> {
        let fixture = fixture()?;
        let (degree, t) = (fixture.params.degree(), fixture.params.plaintext());
        let mut rng = StdRng::seed_from_u64(40);
        for n in 2..=8 {
            for k in 1..=4 {
                for (seed, bids) in provider_bid_sets(n, &mut rng).into_iter().enumerate() {
                    let masks: Vec<Vec<u64>> =
                        (0..k).map(|_| mask_slots(&mut rng, degree, t)).collect();
                    let output = provider_output(&fixture, &bids, &masks, 700 + seed as u64)?;
                    let slots = decrypt_slots(&fixture, &output)?;
                    check_provider(&slots, &bids, &format!("n = {n}, k = {k}"));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn the_provider_type_decodes_exactly_under_adversarial_masks() -> Result<()> {
        let fixture = fixture()?;
        let (degree, t) = (fixture.params.degree(), fixture.params.plaintext());
        let mut rng = StdRng::seed_from_u64(41);
        for n in [2, 3, 5, 8] {
            let sets = provider_bid_sets(n, &mut rng);
            for k in 1..=4 {
                for (name, masks) in mask_sets(k, degree, t, &mut rng) {
                    // A top tie, the zero bids and a random set.
                    for bids in [&sets[0], &sets[3], &sets[5]] {
                        let output = provider_output(&fixture, bids, &masks, 800)?;
                        let slots = decrypt_slots(&fixture, &output)?;
                        check_provider(&slots, bids, &format!("n = {n}, k = {k}, masks: {name}"));
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn the_provider_type_has_the_result_of_the_second_price_type() -> Result<()> {
        let fixture = fixture()?;
        let (degree, t) = (fixture.params.degree(), fixture.params.plaintext());
        let mut rng = StdRng::seed_from_u64(42);
        for (seed, (bids, winner)) in TIE_ROUNDS.into_iter().enumerate() {
            let masks = vec![mask_slots(&mut rng, degree, t), mask_slots(&mut rng, degree, t)];
            let slots = decrypt_slots(
                &fixture,
                &provider_output(&fixture, bids, &masks, 900 + seed as u64)?,
            )?;
            let (expected_winner, price) = expected(AuctionType::ProviderSecondPrice, bids);
            assert_eq!(expected_winner, winner, "bids {bids:?}");
            assert_eq!(decode_provider(&slots, bids.len()), Some((winner, price)), "bids {bids:?}");
        }
        Ok(())
    }

    #[test]
    fn the_provider_output_keeps_a_noise_budget_at_eight_bidders_and_four_providers() -> Result<()> {
        let fixture = fixture()?;
        let (degree, t) = (fixture.params.degree(), fixture.params.plaintext());
        let mut rng = StdRng::seed_from_u64(43);
        let bids = [3, 9, 9, 15, 0, 15, 7, 2];
        let masks: Vec<Vec<u64>> = (0..4).map(|_| mask_slots(&mut rng, degree, t)).collect();
        let output = Ciphertext::from_bytes(
            &provider_output(&fixture, &bids, &masks, 1000)?,
            &fixture.params,
        )?;
        // SAFETY: `measure_noise` has a variable-time path that depends on the noise. The test
        // holds the secret key and only reads the budget.
        let noise = unsafe { fixture.secret_key.measure_noise(&output) }?;
        let log2_q: f64 = fixture.params.moduli().iter().map(|&q| (q as f64).log2()).sum();
        let budget = log2_q - (t as f64).log2() - 1.0 - noise as f64;
        eprintln!("type 1, n = 8, k = 4: noise {noise} bits, log2 q = {log2_q:.1}, budget {budget:.1} bits");
        // About 66 bits when measured; the output stops decrypting exactly at 0.
        assert!(budget > 30.0, "the budget is {budget} bits");
        check_provider(&decrypt_slots(&fixture, &output.to_bytes())?, &bids, "n = 8, k = 4");
        Ok(())
    }

    #[test]
    #[should_panic(expected = "masks of its providers")]
    fn rejects_a_provider_round_without_its_masks() {
        // The policy selects only the configuration when a mask does not open.
        let fixture = fixture().unwrap();
        run_with_providers(
            &fixture,
            AuctionType::ProviderSecondPrice,
            &[[0xa0; 20], [0xa1; 20]],
            vec![],
        );
    }

    #[test]
    #[should_panic(expected = "2 to 8 bidders")]
    fn rejects_a_provider_round_with_one_bidder() {
        let fixture = fixture().unwrap();
        let mut rng = StdRng::seed_from_u64(44);
        let mask = mask_slots(&mut rng, fixture.params.degree(), fixture.params.plaintext());
        provider_output(&fixture, &[4], &[mask], 1).unwrap();
    }

    #[test]
    #[should_panic(expected = "2 to 8 bidders")]
    fn rejects_a_ninth_bidder_of_the_provider_type() {
        let fixture = fixture().unwrap();
        let mut rng = StdRng::seed_from_u64(45);
        let mask = mask_slots(&mut rng, fixture.params.degree(), fixture.params.plaintext());
        provider_output(&fixture, &[1, 2, 3, 4, 5, 6, 7, 8, 9], &[mask], 1).unwrap();
    }

    #[test]
    #[should_panic(expected = "multiple of 2")]
    fn rejects_a_provider_bid_with_a_missing_ciphertext() {
        let fixture = fixture().unwrap();
        let mut rng = StdRng::seed_from_u64(46);
        let mask = encrypt_slots(
            &fixture,
            &mask_slots(&mut rng, fixture.params.degree(), fixture.params.plaintext()),
        )
        .unwrap();
        let mut ciphertexts = vec![(mask, 1)];
        ciphertexts.extend(
            encrypt_bids(&fixture, AuctionType::ProviderSecondPrice, &[1, 2], 2).unwrap(),
        );
        ciphertexts.pop();
        run_with_providers(
            &fixture,
            AuctionType::ProviderSecondPrice,
            &[[0xa0; 20]],
            ciphertexts,
        );
    }

    /// The shares of the no-provider type: the plaintext of role `role` of the last bidder is set so
    /// that the sum of the shares of every bidder is `target` in each slot, mod `t`. Bidders who
    /// collude can choose their shares so, which is the strongest choice of shares.
    fn set_share_sum(plaintexts: &mut [Vec<Vec<u64>>], role: usize, target: &[u64], t: u64) {
        let (last, others) = plaintexts.split_last_mut().expect("a bidder");
        for (slot, &want) in target.iter().enumerate() {
            let rest = others.iter().map(|bidder| bidder[role][slot]).sum::<u64>() % t;
            last[role][slot] = (want + t - rest) % t;
        }
    }

    /// The output slots of the no-provider type on the plaintext slots `[bidder][role]`, from the
    /// formulas of the module documentation, with every operation mod `t`. It does not use the
    /// ciphertext code, so it checks the formulas, the zero failure and the decoder on their own.
    fn qnr_model(t: u64, plaintexts: &[Vec<Vec<u64>>]) -> Vec<u64> {
        let (n, t) = (plaintexts.len(), t as i64);
        (0..plaintexts[0][0].len())
            .map(|slot| {
                let region = slot / LEVELS;
                let sum = |role: usize| -> i64 {
                    plaintexts.iter().map(|bidder| bidder[role][slot] as i64).sum()
                };
                let (at_least, above, s1, s2) = (sum(0), sum(1), sum(2), sum(3));
                let (own_at_least, own_above, ties_before) = if region < n {
                    let own = &plaintexts[region];
                    let ties_before = plaintexts[..region]
                        .iter()
                        .map(|bidder| bidder[0][slot] as i64 - bidder[1][slot] as i64)
                        .sum();
                    (own[0][slot] as i64, own[1][slot] as i64, ties_before)
                } else {
                    (0, 0, 0)
                };
                let ties = (own_at_least - own_above) * ties_before;
                let beaten = above - own_above + 1 - own_at_least + ties;
                let tests = (beaten * (at_least * (at_least - 1))).rem_euclid(t);
                let used = i64::from(region < n);
                let r = ((s1 * s1 - 3).rem_euclid(t) * used % t) * (s2 * s2 - 3).rem_euclid(t) % t;
                (tests * r % t) as u64
            })
            .collect()
    }

    /// The shares that drive `S1` and `S2` through every value of `0..t`: three ramps that move
    /// by 128 slots each, then constant shares at both ends.
    fn adversarial_share_sums(degree: usize, t: u64) -> Vec<(String, Vec<u64>, Vec<u64>)> {
        let mut sums: Vec<(String, Vec<u64>, Vec<u64>)> = (0..3u64)
            .map(|run| {
                let ramp = |offset: u64| -> Vec<u64> {
                    (0..degree as u64).map(|s| (s + offset) % t).collect()
                };
                (format!("ramp {run}"), ramp(128 * run), ramp(128 * run + 64))
            })
            .collect();
        sums.push(("S = 0".to_string(), vec![0; degree], vec![0; degree]));
        sums.push(("S = t - 1".to_string(), vec![t - 1; degree], vec![t - 1; degree]));
        sums
    }

    #[test]
    fn three_is_not_a_square_modulo_the_plaintext_modulus() {
        // The no-provider type fails nowhere because `S^2 - 3` is never zero. The demo parameters
        // use t = 257, and 65537 is the other modulus of the preset family.
        for t in [257u64, 65537] {
            assert!((0..t).all(|s| (s * s + t - 3) % t != 0), "t = {t}");
        }
    }

    #[test]
    fn the_no_provider_formulas_are_exact_for_every_bid_set_of_two_and_three_bidders() -> Result<()> {
        let fixture = fixture()?;
        let t = fixture.params.plaintext();
        let mut seed = 0;
        for n in 2..=3u32 {
            for code in 0..LEVELS.pow(n) {
                let bids: Vec<usize> =
                    (0..n).map(|j| code / LEVELS.pow(j) % LEVELS).collect();
                seed += 1;
                let inputs = plaintexts(&fixture, AuctionType::QnrSecondPrice, &bids, seed);
                check_provider(&qnr_model(t, &inputs), &bids, &format!("n = {n}"));
            }
        }
        Ok(())
    }

    #[test]
    fn the_no_provider_formulas_are_exact_for_two_to_eight_bidders() -> Result<()> {
        let fixture = fixture()?;
        let t = fixture.params.plaintext();
        let mut rng = StdRng::seed_from_u64(51);
        let mut seed = 10_000;
        for n in 2..=8 {
            let mut sets = provider_bid_sets(n, &mut rng);
            // Random sets, and sets with few distinct bids, which tie a lot.
            for _ in 0..200 {
                sets.push((0..n).map(|_| rng.random_range(0..LEVELS)).collect());
                sets.push((0..n).map(|_| rng.random_range(LEVELS - 2..LEVELS)).collect());
            }
            for bids in sets {
                seed += 1;
                let inputs = plaintexts(&fixture, AuctionType::QnrSecondPrice, &bids, seed);
                check_provider(&qnr_model(t, &inputs), &bids, &format!("n = {n}"));
            }
        }
        Ok(())
    }

    #[test]
    fn the_no_provider_formulas_are_exact_for_every_value_of_the_share_sums() -> Result<()> {
        let fixture = fixture()?;
        let (degree, t) = (fixture.params.degree(), fixture.params.plaintext());
        let mut rng = StdRng::seed_from_u64(52);
        let (mut seen_1, mut seen_2) = (std::collections::BTreeSet::new(), std::collections::BTreeSet::new());
        for n in 2..=8 {
            let sets = provider_bid_sets(n, &mut rng);
            // Every offset moves the sums by one more value, so the offsets cover `0..t` in the
            // first sum and, with the step of 5, in the second.
            for offset in 0..t {
                let first: Vec<u64> = (0..degree as u64).map(|s| (offset + s) % t).collect();
                let second: Vec<u64> = (0..degree as u64).map(|s| (3 * offset + 5 * s) % t).collect();
                seen_1.extend(first.iter().copied());
                seen_2.extend(second.iter().copied());
                for bids in [&sets[0], &sets[3], &sets[4], &sets[5]] {
                    let mut inputs = plaintexts(&fixture, AuctionType::QnrSecondPrice, bids, offset);
                    set_share_sum(&mut inputs, 2, &first, t);
                    set_share_sum(&mut inputs, 3, &second, t);
                    check_provider(&qnr_model(t, &inputs), bids, &format!("n = {n}, offset {offset}"));
                }
            }
        }
        assert_eq!(seen_1.len() as u64, t);
        assert_eq!(seen_2.len() as u64, t);
        Ok(())
    }

    #[test]
    fn the_no_provider_type_decodes_exactly_for_every_bidder_count() -> Result<()> {
        let fixture = fixture()?;
        let t = fixture.params.plaintext();
        let mut rng = StdRng::seed_from_u64(53);
        for n in 2..=8 {
            let sets = provider_bid_sets(n, &mut rng);
            // Random bids, a top tie, a late top tie and only zero bids.
            for (seed, bids) in [&sets[0], &sets[3], &sets[4], &sets[5]].into_iter().enumerate() {
                let inputs = plaintexts(&fixture, AuctionType::QnrSecondPrice, bids, 1100 + seed as u64);
                let slots = decrypt_slots(&fixture, &output(&fixture, AuctionType::QnrSecondPrice, &inputs)?)?;
                assert_eq!(slots, qnr_model(t, &inputs), "n = {n}, bids {bids:?}");
                check_provider(&slots, bids, &format!("n = {n}"));
            }
        }
        Ok(())
    }

    #[test]
    fn the_no_provider_type_decodes_exactly_under_adversarial_shares() -> Result<()> {
        let fixture = fixture()?;
        let (degree, t) = (fixture.params.degree(), fixture.params.plaintext());
        let mut rng = StdRng::seed_from_u64(54);
        let sums = adversarial_share_sums(degree, t);
        // The three ramps reach every value, in the first sum and in the second.
        let ramps = &sums[..3];
        let reached_1: std::collections::BTreeSet<u64> =
            ramps.iter().flat_map(|sum| sum.1.iter().copied()).collect();
        let reached_2: std::collections::BTreeSet<u64> =
            ramps.iter().flat_map(|sum| sum.2.iter().copied()).collect();
        assert_eq!((reached_1.len() as u64, reached_2.len() as u64), (t, t));
        for n in [2, 8] {
            let sets = provider_bid_sets(n, &mut rng);
            for (name, first, second) in &sums {
                for bids in [&sets[0], &sets[3]] {
                    let mut inputs = plaintexts(&fixture, AuctionType::QnrSecondPrice, bids, 1200);
                    set_share_sum(&mut inputs, 2, first, t);
                    set_share_sum(&mut inputs, 3, second, t);
                    let slots = decrypt_slots(&fixture, &output(&fixture, AuctionType::QnrSecondPrice, &inputs)?)?;
                    assert_eq!(slots, qnr_model(t, &inputs), "n = {n}, {name}");
                    check_provider(&slots, bids, &format!("n = {n}, shares: {name}"));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn the_no_provider_type_has_the_result_of_the_second_price_type() -> Result<()> {
        let fixture = fixture()?;
        for (seed, (bids, winner)) in TIE_ROUNDS.into_iter().enumerate() {
            let inputs = plaintexts(&fixture, AuctionType::QnrSecondPrice, bids, 1300 + seed as u64);
            let slots = decrypt_slots(&fixture, &output(&fixture, AuctionType::QnrSecondPrice, &inputs)?)?;
            let (expected_winner, price) = expected(AuctionType::QnrSecondPrice, bids);
            assert_eq!(expected_winner, winner, "bids {bids:?}");
            assert_eq!(decode_provider(&slots, bids.len()), Some((winner, price)), "bids {bids:?}");
        }
        Ok(())
    }

    #[test]
    fn the_no_provider_output_keeps_a_noise_budget_at_eight_bidders() -> Result<()> {
        let fixture = fixture()?;
        let t = fixture.params.plaintext();
        let bids = [3, 9, 9, 15, 0, 15, 7, 2];
        let inputs = plaintexts(&fixture, AuctionType::QnrSecondPrice, &bids, 1400);
        let output = Ciphertext::from_bytes(
            &output(&fixture, AuctionType::QnrSecondPrice, &inputs)?,
            &fixture.params,
        )?;
        // SAFETY: `measure_noise` has a variable-time path that depends on the noise. The test
        // holds the secret key and only reads the budget.
        let noise = unsafe { fixture.secret_key.measure_noise(&output) }?;
        let log2_q: f64 = fixture.params.moduli().iter().map(|&q| (q as f64).log2()).sum();
        let budget = log2_q - (t as f64).log2() - 1.0 - noise as f64;
        eprintln!("type 2, n = 8: noise {noise} bits, log2 q = {log2_q:.1}, budget {budget:.1} bits");
        // The output stops decrypting exactly at 0.
        assert!(budget > 20.0, "the budget is {budget} bits");
        let slots = decrypt_slots(&fixture, &output.to_bytes())?;
        assert_eq!(slots, qnr_model(t, &inputs));
        check_provider(&slots, &bids, "n = 8");
        Ok(())
    }

    #[test]
    #[should_panic(expected = "multiple of 4")]
    fn rejects_a_no_provider_bid_with_a_missing_ciphertext() {
        let fixture = fixture().unwrap();
        let mut ciphertexts =
            encrypt_bids(&fixture, AuctionType::QnrSecondPrice, &[1, 2], 2).unwrap();
        ciphertexts.pop();
        run(&fixture, AuctionType::QnrSecondPrice, ciphertexts);
    }

    #[test]
    #[should_panic(expected = "2 to 8 bidders")]
    fn rejects_a_no_provider_round_with_one_bidder() {
        let fixture = fixture().unwrap();
        let ciphertexts = encrypt_bids(&fixture, AuctionType::QnrSecondPrice, &[4], 1).unwrap();
        run(&fixture, AuctionType::QnrSecondPrice, ciphertexts);
    }

    #[test]
    #[should_panic(expected = "2 to 8 bidders")]
    fn rejects_a_ninth_bidder_of_the_no_provider_type() {
        let fixture = fixture().unwrap();
        let ciphertexts = encrypt_bids(
            &fixture,
            AuctionType::QnrSecondPrice,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9],
            1,
        )
        .unwrap();
        run(&fixture, AuctionType::QnrSecondPrice, ciphertexts);
    }

    #[test]
    fn a_bid_of_four_ciphertexts_is_chosen_whole_or_not_at_all() {
        let four = |bidder, version, opens: [bool; 4]| run_of(bidder, version, &opens);
        let all = [true; 4];
        // Leaves 1-4 are version 1 of bidder 1, leaves 5-8 version 2, leaves 9-12 bidder 2.
        assert_eq!(
            selected(&[four(1, 1, all), four(1, 2, all), four(2, 1, all)]),
            [0, 5, 6, 7, 8, 9, 10, 11, 12]
        );
        // A share that does not open drops the update, and version 1 stays.
        assert_eq!(
            selected(&[four(1, 1, all), four(1, 2, [true, true, true, false]), four(2, 1, all)]),
            [0, 1, 2, 3, 4, 9, 10, 11, 12]
        );
        // A bidder whose only bid has such a share is dropped whole.
        assert_eq!(
            selected(&[four(1, 1, [true, false, true, true]), four(2, 1, all)]),
            [0, 5, 6, 7, 8]
        );
    }
}
