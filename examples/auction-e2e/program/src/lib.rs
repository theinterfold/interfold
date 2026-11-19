// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The FHE program of the auction example: a sealed-bid second-price auction. It shows the winner
//! and the second-highest bid, and nothing else. The masks are random shares that the bidders
//! send, so the auction needs no mask provider.
//!
//! Input 0 of a round is its configuration, [`config_input`]: the domain bytes and the auction
//! type. It is not a ciphertext. `AuctionProgram.validate` inserts its leaf, so the compute proof
//! binds the type through the input root (see [`policy`]).
//!
//! Each bidder sends [`ROLES`] ciphertexts that do not depend on the bidder's index, on the number
//! of bidders or on the other bids. `AuctionProgram.publishInput` verifies one proof for the whole
//! bid and inserts one leaf per ciphertext as consecutive leaves in role order. A bidder may bid
//! again (an update), so the tree can hold several bids of one bidder. The policy picks, for each
//! bidder, its latest bid whose bytes open their commitments (see [`select_bids`]). After the
//! configuration the processor then receives one group of ciphertexts per chosen bid, in leaf
//! order. The bidder position is the place of the chosen bid in that order. The position does not
//! depend on the ciphertext bytes. A bidder that updates is placed where its update is published,
//! so an update loses the place of the earlier bid. If the top bids tie, the tied bidder with the
//! lowest position (the one whose chosen bid was published first) wins. All ciphertexts are
//! SIMD-encoded; a bid is a level `b` in `0..levels`:
//!
//! ```text
//! ge  slot i  [b >= i % levels]
//! gt  slot i  [b >  i % levels]
//! s1  slot i  uniform in 0..t
//! s2  slot i  uniform in 0..t
//! ```
//!
//! # Shape
//!
//! An [`AuctionShape`] is the number of price levels and the most bidders. [`fhe_processor`] runs
//! [`SHAPE`], which is [`LEVELS`] levels and [`MAX_BIDDERS`] bidders; [`run_auction`] runs any
//! shape that fits the ring (`levels * max_bidders <= degree`). The BFV parameters of a shape and
//! of a failure probability come from the parameter search:
//!
//! ```text
//! cargo run -p e3-fhe-params --bin search_params -- --bidders 8 --levels 16 --failure-bits 40
//! ```
//!
//! # Lanes
//!
//! The slots are groups of `levels` slots. With `n` bidders (2 to `max_bidders`), lane `j` is the
//! slots `levels j .. levels (j + 1)` and belongs to the bidder at position `j`: level `p` of lane
//! `j` is slot `levels j + p`. `used` is 1 on the slots `0 .. levels n` and 0 elsewhere.
//!
//! # The tests
//!
//! Slot `p` of lane `k` tests whether that bidder beats every other bidder at level `p`:
//!
//! ```text
//! g_k[p] = #{j != k : b_j > p} + [b_k < p] + [b_k = p] * #{j < k : b_j = p}
//! ```
//!
//! `g_k[p]` is zero exactly when no other bid is above `p`, `b_k >= p`, and no earlier bidder ties
//! `k` at `p`. With `c'[p] = #{j : b_j >= p}` the test vector is `g * c'(c' - 1)`. With `s` the
//! second-highest bid:
//!
//! - `p < s`: two or more bids are above `p`, the slot is non-zero;
//! - `p = s`: the slot is zero in the lane of the winner (a tie goes to the lowest position) and
//!   non-zero in every other lane;
//! - `p > s`: at most one bid is at or above `p`, the slot is zero.
//!
//! Every non-zero `g` is a whole number in `1 ..= n`, and every non-zero `c'(c' - 1)` is one in
//! `2 ..= n (n - 1)`. Both are below `t`, and `t` is prime, so the test is non-zero mod `t`
//! exactly where it is non-zero as a whole number.
//!
//! # The mask
//!
//! With `S1 = sum_j s1_j`, `S2 = sum_j s2_j` over the chosen bids and `c` the smallest quadratic
//! non-residue mod `t` ([`non_residue`]; 3 for `t` = 257, 65537 and 12451841), the mask is
//!
//! ```text
//! r = S1 * S1 - c * S2 * S2
//! ```
//!
//! This is the norm of `S1 + S2 sqrt(c)` in the quadratic extension of the integers mod `t`. It is
//! zero only when `S1 = S2 = 0`. If one bidder is honest, `(S1, S2)` is uniform in every slot,
//! and then `r` is zero with probability `1 / t^2` and otherwise uniform over the non-zero
//! residues. The output `tests * r` then shows only where it is zero: a function of the winner
//! and of `s`. It does not show the winning bid, the runner-up, any count or a tie.
//!
//! A slot whose mask is zero reads as zero whatever its test holds. An auction of `n` bidders
//! has `levels n` used slots, so it can fail with probability at most `levels n / t^2`. The
//! parameter search takes `t` from the failure probability an auction may have. [`decode_result`]
//! checks the whole zero pattern, so it returns `None` for a pattern that no winner and price
//! produce, which is what one zero mask gives.
//!
//! # The products
//!
//! With `sel_j` the selector of lane `j` and `after_j` the selector of the lanes after `j` up to
//! the last used lane, the program computes
//!
//! ```text
//! ties   = (sum_j (ge_j - gt_j) * sel_j) x (sum_j (ge_j - gt_j) * after_j)
//! beaten = (sum_j gt_j) * used - sum_j gt_j * sel_j + used - sum_j ge_j * sel_j + ties
//! two    = (sum_j ge_j) x (sum_j ge_j - 1)
//! r      = S1 x S1 - c * (S2 x S2)
//! out    = beaten x (two x r)
//! ```
//!
//! where `x` is a ct*ct product, relinearized, and `*` a product with a plaintext. `beaten` is `g`
//! on the used lanes and zero on the others (`used` multiplies the count of the bids above and
//! stands in for the 1), so the output is zero on the lanes that do not exist. There are 6 ct*ct
//! products and the output is at depth 3. `beaten` carries the noise of the selectors, which a
//! plaintext product multiplies by up to `degree * t`. It is the last factor, so that noise
//! passes through one more product and not through two.
//!
//! See `decodeResult` in the design package under `sdk/` for the client decoder.

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

/// The number of levels of [`SHAPE`], which is the period of a bidder's thermometer. A bid is in
/// `0..LEVELS`.
pub const LEVELS: usize = 16;

/// The most bidders of [`SHAPE`]. The smallest number of every shape is two.
pub const MAX_BIDDERS: usize = 8;

/// The ciphertexts one bidder sends: `[ge, gt, s1, s2]`.
pub const ROLES: usize = 4;

/// The `uint8` that `AuctionProgram` stores for this auction: second-price, with the masks from
/// the bidders.
pub const AUCTION_TYPE: u8 = 2;

/// The prefix of the configuration input. `AuctionProgram.CONFIG_DOMAIN` is the same bytes.
pub const CONFIG_DOMAIN: &[u8] = b"interfold-auction-config-v1";

/// The number of price levels and the most bidders of an auction. A lane is `levels` slots, and
/// there is one lane per bidder, so `levels * max_bidders` must not pass the ring degree.
///
/// The BFV parameters must be searched for the shape: give `max_bidders` and `levels` to
/// `search_params --bidders .. --levels ..`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuctionShape {
    /// The period of a thermometer. A bid is in `0..levels`.
    pub levels: usize,
    /// The most bidders of an auction, which is the number of lanes.
    pub max_bidders: usize,
}

/// The shape [`fhe_processor`] runs.
pub const SHAPE: AuctionShape = AuctionShape {
    levels: LEVELS,
    max_bidders: MAX_BIDDERS,
};

/// Input 0 of a round: the domain bytes and the type byte.
pub fn config_input() -> Vec<u8> {
    [CONFIG_DOMAIN, &[AUCTION_TYPE]].concat()
}

/// Whether `input` is the configuration of this auction: [`config_input`] and nothing more.
pub fn is_config_input(input: &[u8]) -> bool {
    input.strip_prefix(CONFIG_DOMAIN) == Some(&[AUCTION_TYPE])
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

/// The smallest quadratic non-residue modulo the odd prime `t`: the `c` of the mask
/// `S1 * S1 - c * S2 * S2`. By Euler's criterion `c` is a non-residue exactly when
/// `c^((t - 1) / 2) = -1 (mod t)`. The parameter search computes the same value.
///
/// # Panics
///
/// If `t` has no non-residue below `2^16`, which no odd prime does.
pub fn non_residue(t: u64) -> u64 {
    let power = |base: u64, mut exponent: u64| -> u64 {
        let (mut result, mut square) = (1u128, base as u128 % t as u128);
        while exponent > 0 {
            if exponent & 1 == 1 {
                result = result * square % t as u128;
            }
            square = square * square % t as u128;
            exponent >>= 1;
        }
        result as u64
    };
    (2..t.min(1 << 16))
        .find(|&c| power(c, (t - 1) / 2) == t - 1)
        .expect("the plaintext modulus must be an odd prime")
}

/// The slots of lane `j`: level `p` is slot `levels j + p`.
fn lane(levels: usize, j: usize) -> Range<usize> {
    j * levels..(j + 1) * levels
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

fn sum<'a>(cts: impl IntoIterator<Item = &'a Ciphertext>) -> Ciphertext {
    let mut cts = cts.into_iter();
    let first = cts.next().expect("a round has two or more bidders").clone();
    cts.fold(first, |acc, ct| &acc + ct)
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

/// Computes the output of the auction: the second-price test vector under the mask. See the
/// module documentation.
///
/// `bids[j]` is `([b_j >= p], [b_j > p])` of bidder position `j`, and lane `j` is its lane. `s1`
/// and `s2` are the sums of the shares of the bidders. Every ct*ct product is relinearized.
fn second_price(
    levels: usize,
    params: &Arc<fhe::bfv::BfvParameters>,
    relinearization_key: &LBFVRelinearizationKey,
    bids: &[(Ciphertext, Ciphertext)],
    s1: &Ciphertext,
    s2: &Ciphertext,
) -> Ciphertext {
    let end = bids.len() * levels;
    let mul = |a: &Ciphertext, b: &Ciphertext| multiply(relinearization_key, a, b);

    // The slots of the lanes that exist. The groups beyond them hold the thermometers and the
    // shares like every other group. `beaten` is zeroed there, so the output shows only used lanes.
    let used = ones_in(params, [0..end]);
    let (mut own_at_least, mut own_above, mut ties_before) = (vec![], vec![], vec![]);
    for (j, (at_least, above)) in bids.iter().enumerate() {
        // Lane j: its own slots, and the slots of the lanes after it (lane j wins a tie there).
        let selector = ones_in(params, [lane(levels, j)]);
        own_at_least.push(at_least * &selector);
        own_above.push(above * &selector);
        ties_before
            .push(&(at_least - above) * &ones_in(params, [lane(levels, j + 1).start..end]));
    }
    let own_at_least = sum(&own_at_least);
    let own_above = sum(&own_above);
    // #{j < k : b_j = p} in lane k.
    let ties_before = sum(&ties_before);
    let above = sum(bids.iter().map(|bid| &bid.1));
    let at_least = sum(bids.iter().map(|bid| &bid.0));
    let one = constant_slots(params, 1);

    // [b_k = p] * #{j < k : b_j = p} in lane k.
    let ties = mul(&(&own_at_least - &own_above), &ties_before);
    // #{j != k : b_j > p} + [b_k < p] + ties in the used lanes, and 0 in the others: `used` is on
    // the fresh sum of the bids above, where a plaintext product costs the least noise, and it
    // stands in for the 1.
    let others_above = &(&above * &used) - &own_above;
    let beaten = &(&(&others_above + &used) - &own_at_least) + &ties;
    let two_at_least = mul(&at_least, &(&at_least - &one));
    // r = S1 * S1 - c * S2 * S2, which is zero only where both sums are.
    let c = constant_slots(params, non_residue(params.plaintext()));
    let mask = &mul(s1, s1) - &(&mul(s2, s2) * &c);
    // `beaten` has the noise of the selectors, so it is the last factor.
    mul(&beaten, &mul(&two_at_least, &mask))
}

/// Runs the auction of [`SHAPE`] over the inputs of the round. See [`run_auction`].
pub fn fhe_processor(inputs: FHEProcessorInput<'_>) -> Vec<u8> {
    run_auction(SHAPE, inputs)
}

/// Runs the auction of `shape` over the inputs of the round.
///
/// The selected inputs arrive one at a time, in leaf order: the configuration, then the [`ROLES`]
/// ciphertexts of each chosen bid in role order (see [`select_bids`]). The on-chain index is not
/// used, only the position.
///
/// # Panics
///
/// If the shape does not fit the ring, if input 0 is not the configuration, if the number of bid
/// ciphertexts is not a multiple of [`ROLES`], if there are fewer than two or more than
/// `shape.max_bidders` bidders, if an input is not a ciphertext of the parameters, or if the l-BFV
/// relinearization key is missing. A malformed round has no meaningful result, so there is nothing
/// to recover to.
pub fn run_auction(shape: AuctionShape, inputs: FHEProcessorInput<'_>) -> Vec<u8> {
    let relinearization_key = inputs
        .relinearization_key
        .expect("the auction program requires the l-BFV relinearization key");

    let params = inputs.params;
    assert!(
        shape.levels >= 1
            && shape.max_bidders >= 2
            && shape.levels * shape.max_bidders <= params.degree(),
        "{} levels and {} bidders do not fit {} slots",
        shape.levels,
        shape.max_bidders,
        params.degree()
    );
    let (config, _) = inputs
        .ciphertexts
        .next()
        .expect("input 0 must be the auction configuration");
    assert!(
        is_config_input(&config),
        "input 0 must be the auction configuration"
    );

    let mut ciphertexts = Vec::new();
    while let Some((bytes, _)) = inputs.ciphertexts.next() {
        ciphertexts.push(
            Ciphertext::from_bytes(&bytes, params)
                .expect("a selected input is a ciphertext of the round"),
        );
    }
    assert!(
        ciphertexts.len() % ROLES == 0,
        "the number of ciphertexts must be a multiple of {ROLES}: {ROLES} per bidder"
    );
    let n = ciphertexts.len() / ROLES;
    assert!(
        (2..=shape.max_bidders).contains(&n),
        "an auction needs 2 to {} bidders, got {n}",
        shape.max_bidders
    );

    let s1 = sum(ciphertexts.iter().skip(2).step_by(ROLES));
    let s2 = sum(ciphertexts.iter().skip(3).step_by(ROLES));
    let bids: Vec<(Ciphertext, Ciphertext)> = ciphertexts
        .chunks(ROLES)
        .map(|bidder| (bidder[0].clone(), bidder[1].clone()))
        .collect();
    drop(ciphertexts);

    second_price(shape.levels, params, relinearization_key, &bids, &s1, &s2).to_bytes()
}

/// `(winner position, price)` as the client reads the slots of the decrypted output of an auction
/// of `bidders` bidders, or `None` when the slots are not the output of any winner and price.
///
/// The pattern is strict: the slots beyond the used lanes are zero, no slot above the price is
/// non-zero, exactly one lane is zero at the price, and every slot below the price is non-zero.
/// The price is the highest level where some lane is non-zero. A mask that is zero in a used
/// slot breaks the pattern, so a failed round reads as `None` and not as another result.
pub fn decode_result(slots: &[u64], shape: AuctionShape, bidders: usize) -> Option<(usize, usize)> {
    let levels = shape.levels;
    if !(2..=shape.max_bidders).contains(&bidders) || slots.len() < bidders * levels {
        return None;
    }
    let at = |lane: usize, level: usize| slots[lane * levels + level];
    if slots[bidders * levels..].iter().any(|&slot| slot != 0) {
        return None;
    }
    let price = (0..levels)
        .rev()
        .find(|&level| (0..bidders).any(|lane| at(lane, level) != 0))?;
    let winners: Vec<usize> = (0..bidders).filter(|&lane| at(lane, price) == 0).collect();
    let below_set = (0..bidders).all(|lane| (0..price).all(|level| at(lane, level) != 0));
    match (&winners[..], below_set) {
        ([winner], true) => Some((*winner, price)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use e3_compute_provider::hashing::keccak256;
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

    /// The demo parameters: degree 128 and t = 257. `tests/threshold.rs` runs the parameters of
    /// the search, with a committee and its smudging noise.
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
    /// shares come from `seed`, which makes the plaintexts reproducible.
    fn plaintexts(fixture: &Fixture, bids: &[usize], seed: u64) -> Vec<Vec<Vec<u64>>> {
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
                // The two shares: uniform in every slot.
                for _ in 2..ROLES {
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

    /// Encrypts the bids with the shares of `plaintexts(.., seed)`.
    fn encrypt_bids(fixture: &Fixture, bids: &[usize], seed: u64) -> Result<Vec<(Vec<u8>, u64)>> {
        let mut ciphertexts = Vec::new();
        for slots in plaintexts(fixture, bids, seed).iter().flatten() {
            let index = ciphertexts.len() as u64 + 1;
            ciphertexts.push((encrypt_slots(fixture, slots)?, index));
        }
        Ok(ciphertexts)
    }

    /// Runs the program over the configuration and then `ciphertexts`.
    fn run(fixture: &Fixture, ciphertexts: Vec<(Vec<u8>, u64)>) -> Vec<u8> {
        let inputs = std::iter::once((config_input(), 0)).chain(ciphertexts);
        fhe_processor(FHEProcessorInput {
            ciphertexts: &mut inputs.into_iter(),
            params: &fixture.params,
            relinearization_key: Some(&fixture.rlk),
        })
    }

    /// The output over the plaintext slots `[bidder][role]`, as bytes.
    fn output(fixture: &Fixture, plaintexts: &[Vec<Vec<u64>>]) -> Result<Vec<u8>> {
        let mut ciphertexts = Vec::new();
        for slots in plaintexts.iter().flatten() {
            let index = ciphertexts.len() as u64 + 1;
            ciphertexts.push((encrypt_slots(fixture, slots)?, index));
        }
        Ok(run(fixture, ciphertexts))
    }

    fn decrypt_slots(fixture: &Fixture, result: &[u8]) -> Result<Vec<u64>> {
        let decrypted = fixture
            .secret_key
            .try_decrypt(&Ciphertext::from_bytes(result, &fixture.params)?)?;
        Ok(Vec::<u64>::try_decode(&decrypted, Encoding::simd())?)
    }

    /// The winner and the price on the plaintext bids: the highest bid wins (a tie goes to the
    /// lowest position) and pays the second-highest bid.
    fn expected(bids: &[usize]) -> (usize, usize) {
        let mut order: Vec<usize> = (0..bids.len()).collect();
        // The sort is stable, so the lowest position of equal bids comes first.
        order.sort_by_key(|&j| std::cmp::Reverse(bids[j]));
        (order[0], bids[order[1]])
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

    /// The output slots on the plaintext slots `[bidder][role]`, from the formulas of the module
    /// documentation, with every operation mod `t`. It does not use the ciphertext code, so it
    /// checks the formulas and the decoder on their own.
    fn model(t: u64, plaintexts: &[Vec<Vec<u64>>]) -> Vec<u64> {
        let (n, c, t) = (plaintexts.len(), non_residue(t) as i64, t as i64);
        (0..plaintexts[0][0].len())
            .map(|slot| {
                let lane = slot / LEVELS;
                let sum = |role: usize| -> i64 {
                    plaintexts
                        .iter()
                        .map(|bidder| bidder[role][slot] as i64)
                        .sum::<i64>()
                        % t
                };
                let (at_least, above, s1, s2) = (sum(0), sum(1), sum(2), sum(3));
                let used = i64::from(lane < n);
                let (own_at_least, own_above, ties_before) = if lane < n {
                    let own = &plaintexts[lane];
                    let ties_before = plaintexts[..lane]
                        .iter()
                        .map(|bidder| bidder[0][slot] as i64 - bidder[1][slot] as i64)
                        .sum();
                    (own[0][slot] as i64, own[1][slot] as i64, ties_before)
                } else {
                    (0, 0, 0)
                };
                let ties = (own_at_least - own_above) * ties_before;
                let beaten = above * used - own_above + used - own_at_least + ties;
                let tests = (beaten * (at_least * (at_least - 1))).rem_euclid(t);
                let mask = (s1 * s1 - c * (s2 * s2 % t)).rem_euclid(t);
                (tests * mask % t) as u64
            })
            .collect()
    }

    /// Whether the mask of each slot is non-zero: it is zero only where both share sums are.
    fn mask_is_set(t: u64, plaintexts: &[Vec<Vec<u64>>]) -> Vec<bool> {
        (0..plaintexts[0][0].len())
            .map(|slot| {
                let sum = |role: usize| -> u64 {
                    plaintexts.iter().map(|bidder| bidder[role][slot]).sum::<u64>() % t
                };
                sum(2) != 0 || sum(3) != 0
            })
            .collect()
    }

    /// Whether each slot of the tests is non-zero, on the plaintext bids.
    fn tests_pattern(bids: &[usize], degree: usize) -> Vec<bool> {
        let (winner, price) = expected(bids);
        (0..degree)
            .map(|slot| {
                let (lane, level) = (slot / LEVELS, slot % LEVELS);
                lane < bids.len() && (level < price || (level == price && lane != winner))
            })
            .collect()
    }

    /// Checks the output `slots` of the plaintexts `inputs` of `bids`: a slot is non-zero exactly
    /// where its test and its mask are. When no mask of a used slot is zero, the decoder gives
    /// the winner and the price. Returns whether the round decoded.
    fn check(t: u64, slots: &[u64], bids: &[usize], inputs: &[Vec<Vec<u64>>], context: &str) -> bool {
        let masks = mask_is_set(t, inputs);
        let wanted: Vec<bool> = tests_pattern(bids, slots.len())
            .iter()
            .zip(&masks)
            .map(|(test, mask)| *test && *mask)
            .collect();
        let pattern: Vec<bool> = slots.iter().map(|&s| s != 0).collect();
        assert_eq!(
            pattern, wanted,
            "{context}, bids {bids:?}: the zero pattern is not the one of the tests under the mask"
        );
        let decoded = decode_result(slots, SHAPE, bids.len());
        if masks[..bids.len() * LEVELS].iter().all(|set| *set) {
            assert_eq!(decoded, Some(expected(bids)), "{context}, bids {bids:?}");
        } else {
            // A zero mask never gives another winner or price.
            assert!(
                decoded.is_none() || decoded == Some(expected(bids)),
                "{context}, bids {bids:?}: a failed round decoded to {decoded:?}"
            );
        }
        decoded.is_some()
    }

    /// Bid sets of `n` bidders: random bids, equal bids, ties at the top, only zero bids, and one
    /// bid above zero bids.
    fn bid_sets(n: usize, rng: &mut StdRng) -> Vec<Vec<usize>> {
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

    /// Sets the shares of role `role` of the last bidder so that the sum of the shares of every
    /// bidder is `target` in each slot, mod `t`. Bidders who collude can choose their shares so,
    /// which is the strongest choice of shares.
    fn set_share_sum(plaintexts: &mut [Vec<Vec<u64>>], role: usize, target: &[u64], t: u64) {
        let (last, others) = plaintexts.split_last_mut().expect("a bidder");
        for (slot, &want) in target.iter().enumerate() {
            let rest = others.iter().map(|bidder| bidder[role][slot]).sum::<u64>() % t;
            last[role][slot] = (want + t - rest) % t;
        }
    }

    #[test]
    fn the_non_residue_is_three_for_the_usual_moduli() {
        // 257 is the demo modulus; 65537 and 12451841 are what the parameter search takes at
        // degree 16384 for a failure probability of 2^-25 and 2^-40.
        for t in [257u64, 65537, 12451841] {
            assert_eq!(non_residue(t), 3, "t = {t}");
        }
        // 3 is a square mod 786433 (886^2 = 3), so the next non-residue is taken.
        assert_eq!(non_residue(786433), 5);
    }

    #[test]
    fn the_mask_is_zero_only_where_both_sums_are_and_uniform_elsewhere() {
        // r = S1^2 - c S2^2 over every pair of sums mod t: zero once, and every non-zero value
        // t + 1 times.
        let t = 257u64;
        let c = non_residue(t);
        let mut counts = vec![0u64; t as usize];
        for s1 in 0..t {
            for s2 in 0..t {
                counts[((s1 * s1 + (t - c) * (s2 * s2 % t)) % t) as usize] += 1;
            }
        }
        assert_eq!(counts[0], 1);
        assert!(counts[1..].iter().all(|&count| count == t + 1));
    }

    #[test]
    fn the_formulas_are_exact_for_every_bid_set_of_two_and_three_bidders() -> Result<()> {
        let fixture = fixture()?;
        let t = fixture.params.plaintext();
        let mut seed = 0;
        for n in 2..=3u32 {
            for code in 0..LEVELS.pow(n) {
                let bids: Vec<usize> =
                    (0..n).map(|j| code / LEVELS.pow(j) % LEVELS).collect();
                seed += 1;
                let inputs = plaintexts(&fixture, &bids, seed);
                check(t, &model(t, &inputs), &bids, &inputs, &format!("n = {n}"));
            }
        }
        Ok(())
    }

    #[test]
    fn the_formulas_are_exact_for_two_to_eight_bidders() -> Result<()> {
        let fixture = fixture()?;
        let t = fixture.params.plaintext();
        let mut rng = StdRng::seed_from_u64(51);
        let mut seed = 10_000;
        let (mut rounds, mut decoded) = (0, 0);
        for n in 2..=8 {
            let mut sets = bid_sets(n, &mut rng);
            // Random sets, and sets with few distinct bids, which tie a lot.
            for _ in 0..200 {
                sets.push((0..n).map(|_| rng.random_range(0..LEVELS)).collect());
                sets.push((0..n).map(|_| rng.random_range(LEVELS - 2..LEVELS)).collect());
            }
            for bids in sets {
                seed += 1;
                let inputs = plaintexts(&fixture, &bids, seed);
                rounds += 1;
                decoded +=
                    usize::from(check(t, &model(t, &inputs), &bids, &inputs, &format!("n = {n}")));
            }
        }
        // t = 257 fails a round of 8 bidders with probability 128 / 257^2, about 1 in 500.
        assert!(decoded * 100 >= rounds * 99, "{decoded} of {rounds} rounds decoded");
        Ok(())
    }

    #[test]
    fn the_formulas_are_exact_for_every_value_of_the_share_sums() -> Result<()> {
        let fixture = fixture()?;
        let (degree, t) = (fixture.params.degree(), fixture.params.plaintext());
        let mut rng = StdRng::seed_from_u64(52);
        let mut seen = std::collections::BTreeSet::new();
        for n in 2..=8 {
            let sets = bid_sets(n, &mut rng);
            // Every offset moves the sums by one more value, so the offsets cover `0..t` in the
            // first sum and, with the step of 5, in the second.
            for offset in 0..t {
                let first: Vec<u64> = (0..degree as u64).map(|s| (offset + s) % t).collect();
                let second: Vec<u64> = (0..degree as u64).map(|s| (3 * offset + 5 * s) % t).collect();
                seen.extend(first.iter().zip(&second).map(|(a, b)| (*a, *b)));
                for bids in [&sets[0], &sets[3], &sets[4], &sets[5]] {
                    let mut inputs = plaintexts(&fixture, bids, offset);
                    set_share_sum(&mut inputs, 2, &first, t);
                    set_share_sum(&mut inputs, 3, &second, t);
                    check(t, &model(t, &inputs), bids, &inputs, &format!("n = {n}, offset {offset}"));
                }
            }
        }
        // The pairs of sums include the pair of zeros, where the mask is zero.
        assert!(seen.contains(&(0, 0)));
        assert!(seen.len() > 10_000);
        Ok(())
    }

    #[test]
    fn the_program_decodes_exactly_for_every_bidder_count() -> Result<()> {
        let fixture = fixture()?;
        let t = fixture.params.plaintext();
        let mut rng = StdRng::seed_from_u64(53);
        for n in 2..=8 {
            let sets = bid_sets(n, &mut rng);
            // Random bids, a top tie, a late top tie and only zero bids.
            for (seed, bids) in [&sets[0], &sets[3], &sets[4], &sets[5]].into_iter().enumerate() {
                let inputs = plaintexts(&fixture, bids, 1100 + seed as u64);
                let slots = decrypt_slots(&fixture, &output(&fixture, &inputs)?)?;
                assert_eq!(slots, model(t, &inputs), "n = {n}, bids {bids:?}");
                check(t, &slots, bids, &inputs, &format!("n = {n}"));
            }
        }
        Ok(())
    }

    #[test]
    fn the_program_decodes_exactly_under_adversarial_shares() -> Result<()> {
        let fixture = fixture()?;
        let (degree, t) = (fixture.params.degree(), fixture.params.plaintext());
        let mut rng = StdRng::seed_from_u64(54);
        // Ramps that reach every value in both sums, and constant sums at both ends.
        let ramp = |offset: u64| -> Vec<u64> {
            (0..degree as u64).map(|s| (s + offset) % t).collect()
        };
        let sums = [
            ("ramp 0", ramp(0), ramp(64)),
            ("ramp 1", ramp(128), ramp(192)),
            ("ramp 2", ramp(256), ramp(320)),
            ("S1 = 0", vec![0; degree], ramp(1)),
            ("S2 = 0", ramp(1), vec![0; degree]),
            ("S = t - 1", vec![t - 1; degree], vec![t - 1; degree]),
        ];
        for n in [2, 8] {
            let sets = bid_sets(n, &mut rng);
            for (name, first, second) in &sums {
                for bids in [&sets[0], &sets[3]] {
                    let mut inputs = plaintexts(&fixture, bids, 1200);
                    set_share_sum(&mut inputs, 2, first, t);
                    set_share_sum(&mut inputs, 3, second, t);
                    let slots = decrypt_slots(&fixture, &output(&fixture, &inputs)?)?;
                    assert_eq!(slots, model(t, &inputs), "n = {n}, {name}");
                    check(t, &slots, bids, &inputs, &format!("n = {n}, shares: {name}"));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn a_zero_mask_fails_the_round_and_never_gives_another_result() -> Result<()> {
        let fixture = fixture()?;
        let (degree, t) = (fixture.params.degree(), fixture.params.plaintext());
        let bids = [3, 9, 9, 15, 0, 15, 7, 2];
        let (winner, price) = expected(&bids);
        assert_eq!((winner, price), (3, 15));

        // Both sums are zero in every slot: the output is zero, and the decoder says so.
        let mut inputs = plaintexts(&fixture, &bids, 1500);
        set_share_sum(&mut inputs, 2, &vec![0; degree], t);
        set_share_sum(&mut inputs, 3, &vec![0; degree], t);
        let slots = decrypt_slots(&fixture, &output(&fixture, &inputs)?)?;
        assert!(slots.iter().all(|&slot| slot == 0));
        assert_eq!(decode_result(&slots, SHAPE, bids.len()), None);

        // Both sums are zero in one used slot: below the price, at the price in a losing lane,
        // and at the price in the lane of the winner (where the test is zero anyway).
        for (lane, level, decodes) in [(1, 4, false), (5, price, false), (winner, price, true)] {
            let mut inputs = plaintexts(&fixture, &bids, 1501);
            for role in 2..ROLES {
                let mut target: Vec<u64> = (0..degree as u64).map(|s| 1 + s % (t - 1)).collect();
                target[lane * LEVELS + level] = 0;
                set_share_sum(&mut inputs, role, &target, t);
            }
            let slots = decrypt_slots(&fixture, &output(&fixture, &inputs)?)?;
            assert_eq!(slots, model(t, &inputs));
            assert_eq!(slots[lane * LEVELS + level], 0);
            let decoded = check(t, &slots, &bids, &inputs, &format!("zero at {lane}, {level}"));
            assert_eq!(decoded, decodes, "zero at lane {lane}, level {level}");
        }
        Ok(())
    }

    #[test]
    fn the_result_is_the_one_of_the_second_price_auction() -> Result<()> {
        let fixture = fixture()?;
        let t = fixture.params.plaintext();
        for (seed, (bids, winner)) in TIE_ROUNDS.into_iter().enumerate() {
            let inputs = plaintexts(&fixture, bids, 1300 + seed as u64);
            let slots = decrypt_slots(&fixture, &output(&fixture, &inputs)?)?;
            assert_eq!(expected(bids).0, winner, "bids {bids:?}");
            check(t, &slots, bids, &inputs, "tie rounds");
        }
        Ok(())
    }

    #[test]
    fn the_output_keeps_a_noise_budget_at_eight_bidders() -> Result<()> {
        let fixture = fixture()?;
        let t = fixture.params.plaintext();
        let bids = [3, 9, 9, 15, 0, 15, 7, 2];
        let inputs = plaintexts(&fixture, &bids, 1400);
        let output = Ciphertext::from_bytes(&output(&fixture, &inputs)?, &fixture.params)?;
        // SAFETY: `measure_noise` has a variable-time path that depends on the noise. The test
        // holds the secret key and only reads the budget.
        let noise = unsafe { fixture.secret_key.measure_noise(&output) }?;
        let log2_q: f64 = fixture.params.moduli().iter().map(|&q| (q as f64).log2()).sum();
        let budget = log2_q - (t as f64).log2() - 1.0 - noise as f64;
        eprintln!("n = 8: noise {noise} bits, log2 q = {log2_q:.1}, budget {budget:.1} bits");
        // The output stops decrypting exactly at 0.
        assert!(budget > 20.0, "the budget is {budget} bits");
        let slots = decrypt_slots(&fixture, &output.to_bytes())?;
        assert_eq!(slots, model(t, &inputs));
        check(t, &slots, &bids, &inputs, "n = 8");
        Ok(())
    }

    #[test]
    fn another_shape_runs_on_the_same_ring() -> Result<()> {
        // 4 bidders and 32 levels are the same 128 slots.
        let fixture = fixture()?;
        let shape = AuctionShape {
            levels: 32,
            max_bidders: 4,
        };
        let (degree, t) = (fixture.params.degree(), fixture.params.plaintext());
        let mut rng = StdRng::seed_from_u64(55);
        for (bids, wanted) in [
            (vec![31, 4, 17, 17], (0, 17)),
            (vec![20, 20, 3], (0, 20)),
            (vec![0, 31], (1, 0)),
        ] {
            let mut ciphertexts = vec![(config_input(), 0)];
            for &bid in &bids {
                let ge: Vec<u64> = (0..degree).map(|i| u64::from(bid >= i % 32)).collect();
                let gt: Vec<u64> = (0..degree).map(|i| u64::from(bid > i % 32)).collect();
                let share = |rng: &mut StdRng| -> Vec<u64> {
                    (0..degree).map(|_| rng.random_range(0..t)).collect()
                };
                for slots in [ge, gt, share(&mut rng), share(&mut rng)] {
                    let index = ciphertexts.len() as u64;
                    ciphertexts.push((encrypt_slots(&fixture, &slots)?, index));
                }
            }
            let result = run_auction(
                shape,
                FHEProcessorInput {
                    ciphertexts: &mut ciphertexts.into_iter(),
                    params: &fixture.params,
                    relinearization_key: Some(&fixture.rlk),
                },
            );
            let slots = decrypt_slots(&fixture, &result)?;
            let decoded = decode_result(&slots, shape, bids.len());
            // A zero mask fails a round and never gives another result.
            assert!(decoded.is_none() || decoded == Some(wanted), "bids {bids:?}: {decoded:?}");
            // The seed gives no zero mask for these rounds.
            assert_eq!(decoded, Some(wanted), "bids {bids:?}");
        }
        Ok(())
    }

    #[test]
    fn the_decoder_rejects_what_no_winner_and_price_give() {
        let (winner, price) = (2usize, 5usize);
        let good: Vec<u64> = (0..128)
            .map(|slot| {
                let (lane, level) = (slot / LEVELS, slot % LEVELS);
                u64::from(lane < 4 && (level < price || (level == price && lane != winner)))
            })
            .collect();
        assert_eq!(decode_result(&good, SHAPE, 4), Some((winner, price)));
        // More or fewer bidders than the lanes that are set.
        assert_eq!(decode_result(&good, SHAPE, 3), None);
        assert_eq!(decode_result(&good, SHAPE, 1), None);
        assert_eq!(decode_result(&good, SHAPE, 9), None);
        // A zero below the price, a second zero at the price, and a slot above the price.
        for (slot, value) in [(LEVELS + 2, 0), (price, 0), (3 * LEVELS + price + 1, 7)] {
            let mut bad = good.clone();
            bad[slot] = value;
            assert_eq!(decode_result(&bad, SHAPE, 4), None, "slot {slot}");
        }
        assert_eq!(decode_result(&[0; 128], SHAPE, 4), None);
        assert_eq!(decode_result(&good[..48], SHAPE, 4), None);
    }

    #[test]
    #[should_panic(expected = "multiple of 4")]
    fn rejects_a_bid_with_a_missing_ciphertext() {
        let fixture = fixture().unwrap();
        let mut ciphertexts = encrypt_bids(&fixture, &[1, 2], 2).unwrap();
        ciphertexts.pop();
        run(&fixture, ciphertexts);
    }

    #[test]
    #[should_panic(expected = "2 to 8 bidders")]
    fn rejects_a_round_with_one_bidder() {
        let fixture = fixture().unwrap();
        let ciphertexts = encrypt_bids(&fixture, &[4], 1).unwrap();
        run(&fixture, ciphertexts);
    }

    #[test]
    #[should_panic(expected = "2 to 8 bidders")]
    fn rejects_a_ninth_bidder() {
        let fixture = fixture().unwrap();
        let ciphertexts = encrypt_bids(&fixture, &[1, 2, 3, 4, 5, 6, 7, 8, 9], 1).unwrap();
        run(&fixture, ciphertexts);
    }

    #[test]
    #[should_panic(expected = "auction configuration")]
    fn rejects_a_round_without_the_configuration() {
        let fixture = fixture().unwrap();
        let ciphertexts = encrypt_bids(&fixture, &[5, 6], 5).unwrap();
        fhe_processor(FHEProcessorInput {
            ciphertexts: &mut ciphertexts.into_iter(),
            params: &fixture.params,
            relinearization_key: Some(&fixture.rlk),
        });
    }

    #[test]
    #[should_panic(expected = "auction configuration")]
    fn rejects_the_configuration_of_another_auction_type() {
        let fixture = fixture().unwrap();
        let ciphertexts = encrypt_bids(&fixture, &[5, 6], 5).unwrap();
        let config = [CONFIG_DOMAIN, &[0u8]].concat();
        let inputs = std::iter::once((config, 0)).chain(ciphertexts);
        fhe_processor(FHEProcessorInput {
            ciphertexts: &mut inputs.into_iter(),
            params: &fixture.params,
            relinearization_key: Some(&fixture.rlk),
        });
    }

    #[test]
    #[should_panic(expected = "do not fit")]
    fn rejects_a_shape_that_does_not_fit_the_ring() {
        let fixture = fixture().unwrap();
        let ciphertexts = encrypt_bids(&fixture, &[5, 6], 5).unwrap();
        let inputs = std::iter::once((config_input(), 0)).chain(ciphertexts);
        run_auction(
            AuctionShape {
                levels: 32,
                max_bidders: 8,
            },
            FHEProcessorInput {
                ciphertexts: &mut inputs.into_iter(),
                params: &fixture.params,
                relinearization_key: Some(&fixture.rlk),
            },
        );
    }

    #[test]
    fn the_configuration_is_the_domain_and_the_type_byte() {
        // `AuctionProgram` stores the same number for this auction type.
        assert_eq!(config_input(), b"interfold-auction-config-v1\x02");
        assert!(is_config_input(&config_input()));
        for byte in [0u8, 1, 3, 255] {
            assert!(!is_config_input(&[CONFIG_DOMAIN, &[byte]].concat()), "{byte}");
        }
        assert!(!is_config_input(CONFIG_DOMAIN));
        assert!(!is_config_input(&CONFIG_DOMAIN[1..]));
        // Nothing follows the type byte: this auction has no providers.
        assert!(!is_config_input(&[&config_input()[..], &[0x11; 20]].concat()));
    }

    #[test]
    fn the_configuration_leaf_is_the_reduced_hash_of_the_configuration() {
        // `AuctionProgram.configLeaf` computes `keccak256(CONFIG_DOMAIN || type) mod BN254`.
        // Input 0 must get that leaf, whatever commitment and metadata come with it.
        let zero = [0u8; 32];
        let config = config_input();
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
            leaf_from_digest(&keccak256(b"interfold-auction-config-v1\x02"))
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

    /// The 4 records of a bid; `opens[r]` says whether role `r` opens its commitment.
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

    const OPENS: [bool; ROLES] = [true; ROLES];

    #[test]
    fn the_latest_valid_version_of_a_bidder_is_selected() {
        // Leaves 1-4 are version 1, leaves 5-8 version 2, leaves 9-12 version 3.
        assert_eq!(
            selected(&[bid(1, 1, OPENS), bid(1, 2, OPENS), bid(1, 3, OPENS)]),
            [0, 9, 10, 11, 12]
        );
    }

    #[test]
    fn a_bidder_falls_back_to_an_earlier_version_when_the_latest_does_not_open() {
        assert_eq!(
            selected(&[bid(1, 1, OPENS), bid(1, 2, [true, false, true, true])]),
            [0, 1, 2, 3, 4]
        );
        // The first usable one counts, not the first one.
        assert_eq!(
            selected(&[
                bid(1, 1, OPENS),
                bid(1, 2, [false, true, true, true]),
                bid(1, 3, [true, true, true, false]),
            ]),
            [0, 1, 2, 3, 4]
        );
    }

    #[test]
    fn a_bidder_with_one_bad_ciphertext_in_its_only_bid_is_dropped_whole() {
        for bad in 0..ROLES {
            let mut opens = OPENS;
            opens[bad] = false;
            assert_eq!(
                selected(&[bid(1, 1, opens), bid(2, 1, OPENS)]),
                [0, 5, 6, 7, 8],
                "role {bad} does not open"
            );
        }
    }

    #[test]
    fn bidders_are_ordered_by_the_leaf_of_the_selected_bid() {
        // bidder 1: leaves 1-4 and 9-12, bidder 2: leaves 5-8. Bidder 1 counts at its update, so
        // it comes after bidder 2.
        assert_eq!(
            selected(&[bid(1, 1, OPENS), bid(2, 1, OPENS), bid(1, 2, OPENS)]),
            [0, 5, 6, 7, 8, 9, 10, 11, 12]
        );
    }

    #[test]
    fn the_configuration_is_always_selected() {
        assert_eq!(selected(&[]), [0]);
        assert_eq!(selected(&[bid(1, 1, [false; ROLES])]), [0]);
        assert_eq!(select_bids(&[]), Vec::<usize>::new());
    }

    #[test]
    fn a_bid_with_malformed_metadata_or_no_commitment_is_never_selected() {
        for length in [0, 24, 26] {
            let mut malformed = bid(1, 1, OPENS);
            for row in &mut malformed {
                row.metadata = vec![1; length];
            }
            assert_eq!(selected(&[malformed, bid(2, 1, OPENS)]), [0, 5, 6, 7, 8]);
        }

        let mut no_commitment = bid(1, 1, OPENS);
        no_commitment[1].commitment = None;
        assert_eq!(selected(&[no_commitment, bid(2, 1, OPENS)]), [0, 5, 6, 7, 8]);
    }
}
