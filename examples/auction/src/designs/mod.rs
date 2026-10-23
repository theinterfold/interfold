// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The auction designs. A tie goes to the bidder with the higher tie priority
//! ([`Setup::tie_priority`]). The priority is the index, except for the designs that draw a random
//! order after the bids close ([`Design::random_tie_order`]). The ratio-lane designs do not use the
//! priority: their output shows the tie set, and a random lane in the output picks the winner.

mod blind;
mod first_price;
mod rank;
mod rank_batched;
mod ratio;
mod second_price;
mod vickrey;

pub use blind::{FirstPriceBlind, SecondPriceBlind};
pub use first_price::FirstPrice;
pub use rank::{Rank, RankSecret};
pub use rank_batched::RankBatched;
pub use ratio::{group_size, LaneReading, RatioFirstPrice, RatioSecondPrice};
pub use second_price::SecondPrice;
pub use vickrey::{slot_level, Vickrey, VickreyCompact};

use crate::evaluator::Evaluator;
use fhe::bfv::{BfvParameters, Ciphertext};
use fhe::lbfv::LBFVPublicKey;
use rand::{CryptoRng, RngCore};
use std::fmt;
use std::sync::Arc;

/// One auction: parameters, number of bidders, and bid range `0..levels`.
pub struct Setup {
    pub params: Arc<BfvParameters>,
    pub bidders: usize,
    pub levels: usize,
    /// The tie priority of each bidder: a permutation of `0..bidders`. On a tie, the higher
    /// priority wins. It is the identity, except for designs with [`Design::random_tie_order`].
    pub tie_priority: Vec<usize>,
}

impl Setup {
    /// A setup where the tie priority is the bidder index.
    pub fn new(params: Arc<BfvParameters>, bidders: usize, levels: usize) -> Self {
        Setup {
            params,
            bidders,
            levels,
            tie_priority: (0..bidders).collect(),
        }
    }
}

/// The price that a design makes public.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PriceRule {
    /// No price. The winner opens a bid commitment outside the program.
    None,
    /// The winning bid.
    First,
    /// The second-highest bid (Vickrey).
    Second,
}

/// What everybody can read from the decrypted output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicResult {
    /// `None` when the output does not name exactly one winner.
    pub winner: Option<usize>,
    pub price: Option<u64>,
}

/// The decrypted output: the plaintext that Interfold makes public. Threshold decryption gives
/// a plaintext without an encoding, so it reads both ways.
pub struct Output {
    pub coefficients: Vec<u64>,
    pub slots: Vec<u64>,
}

impl PublicResult {
    /// The result computed on plaintext bids, with ties broken by `tie_priority`.
    pub fn expected(bids: &[u64], rule: PriceRule, tie_priority: &[usize]) -> Self {
        let order = ranking(bids, tie_priority);
        let price = match rule {
            PriceRule::None => None,
            PriceRule::First => Some(bids[order[0]]),
            PriceRule::Second => Some(bids[order[1]]),
        };
        PublicResult {
            winner: Some(order[0]),
            price,
        }
    }
}

/// Bidder indices from the winner down. A tie goes to the higher `tie_priority`.
pub fn ranking(bids: &[u64], tie_priority: &[usize]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..bids.len()).collect();
    order.sort_by(|&a, &b| (bids[b], tie_priority[b]).cmp(&(bids[a], tie_priority[a])));
    order
}

/// The 1-based rank of each bidder (1 = winner). A tie goes to the higher index.
pub fn ranks(bids: &[u64]) -> Vec<usize> {
    let index_priority: Vec<usize> = (0..bids.len()).collect();
    let mut ranks = vec![0; bids.len()];
    for (position, index) in ranking(bids, &index_priority).into_iter().enumerate() {
        ranks[index] = position + 1;
    }
    ranks
}

/// An E3 program for a sealed-bid auction, with its client-side encoding and its decoding.
pub trait Design {
    /// What a bidder keeps after it submits.
    type Secret;

    fn name(&self) -> &'static str;

    /// What the decrypted output reveals, in one line.
    fn disclosure(&self) -> &'static str;

    fn price_rule(&self) -> PriceRule;

    /// How a contract reads the result from the published plaintext, in one line.
    fn readout(&self) -> &'static str;

    /// The number of ct×ct products on the longest path of the program.
    fn depth(&self, bidders: usize) -> u32;

    /// Whether the program breaks ties with [`Setup::tie_priority`], drawn at random after the
    /// bids close. Only a design whose submissions do not depend on the bidder index can do this.
    /// The other designs break ties by index.
    fn random_tie_order(&self) -> bool {
        false
    }

    /// Fails when the slots or the plaintext modulus cannot hold this auction.
    fn check(&self, setup: &Setup) -> Result<(), SetupError>;

    /// Encodes and encrypts the bid of bidder `index`.
    fn submit<R: RngCore + CryptoRng>(
        &self,
        setup: &Setup,
        index: usize,
        bid: u64,
        public_key: &LBFVPublicKey,
        rng: &mut R,
    ) -> (Vec<Ciphertext>, Self::Secret);

    /// The E3 program: all submissions in, one ciphertext out.
    fn evaluate(
        &self,
        setup: &Setup,
        submissions: &[Vec<Ciphertext>],
        evaluator: &Evaluator,
    ) -> Ciphertext;

    /// Reads the public result from the decrypted output.
    fn decode(&self, setup: &Setup, output: &Output) -> PublicResult;

    /// The result that the program must give for plaintext `bids`. `secrets` are the secrets that
    /// the bidders kept. The default is the rule on the tie priority. A design that picks the
    /// winner from a value that depends on the secrets overrides it.
    fn expected(&self, setup: &Setup, bids: &[u64], _secrets: &[Self::Secret]) -> PublicResult {
        PublicResult::expected(bids, self.price_rule(), &setup.tie_priority)
    }

    /// A line about the ties that the output shows, for designs that show any.
    fn tie_note(&self, _setup: &Setup, _output: &Output) -> Option<String> {
        None
    }

    /// Whether each bidder can read its own rank from the output with its secret.
    fn reveals_own_rank(&self) -> bool {
        false
    }

    /// The rank that bidder `index` reads from the output with its secret. `None` when the
    /// design does not reveal it or the value does not decode.
    fn own_rank(
        &self,
        _setup: &Setup,
        _output: &Output,
        _index: usize,
        _secret: &Self::Secret,
    ) -> Option<usize> {
        None
    }

    /// The rank that each bidder must read, for designs that reveal it.
    fn expected_ranks(&self, bids: &[u64]) -> Vec<usize> {
        ranks(bids)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SetupError {
    TooFewBidders {
        bidders: usize,
    },
    BidOutOfRange {
        index: usize,
        bid: u64,
        levels: usize,
    },
    NotEnoughSlots {
        needed: usize,
        available: usize,
    },
    PlaintextModulusTooSmall {
        needed: u64,
        modulus: u64,
    },
    DepthTooLarge {
        depth: u32,
        required_bits: f64,
        limit_bits: f64,
    },
}

impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SetupError::TooFewBidders { bidders } => {
                write!(f, "an auction needs 2 or more bidders, got {bidders}")
            }
            SetupError::BidOutOfRange { index, bid, levels } => {
                write!(f, "bid {bid} of bidder {index} is not in 0..{levels}")
            }
            SetupError::NotEnoughSlots { needed, available } => write!(
                f,
                "the design needs {needed} slots, the ring has {available}: use fewer bidders or levels"
            ),
            SetupError::PlaintextModulusTooSmall { needed, modulus } => write!(
                f,
                "the design encodes values up to {needed}, the plaintext modulus is {modulus}: use fewer bidders or levels"
            ),
            SetupError::DepthTooLarge {
                depth,
                required_bits,
                limit_bits,
            } => write!(
                f,
                "depth {depth} needs log2(q) = {required_bits:.1}, the security limit is {limit_bits:.1}: use fewer bidders"
            ),
        }
    }
}

impl std::error::Error for SetupError {}

/// Shared capacity check: `slots` SIMD slots or coefficients, and encoded values below `values`.
fn check_capacity(setup: &Setup, slots: usize, values: u64) -> Result<(), SetupError> {
    let available = setup.params.degree();
    if slots > available {
        return Err(SetupError::NotEnoughSlots {
            needed: slots,
            available,
        });
    }
    let modulus = setup.params.plaintext();
    if values > modulus {
        return Err(SetupError::PlaintextModulusTooSmall {
            needed: values,
            modulus,
        });
    }
    Ok(())
}

/// `⌈log2 n⌉` for `n ≥ 1`.
fn tree_depth(n: usize) -> u32 {
    n.next_power_of_two().trailing_zeros()
}
