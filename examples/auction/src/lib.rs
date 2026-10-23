// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sealed-bid auction designs over l-BFV encrypted bids.
//!
//! Each design is one E3-style program: bidders encrypt under one public key, the program
//! evaluates with the l-BFV relinearization key, and it returns one ciphertext. Interfold
//! decrypts that ciphertext and publishes the whole plaintext, so a design is judged by what
//! that plaintext reveals.
//!
//! One party creates the keys here. Threshold key generation and decryption change who holds the
//! secret, not what the program computes or what the plaintext reveals.

pub mod designs;
pub mod encoding;
pub mod evaluator;
pub mod keys;
pub mod params;
pub mod run;

pub use designs::{
    Design, FirstPrice, FirstPriceBlind, Output, PriceRule, PublicResult, Rank, RankBatched,
    RatioFirstPrice, RatioSecondPrice, SecondPrice, SecondPriceBlind, Setup, Vickrey,
    VickreyCompact,
};
pub use params::Profile;
pub use run::{run, Report, SetupError, Stats};
