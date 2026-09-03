// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Auction app leg (ParamSet 2): proves the message polynomial `m` (the
//! SAME `m` the Greco ct0 leg commits to) is the slot-replicated encoding
//! of `value_raw / cap`, that `0 <= value_raw <= balance`, and that
//! `(address, balance)` is a leaf under `merkle_root`.
//!
//! Public inputs: `cap`, `address` (the on-chain gate equates it to
//! `msg.sender`), `merkle_root` (the gate compares it to the root stored
//! for the E3). Public output: `m_commitment`.

use lib::configs::ckks_app_ps2::{
    CKKS_AUCTION_BIT_M, CKKS_AUCTION_BIT_TAIL, CKKS_AUCTION_CONFIGS, CKKS_AUCTION_MERKLE_MAX_DEPTH,
    CKKS_AUCTION_N,
};
use lib::core::threshold::ckks_app_validity::auction_validity;
use lib::math::polynomial::Polynomial;

fn main(
    m: Polynomial<CKKS_AUCTION_N>,
    value_raw: Field,
    balance: Field,
    depth: u32,
    indices: [bool; CKKS_AUCTION_MERKLE_MAX_DEPTH],
    siblings: [Field; CKKS_AUCTION_MERKLE_MAX_DEPTH],
    cap: pub Field,
    address: pub Field,
    merkle_root: pub Field,
) -> pub Field {
    auction_validity::<CKKS_AUCTION_N, CKKS_AUCTION_BIT_M, CKKS_AUCTION_BIT_TAIL, CKKS_AUCTION_MERKLE_MAX_DEPTH>(
        CKKS_AUCTION_CONFIGS,
        m,
        value_raw,
        cap,
        balance,
        address,
        merkle_root,
        depth,
        indices,
        siblings,
    )
}
