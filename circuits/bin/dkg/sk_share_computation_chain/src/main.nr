// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! A chunk of chunked C2a other than the last: C2's per-coefficient checks on
//! `SHARE_COMPUTATION_CHUNK_SIZE` coefficients, continuing every commitment sponge from `h_in`.
//! See `lib::core::dkg::share_computation_chain`.

use lib::configs::default::dkg::{
    L_THRESHOLD, SHARE_COMPUTATION_BIT_SHARE, SHARE_COMPUTATION_CHUNK_SIZE,
    SHARE_COMPUTATION_SK_CONFIGS,
};
use lib::configs::default::{N_PARTIES, T};
use lib::core::dkg::share_computation_chain::share_computation_chunk;
use lib::math::safe::STATE_SIZE;

fn main(
    h_in: pub Field,
    states_in: [[Field; STATE_SIZE]; N_PARTIES * L_THRESHOLD + 1],
    positions_in: [u32; N_PARTIES * L_THRESHOLD + 1],
    y_chunk: [[[Field; N_PARTIES + 1]; L_THRESHOLD]; SHARE_COMPUTATION_CHUNK_SIZE],
) -> pub Field {
    share_computation_chunk::<SHARE_COMPUTATION_CHUNK_SIZE, L_THRESHOLD, N_PARTIES, T, SHARE_COMPUTATION_BIT_SHARE, 1>(
        SHARE_COMPUTATION_SK_CONFIGS,
        h_in,
        states_in,
        positions_in,
        y_chunk,
    )
}
