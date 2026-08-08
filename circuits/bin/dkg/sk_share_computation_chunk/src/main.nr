// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::dkg::{
    L_THRESHOLD, N, PARITY_MATRIX, SHARE_COMPUTATION_BIT_SHARE, SHARE_COMPUTATION_CHUNK_SIZE,
    SHARE_COMPUTATION_N_CHUNKS, SHARE_COMPUTATION_SK_BIT_SECRET, SHARE_COMPUTATION_SK_CONFIGS,
};
use lib::configs::default::{N_PARTIES, T};
use lib::core::dkg::share_computation::check_range_bounds;
use lib::core::dkg::share_computation::verify_parity_check;
use lib::math::commitments::{
    compute_sc_party_share_chunk_commitment, compute_sc_secret_chunk_commitment,
};
use lib::math::polynomial::Polynomial;

pub global CHUNK_PUBLIC_LEN: u32 = 1 + (N_PARTIES * L_THRESHOLD);

fn main(
    chunk_idx: pub u32,
    secret_chunk: Polynomial<SHARE_COMPUTATION_CHUNK_SIZE>,
    y_chunk: [[[Field; N_PARTIES + 1]; L_THRESHOLD]; SHARE_COMPUTATION_CHUNK_SIZE],
) -> pub [Field; CHUNK_PUBLIC_LEN] {
    assert(chunk_idx < SHARE_COMPUTATION_N_CHUNKS);

    for coeff_idx in 0..SHARE_COMPUTATION_CHUNK_SIZE {
        for mod_idx in 0..L_THRESHOLD {
            assert(y_chunk[coeff_idx][mod_idx][0] == secret_chunk.coefficients[coeff_idx]);
        }
    }

    check_range_bounds::<SHARE_COMPUTATION_CHUNK_SIZE, L_THRESHOLD, N_PARTIES, SHARE_COMPUTATION_BIT_SHARE>(
        SHARE_COMPUTATION_SK_CONFIGS.qis,
        y_chunk,
    );
    verify_parity_check::<SHARE_COMPUTATION_CHUNK_SIZE, L_THRESHOLD, N_PARTIES, T>(
        SHARE_COMPUTATION_SK_CONFIGS.qis,
        PARITY_MATRIX,
        y_chunk,
    );

    let mut out: [Field; CHUNK_PUBLIC_LEN] = [0; CHUNK_PUBLIC_LEN];
    let mut reversed_secret: [Field; SHARE_COMPUTATION_CHUNK_SIZE] =
        [0; SHARE_COMPUTATION_CHUNK_SIZE];
    for i in 0..SHARE_COMPUTATION_CHUNK_SIZE {
        reversed_secret[SHARE_COMPUTATION_CHUNK_SIZE - 1 - i] = secret_chunk.coefficients[i];
    }
    out[0] = compute_sc_secret_chunk_commitment::<SHARE_COMPUTATION_CHUNK_SIZE, SHARE_COMPUTATION_SK_BIT_SECRET>(
        0,
        chunk_idx,
        N,
        Polynomial::new(reversed_secret),
    );

    for party_idx in 0..N_PARTIES {
        for mod_idx in 0..L_THRESHOLD {
            let mut reversed_share: [Field; SHARE_COMPUTATION_CHUNK_SIZE] =
                [0; SHARE_COMPUTATION_CHUNK_SIZE];
            for i in 0..SHARE_COMPUTATION_CHUNK_SIZE {
                reversed_share[SHARE_COMPUTATION_CHUNK_SIZE - 1 - i] =
                    y_chunk[i][mod_idx][party_idx + 1];
            }
            out[1 + party_idx * L_THRESHOLD + mod_idx] = compute_sc_party_share_chunk_commitment::<SHARE_COMPUTATION_CHUNK_SIZE, SHARE_COMPUTATION_BIT_SHARE>(
                party_idx,
                mod_idx,
                chunk_idx,
                N,
                Polynomial::new(reversed_share),
            );
        }
    }

    out
}
