// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::dkg::{
    L_THRESHOLD, N, PARITY_MATRIX, SHARE_COMPUTATION_BIT_SHARE, SHARE_COMPUTATION_CHUNK_SIZE,
    SHARE_COMPUTATION_E_SM_BIT_SECRET, SHARE_COMPUTATION_E_SM_CONFIGS, SHARE_COMPUTATION_N_CHUNKS,
};
use lib::configs::default::{N_PARTIES, T};
use lib::configs::default::threshold::{
    PK_GENERATION_BIT_E_SM_LIFTED, PK_GENERATION_BIT_E_SM_QUOTIENT, PK_GENERATION_E_SM_BOUND,
    PK_GENERATION_E_SM_QUOTIENT_BOUNDS,
};
use lib::core::dkg::share_computation::{
    centered_residue, check_range_bounds, verify_parity_check_bounded,
};
use lib::math::commitments::{
    compute_sc_esm_secret_chunk_commitment, compute_sc_party_share_chunk_commitment_bounded,
};
use lib::math::polynomial::Polynomial;

pub global CHUNK_PUBLIC_LEN: u32 = 1 + (N_PARTIES * L_THRESHOLD);

/// Proves the chunk's residues are those of one integer smudging noise bounded by `e_sm_bound`.
/// On the l-BFV path no C1 proof carries this bound, so every C2b leaf checks it for its own
/// coefficients; the finalizer's chunk-index checks make the leaves cover the whole polynomial.
///
/// `centered[l][i]` is the residue or the residue minus `q_l` (see `centered_residue`), and the
/// checked packing of the leaf's secret commitment keeps it below `2^(nibble_bits + 4)` in
/// magnitude, where `nibble_bits` is `E_SM_BIT_SECRET` rounded up to a nibble. Either choice
/// satisfies the lift, so the leaf's secret commitment (and the C2b root) is not canonical; nothing
/// on the l-BFV path opens it, and an anchor on it would first need `|centered| <= (q_l - 1) / 2`. The
/// shifted quotient is below `2^(BIT_E_SM_QUOTIENT + 1)`, so `|quotient * q_l|` is below
/// `2^(BIT_E_SM_QUOTIENT + 65)`. With the lifted bound, every term of the relation stays far
/// below the field prime, so the relation holds over the integers and each residue is the lifted
/// value modulo `q_l`. A one-sided quotient check is enough for that; it is not a secret bound.
fn check_e_sm_lift<let CHUNK: u32>(
    centered: [[Field; CHUNK]; L_THRESHOLD],
    e_sm_lifted_chunk: Polynomial<CHUNK>,
    e_sm_quotients_chunk: [Polynomial<CHUNK>; L_THRESHOLD],
) {
    e_sm_lifted_chunk.range_check_2bounds::<PK_GENERATION_BIT_E_SM_LIFTED>(
        PK_GENERATION_E_SM_BOUND,
        PK_GENERATION_E_SM_BOUND,
    );
    for mod_idx in 0..L_THRESHOLD {
        let q = SHARE_COMPUTATION_E_SM_CONFIGS.qis[mod_idx];
        for i in 0..CHUNK {
            let quotient = e_sm_quotients_chunk[mod_idx].coefficients[i];
            (quotient + PK_GENERATION_E_SM_QUOTIENT_BOUNDS[mod_idx])
                .assert_max_bit_size::<PK_GENERATION_BIT_E_SM_QUOTIENT + 1>();
            assert(
                e_sm_lifted_chunk.coefficients[i] == centered[mod_idx][i] + quotient * q,
                "Smudging noise CRT consistency failed",
            );
        }
    }
}

fn main(
    chunk_idx: pub u32,
    secret_chunk: [Polynomial<SHARE_COMPUTATION_CHUNK_SIZE>; L_THRESHOLD],
    y_chunk: [[[Field; N_PARTIES + 1]; L_THRESHOLD]; SHARE_COMPUTATION_CHUNK_SIZE],
    e_sm_lifted_chunk: Polynomial<SHARE_COMPUTATION_CHUNK_SIZE>,
    e_sm_quotients_chunk: [Polynomial<SHARE_COMPUTATION_CHUNK_SIZE>; L_THRESHOLD],
) -> pub [Field; CHUNK_PUBLIC_LEN] {
    assert(chunk_idx < SHARE_COMPUTATION_N_CHUNKS);

    for coeff_idx in 0..SHARE_COMPUTATION_CHUNK_SIZE {
        for mod_idx in 0..L_THRESHOLD {
            assert(y_chunk[coeff_idx][mod_idx][0] == secret_chunk[mod_idx].coefficients[coeff_idx]);
        }
    }

    check_range_bounds::<SHARE_COMPUTATION_CHUNK_SIZE, L_THRESHOLD, N_PARTIES, SHARE_COMPUTATION_BIT_SHARE>(
        SHARE_COMPUTATION_E_SM_CONFIGS.qis,
        y_chunk,
    );
    verify_parity_check_bounded::<SHARE_COMPUTATION_CHUNK_SIZE, L_THRESHOLD, N_PARTIES, T, SHARE_COMPUTATION_BIT_SHARE>(
        SHARE_COMPUTATION_E_SM_CONFIGS.qis,
        PARITY_MATRIX,
        y_chunk,
    );

    let mut out: [Field; CHUNK_PUBLIC_LEN] = [0; CHUNK_PUBLIC_LEN];
    let mut centered: [[Field; SHARE_COMPUTATION_CHUNK_SIZE]; L_THRESHOLD] =
        [[0; SHARE_COMPUTATION_CHUNK_SIZE]; L_THRESHOLD];
    let mut normalized: [Polynomial<SHARE_COMPUTATION_CHUNK_SIZE>; L_THRESHOLD] =
        [Polynomial::new([0; SHARE_COMPUTATION_CHUNK_SIZE]); L_THRESHOLD];
    for mod_idx in 0..L_THRESHOLD {
        let q = SHARE_COMPUTATION_E_SM_CONFIGS.qis[mod_idx];
        let mut coefficients: [Field; SHARE_COMPUTATION_CHUNK_SIZE] =
            [0; SHARE_COMPUTATION_CHUNK_SIZE];
        for i in 0..SHARE_COMPUTATION_CHUNK_SIZE {
            let value = centered_residue(secret_chunk[mod_idx].coefficients[i], q);
            centered[mod_idx][i] = value;
            coefficients[SHARE_COMPUTATION_CHUNK_SIZE - 1 - i] = value;
        }
        normalized[mod_idx] = Polynomial::new(coefficients);
    }
    check_e_sm_lift(centered, e_sm_lifted_chunk, e_sm_quotients_chunk);

    out[0] = compute_sc_esm_secret_chunk_commitment::<SHARE_COMPUTATION_CHUNK_SIZE, L_THRESHOLD, SHARE_COMPUTATION_E_SM_BIT_SECRET>(
        chunk_idx,
        N,
        normalized,
    );

    for party_idx in 0..N_PARTIES {
        for mod_idx in 0..L_THRESHOLD {
            let mut reversed_share: [Field; SHARE_COMPUTATION_CHUNK_SIZE] =
                [0; SHARE_COMPUTATION_CHUNK_SIZE];
            for i in 0..SHARE_COMPUTATION_CHUNK_SIZE {
                reversed_share[SHARE_COMPUTATION_CHUNK_SIZE - 1 - i] =
                    y_chunk[i][mod_idx][party_idx + 1];
            }
            out[1 + party_idx * L_THRESHOLD + mod_idx] = compute_sc_party_share_chunk_commitment_bounded::<SHARE_COMPUTATION_CHUNK_SIZE, SHARE_COMPUTATION_BIT_SHARE>(
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

#[test]
fn test_e_sm_lift_accepts_small_noise() {
    let lifted = Polynomial::new([7, -5]);
    check_e_sm_lift(
        [[7, -5]; L_THRESHOLD],
        lifted,
        [Polynomial::new([0, 0]); L_THRESHOLD],
    );
}

#[test]
fn test_e_sm_lift_accepts_noise_above_a_modulus() {
    // q_0 + 3 has quotient 1 modulo every q_l here; its residue is q_0 + 3 - q_l.
    let q0 = SHARE_COMPUTATION_E_SM_CONFIGS.qis[0];
    let mut centered: [[Field; 1]; L_THRESHOLD] = [[0; 1]; L_THRESHOLD];
    for l in 0..L_THRESHOLD {
        centered[l] = [q0 + 3 - SHARE_COMPUTATION_E_SM_CONFIGS.qis[l]];
    }
    check_e_sm_lift(
        centered,
        Polynomial::new([q0 + 3]),
        [Polynomial::new([1]); L_THRESHOLD],
    );
}

#[test(should_fail)]
fn test_e_sm_lift_rejects_noise_above_the_bound() {
    let too_large = PK_GENERATION_E_SM_BOUND + 1;
    check_e_sm_lift(
        [[too_large]; L_THRESHOLD],
        Polynomial::new([too_large]),
        [Polynomial::new([0]); L_THRESHOLD],
    );
}

#[test(should_fail)]
fn test_e_sm_lift_rejects_a_wrong_quotient() {
    let lifted = Polynomial::new([7, -5]);
    let mut quotients = [Polynomial::new([0, 0]); L_THRESHOLD];
    quotients[0] = Polynomial::new([1, 0]);
    check_e_sm_lift([[7, -5]; L_THRESHOLD], lifted, quotients);
}

#[test(should_fail)]
fn test_e_sm_lift_rejects_a_field_only_quotient() {
    // The relation holds modulo the field prime, but only through a quotient far outside its
    // bound; the integer relation (and so the residue) is not implied.
    let quotient: Field = 2.pow_32(200);
    let mut centered: [[Field; 1]; L_THRESHOLD] = [[0; 1]; L_THRESHOLD];
    for l in 0..L_THRESHOLD {
        centered[l] = [7 - quotient * SHARE_COMPUTATION_E_SM_CONFIGS.qis[l]];
    }
    check_e_sm_lift(
        centered,
        Polynomial::new([7]),
        [Polynomial::new([quotient]); L_THRESHOLD],
    );
}
