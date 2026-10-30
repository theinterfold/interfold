// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::dkg::{
    L_THRESHOLD, N, SHARE_COMPUTATION_BIT_SHARE, SHARE_COMPUTATION_CHUNK_SIZE,
    SHARE_COMPUTATION_E_SM_BIT_SECRET, SHARE_COMPUTATION_E_SM_CONFIGS, SHARE_COMPUTATION_N_CHUNKS,
};
use lib::configs::default::{N_PARTIES, T};
use lib::configs::default::threshold::{
    PK_GENERATION_BIT_E_SM_HIGH, PK_GENERATION_BIT_E_SM_SPLIT_QUOTIENT,
    PK_GENERATION_E_SM_BOUND_MOD_Q, PK_GENERATION_E_SM_RADIX_MOD_Q, PK_GENERATION_E_SM_SPLIT_BITS,
    PK_GENERATION_E_SM_TWICE_BOUND_HIGH, PK_GENERATION_E_SM_TWICE_BOUND_LOW,
};
use lib::core::dkg::share_computation::{
    centered_residue, check_range_bounds, verify_shamir_finite_differences,
};
use lib::math::commitments::{
    compute_sc_esm_secret_chunk_commitment, compute_sc_party_share_chunk_commitment_bounded,
};
use lib::math::polynomial::Polynomial;

pub global CHUNK_PUBLIC_LEN: u32 = 1 + (N_PARTIES * L_THRESHOLD);

/// The chunk's smudging-noise witness: per coefficient, `B + e = plus_high * 2^K + plus_low` and
/// `B - e = minus_high * 2^K + minus_low`, the carry out of `plus_low + minus_low`, and one CRT
/// quotient per limb. `e` itself is never a witness: at secure-16384 the bound `B` exceeds the field.
pub struct ESmSplit<let CHUNK: u32> {
    plus_high: Polynomial<CHUNK>,
    plus_low: Polynomial<CHUNK>,
    minus_high: Polynomial<CHUNK>,
    minus_low: Polynomial<CHUNK>,
    carry: Polynomial<CHUNK>,
    quotients: [Polynomial<CHUNK>; L_THRESHOLD],
}

/// Proves the chunk's residues are those of one integer smudging noise `e` with `|e| <= B`.
/// On the l-BFV path no C1 proof carries this bound, so every C2b leaf checks it for its own
/// coefficients; the finalizer's chunk-index checks make the leaves cover the whole polynomial.
///
/// **Bound.** `plus = B + e` and `minus = B - e` are each split at `K` bits with both parts range
/// checked, so both are non-negative integers below `2^(K + BIT_E_SM_HIGH)`. Their sum is checked to
/// be `2B` limb by limb: `plus_low + minus_low = TWICE_BOUND_LOW + carry * 2^K` and
/// `plus_high + minus_high + carry = TWICE_BOUND_HIGH`, with a boolean carry. Every term of both
/// equations is below `2^(max(K, BIT_E_SM_HIGH) + 2)`, far below the field, so they hold over the
/// integers and `plus + minus = 2B`. Two non-negative integers summing to `2B` give
/// `-B <= e = plus - B <= B`.
///
/// **Residue.** `plus_high * (2^K mod q_l) + plus_low - (B mod q_l) - centered[l] = q_l * t_l` with
/// `t_l` in `[-2^BIT_E_SM_SPLIT_QUOTIENT, 2^BIT_E_SM_SPLIT_QUOTIENT)`. The generator sizes that window
/// to cover honest quotients and keeps every term far below the field, so the relation holds over
/// the integers and `centered[l]` is congruent to `plus - B = e` modulo `q_l`.
///
/// `centered[l][i]` is the residue or the residue minus `q_l` (see `centered_residue`). Either
/// choice satisfies the relation, so the leaf's secret commitment (and the C2b root) is not
/// canonical; nothing on the l-BFV path opens it, and an anchor on it would first need
/// `|centered| <= (q_l - 1) / 2`.
fn check_e_sm_lift<let CHUNK: u32>(
    centered: [[Field; CHUNK]; L_THRESHOLD],
    split: ESmSplit<CHUNK>,
) {
    let radix = 2.pow_32(PK_GENERATION_E_SM_SPLIT_BITS as Field);
    let quotient_shift = 2.pow_32(PK_GENERATION_BIT_E_SM_SPLIT_QUOTIENT as Field);
    for i in 0..CHUNK {
        let plus_high = split.plus_high.coefficients[i];
        let plus_low = split.plus_low.coefficients[i];
        let minus_high = split.minus_high.coefficients[i];
        let minus_low = split.minus_low.coefficients[i];
        let carry = split.carry.coefficients[i];

        plus_low.assert_max_bit_size::<PK_GENERATION_E_SM_SPLIT_BITS>();
        minus_low.assert_max_bit_size::<PK_GENERATION_E_SM_SPLIT_BITS>();
        plus_high.assert_max_bit_size::<PK_GENERATION_BIT_E_SM_HIGH>();
        minus_high.assert_max_bit_size::<PK_GENERATION_BIT_E_SM_HIGH>();
        assert(carry * (carry - 1) == 0, "smudging split carry must be 0 or 1");
        assert(
            plus_low + minus_low == PK_GENERATION_E_SM_TWICE_BOUND_LOW + carry * radix,
            "smudging noise exceeds its bound",
        );
        assert(
            plus_high + minus_high + carry == PK_GENERATION_E_SM_TWICE_BOUND_HIGH,
            "smudging noise exceeds its bound",
        );

        for mod_idx in 0..L_THRESHOLD {
            let q = SHARE_COMPUTATION_E_SM_CONFIGS.qis[mod_idx];
            let quotient = split.quotients[mod_idx].coefficients[i];
            (quotient + quotient_shift)
                .assert_max_bit_size::<PK_GENERATION_BIT_E_SM_SPLIT_QUOTIENT + 1>();
            assert(
                plus_high * PK_GENERATION_E_SM_RADIX_MOD_Q[mod_idx] + plus_low
                    - PK_GENERATION_E_SM_BOUND_MOD_Q[mod_idx]
                    - centered[mod_idx][i]
                    == quotient * q,
                "Smudging noise CRT consistency failed",
            );
        }
    }
}

fn main(
    chunk_idx: pub u32,
    secret_chunk: [Polynomial<SHARE_COMPUTATION_CHUNK_SIZE>; L_THRESHOLD],
    y_chunk: [[[Field; N_PARTIES + 1]; L_THRESHOLD]; SHARE_COMPUTATION_CHUNK_SIZE],
    e_sm_plus_high_chunk: Polynomial<SHARE_COMPUTATION_CHUNK_SIZE>,
    e_sm_plus_low_chunk: Polynomial<SHARE_COMPUTATION_CHUNK_SIZE>,
    e_sm_minus_high_chunk: Polynomial<SHARE_COMPUTATION_CHUNK_SIZE>,
    e_sm_minus_low_chunk: Polynomial<SHARE_COMPUTATION_CHUNK_SIZE>,
    e_sm_carry_chunk: Polynomial<SHARE_COMPUTATION_CHUNK_SIZE>,
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
    verify_shamir_finite_differences::<SHARE_COMPUTATION_CHUNK_SIZE, L_THRESHOLD, N_PARTIES, T>(
        SHARE_COMPUTATION_E_SM_CONFIGS.qis,
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
    check_e_sm_lift(
        centered,
        ESmSplit {
            plus_high: e_sm_plus_high_chunk,
            plus_low: e_sm_plus_low_chunk,
            minus_high: e_sm_minus_high_chunk,
            minus_low: e_sm_minus_low_chunk,
            carry: e_sm_carry_chunk,
            quotients: e_sm_quotients_chunk,
        },
    );

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

/// A one-coefficient witness with `B + e = plus` and `B - e = minus`, each a `(high, low)` pair, and
/// `e` congruent to `e_mod_q[l]` (in `[0, q_l)`) modulo every limb. The tests build `plus` and
/// `minus` from the limbs of `2B`, so they never form `B`, which exceeds the field at secure-16384.
fn witness(
    plus: (Field, Field),
    minus: (Field, Field),
    carry: Field,
    e_mod_q: [u64; L_THRESHOLD],
) -> ([[Field; 1]; L_THRESHOLD], ESmSplit<1>) {
    let mut centered: [[Field; 1]; L_THRESHOLD] = [[0; 1]; L_THRESHOLD];
    let mut quotients = [Polynomial::new([0]); L_THRESHOLD];
    for l in 0..L_THRESHOLD {
        let q = SHARE_COMPUTATION_E_SM_CONFIGS.qis[l];
        let half = ((q - 1) / 2) as u64;
        let r = if e_mod_q[l] > half {
            (e_mod_q[l] as Field) - q
        } else {
            e_mod_q[l] as Field
        };
        centered[l] = [r];
        let numerator = plus.0 * PK_GENERATION_E_SM_RADIX_MOD_Q[l] + plus.1
            - PK_GENERATION_E_SM_BOUND_MOD_Q[l]
            - r;
        quotients[l] = Polynomial::new([numerator / q]);
    }
    let split = ESmSplit {
        plus_high: Polynomial::new([plus.0]),
        plus_low: Polynomial::new([plus.1]),
        minus_high: Polynomial::new([minus.0]),
        minus_low: Polynomial::new([minus.1]),
        carry: Polynomial::new([carry]),
        quotients,
    };
    (centered, split)
}

/// `e = B - x` (`top`) or `e = x - B`, for a small `x`: the distance `x` on one side and `2B - x`
/// on the other.
fn edge(x: u64, top: bool) -> ([[Field; 1]; L_THRESHOLD], ESmSplit<1>) {
    let near =
        (PK_GENERATION_E_SM_TWICE_BOUND_HIGH, PK_GENERATION_E_SM_TWICE_BOUND_LOW - x as Field);
    let far = (0, x as Field);
    let mut e_mod_q = [0; L_THRESHOLD];
    for l in 0..L_THRESHOLD {
        let q = SHARE_COMPUTATION_E_SM_CONFIGS.qis[l] as u64;
        let b = PK_GENERATION_E_SM_BOUND_MOD_Q[l] as u64;
        e_mod_q[l] = if top {
            (b + q - x) % q
        } else {
            (x + q - b) % q
        };
    }
    if top {
        witness(near, far, 0, e_mod_q)
    } else {
        witness(far, near, 0, e_mod_q)
    }
}

#[test]
fn test_e_sm_lift_accepts_the_upper_bound() {
    let (centered, split) = edge(0, true);
    check_e_sm_lift(centered, split);
}

#[test]
fn test_e_sm_lift_accepts_the_lower_bound() {
    let (centered, split) = edge(0, false);
    check_e_sm_lift(centered, split);
}

#[test]
fn test_e_sm_lift_accepts_noise_inside_the_bound() {
    let (centered, split) = edge(5, true);
    check_e_sm_lift(centered, split);
    let (centered, split) = edge(5, false);
    check_e_sm_lift(centered, split);
}

/// `B - e = 2^K - 1`, so the low limbs sum past `2^K` and the carry moves one unit into the high
/// limb: `plus = (TWICE_BOUND_HIGH - 1, TWICE_BOUND_LOW + 1)`. Here `e = B - (2^K - 1)`, which is
/// `b - c + 1` modulo `q_l` for `c = 2^K mod q_l`.
#[test]
fn test_e_sm_lift_accepts_a_carry() {
    let radix = 2.pow_32(PK_GENERATION_E_SM_SPLIT_BITS as Field);
    let mut e_mod_q = [0; L_THRESHOLD];
    for l in 0..L_THRESHOLD {
        let q = SHARE_COMPUTATION_E_SM_CONFIGS.qis[l] as u64;
        let b = PK_GENERATION_E_SM_BOUND_MOD_Q[l] as u64;
        let c = PK_GENERATION_E_SM_RADIX_MOD_Q[l] as u64;
        e_mod_q[l] = (b + 2 * q - c + 1) % q;
    }
    let (centered, split) = witness(
        (PK_GENERATION_E_SM_TWICE_BOUND_HIGH - 1, PK_GENERATION_E_SM_TWICE_BOUND_LOW + 1),
        (0, radix - 1),
        1,
        e_mod_q,
    );
    check_e_sm_lift(centered, split);
}

#[test(should_fail_with = "smudging noise exceeds its bound")]
fn test_e_sm_lift_rejects_noise_above_the_bound() {
    // `e = B + 1`: `plus` is `2B + 1`, so `minus` would have to be `-1`.
    let (centered, mut split) = edge(0, true);
    split.plus_low.coefficients[0] += 1;
    check_e_sm_lift(centered, split);
}

#[test(should_fail_with = "smudging noise exceeds its bound")]
fn test_e_sm_lift_rejects_noise_below_the_bound() {
    let (centered, mut split) = edge(0, false);
    split.minus_low.coefficients[0] += 1;
    check_e_sm_lift(centered, split);
}

#[test(should_fail)]
fn test_e_sm_lift_rejects_a_negative_limb() {
    // `e = B + 1` with `minus = -1` written as a field element: the low limb's range check fails.
    let (centered, mut split) = edge(0, true);
    split.plus_low.coefficients[0] += 1;
    split.minus_low.coefficients[0] = -1;
    check_e_sm_lift(centered, split);
}

#[test(should_fail_with = "smudging split carry must be 0 or 1")]
fn test_e_sm_lift_rejects_a_non_boolean_carry() {
    let (centered, mut split) = edge(0, true);
    split.carry.coefficients[0] = 2;
    split.plus_high.coefficients[0] -= 2;
    check_e_sm_lift(centered, split);
}

#[test(should_fail_with = "Smudging noise CRT consistency failed")]
fn test_e_sm_lift_rejects_a_wrong_residue() {
    let (mut centered, split) = edge(5, true);
    centered[0][0] += 1;
    check_e_sm_lift(centered, split);
}

#[test(should_fail)]
fn test_e_sm_lift_rejects_a_field_only_quotient() {
    // The relation holds modulo the field prime, but only through a quotient far outside its
    // window; the integer relation (and so the residue) is not implied.
    let (mut centered, mut split) = edge(5, true);
    let quotient: Field = 2.pow_32(200);
    centered[0][0] -= quotient * SHARE_COMPUTATION_E_SM_CONFIGS.qis[0];
    split.quotients[0] = Polynomial::new([split.quotients[0].coefficients[0] + quotient]);
    check_e_sm_lift(centered, split);
}
