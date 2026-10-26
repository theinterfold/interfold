// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Tests of the offer rules. The vectors come from `sdk/test-vectors/layout.json`, which the TypeScript
//! reference encoding (`sdk/src/layout.ts`) writes, so these tests fail if the circuit and the
//! reference disagree.
use crate::{
    check_lanes, check_mask, check_parameters, k1_is_slots, LANE_QUOTIENT_BITS, lane_slots, LEVELS,
    MASK_QUOTIENT_BITS, SLOTS,
};
use crate::constants::TABLE_UNIT;
use crate::vectors::{
    BUYER_SHARE, BUYER_SLOTS, BUYER_STEP, CASES, SELLER_SHARE, SELLER_SLOTS, SELLER_STEP,
};
use interfold_lib::configs::insecure_simd::threshold::{N, PLAINTEXT_MODULUS};
use interfold_lib::math::polynomial::Polynomial;

/// `k1` of the plaintext with the slot values `slots`: the combination mod `t` of the units.
fn honest_k1(slots: [Field; SLOTS]) -> Polynomial<N> {
    // Safety: a test helper, the circuit under test is not trusted with it.
    unsafe {
        honest_k1_hint(slots)
    }
}

unconstrained fn honest_k1_hint(slots: [Field; SLOTS]) -> Polynomial<N> {
    let t = PLAINTEXT_MODULUS as u64;
    let mut k1 = Polynomial { coefficients: [0; N] };
    for i in 0..N {
        let mut sum: u64 = 0;
        for s in 0..SLOTS {
            sum += (slots[s] as u64) * (TABLE_UNIT[s][i] as u64);
        }
        k1.coefficients[i] = (sum % t) as Field;
    }
    k1
}

/// `x + 1` mod `t`, for `x` below `t`.
fn plus_one(x: Field) -> Field {
    (((x as u64) + 1) % (PLAINTEXT_MODULUS as u64)) as Field
}

fn honest_lanes(role: Field, step: Field, share: Field) -> [Polynomial<N>; 2] {
    let slots = lane_slots(role, step, share);
    [honest_k1(slots[0]), honest_k1(slots[1])]
}

#[test]
fn seller_lanes_match_the_reference_vectors() {
    for c in 0..CASES {
        let slots = lane_slots(0, SELLER_STEP[c], SELLER_SHARE[c]);
        assert(slots[0] == SELLER_SLOTS[c][0], "seller lanes 0..8");
        assert(slots[1] == SELLER_SLOTS[c][1], "seller lanes 8..16");
    }
}

#[test]
fn buyer_lanes_match_the_reference_vectors() {
    for c in 0..CASES {
        let slots = lane_slots(1, BUYER_STEP[c], BUYER_SHARE[c]);
        assert(slots[0] == BUYER_SLOTS[c][0], "buyer lanes 0..8");
        assert(slots[1] == BUYER_SLOTS[c][1], "buyer lanes 8..16");
    }
}

#[test]
fn the_vector_masks_are_masks() {
    for c in 0..CASES {
        check_mask(honest_k1(SELLER_SLOTS[c][2]), SELLER_SLOTS[c][2]);
        check_mask(honest_k1(BUYER_SLOTS[c][2]), BUYER_SLOTS[c][2]);
    }
}

#[test]
fn accepts_the_offers_of_the_vectors() {
    for c in 0..CASES {
        check_lanes(
            honest_lanes(0, SELLER_STEP[c], SELLER_SHARE[c]),
            0,
            16,
            SELLER_STEP[c],
            SELLER_SHARE[c],
        );
        check_lanes(
            honest_lanes(1, BUYER_STEP[c], BUYER_SHARE[c]),
            1,
            16,
            BUYER_STEP[c],
            BUYER_SHARE[c],
        );
    }
}

#[test]
fn tensor_entries_are_bits() {
    for c in 0..CASES {
        let seller = lane_slots(0, SELLER_STEP[c], SELLER_SHARE[c]);
        let buyer = lane_slots(1, BUYER_STEP[c], BUYER_SHARE[c]);
        for h in 0..2 {
            for s in 0..SLOTS {
                assert(seller[h][s] * (seller[h][s] - 1) == 0, "seller entries are 0 or 1");
                assert(buyer[h][s] * (buyer[h][s] - 1) == 0, "buyer entries are 0 or 1");
            }
        }
    }
}

#[test]
fn accepts_the_extreme_steps_and_shares() {
    for r in 0..2 {
        let role = r as Field;
        for step in [0, 8, 15] {
            for share in [5, 15] {
                check_lanes(honest_lanes(role, step, share), role, 16, step, share);
            }
        }
    }
}

#[test]
fn accepts_the_top_step_of_a_shorter_negotiation() {
    check_lanes(honest_lanes(0, 4, 9), 0, 5, 4, 9);
    check_lanes(honest_lanes(1, 1, 3), 1, 2, 1, 3);
    check_lanes(honest_lanes(1, 0, 3), 1, 2, 0, 3);
}

#[test]
fn accepts_a_mask_of_extreme_values() {
    // All zero.
    let zero = [0; SLOTS];
    check_mask(honest_k1(zero), zero);
    // Every level has the values `t - 1` in 7 groups and `7` in the last, which sums to `7 * 256 + 7 = 0 mod t`.
    let mut largest = zero;
    for g in 0..8 {
        for i in 0..LEVELS {
            largest[g * LEVELS + i] = if g == 7 { 7 } else { PLAINTEXT_MODULUS - 1 };
        }
    }
    check_mask(honest_k1(largest), largest);
}

#[test]
fn accepts_a_mask_with_values_above_t() {
    // `v` and `v + t` are the same plaintext: only the sum mod `t` matters.
    let zero = [0; SLOTS];
    let mut mask = zero;
    mask[0] = PLAINTEXT_MODULUS + 3;
    mask[LEVELS] = PLAINTEXT_MODULUS - 3;
    let mut plain = zero;
    plain[0] = 3;
    plain[LEVELS] = PLAINTEXT_MODULUS - 3;
    check_mask(honest_k1(plain), mask);
}

#[test(should_fail_with = "the mask does not sum to 0 over the groups")]
fn rejects_a_mask_with_a_non_zero_sum() {
    let mut mask = SELLER_SLOTS[0][2];
    mask[5] = plus_one(mask[5]);
    check_mask(honest_k1(mask), mask);
}

#[test(should_fail_with = "the mask does not sum to 0 over the groups")]
fn rejects_a_mask_that_is_zero_except_for_one_slot() {
    let mut mask = [0; SLOTS];
    mask[40] = 1;
    check_mask(honest_k1(mask), mask);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed slots")]
fn rejects_a_mask_with_another_k1() {
    let mask = SELLER_SLOTS[0][2];
    check_mask(honest_k1(BUYER_SLOTS[0][2]), mask);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed slots")]
fn rejects_a_mask_with_a_changed_coefficient() {
    let mask = SELLER_SLOTS[0][2];
    let mut k1 = honest_k1(mask);
    k1.coefficients[17] = plus_one(k1.coefficients[17]);
    check_mask(k1, mask);
}

#[test(should_fail)]
fn rejects_a_mask_value_beyond_its_range() {
    // `v + 2^9` has the same residue as `v` but it is out of range, so the sums could wrap.
    let mut mask = SELLER_SLOTS[0][2];
    mask[0] += 512;
    check_mask(honest_k1(SELLER_SLOTS[0][2]), mask);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed slots")]
fn rejects_the_lanes_of_another_share() {
    check_lanes(honest_lanes(0, 6, 3), 0, 16, 6, 4);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed slots")]
fn rejects_the_lanes_of_another_step() {
    check_lanes(honest_lanes(0, 6, 3), 0, 16, 7, 3);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed slots")]
fn rejects_the_buyer_lanes_for_the_seller_role() {
    check_lanes(honest_lanes(1, 6, 3), 0, 16, 6, 3);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed slots")]
fn rejects_the_seller_lanes_for_the_buyer_role() {
    check_lanes(honest_lanes(0, 6, 3), 1, 16, 6, 3);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed slots")]
fn rejects_swapped_lane_ciphertexts() {
    let k1s = honest_lanes(0, 6, 3);
    check_lanes([k1s[1], k1s[0]], 0, 16, 6, 3);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed slots")]
fn rejects_a_non_tensor_k1() {
    let mut k1s = honest_lanes(1, 6, 3);
    k1s[0].coefficients[3] = plus_one(k1s[0].coefficients[3]);
    check_lanes(k1s, 1, 16, 6, 3);
}

#[test(should_fail_with = "the step is not below levels")]
fn rejects_a_step_equal_to_the_levels() {
    check_lanes(honest_lanes(0, 5, 3), 0, 5, 5, 3);
}

#[test(should_fail_with = "the step is not below levels")]
fn rejects_a_step_above_the_levels() {
    check_lanes(honest_lanes(1, 9, 3), 1, 5, 9, 3);
}

#[test(should_fail_with = "levels is not in 2..=LEVELS")]
fn rejects_one_level() {
    check_parameters(0, 1, 0);
}

#[test(should_fail_with = "levels is not in 2..=LEVELS")]
fn rejects_zero_levels() {
    check_parameters(0, 0, 0);
}

#[test(should_fail_with = "levels is not in 2..=LEVELS")]
fn rejects_more_levels_than_slots() {
    check_parameters(0, 17, 0);
}

#[test(should_fail)]
fn rejects_a_levels_value_beyond_the_range_check() {
    // `2^32 + 2` would be 2 after a truncation to `u32`.
    check_parameters(0, 0x100000002, 0);
}

#[test(should_fail_with = "the role is not 0 or 1")]
fn rejects_the_role_2() {
    check_parameters(2, 16, 0);
}

#[test(should_fail_with = "the role is not 0 or 1")]
fn rejects_the_lane_slots_of_the_role_2() {
    let _ = lane_slots(2, 3, 3);
}

#[test(should_fail_with = "the step is in 0..LEVELS")]
fn rejects_a_step_beyond_the_slots() {
    let _ = lane_slots(0, 16, 3);
}

#[test(should_fail_with = "the share is not below LANES")]
fn rejects_a_share_beyond_the_lanes() {
    let _ = lane_slots(0, 3, 16);
}

#[test(should_fail)]
fn rejects_a_step_beyond_the_range_check() {
    check_parameters(0, 16, 0x100000000);
}

#[test]
fn the_quotient_bounds_hold_for_the_largest_sums() {
    // Every slot value is `2^9 - 1` (a mask has such values at most): the sum of a coefficient and its
    // quotient stay within the bounds, so an honest witness passes the range checks.
    let mut mask = [0; SLOTS];
    for s in 0..SLOTS {
        mask[s] = 511;
    }
    let t = PLAINTEXT_MODULUS as u64;
    let mut k1 = Polynomial { coefficients: [0; N] };
    for i in 0..N {
        let mut sum: u64 = 0;
        for s in 0..SLOTS {
            sum += 511 * (TABLE_UNIT[s][i] as u64);
        }
        assert(sum / t < (1 as u64) << (MASK_QUOTIENT_BITS as u64));
        k1.coefficients[i] = (sum % t) as Field;
    }
    k1_is_slots::<MASK_QUOTIENT_BITS>(k1, mask);
    let mut ones = [0; SLOTS];
    for s in 0..SLOTS {
        ones[s] = 1;
    }
    k1_is_slots::<LANE_QUOTIENT_BITS>(honest_k1(ones), ones);
}
