// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Summing committed polynomials while they are still packed.
//!
//! The aggregation circuits (l-BFV C4, PK aggregation, RLK aggregation) each open `H` parties'
//! commitments to one CRT limb and publish a commitment to the centred sum modulo `q`. Opening a
//! commitment coefficient by coefficient rebuilds every packed carrier from witnessed values and
//! range-checks each digit, which is almost all of these circuits at larger committees. Here the
//! witnesses are the packed carriers themselves: they are hashed straight into the parties'
//! commitments (collision resistance makes them the creator's carriers, whose digits the creating
//! circuit bounded), added carrier-wise, and only the sum is unpacked.

use crate::math::helpers::assert_in_residue_range;

/// Values per carrier. Every caller's width rounds to a 48-60-bit nibble, which packs four.
pub global PACKED_SLOTS: u32 = 4;

/// Unpacks the carrier-wise sum of `H` parties' carriers for one CRT limb and returns the carriers
/// of the centred sum modulo `q`, packed in the same layout.
///
/// `carrier(party, g)` is party `party`'s carrier `g`: values `4g..4g + 4`, digit `v + 2^nib` in
/// radix `R = 2^(nib + 4)`, `nib` being `BIT` rounded up to a nibble, as `pack::<_, BIT>` builds
/// it. The returned carrier `g` is `pack::<_, BIT>` of the four centred residues of the slot sums,
/// so hashing the returned carriers gives the commitment the coefficient-wise circuit computes.
///
/// `signed` selects how the parties' values were bounded by the circuits that committed them:
/// - `false`: canonical residues in `[0, q)` (shares, C4). Slot sums lie in `[0, H * q)`.
/// - `true`: centred residues in `[-(q-1)/2, (q-1)/2]` (key rows). Slot sums lie in
///   `[-H * (q-1)/2, H * (q-1)/2]`.
///
/// Soundness. With `K = nib + 4 - BIT_Q` and `q < 2^BIT_Q`, hints `k_i, c_i` satisfy
/// `c_i + half in [0, q)`, `k_i` in a `2^K`-wide window (`[0, 2^K)`, or `[-2^(K-1), 2^(K-1))` when
/// signed) and `S == sum_i R^(3 - i) * (k_i * q + c_i)`, where `S` is the carrier sum with the base
/// offsets removed. Each digit `k_i * q + c_i` lies in a window of width `2^K * q < R`, so two digit
/// vectors meeting the same `S` agree slot by slot from the lowest one up: the digits are the slot
/// sums, and `c_i` is their centred residue. Every term is below `2^245` in magnitude, far from the
/// field prime, so the field identity is the integer one. The honest carry stays in its window
/// because of the committee bound asserted below.
pub fn reduce_packed_sum<let N4: u32, let H: u32, let BIT: u32, let BIT_Q: u32, Env>(
    carrier: fn[Env](u32, u32) -> Field,
    q: Field,
    signed: bool,
) -> [Field; N4] {
    let nib = ((BIT + 3) / 4) * 4;
    let slot_bits = nib + 4;
    assert(254 / slot_bits == PACKED_SLOTS, "packed sums need four values per carrier");
    assert(slot_bits > BIT_Q, "the modulus must leave room for a carry in each slot");
    let carry_bits = slot_bits - BIT_Q;
    if signed {
        // |carry| <= (H + 1) / 2 must fit [-2^(K-1), 2^(K-1)).
        assert(H + 1 < (1 << carry_bits), "committee exceeds the packed-sum carry bound");
    } else {
        // carry <= H must fit [0, 2^K).
        assert(H < (1 << carry_bits), "committee exceeds the packed-sum carry bound");
    }
    (q - 1).assert_max_bit_size::<BIT_Q>();

    let half = (q - 1) / 2;
    let base = 2.pow_32(nib as Field);
    let radix = 2.pow_32(slot_bits as Field);
    let weights = [radix * radix * radix, radix * radix, radix, 1];
    let packed_base = base * (weights[0] + weights[1] + weights[2] + weights[3]);
    // Signed sums are read from `S + T * sum(w)`, which keeps every honest slot in [0, R); the
    // carry is stored shifted by 2^(K-1) so its range check is one-sided.
    let slot_offset = if signed {
        2.pow_32((slot_bits - 1) as Field)
    } else {
        0
    };
    let carry_shift = if signed {
        2.pow_32((carry_bits - 1) as Field)
    } else {
        0
    };
    let packed_offset = slot_offset * (weights[0] + weights[1] + weights[2] + weights[3]);

    let mut out: [Field; N4] = [0; N4];
    for g in 0..N4 {
        let mut sum = 0;
        for party in 0..H {
            sum += carrier(party, g);
        }
        sum -= (H as Field) * packed_base;

        // Safety: the carry window, the centred window and the recombination below pin every hint,
        // as argued above.
        let (carries, centred) = unsafe {
            __unpack_and_centre(
                sum + packed_offset,
                slot_bits,
                slot_offset,
                carry_shift,
                q,
                half,
            )
        };
        let mut recombined = 0;
        let mut carry_weight = 0;
        for i in 0..PACKED_SLOTS {
            (carries[i] + carry_shift).assert_max_bit_size::<((BIT + 3) / 4) * 4 + 4 - BIT_Q>();
            assert_in_residue_range::<BIT_Q>(centred[i] + half, q);
            recombined += weights[i] * (carries[i] * q + centred[i]);
            carry_weight += weights[i] * carries[i];
        }
        assert(recombined == sum, "packed sum does not unpack");

        // `sum_i R^(3 - i) * (c_i + base) = S - q * sum_i R^(3 - i) * k_i + B`.
        out[g] = sum - q * carry_weight + packed_base;
    }
    out
}

/// Splits `shifted` into four `slot_bits`-wide slots (most significant first), removes
/// `slot_offset` from each to get the slot sum `s`, and splits `s` into the carry
/// `k = floor((s + half) / q)` and `c = s - k * q`.
unconstrained fn __unpack_and_centre(
    shifted: Field,
    slot_bits: u32,
    slot_offset: Field,
    carry_shift: Field,
    q: Field,
    half: Field,
) -> ([Field; 4], [Field; 4]) {
    let bits: [bool; 254] = shifted.to_be_bits();
    let q64 = q as u64;
    let half64 = half as u64;
    let offset64 = slot_offset as u64;
    // Adding `carry_shift * q` keeps the dividend non-negative for signed slot sums.
    let lift64 = (carry_shift as u64) * q64;
    let mut carries = [0; 4];
    let mut centred = [0; 4];
    for i in 0..4 {
        let first = 254 - (4 - i) * slot_bits;
        let mut slot: u64 = 0;
        for b in 0..slot_bits {
            slot = (slot << 1) | (bits[first + b] as u64);
        }
        let shifted_carry = (slot + half64 + lift64 - offset64) / q64;
        let carry = (shifted_carry as Field) - carry_shift;
        carries[i] = carry;
        centred[i] = (slot as Field) - slot_offset - carry * q;
    }
    (carries, centred)
}

#[test]
fn test_unsigned_packed_sum_centres_each_slot() {
    // q = 101, two parties, BIT = 51 (four 56-bit slots). Slot sums 0, 50, 51, 200.
    let base = 2.pow_32(52);
    let r = 2.pow_32(56);
    let pack4 = |a: Field, b: Field, c: Field, d: Field| {
        (((a + base) * r + (b + base)) * r + (c + base)) * r + (d + base)
    };
    let parties = [[pack4(0, 25, 50, 100)], [pack4(0, 25, 1, 100)]];
    let out = reduce_packed_sum::<1, 2, 51, 51, _>(|p, g| parties[p][g], 101, false);
    // 0 -> 0, 50 -> 50, 51 -> -50, 200 -> -2.
    assert(out[0] == pack4(0, 50, -50, -2));
}

#[test]
fn test_signed_packed_sum_centres_each_slot() {
    // q = 101, three parties with centred values; slot sums -150, 0, 150, -7.
    let base = 2.pow_32(52);
    let r = 2.pow_32(56);
    let pack4 = |a: Field, b: Field, c: Field, d: Field| {
        (((a + base) * r + (b + base)) * r + (c + base)) * r + (d + base)
    };
    let parties = [[pack4(-50, 10, 50, -1)], [pack4(-50, -20, 50, -3)], [pack4(-50, 10, 50, -3)]];
    let out = reduce_packed_sum::<1, 3, 50, 51, _>(|p, g| parties[p][g], 101, true);
    // -150 -> -150 + 202 = 52 -> 52 - 101 = -49; 0 -> 0; 150 -> 49; -7 -> -7.
    assert(out[0] == pack4(-49, 0, 49, -7));
}

#[test]
fn packed_sum_at_a_secure_modulus_with_fourteen_senders() {
    // A 51-bit modulus takes the windowed residue check, with values at both window ends.
    let q: Field = 1125899917262849;
    let half: Field = 562949958631424;
    let unsigned = crate::math::helpers::pack::<4, 51>([q - 1, half, half + 1, 0]);
    let unsigned_expected = crate::math::helpers::pack::<4, 51>([-14, -7, 7, 0]);
    let unsigned_out = reduce_packed_sum::<1, 14, 51, 51, _>(|_, _| unsigned[0], q, false);
    assert(unsigned_out[0] == unsigned_expected[0]);

    let signed = crate::math::helpers::pack::<4, 50>([half, -half, 1, -1]);
    let signed_expected = crate::math::helpers::pack::<4, 50>([-7, 7, 14, -14]);
    let signed_out = reduce_packed_sum::<1, 14, 50, 51, _>(|_, _| signed[0], q, true);
    assert(signed_out[0] == signed_expected[0]);
}
