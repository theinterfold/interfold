// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Two-limb lift of the smudging noise, for presets whose smudging bound `B` does not fit the
//! field. The one-element lift of C2b needs `B` and `quotient * q_l` below the field prime; this
//! check keeps every term below `2^251` by splitting the integer at `2^K`.
//!
//! For each coefficient the prover gives `u = x + B` as `lo + 2^K * hi`, where `x` is the signed
//! smudging noise. The check proves:
//!
//! 1. `0 <= u <= 2B`, so `|x| <= B`: `lo < 2^K`, `hi <= span_hi`, and when `hi == span_hi` also
//!    `lo <= span_lo`, with `2B = span_hi * 2^K + span_lo`;
//! 2. `x` is congruent to the given centered residue in every limb:
//!    `centered_l + quotient_l * q_l == (lo - B_lo) + radix_l * (hi - B_hi)`, with
//!    `radix_l = 2^K mod q_l` and `B = B_hi * 2^K + B_lo`. The right side is `x` reduced by the
//!    split, so equality modulo `q_l` is the residue claim.
//!
//! The constants guarantee that both sides of the relation stay below half of the field prime
//! (the generator checks this), so the field equation is an integer equation. The quotient check
//! is one-sided: it admits `|quotient| < 2^(BIT_QUOTIENT + 1)`, which is a width bound and not a
//! secret bound.

use crate::math::polynomial::Polynomial;

pub fn check_wide_lift<let CHUNK: u32, let L: u32, let K: u32, let BIT_HI: u32, let BIT_QUOTIENT: u32>(
    qis: [Field; L],
    radix: [Field; L],
    quotient_bounds: [Field; L],
    bound_hi: Field,
    bound_lo: Field,
    span_hi: Field,
    span_lo: Field,
    centered: [[Field; CHUNK]; L],
    lo: Polynomial<CHUNK>,
    hi: [Field; CHUNK],
    quotients: [Polynomial<CHUNK>; L],
) {
    for i in 0..CHUNK {
        let hi_i = hi[i];
        let lo_i = lo.coefficients[i];

        lo_i.assert_max_bit_size::<K>();
        hi_i.assert_max_bit_size::<BIT_HI>();
        // `hi <= span_hi`: a larger `hi` wraps this difference to a value near the field prime.
        (span_hi - hi_i).assert_max_bit_size::<BIT_HI>();
        if hi_i == span_hi {
            (span_lo - lo_i).assert_max_bit_size::<K>();
        }

        for l in 0..L {
            let quotient = quotients[l].coefficients[i];
            (quotient + quotient_bounds[l]).assert_max_bit_size::<BIT_QUOTIENT + 1>();
            assert(
                (lo_i - bound_lo) + radix[l] * (hi_i - bound_hi)
                    == centered[l][i] + quotient * qis[l],
                "Smudging noise CRT consistency failed",
            );
        }
    }
}

// Toy parameters: K = 8 and B = 1000 = 3 * 256 + 232, so 2B = 2000 = 7 * 256 + 208. The moduli are
// 1009 and 1013 and both radixes are 256.
global TOY_K: u32 = 8;
global TOY_BIT_HI: u32 = 3;
global TOY_BIT_QUOTIENT: u32 = 3;
global TOY_QIS: [Field; 2] = [1009, 1013];
global TOY_RADIX: [Field; 2] = [256, 256];
// (256 + 256 * 7 + q) / q + 1 = 4 for both moduli.
global TOY_QUOTIENT_BOUNDS: [Field; 2] = [4, 4];

struct ToyWitness {
    lo: Field,
    hi: Field,
    centered: [Field; 2],
    quotients: [Field; 2],
}

/// Noir has no signed-to-Field cast, so build the field element from the magnitude.
fn to_field(v: i64) -> Field {
    if v < 0 {
        0 - ((0 - v) as u64 as Field)
    } else {
        v as u64 as Field
    }
}

/// The honest witness for noise `x`, with `u = x + 1000` split at 256. A negative `u` borrows from
/// `hi`, so that the relation still holds: `lo` is `u mod 256` and `hi` may be `-1`.
fn toy_witness(x: i64) -> ToyWitness {
    let u = x + 1000;
    let mut hi = u / 256;
    let mut lo = u % 256;
    if lo < 0 {
        lo += 256;
        hi -= 1;
    }
    let qs: [i64; 2] = [1009, 1013];
    let mut centered = [0; 2];
    let mut quotients = [0; 2];
    for l in 0..2 {
        let c = x % qs[l];
        centered[l] = to_field(c);
        quotients[l] = to_field((x - c) / qs[l]);
    }
    ToyWitness { lo: to_field(lo), hi: to_field(hi), centered, quotients }
}

fn toy_check(w: ToyWitness) {
    check_wide_lift::<1, 2, TOY_K, TOY_BIT_HI, TOY_BIT_QUOTIENT>(
        TOY_QIS,
        TOY_RADIX,
        TOY_QUOTIENT_BOUNDS,
        3,
        232,
        7,
        208,
        [[w.centered[0]], [w.centered[1]]],
        Polynomial::new([w.lo]),
        [w.hi],
        [Polynomial::new([w.quotients[0]]), Polynomial::new([w.quotients[1]])],
    );
}

#[test]
fn accepts_noise_inside_the_bound() {
    toy_check(toy_witness(0));
    toy_check(toy_witness(37));
    toy_check(toy_witness(-37));
    toy_check(toy_witness(999));
}

#[test]
fn accepts_the_bound_in_both_directions() {
    toy_check(toy_witness(1000));
    toy_check(toy_witness(-1000));
}

#[test(should_fail_with = "Smudging noise CRT consistency failed")]
fn rejects_a_wrong_residue_in_one_limb() {
    let mut w = toy_witness(37);
    w.centered[1] += 1;
    toy_check(w);
}

#[test(should_fail)]
fn rejects_noise_one_above_the_bound() {
    // u = 2001: hi = 7 equals span_hi and lo = 209 is above span_lo = 208.
    toy_check(toy_witness(1001));
}

#[test(should_fail)]
fn rejects_noise_one_below_the_bound() {
    // u = -1: hi = -1 is outside [0, 2^BIT_HI).
    toy_check(toy_witness(-1001));
}

#[test(should_fail)]
fn rejects_a_high_limb_above_the_span() {
    // u = 2048 = 8 * 256: hi = 8 does not fit BIT_HI and is above span_hi.
    toy_check(toy_witness(1048));
}

#[test(should_fail)]
fn rejects_a_low_limb_above_its_width() {
    // Move 256 from hi to lo: the relation holds, but lo no longer fits K bits.
    let mut w = toy_witness(37);
    w.lo += 256;
    w.hi -= 1;
    toy_check(w);
}

#[test(should_fail)]
fn rejects_a_quotient_outside_its_window() {
    // Shift 100 * q_0 from the residue into the quotient: the relation still holds exactly, but
    // the quotient leaves its window.
    let mut w = toy_witness(37);
    w.quotients[0] += 100;
    w.centered[0] -= 100 * 1009;
    toy_check(w);
}
