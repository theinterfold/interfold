// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! fhe.rs v0.6.0 PRF on native (not centered) power-basis residues, low degree first.
//! C6 must separately authenticate the designated set, ciphertext, and directed key openings.

use crate::math::safe::SafeSponge;

fn domain<let K: u32>(label: [u8; K]) -> [u8; 64] {
    let mut result = [0; 64];
    for i in 0..K {
        result[i] = label[i];
    }
    result
}

pub fn context_digest<let D: u32, let L: u32, let S: u32>(
    ids: [u32; S],
    ct: [[[u64; D]; L]; 2],
    qis: [u64; L],
) -> [Field; 2] {
    let mut input = [0; S + 7 + 2 * L * D];
    input[0] = S as Field;
    for i in 0..S {
        assert(ids[i] > 0);
        if i > 0 {
            assert(ids[i - 1] < ids[i]);
        }
        input[1 + i] = ids[i] as Field;
    }
    // Level zero, two components. Each component carries its own dimensions.
    input[S + 2] = 2;
    for c in 0..2 {
        let start = S + 3 + c * (2 + L * D);
        input[start] = L as Field;
        input[start + 1] = D as Field;
        for l in 0..L {
            for j in 0..D {
                assert(ct[c][l][j] < qis[l]);
                input[start + 2 + l * D + j] = ct[c][l][j] as Field;
            }
        }
    }
    let mut sponge = SafeSponge::start(
        [0x80000000 | input.len(), 2],
        domain("fhe.rs/trbfv/prf/poseidon2/ctx".as_bytes()),
    );
    sponge.absorb(input.as_vector());
    let digest = sponge.squeeze();
    sponge.finish();
    [digest[0], digest[1]]
}

// Divide the canonical integer, not its low u128. Every intermediate fits in u128 for u64 q.
fn divide(x: Field, q: u64) -> (Field, u64) {
    let bytes = x.to_be_bytes::<32>();
    let mut quotient: Field = 0;
    let mut rem: u128 = 0;
    for block in 0..4 {
        let mut limb: u64 = 0;
        for j in 0..8 {
            limb = (limb << 8) | bytes[8 * block + j] as u64;
        }
        let dividend = (rem << 64) | limb as u128;
        quotient = quotient * 0x10000000000000000 + (dividend / q as u128) as Field;
        rem = dividend % q as u128;
    }
    (quotient, rem as u64)
}

unconstrained fn division_hint(x: Field, q: u64) -> (Field, u64) {
    divide(x, q)
}

fn check_division(x: Field, q: u64, k: Field, r: u64, max_k: Field, max_r: u64) {
    // q >= 16 implies floor((p-1)/q) < 2^250. The two range checks order k as integers.
    k.assert_max_bit_size::<250>();
    (max_k - k).assert_max_bit_size::<250>();
    assert(r < q);
    assert((k != max_k) | (r <= max_r));
    assert(k * q as Field + r as Field == x);
}

fn evaluate<let D: u32, let L: u32>(
    digest: [Field; 2],
    key: [u8; 32],
    qis: [u64; L],
) -> [[u64; D]; L] {
    let mut key_field: Field = 0;
    for i in 0..32 {
        key_field = key_field * 256 + key[31 - i] as Field;
    }
    let mut sponge = SafeSponge::start(
        [0x80000003, D * L],
        domain("fhe.rs/trbfv/prf/poseidon2/eval".as_bytes()),
    );
    sponge.absorb([key_field, digest[0], digest[1]].as_vector());
    let fields = sponge.squeeze_after_absorb::<D * L>();
    sponge.finish();
    let mut output = [[0; D]; L];
    for l in 0..L {
        let q = qis[l];
        assert(q >= 16);
        // Moduli are configuration constants: derive trustworthy bounds from p-1 at compile time.
        let (max_k, max_r) = divide(-1, q);
        for j in 0..D {
            let x = fields[l * D + j];
            // Safety: check_division enforces the unique canonical integer quotient and remainder.
            let (k, r) = unsafe { division_hint(x, q) };
            check_division(x, q, k, r, max_k, max_r);
            output[l][j] = r;
        }
    }
    output
}

/// One outgoing and incoming key per other designated party (no self key).
/// The caller selects the keys from its authenticated bundle in canonical peer order.
pub fn mask<let D: u32, let L: u32, let T: u32>(
    ids: [u32; T + 1],
    ct: [[[u64; D]; L]; 2],
    qis: [u64; L],
    outgoing: [[u8; 32]; T],
    incoming: [[u8; 32]; T],
) -> [[u64; D]; L] {
    let digest = context_digest(ids, ct, qis);
    let mut result = [[0; D]; L];
    for peer in 0..T {
        let plus = evaluate::<D, L>(digest, outgoing[peer], qis);
        let minus = evaluate::<D, L>(digest, incoming[peer], qis);
        for l in 0..L {
            let q = qis[l] as u128;
            for j in 0..D {
                let sum = result[l][j] as u128 + plus[l][j] as u128 + q - minus[l][j] as u128;
                result[l][j] = (sum % q) as u64;
            }
        }
    }
    result
}

#[test]
fn upstream_power_basis_vector() {
    // Native power-basis image of fhe.rs v0.6.0's prf_power_basis_reference_vector.
    let ct = [
        [
            [32773, 30856, 63481, 30584, 512, 30584, 63481, 30856],
            [57359, 71196, 49736, 89167, 2645, 89167, 49736, 71196],
        ],
        [
            [32873, 30856, 63481, 30584, 512, 30584, 63481, 30856],
            [57459, 71196, 49736, 89167, 2645, 89167, 49736, 71196],
        ],
    ];
    let qis = [65537, 114689];
    // Intermediate values from hash_context and evaluate at upstream revision 30cce841.
    // A final mask alone cannot detect an additive offset common to every directed evaluation.
    let digest = context_digest([1, 3], ct, qis);
    assert(
        digest
            == [
                20088152587186654272929399470649328022743006688529509912763298427222173028876,
                5933437245317500774475080921417249714714237747176598426729470080254157416880,
            ],
    );
    assert(
        evaluate::<8, 2>(digest, [13; 32], qis)
            == [
                [28869, 61573, 61816, 792, 33670, 37665, 63994, 59389],
                [25578, 22073, 47056, 61866, 67456, 53649, 28931, 98189],
            ],
    );
    assert(
        mask([1, 3], ct, qis, [[13; 32]], [[31; 32]])
            == [
                [52534, 10163, 28151, 52807, 5238, 63673, 55848, 33749],
                [96294, 70599, 3822, 71735, 29132, 20165, 76778, 9623],
            ],
    );
    assert(
        mask([1, 3], ct, qis, [[31; 32]], [[13; 32]])
            == [
                [13003, 55374, 37386, 12730, 60299, 1864, 9689, 31788],
                [18395, 44090, 110867, 42954, 85557, 94524, 37911, 105066],
            ],
    );
}

#[test]
fn canonical_reduction_endpoints() {
    let q: u64 = 65537;
    let (max_k, max_r) = comptime { divide(-1, 65537) };
    check_division(-1, q, max_k, max_r, max_k, max_r);
    check_division(0, q, 0, 0, max_k, max_r);
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn quotient_above_canonical_maximum_is_rejected() {
    let (max_k, max_r) = comptime { divide(-1, 65537) };
    // Even a hint that also has a bad remainder must fail the quotient range check itself.
    check_division(0, 65537, max_k + 1, 65537, max_k, max_r);
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn quotient_must_fit_the_integer_window() {
    let (max_k, max_r) = comptime { divide(-1, 65537) };
    check_division(0, 65537, -1, 65537, max_k, max_r);
}

#[test(should_fail)]
fn canonical_reduction_rejects_p_as_zero() {
    let (max_k, max_r) = comptime { divide(-1, 65537) };
    check_division(0, 65537, max_k, max_r + 1, max_k, max_r);
}
