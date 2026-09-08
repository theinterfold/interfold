// SPDX-License-Identifier: LGPL-3.0-only
// Shared arithmetic for the secure-8192 circuit paths.
use crate::math::helpers::compute_safe;
use crate::math::polynomial::Polynomial;
use ::bignum::BigNum;
use ::bignum::bignum::to_field;
use ::bignum::SecureThreshold8192;

pub global TH_Q: [Field; 3] = [144115188098531329, 144115188097220609, 144115188094795777];
pub global TH_T: Field = 1000000;
// INTERFOLD_MAX_SUITE_V1. The circuit identifier is also absorbed into each transcript.
pub global DS: [u8; 64] = [
    73, 78, 84, 69, 82, 70, 79, 76, 68, 95, 77, 65, 88, 95, 83, 85, 73, 84, 69, 95, 86, 49, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
];

pub fn parameters<let N: u32, let L: u32>(q: [Field; L]) {
    assert(N == 8192);
    assert(L == 3);
    for l in 0..L {
        assert(q[l] == TH_Q[l]);
    }
}

pub fn range<let B: u32>(v: Field, upper_exclusive: Field) {
    // Both bounds must remain below the native field. Callers pass fixed positive bounds.
    assert(B > 0);
    assert(B <= 192);
    v.assert_max_bit_size::<B>();
    (upper_exclusive - 1 - v).assert_max_bit_size::<B>();
}

// Flags are hints only. check_split proves both the flag and the exact interval.
unconstrained fn flags_hint<let N: u32, let K: u32>(a: [Field; N], offset: Field) -> [Field; N] {
    let mut out = [0; N];
    for j in 0..N {
        out[j] = ((((a[j] + offset) as u128) >> (K as u128)) & 1) as Field;
    }
    out
}

pub fn check_split<let K: u32, let G: u32>(v: Field, gap: Field, flag: Field) {
    assert(K > G);
    assert(K <= 62);
    assert(G > 0);
    gap.assert_max_bit_size::<G>();
    assert(gap != 0);
    flag.assert_max_bit_size::<1>();
    let low = v - flag * 2.pow_32(K as Field);
    low.assert_max_bit_size::<K>();
    (gap - 1 - flag * low).assert_max_bit_size::<G>();
}

pub fn native<let N: u32>(a: Polynomial<N>, q: Field) {
    // Each pinned threshold prime is 2^57 + a positive 25-bit gap.
    assert((q == TH_Q[0]) | (q == TH_Q[1]) | (q == TH_Q[2]));
    // Safety: check_split constrains each flag and the exact native interval.
    let flags = unsafe { flags_hint::<N, 57>(a.coefficients, 0) };
    for j in 0..N {
        check_split::<57, 25>(a.coefficients[j], q - 144115188075855872, flags[j]);
    }
}

pub fn centered<let N: u32>(a: Polynomial<N>, q: Field) {
    assert((q == TH_Q[0]) | (q == TH_Q[1]) | (q == TH_Q[2]));
    let half = (q - 1) / 2;
    // Safety: check_split constrains each flag and the exact centered interval.
    let flags = unsafe { flags_hint::<N, 57>(a.coefficients, half) };
    for j in 0..N {
        check_split::<57, 25>(a.coefficients[j] + half, q - 144115188075855872, flags[j]);
    }
}

// Inputs must already have the respective canonical bounds. Outputs are checked independently.
unconstrained fn centering_flags<let N: u32>(a: [Field; N], q: Field) -> [Field; N] {
    let mut out = [0; N];
    let half = ((q as u64) - 1) / 2;
    for j in 0..N {
        out[j] = ((a[j] as u64) > half) as Field;
    }
    out
}

pub fn native_to_centered<let N: u32>(a: Polynomial<N>, q: Field) -> Polynomial<N> {
    // Safety: boolean flags and canonical output checks fix the representative.
    let flags = unsafe { centering_flags(a.coefficients, q) };
    let mut out = [0; N];
    for j in 0..N {
        flags[j].assert_max_bit_size::<1>();
        out[j] = a.coefficients[j] - q * flags[j];
    }
    let p = Polynomial::new(out);
    centered(p, q);
    p
}

unconstrained fn native_flags<let N: u32>(a: [Field; N], q: Field) -> [Field; N] {
    let mut out = [0; N];
    let half = (q - 1) / 2;
    for j in 0..N {
        out[j] = (((a[j] + half) as u64) < (half as u64)) as Field;
    }
    out
}

pub fn centered_to_native<let N: u32>(a: Polynomial<N>, q: Field) -> Polynomial<N> {
    // Safety: boolean flags and canonical output checks fix the representative.
    let flags = unsafe { native_flags(a.coefficients, q) };
    let mut out = [0; N];
    for j in 0..N {
        flags[j].assert_max_bit_size::<1>();
        out[j] = a.coefficients[j] + q * flags[j];
    }
    let p = Polynomial::new(out);
    native(p, q);
    p
}

pub fn reverse<let N: u32>(p: Polynomial<N>) -> Polynomial<N> {
    let mut out = [0; N];
    for j in 0..N {
        out[j] = p.coefficients[N - 1 - j];
    }
    Polynomial::new(out)
}

// Every digit must already be bounded to [0,2^W). This is challenge-only packing.
pub fn append<let N: u32, let W: u32>(
    mut inputs: [Field],
    p: Polynomial<N>,
    offset: Field,
) -> [Field] {
    assert(W > 0);
    assert(W <= 192);
    let group = 253 / W;
    let radix = 2.pow_32(W as Field);
    let chunks = (N + group - 1) / group;
    for c in 0..chunks {
        let remaining = N - c * group;
        let take = if remaining < group { remaining } else { group };
        let mut acc: Field = 0;
        for j in 0..take {
            acc = acc * radix + p.coefficients[c * group + j] + offset;
        }
        for _ in 0..(group - take) {
            acc = acc * radix + offset;
        }
        inputs = inputs.push_back(acc);
    }
    inputs
}

pub fn challenge(inputs: [Field]) -> Field {
    compute_safe(DS, inputs, [0x80000000 | inputs.len(), 1])[0]
}

// Kernel[j] evaluates X^(N-1-j)*u modulo X^N+1. No product hint is accepted.
pub fn kernel<let N: u32>(u: Polynomial<N>, x: Field) -> [Field; N] {
    assert(N > 0);
    let phi = x.pow_32(N as Field) + 1;
    let mut out = [0; N];
    out[N - 1] = u.eval(x);
    for j in 1..N {
        out[N - 1 - j] = x * out[N - j] - phi * u.coefficients[j - 1];
    }
    out
}

pub fn dot<let N: u32>(a: Polynomial<N>, k: [Field; N]) -> Field {
    let mut out: Field = 0;
    for j in 0..N {
        out += a.coefficients[j] * k[j];
    }
    out
}

pub unconstrained fn divide_u128_hint(x: Field, q: Field) -> Field {
    ((x as u128) / (q as u128)) as Field
}

// This dependency runs ONLY in the hint. Range/equality checks in the caller prove the result.
pub unconstrained fn divide_big_hint(x: Field, q: Field) -> Field {
    to_field(
        SecureThreshold8192::from(x).udiv(&SecureThreshold8192::from(q)),
    )
}

pub fn divisible<let QB: u32>(x: Field, q: Field) {
    // Safety: the quotient bound and integer equality below constrain k.
    let k = unsafe { divide_u128_hint(x, q) };
    k.assert_max_bit_size::<QB>();
    assert(x == q * k);
}

pub fn reduce_small_sum<let N: u32>(a: Polynomial<N>, q: Field) -> Polynomial<N> {
    // Callers bound the sum of at most ten native shares; the rounded carry is <=10.
    let mut out = [0; N];
    let half = (q - 1) / 2;
    for j in 0..N {
        // Safety: the bounded carry and canonical remainder constrain the reduction.
        let k = unsafe { divide_u128_hint(a.coefficients[j] + half, q) };
        k.assert_max_bit_size::<4>();
        out[j] = a.coefficients[j] - q * k;
    }
    let p = Polynomial::new(out);
    centered(p, q);
    p
}

#[test]
fn split_exact_boundaries() {
    check_split::<5, 3>(0, 5, 0);
    check_split::<5, 3>(31, 5, 0);
    check_split::<5, 3>(32, 5, 1);
    check_split::<5, 3>(36, 5, 1);
}
#[test(should_fail)]
fn split_rejects_upper() {
    check_split::<5, 3>(37, 5, 1);
}
#[test(should_fail)]
fn split_rejects_bad_flag() {
    check_split::<5, 3>(32, 5, 0);
}
#[test(should_fail)]
fn split_rejects_negative() {
    check_split::<5, 3>(-1, 5, 0);
}
#[test]
fn centered_roundtrip() {
    let q = TH_Q[0];
    let half = (q - 1) / 2;
    let a = Polynomial::new([0, 1, half, half + 1, q - 1]);
    native(a, q);
    let b = native_to_centered(a, q);
    let c = centered_to_native(b, q);
    assert(a.coefficients == c.coefficients);
}
#[test]
fn kernel_identity() {
    let a = Polynomial::new([4, 3, 2, 1]);
    let u = Polynomial::new([-1, 0, 1, -1]);
    let mut prod = [0; 7];
    for i in 0..4 {
        for j in 0..4 {
            prod[i + j] += a.coefficients[i] * u.coefficients[j];
        }
    }
    let p = Polynomial::new(
        [prod[3], prod[4] - prod[0], prod[5] - prod[1], prod[6] - prod[2]],
    );
    let points: [Field; 4] = [0, 1, 2, 17];
    for j in 0..4 {
        let x = points[j];
        assert(dot(a, kernel(u, x)) == p.eval(x));
    }
}

#[test]
fn small_sum_carry_covers_ten_shares() {
    let q = TH_Q[0];
    let sums = Polynomial::new([0, q, 10 * (q - 1), (q - 1) / 2 + 1]);
    let actual = reduce_small_sum(sums, q);
    assert(actual.coefficients == [0, 0, -10, -(q - 1) / 2]);
}

// Reduce descending-order coefficients modulo X^N + 1.
pub fn fold_negacyclic<let N: u32>(poly: Polynomial<2 * N - 1>) -> Polynomial<N> {
    assert(N >= 2);
    let mut reduced = [0; N];
    reduced[0] = poly.coefficients[N - 1];
    for j in 1..N {
        reduced[j] = poly.coefficients[N - 1 + j] - poly.coefficients[j - 1];
    }
    Polynomial::new(reduced)
}
