// SPDX-License-Identifier: LGPL-3.0-only
// Arithmetic for the secure-8192 share-encryption circuit.
use crate::math::polynomial::Polynomial;
use crate::math::secure_arithmetic::fold_negacyclic;

pub global SECURE_T: Field = 144115188098531329;
pub global SECURE_SCALE: Field = 8200076927336457;
pub global SECURE_Q: [Field; 2] = [576460752303439873, 576460752303702017];
pub global SECURE_K0: [Field; 2] = [240095369310641205, 34620936476510664];
pub global SMALL_D: [Field; 2] = [361693196, 362741772];
pub global ALPHA: [Field; 2] = [3415324443819497, 492478180464660];
pub global BETA: [Field; 2] = [60023842337102902, 8655234120485321];
pub global DELTA: Field = 2305843008852066296;

// C3_MAX_SECURE_V3, padded to the existing SAFE domain-separator size.
pub global DS_C3_MAX_V3: [u8; 64] = [
    67, 51, 95, 77, 65, 88, 95, 83, 69, 67, 85, 82, 69, 95, 86, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
];

// This hint is not trusted. check_near_power_with_flag constrains every consequence.
unconstrained fn high_flag_hint<let K: u32>(x: Field) -> Field {
    (((x as u128) >> (K as u128)) & 1) as Field
}

// Exact interval 0 <= x < 2^K + gap, not an approximate or narrower interval.
// A bad hint cannot satisfy these checks for an out-of-range field element.
pub fn check_near_power_with_flag<let K: u32, let GAP_BITS: u32>(
    x: Field,
    gap: Field,
    flag: Field,
) {
    assert(K > 0);
    assert(K <= 62);
    assert(GAP_BITS > 0);
    assert(GAP_BITS < K);
    gap.assert_max_bit_size::<GAP_BITS>();
    assert(gap != 0);
    flag.assert_max_bit_size::<1>();
    let low = x - flag * 2.pow_32(K as Field);
    low.assert_max_bit_size::<K>();
    (gap - 1 - flag * low).assert_max_bit_size::<GAP_BITS>();
}

pub fn check_near_power<let K: u32, let GAP_BITS: u32>(x: Field, gap: Field) {
    // Safety: check_near_power_with_flag constrains the flag and exact interval.
    let flag = unsafe { high_flag_hint::<K>(x) };
    check_near_power_with_flag::<K, GAP_BITS>(x, gap, flag);
}

// Batch hint generation avoids one unconstrained call for every coefficient.
unconstrained fn high_flags_hint<let N: u32, let K: u32>(
    values: [Field; N],
    offset: Field,
) -> [Field; N] {
    let mut flags = [0; N];
    for j in 0..N {
        flags[j] = ((((values[j] + offset) as u128) >> (K as u128)) & 1) as Field;
    }
    flags
}

pub fn canonical_poly<let N: u32, let GAP_BITS: u32>(poly: Polynomial<N>, q: Field) {
    let gap = q - 576460752303423488; // 2^59
    let half = (q - 1) / 2;
    // Safety: each flag is checked with its shifted coefficient below.
    let flags = unsafe { high_flags_hint::<N, 59>(poly.coefficients, half) };
    for j in 0..N {
        check_near_power_with_flag::<59, GAP_BITS>(poly.coefficients[j] + half, gap, flags[j]);
    }
}

pub fn canonical_message<let N: u32>(message: Polynomial<N>) {
    // Safety: each flag is checked with its message coefficient below.
    let flags = unsafe { high_flags_hint::<N, 57>(message.coefficients, 0) };
    for j in 0..N {
        check_near_power_with_flag::<57, 25>(message.coefficients[j], 22675457, flags[j]);
    }
}

// All arithmetic in this hint fits u128 for the pinned secure parameters.
// The range and centered remainder checks below determine its unique correct value.
unconstrained fn rounding_hint(message: Field) -> Field {
    let m = message as u128;
    let scale = SECURE_SCALE as u128;
    let t = SECURE_T as u128;
    ((scale * m + t / 2) / t) as Field
}

// Caller must also constrain message to [0, SECURE_T).
pub fn check_rounding(message: Field, z: Field) {
    z.assert_max_bit_size::<53>();
    let centered_shifted = SECURE_SCALE * message - SECURE_T * z + (SECURE_T - 1) / 2;
    check_near_power::<57, 25>(centered_shifted, 22675457);
}

unconstrained fn rounding_batch_hint<let N: u32>(message: [Field; N]) -> ([Field; N], [Field; N]) {
    let mut z = [0; N];
    let mut flags = [0; N];
    for j in 0..N {
        z[j] = rounding_hint(message[j]);
        let shifted = SECURE_SCALE * message[j] - SECURE_T * z[j] + (SECURE_T - 1) / 2;
        flags[j] = (((shifted as u128) >> 57) & 1) as Field;
    }
    (z, flags)
}

pub fn rounding_carries<let N: u32>(message: Polynomial<N>) -> Polynomial<N> {
    // Safety: the carry bound and centered remainder checks fix every rounded value.
    let (z, flags) = unsafe { rounding_batch_hint(message.coefficients) };
    for j in 0..N {
        z[j].assert_max_bit_size::<53>();
        let shifted = SECURE_SCALE * message.coefficients[j] - SECURE_T * z[j] + (SECURE_T - 1) / 2;
        check_near_power_with_flag::<57, 25>(shifted, 22675457, flags[j]);
    }
    Polynomial::new(z)
}

// Every digit must already be constrained to [0, 2^WIDTH).
// Padding is fixed; at most 253 bits fit below the BN254 scalar modulus.
// This encoding is used ONLY inside the new C3 challenge, not public commitments.
pub fn append_offset<let N: u32, let WIDTH: u32>(
    mut inputs: [Field],
    poly: Polynomial<N>,
    offset: Field,
) -> [Field] {
    assert(WIDTH > 0);
    assert(WIDTH <= 62);
    let group = 253 / WIDTH;
    let radix = 2.pow_32(WIDTH as Field);
    let chunks = (N + group - 1) / group;
    for chunk in 0..chunks {
        let remain = N - chunk * group;
        let take = if remain < group { remain } else { group };
        let mut carrier: Field = 0;
        for j in 0..take {
            carrier = carrier * radix + poly.coefficients[chunk * group + j] + offset;
        }
        for _ in 0..(group - take) {
            carrier = carrier * radix + offset;
        }
        inputs = inputs.push_back(carrier);
    }
    inputs
}

// Kernel[j] = (X^(N-1-j) * u mod (X^N+1))(x).
// Compute it in the constrained circuit once and reuse it for all four products.
pub fn product_kernel<let N: u32>(u: Polynomial<N>, x: Field, phi: Field) -> [Field; N] {
    assert(N >= 2);
    let mut kernel = [0; N];
    kernel[N - 1] = u.eval(x);
    for j in 1..N {
        kernel[N - 1 - j] = x * kernel[N - j] - phi * u.coefficients[j - 1];
    }
    kernel
}

pub fn product_dot<let N: u32>(a: Polynomial<N>, kernel: [Field; N]) -> Field {
    let mut out: Field = 0;
    for j in 0..N {
        out += a.coefficients[j] * kernel[j];
    }
    out
}

#[test]
fn near_power_boundaries() {
    // Upper bound 2^5+5=37. Both sides of the split and the inclusive last value are valid.
    check_near_power::<5, 3>(0, 5);
    check_near_power::<5, 3>(31, 5);
    check_near_power::<5, 3>(32, 5);
    check_near_power::<5, 3>(36, 5);
    check_near_power::<57, 25>(SECURE_T - 1, 22675457);
}
#[test(should_fail)]
fn near_power_rejects_upper() {
    check_near_power::<5, 3>(37, 5);
}
#[test(should_fail)]
fn near_power_rejects_negative() {
    check_near_power::<5, 3>(-1, 5);
}
#[test(should_fail)]
fn near_power_rejects_forged_flag() {
    check_near_power_with_flag::<5, 3>(33, 5, 0);
}
#[test(should_fail)]
fn near_power_rejects_nonboolean_flag() {
    check_near_power_with_flag::<5, 3>(33, 5, 2);
}
#[test]
fn rounding_endpoints() {
    check_rounding(0, 0);
    check_rounding(SECURE_T - 1, SECURE_SCALE);
}
#[test(should_fail)]
fn rounding_rejects_increment() {
    check_rounding(0, 1);
}
#[test(should_fail)]
fn rounding_rejects_decrement() {
    check_rounding(SECURE_T - 1, SECURE_SCALE - 1);
}
#[test]
fn secure_constant_identities() {
    assert(DELTA * SECURE_T + SECURE_SCALE == SECURE_Q[0] * SECURE_Q[1]);
    for l in 0..2 {
        assert(SMALL_D[l] == 4 * SECURE_Q[l] - DELTA);
        assert(SECURE_K0[l] * SECURE_T + 1 == BETA[l] * SECURE_Q[l]);
        assert(SECURE_K0[l] * SECURE_SCALE + SMALL_D[l] == ALPHA[l] * SECURE_Q[l]);
    }
}
#[test]
fn kernel_matches_independent_polynomial_product() {
    let a = Polynomial::new([4, 3, 2, 1]);
    let u = Polynomial::new([-1, 0, 1, -1]);
    let mut product = [0; 7];
    for i in 0..4 {
        for j in 0..4 {
            product[i + j] += a.coefficients[i] * u.coefficients[j];
        }
    }
    let reference = fold_negacyclic::<4>(Polynomial::new(product));
    let points: [Field; 5] = [0, 1, -1, 2, 17];
    for i in 0..5 {
        let x = points[i];
        assert(product_dot(a, product_kernel(u, x, x.pow_32(4) + 1)) == reference.eval(x));
    }
}
#[test]
fn packed_digit_order() {
    let p = Polynomial::new([-1, 0, 1]);
    let out = append_offset::<3, 2>([].as_vector(), p, 1);
    let mut reference: Field = (0 * 4 + 1) * 4 + 2;
    for _ in 0..123 {
        reference = reference * 4 + 1;
    }
    assert(out.len() == 1);
    assert(out[0] == reference);
}

#[test]
fn batch_rounding_and_message_endpoints() {
    let message = Polynomial::new([0, 1, (SECURE_T - 1) / 2, SECURE_T - 2, SECURE_T - 1]);
    canonical_message(message);
    let z = rounding_carries(message);
    for j in 0..5 {
        check_rounding(message.coefficients[j], z.coefficients[j]);
    }
}
