// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS private-matching validity leg (client-side submission predicate,
//! ParamSet 5). One party's submission is TWO COEFFICIENT-encoded
//! encryptions proven in FIVE legs bound by shared commitments: Greco
//! ct0 + ct1 for the VECTOR ciphertext, Greco ct0 + ct1 for the MASK
//! ciphertext, and this ONE leg, which takes both message polynomials
//! privately, recomputes both `m_commitment`s (same packing width `BIT_M` /
//! domain separator as the ct0 legs — `ckks_app_validity::commit_message`)
//! and proves the layout predicate.
//!
//! ## Coefficient layout (the policy's contract — `matching_score_policy`,
//! `coefficient_layout::{forward, reversed, mask}`)
//!
//! `Polynomial<N>` stores DESCENDING degree: coefficient `k` is
//! `coefficients[N - 1 - k]`. Coefficient encoding at scale `delta` is a
//! direct per-coefficient rounding `c_k = round(delta * v_k)` — no cosine
//! table, no slots.
//!
//! - role 0 (party A): `m_vec = forward(a)`: `a_j` on coefficient `j + 1`
//!   for `j < K`, every other coefficient 0.
//! - role 1 (party B): `m_vec = reversed(b)`: `b_j` on coefficient
//!   `N - j - 1` for `j < K`, every other coefficient 0.
//! - `m_mask = mask(m)`: the integer `m_j in [0, 2^MASK_BITS)` on
//!   coefficient `j + 1` for `j < MASK_WIDTH`, every other coefficient 0
//!   (coefficient 0 is never masked — it is the result).
//!
//! Vector entries are fixed point `v = V / 2^FRAC_BITS` with `|v| <= 1`
//! (cap-normalised by the app; negative words are `p - |V|`). The network
//! opens `relin(forward(a) * reversed(b)) + mask(m_a) + mask(m_b)`;
//! coefficient 0 is `-<a, b>` (the `t^N == -1` wrap — the app negates).
//!
//! ## Windows
//!
//! With `delta = 2^40` and 16 fractional bits `delta * V / 2^16` is an
//! EXACT integer; the check keeps the credit leg's slack pattern (window
//! form, no field division) but because `delta` is a multiple of `2^16`
//! the window pins `c_k` exactly — a one-unit drift is rejected:
//!
//! - vector: `|2^16 * c_k - delta * V_j| <= 2^15 + SLACK`;
//! - mask: `c_k == delta * m_j` (integers — exact).
//!
//! Every live coefficient is range-checked against the ct0 leg's
//! `m_bound` first so the products above never wrap the field.
//!
//! ## Predicate
//!
//! 1. `role in {0, 1}`; `|V_j| <= 2^FRAC_BITS` (`|v_j| <= 1`);
//! 2. `m_vec` is `forward(v)` (role 0) or `reversed(v)` (role 1), every
//!    other coefficient 0;
//! 3. `m_mask` is `mask(m)` with `m_j < 2^MASK_BITS`, every other
//!    coefficient 0;
//! 4. `address` and `index` are free public inputs the on-chain gate binds
//!    to `msg.sender` and to the sender's registered slot (`index == role`
//!    for matching: slot 0 is A, slot 1 is B).
//!
//! Returns `(m_commitment_vec, m_commitment_mask)`.

use crate::core::threshold::ckks_app_validity::commit_message;
use crate::math::polynomial::Polynomial;

/// Vector length every party packs (`k <= 64` in the policy; the demo
/// pins 16 so the leg stays small).
pub global K: u32 = 16;
/// Cross-term mask width: coefficients `1..=MASK_WIDTH` are masked.
pub global MASK_WIDTH: u32 = 128;
/// Mask entries are integers `< 2^MASK_BITS` (`[0, 1024)`).
pub global MASK_BITS: u32 = 10;
/// Fixed-point fractional bits of vector entries (`v = V / 2^16`).
pub global FRAC_BITS: u32 = 16;
/// `2^FRAC_BITS` — the fixed-point one.
pub global FRAC_SCALE: Field = 65536;
/// Half of `FRAC_SCALE` (the rounding half-window).
pub global FRAC_HALF: Field = 32768;
/// Per-coefficient slack of the encoding window.
pub global SLACK: Field = 8;
/// `2 * (2^15 + SLACK) < 2^VEC_WIN_BITS`.
pub global VEC_WIN_BITS: u32 = FRAC_BITS + 1;

/// Parameters of the matching leg (generated per ParamSet by codegen).
pub struct Configs {
    /// The CKKS scale `delta` (exact integer, e.g. `2^40`).
    pub delta: Field,
    /// Symmetric bound on every message coefficient (the ct0 leg's
    /// `m_bound`).
    pub m_bound: Field,
}

impl Configs {
    pub fn new(delta: Field, m_bound: Field) -> Self {
        Configs { delta, m_bound }
    }
}

/// Asserts `|v| <= 2^FRAC_BITS` for a signed field word (`p - |v|` when
/// negative), i.e. `|v / 2^16| <= 1`.
fn assert_entry_range(v: Field) {
    let shifted = v + FRAC_SCALE;
    shifted.assert_max_bit_size::<FRAC_BITS + 2>();
    (2 * FRAC_SCALE - shifted).assert_max_bit_size::<FRAC_BITS + 2>();
}

/// `0 <= diff + half_window <= 2 * half_window` over the integers.
fn assert_window<let WIN_BITS: u32>(diff: Field, half_window: Field) {
    let shifted = diff + half_window;
    shifted.assert_max_bit_size::<WIN_BITS>();
    (2 * half_window - shifted).assert_max_bit_size::<WIN_BITS>();
}

/// `m` is `forward(v)` when `role == 0` and `reversed(v)` when
/// `role == 1`: `v_j = V_j / 2^16` on coefficient `j + 1` (forward) or
/// `N - j - 1` (reversed), all other coefficients 0.
///
/// Both layouts are checked with ONE pass: for every `j < K` the live
/// coefficient is selected by `role` (a boolean), and the complementary
/// position is required to be zero. Coefficients that are dead in BOTH
/// layouts are required to be zero unconditionally.
pub fn check_vector<let N: u32, let BIT_M: u32>(
    configs: Configs,
    m: Polynomial<N>,
    values: [Field; K],
    role: u32,
) {
    assert(role < 2, "role must be 0 (A, forward) or 1 (B, reversed)");
    let is_b: Field = role as Field;
    let is_a: Field = 1 - is_b;
    let mut live: Polynomial<K> = Polynomial::new([0; K]);
    for j in 0..K {
        let fwd = m.coefficients[N - 1 - (j + 1)];
        let rev = m.coefficients[j];
        live.coefficients[j] = is_a * fwd + is_b * rev;
        // The layout the role does NOT use must be empty.
        assert(is_b * fwd == 0, "vector: forward coefficient must be zero for role B");
        assert(is_a * rev == 0, "vector: reversed coefficient must be zero for role A");
    }
    live.range_check_2bounds::<BIT_M>(configs.m_bound, configs.m_bound);
    for j in 0..K {
        // |2^16 * c - delta * V_j| <= 2^15 + SLACK
        let diff = FRAC_SCALE * live.coefficients[j] - configs.delta * values[j];
        assert_window::<VEC_WIN_BITS>(diff, FRAC_HALF + SLACK);
    }
    assert(m.coefficients[N - 1] == 0, "vector: coefficient 0 must be zero");
    for k in K + 1..N - K {
        assert(m.coefficients[N - 1 - k] == 0, "vector: dead coefficient must be zero");
    }
}

/// `m` is `mask(mask)`: the integer `mask_j < 2^MASK_BITS` on coefficient
/// `j + 1`, all other coefficients 0.
pub fn check_mask<let N: u32>(configs: Configs, m: Polynomial<N>, mask: [Field; MASK_WIDTH]) {
    for j in 0..MASK_WIDTH {
        mask[j].assert_max_bit_size::<MASK_BITS>();
        assert(
            m.coefficients[N - 1 - (j + 1)] == configs.delta * mask[j],
            "mask: coefficient is not delta * mask[j]",
        );
    }
    assert(m.coefficients[N - 1] == 0, "mask: coefficient 0 must be zero");
    for k in MASK_WIDTH + 1..N {
        assert(m.coefficients[N - 1 - k] == 0, "mask: tail coefficient must be zero");
    }
}

/// Private-matching validity. Returns `(m_commitment_vec, m_commitment_mask)`.
pub fn matching_validity<let N: u32, let BIT_M: u32>(
    configs: Configs,
    m_vec: Polynomial<N>,
    m_mask: Polynomial<N>,
    values: [Field; K],
    mask: [Field; MASK_WIDTH],
    role: u32,
    _address: Field,
    _index: u32,
) -> (Field, Field) {
    for j in 0..K {
        assert_entry_range(values[j]);
    }
    check_vector::<N, BIT_M>(configs, m_vec, values, role);
    check_mask::<N>(configs, m_mask, mask);
    (commit_message::<N, BIT_M>(m_vec), commit_message::<N, BIT_M>(m_mask))
}

// ---------------------------------------------------------------------
// Tests (N = 512 with the ParamSet-5 constants; the leg has no table so
// the full-size vectors are cheap to build in-test). Pinned against
// `crates/zk-helpers/.../ckks_matching_validity.rs`.
// ---------------------------------------------------------------------

global TEST_N: u32 = 512;
global TEST_DELTA: Field = 1099511627776; // 2^40
global TEST_M_BOUND: Field = 1125899906842625; // 2^40 * 1024 + 1
global TEST_BIT_M: u32 = 51;
global TEST_ADDRESS: Field = 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266;
// [0.5, -0.25, 1.0, -1.0, 0.125, 0, 0.75, -0.5, 0.3, -0.7, 0.9, -0.1, 0.6, 0.2, -0.4, 0.05] * 2^16
global TEST_VALUES: [Field; K] = [
    32768, -16384, 65536, -65536, 8192, 0, 49152, -32768, 19661, -45875, 58982, -6554, 39322, 13107,
    -26214, 3277,
];

fn test_configs() -> Configs {
    Configs::new(TEST_DELTA, TEST_M_BOUND)
}

/// `round(delta * V / 2^16)` for a signed fixed-point word: exact since
/// `delta = 2^40` is a multiple of `2^16`.
fn encoded(v: Field) -> Field {
    v * (TEST_DELTA / FRAC_SCALE)
}

fn test_mask() -> [Field; MASK_WIDTH] {
    let mut m = [0; MASK_WIDTH];
    for j in 0..MASK_WIDTH {
        m[j] = ((j * 37 + 11) % 1024) as Field;
    }
    m
}

fn forward_poly(values: [Field; K]) -> Polynomial<TEST_N> {
    let mut c = [0; TEST_N];
    for j in 0..K {
        c[TEST_N - 1 - (j + 1)] = encoded(values[j]);
    }
    Polynomial::new(c)
}

fn reversed_poly(values: [Field; K]) -> Polynomial<TEST_N> {
    let mut c = [0; TEST_N];
    for j in 0..K {
        // coefficient N - j - 1 lives at index j.
        c[j] = encoded(values[j]);
    }
    Polynomial::new(c)
}

fn mask_poly(mask: [Field; MASK_WIDTH]) -> Polynomial<TEST_N> {
    let mut c = [0; TEST_N];
    for j in 0..MASK_WIDTH {
        c[TEST_N - 1 - (j + 1)] = TEST_DELTA * mask[j];
    }
    Polynomial::new(c)
}

fn run(m_vec: Polynomial<TEST_N>, m_mask: Polynomial<TEST_N>, values: [Field; K], role: u32) -> (Field, Field) {
    matching_validity::<TEST_N, TEST_BIT_M>(
        test_configs(),
        m_vec,
        m_mask,
        values,
        test_mask(),
        role,
        TEST_ADDRESS,
        role,
    )
}

#[test]
fn test_matching_accepts_forward_for_role_a() {
    let (cv, cm) = run(forward_poly(TEST_VALUES), mask_poly(test_mask()), TEST_VALUES, 0);
    assert(cv != cm);
    assert(cv == commit_message::<TEST_N, TEST_BIT_M>(forward_poly(TEST_VALUES)));
    assert(cm == commit_message::<TEST_N, TEST_BIT_M>(mask_poly(test_mask())));
}

#[test]
fn test_matching_accepts_reversed_for_role_b() {
    let (cv, _) = run(reversed_poly(TEST_VALUES), mask_poly(test_mask()), TEST_VALUES, 1);
    assert(cv == commit_message::<TEST_N, TEST_BIT_M>(reversed_poly(TEST_VALUES)));
}

#[test(should_fail)]
fn test_matching_rejects_one_unit_coefficient_drift() {
    // With delta a multiple of 2^16 the window pins c exactly: a one-unit
    // drift moves the scaled residual by 2^16 > 2^15 + SLACK.
    let mut m = forward_poly(TEST_VALUES);
    m.coefficients[TEST_N - 2] += 1;
    let _ = run(m, mask_poly(test_mask()), TEST_VALUES, 0);
}

#[test(should_fail)]
fn test_matching_rejects_forward_for_role_b() {
    let _ = run(forward_poly(TEST_VALUES), mask_poly(test_mask()), TEST_VALUES, 1);
}

#[test(should_fail)]
fn test_matching_rejects_reversed_for_role_a() {
    let _ = run(reversed_poly(TEST_VALUES), mask_poly(test_mask()), TEST_VALUES, 0);
}

#[test(should_fail)]
fn test_matching_rejects_wrong_value() {
    let mut values = TEST_VALUES;
    values[3] += 1;
    let _ = run(forward_poly(TEST_VALUES), mask_poly(test_mask()), values, 0);
}

#[test(should_fail)]
fn test_matching_rejects_entry_above_one() {
    let mut values = TEST_VALUES;
    values[0] = 65537;
    let _ = run(forward_poly(values), mask_poly(test_mask()), values, 0);
}

#[test(should_fail)]
fn test_matching_rejects_hidden_coefficient() {
    let mut m = forward_poly(TEST_VALUES);
    m.coefficients[TEST_N - 1 - 100] = TEST_DELTA;
    let _ = run(m, mask_poly(test_mask()), TEST_VALUES, 0);
}

#[test(should_fail)]
fn test_matching_rejects_nonzero_coefficient_zero() {
    let mut m = forward_poly(TEST_VALUES);
    m.coefficients[TEST_N - 1] = TEST_DELTA;
    let _ = run(m, mask_poly(test_mask()), TEST_VALUES, 0);
}

#[test(should_fail)]
fn test_matching_rejects_mask_out_of_range() {
    let mut mask = test_mask();
    mask[5] = 1024;
    let _ = matching_validity::<TEST_N, TEST_BIT_M>(
        test_configs(),
        forward_poly(TEST_VALUES),
        mask_poly(mask),
        TEST_VALUES,
        mask,
        0,
        TEST_ADDRESS,
        0,
    );
}

#[test(should_fail)]
fn test_matching_rejects_mask_on_coefficient_zero() {
    let mut m = mask_poly(test_mask());
    m.coefficients[TEST_N - 1] = TEST_DELTA;
    let _ = run(forward_poly(TEST_VALUES), m, TEST_VALUES, 0);
}

#[test(should_fail)]
fn test_matching_rejects_invalid_role() {
    let _ = run(forward_poly(TEST_VALUES), mask_poly(test_mask()), TEST_VALUES, 2);
}

#[test(should_fail)]
fn test_matching_rejects_mask_mismatch() {
    let mut mask = test_mask();
    mask[0] += 1;
    let _ = matching_validity::<TEST_N, TEST_BIT_M>(
        test_configs(),
        forward_poly(TEST_VALUES),
        mask_poly(test_mask()),
        TEST_VALUES,
        mask,
        0,
        TEST_ADDRESS,
        0,
    );
}
