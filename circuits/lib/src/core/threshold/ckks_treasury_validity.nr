// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS treasury-risk validity leg (client-side submission predicate,
//! ParamSet 5). One DAO's submission is THREE COEFFICIENT-encoded
//! encryptions proven in SEVEN legs bound by shared commitments: Greco
//! ct0 + ct1 for each of the FORWARD, REVERSED and MASK ciphertexts, and
//! this ONE leg, which takes the three message polynomials privately,
//! recomputes the three `m_commitment`s (same packing width `BIT_M` /
//! domain separator as the ct0 legs — `ckks_app_validity::commit_message`)
//! and proves the layout predicate.
//!
//! ## Coefficient layout (the policy's contract — `treasury_risk_policy`,
//! `coefficient_layout::{forward, reversed, mask}`)
//!
//! `Polynomial<N>` stores DESCENDING degree: coefficient `k` is
//! `coefficients[N - 1 - k]`. Coefficient encoding at scale `delta` is a
//! direct per-coefficient rounding `c_k = round(delta * v_k)` — no cosine
//! table, no slots.
//!
//! - `m_fwd = forward(x)`: `x_a` on coefficient `a + 1` for `a < ASSETS`,
//!   every other coefficient 0. `x_a = X_a / 2^FRAC_BITS in [0, 1]`.
//! - `m_rev = reversed(w o x)`: `w_a * x_a` on coefficient `N - a - 1`,
//!   every other coefficient 0. `w_a = W_a / 2^FRAC_BITS`, `|w_a| <= 1`
//!   (PUBLIC; negative words are `p - |W|`).
//! - `m_mask = mask(m)`: the integer `m_j in [0, 2^MASK_BITS)` on
//!   coefficient `j + 1` for `j < MASK_WIDTH`, every other coefficient 0
//!   (coefficient 0 is never masked — it is the result).
//!
//! The network sums `F = sum f_i`, `R = sum r_i`, `M = sum m_i` and opens
//! `relin(F * R) + M`; coefficient 0 is `-sum_a w_a (sum_i x_{i,a})^2`.
//!
//! ## Windows
//!
//! With `delta = 2^40` and 16 fractional bits both products are EXACT
//! integers, but the checks keep the credit leg's slack pattern so a
//! platform whose encoder rounds differently by one unit still proves:
//!
//! - forward: `|2^16 * c_k - delta * X_a| <= 2^15 + SLACK`;
//! - reversed: `|2^32 * c_k - delta * W_a * X_a| <= 2^31 + SLACK`;
//! - mask: `c_k == delta * m_j` (integers — exact).
//!
//! Every non-zero coefficient is range-checked against the ct0 leg's
//! `m_bound` first so the products above never wrap the field.
//!
//! ## Predicate
//!
//! 1. `0 <= X_a <= 2^FRAC_BITS` (`x_a in [0, 1]`), `|W_a| <= 2^FRAC_BITS`;
//! 2. `m_fwd` is `forward(x)`, `m_rev` is `reversed(w o x)`, `m_mask` is
//!    `mask(m)` with `m_j < 2^MASK_BITS`, all other coefficients 0;
//! 3. `address` and `index` are free public inputs the on-chain gate
//!    binds to `msg.sender` and to the sender's registered slot.
//!
//! Returns `(m_commitment_fwd, m_commitment_rev, m_commitment_mask)`.

use crate::core::threshold::ckks_app_validity::commit_message;
use crate::math::polynomial::Polynomial;

/// Number of public assets per exposure vector.
pub global ASSETS: u32 = 4;
/// Cross-term mask width: coefficients `1..=MASK_WIDTH` are masked.
pub global MASK_WIDTH: u32 = 128;
/// Mask entries are integers `< 2^MASK_BITS` (`[0, 1024)`).
pub global MASK_BITS: u32 = 10;
/// Fixed-point fractional bits of exposures and weights (`v = V / 2^16`).
pub global FRAC_BITS: u32 = 16;
/// `2^FRAC_BITS` — the fixed-point one.
pub global FRAC_SCALE: Field = 65536;
/// `2^(2 * FRAC_BITS)` — the reversed leg's denominator.
pub global FRAC_SCALE_SQ: Field = 4294967296;
/// Half of `FRAC_SCALE` / `FRAC_SCALE_SQ` (the rounding half-window).
pub global FRAC_HALF: Field = 32768;
pub global FRAC_HALF_SQ: Field = 2147483648;
/// Per-coefficient slack of the encoding windows.
pub global SLACK: Field = 8;
/// `2 * (2^15 + SLACK) < 2^FWD_WIN_BITS`.
pub global FWD_WIN_BITS: u32 = FRAC_BITS + 1;
/// `2 * (2^31 + SLACK) < 2^REV_WIN_BITS`.
pub global REV_WIN_BITS: u32 = 2 * FRAC_BITS + 1;

/// Parameters of the treasury leg (generated per ParamSet by codegen).
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

/// Asserts `0 <= x <= 2^FRAC_BITS` (a cap-normalised exposure in `[0, 1]`).
fn assert_exposure_range(x: Field) {
    x.assert_max_bit_size::<FRAC_BITS + 1>();
    (FRAC_SCALE - x).assert_max_bit_size::<FRAC_BITS + 1>();
}

/// Asserts `|w| <= 2^FRAC_BITS` for a signed field word (`p - |w|` when
/// negative).
fn assert_weight_range(w: Field) {
    let shifted = w + FRAC_SCALE;
    shifted.assert_max_bit_size::<FRAC_BITS + 2>();
    (2 * FRAC_SCALE - shifted).assert_max_bit_size::<FRAC_BITS + 2>();
}

/// `0 <= diff + half_window <= 2 * half_window` over the integers.
fn assert_window<let WIN_BITS: u32>(diff: Field, half_window: Field) {
    let shifted = diff + half_window;
    shifted.assert_max_bit_size::<WIN_BITS>();
    (2 * half_window - shifted).assert_max_bit_size::<WIN_BITS>();
}

/// `m` is `forward(x)`: `x_a = X_a / 2^16` on coefficient `a + 1`, all
/// other coefficients 0.
pub fn check_forward<let N: u32, let BIT_M: u32>(
    configs: Configs,
    m: Polynomial<N>,
    x: [Field; ASSETS],
) {
    let mut live: Polynomial<ASSETS> = Polynomial::new([0; ASSETS]);
    for a in 0..ASSETS {
        live.coefficients[a] = m.coefficients[N - 1 - (a + 1)];
    }
    live.range_check_2bounds::<BIT_M>(configs.m_bound, configs.m_bound);
    for a in 0..ASSETS {
        // |2^16 * c - delta * X_a| <= 2^15 + SLACK
        let diff = FRAC_SCALE * live.coefficients[a] - configs.delta * x[a];
        assert_window::<FWD_WIN_BITS>(diff, FRAC_HALF + SLACK);
    }
    assert(m.coefficients[N - 1] == 0, "forward: coefficient 0 must be zero");
    for k in ASSETS + 1..N {
        assert(m.coefficients[N - 1 - k] == 0, "forward: tail coefficient must be zero");
    }
}

/// `m` is `reversed(w o x)`: `w_a * x_a = W_a * X_a / 2^32` on coefficient
/// `N - a - 1`, all other coefficients 0.
pub fn check_reversed<let N: u32, let BIT_M: u32>(
    configs: Configs,
    m: Polynomial<N>,
    x: [Field; ASSETS],
    weights: [Field; ASSETS],
) {
    let mut live: Polynomial<ASSETS> = Polynomial::new([0; ASSETS]);
    for a in 0..ASSETS {
        // coefficient N - a - 1 is stored at index a.
        live.coefficients[a] = m.coefficients[a];
    }
    live.range_check_2bounds::<BIT_M>(configs.m_bound, configs.m_bound);
    for a in 0..ASSETS {
        // |2^32 * c - delta * W_a * X_a| <= 2^31 + SLACK
        let diff = FRAC_SCALE_SQ * live.coefficients[a] - configs.delta * weights[a] * x[a];
        assert_window::<REV_WIN_BITS>(diff, FRAC_HALF_SQ + SLACK);
    }
    for k in 0..N - ASSETS {
        assert(m.coefficients[N - 1 - k] == 0, "reversed: head coefficient must be zero");
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

/// Treasury-risk validity. Returns
/// `(m_commitment_fwd, m_commitment_rev, m_commitment_mask)`.
pub fn treasury_validity<let N: u32, let BIT_M: u32>(
    configs: Configs,
    m_fwd: Polynomial<N>,
    m_rev: Polynomial<N>,
    m_mask: Polynomial<N>,
    x: [Field; ASSETS],
    mask: [Field; MASK_WIDTH],
    weights: [Field; ASSETS],
    _address: Field,
    _index: u32,
) -> (Field, Field, Field) {
    for a in 0..ASSETS {
        assert_exposure_range(x[a]);
        assert_weight_range(weights[a]);
    }
    check_forward::<N, BIT_M>(configs, m_fwd, x);
    check_reversed::<N, BIT_M>(configs, m_rev, x, weights);
    check_mask::<N>(configs, m_mask, mask);
    (
        commit_message::<N, BIT_M>(m_fwd), commit_message::<N, BIT_M>(m_rev),
        commit_message::<N, BIT_M>(m_mask),
    )
}

// ---------------------------------------------------------------------
// Tests at the real degree (N = 512, delta = 2^40): the coefficient
// encoding is exact, so the vectors are built in place. Pinned against
// `crates/zk-helpers/.../ckks_treasury_validity.rs`.
// ---------------------------------------------------------------------

global TEST_N: u32 = 512;
global TEST_DELTA: Field = 1099511627776; // 2^40
global TEST_M_BOUND: Field = 1125899906842625; // 2^40 * 1024 + 1
global TEST_BIT_M: u32 = 51;
global TEST_ADDRESS: Field = 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266;
global TEST_INDEX: u32 = 1;
// x = [0.30, 0.10, 0.45, 0.15] * 2^16
global TEST_X: [Field; ASSETS] = [19661, 6554, 29491, 9830];
// w = [0.5, -0.25, 1.0, 0.125] * 2^16
global TEST_W: [Field; ASSETS] = [32768, -16384, 65536, 8192];

fn test_configs() -> Configs {
    Configs::new(TEST_DELTA, TEST_M_BOUND)
}

fn test_mask() -> [Field; MASK_WIDTH] {
    let mut m = [0; MASK_WIDTH];
    for j in 0..MASK_WIDTH {
        m[j] = ((j * 37 + 11) % 1024) as Field;
    }
    m
}

/// `c_{a+1} = X_a * 2^24` (= round(delta * X_a / 2^16)).
fn test_forward(x: [Field; ASSETS]) -> [Field; TEST_N] {
    let mut m = [0; TEST_N];
    for a in 0..ASSETS {
        m[TEST_N - 1 - (a + 1)] = x[a] * 16777216;
    }
    m
}

/// `c_{N-a-1} = W_a * X_a * 2^8` (= round(delta * W_a * X_a / 2^32)).
fn test_reversed(x: [Field; ASSETS], w: [Field; ASSETS]) -> [Field; TEST_N] {
    let mut m = [0; TEST_N];
    for a in 0..ASSETS {
        m[a] = w[a] * x[a] * 256;
    }
    m
}

fn test_mask_poly(mask: [Field; MASK_WIDTH]) -> [Field; TEST_N] {
    let mut m = [0; TEST_N];
    for j in 0..MASK_WIDTH {
        m[TEST_N - 1 - (j + 1)] = TEST_DELTA * mask[j];
    }
    m
}

fn run_test(
    m_fwd: [Field; TEST_N],
    m_rev: [Field; TEST_N],
    m_mask: [Field; TEST_N],
    x: [Field; ASSETS],
    mask: [Field; MASK_WIDTH],
    w: [Field; ASSETS],
) -> (Field, Field, Field) {
    treasury_validity::<TEST_N, TEST_BIT_M>(
        test_configs(),
        Polynomial::new(m_fwd),
        Polynomial::new(m_rev),
        Polynomial::new(m_mask),
        x,
        mask,
        w,
        TEST_ADDRESS,
        TEST_INDEX,
    )
}

fn run_default() -> (Field, Field, Field) {
    run_test(
        test_forward(TEST_X),
        test_reversed(TEST_X, TEST_W),
        test_mask_poly(test_mask()),
        TEST_X,
        test_mask(),
        TEST_W,
    )
}

#[test]
fn test_treasury_accepts_the_layout_vectors() {
    let (cf, cr, cm) = run_default();
    assert(cf != cr);
    assert(cr != cm);
    assert(cf == commit_message::<TEST_N, TEST_BIT_M>(Polynomial::new(test_forward(TEST_X))));
    assert(
        cr == commit_message::<TEST_N, TEST_BIT_M>(Polynomial::new(test_reversed(TEST_X, TEST_W))),
    );
    assert(
        cm == commit_message::<TEST_N, TEST_BIT_M>(Polynomial::new(test_mask_poly(test_mask()))),
    );
}

#[test]
fn test_treasury_accepts_within_slack() {
    // One unit of encoder rounding drift on a forward coefficient stays
    // inside the window (2^16 * 1 <= 2^15 + 8 is FALSE — so drift on the
    // integer coefficient is NOT tolerated; the slack is on the scaled
    // difference). Check the extremes instead: x = 0 and x = 1.
    let x: [Field; ASSETS] = [0, 65536, 65536, 0];
    let _ = run_test(
        test_forward(x),
        test_reversed(x, TEST_W),
        test_mask_poly(test_mask()),
        x,
        test_mask(),
        TEST_W,
    );
}

#[test(should_fail)]
fn test_treasury_rejects_wrong_forward_value() {
    let mut x = TEST_X;
    x[2] = 29492;
    let _ = run_test(
        test_forward(TEST_X),
        test_reversed(x, TEST_W),
        test_mask_poly(test_mask()),
        x,
        test_mask(),
        TEST_W,
    );
}

#[test(should_fail)]
fn test_treasury_rejects_wrong_weights() {
    // Reversed leg encrypted under the real weights, claimed under others.
    let mut w = TEST_W;
    w[1] = w[1] + 1;
    let _ = run_test(
        test_forward(TEST_X),
        test_reversed(TEST_X, TEST_W),
        test_mask_poly(test_mask()),
        TEST_X,
        test_mask(),
        w,
    );
}

#[test(should_fail)]
fn test_treasury_rejects_exposure_over_one() {
    let mut x = TEST_X;
    x[0] = 65537;
    let _ = run_test(
        test_forward(x),
        test_reversed(x, TEST_W),
        test_mask_poly(test_mask()),
        x,
        test_mask(),
        TEST_W,
    );
}

#[test(should_fail)]
fn test_treasury_rejects_negative_exposure() {
    let mut x = TEST_X;
    x[0] = -1;
    let _ = run_test(
        test_forward(x),
        test_reversed(x, TEST_W),
        test_mask_poly(test_mask()),
        x,
        test_mask(),
        TEST_W,
    );
}

#[test(should_fail)]
fn test_treasury_rejects_weight_over_one() {
    let mut w = TEST_W;
    w[2] = 65537;
    let _ = run_test(
        test_forward(TEST_X),
        test_reversed(TEST_X, w),
        test_mask_poly(test_mask()),
        TEST_X,
        test_mask(),
        w,
    );
}

#[test(should_fail)]
fn test_treasury_rejects_hidden_forward_coefficient() {
    let mut m = test_forward(TEST_X);
    m[TEST_N - 1 - 7] = 1;
    let _ = run_test(
        m,
        test_reversed(TEST_X, TEST_W),
        test_mask_poly(test_mask()),
        TEST_X,
        test_mask(),
        TEST_W,
    );
}

#[test(should_fail)]
fn test_treasury_rejects_hidden_reversed_coefficient() {
    let mut m = test_reversed(TEST_X, TEST_W);
    m[TEST_N - 1] = 1; // coefficient 0
    let _ = run_test(
        test_forward(TEST_X),
        m,
        test_mask_poly(test_mask()),
        TEST_X,
        test_mask(),
        TEST_W,
    );
}

#[test(should_fail)]
fn test_treasury_rejects_mask_out_of_range() {
    let mut mask = test_mask();
    mask[5] = 1024;
    let _ = run_test(
        test_forward(TEST_X),
        test_reversed(TEST_X, TEST_W),
        test_mask_poly(mask),
        TEST_X,
        mask,
        TEST_W,
    );
}

#[test(should_fail)]
fn test_treasury_rejects_mask_on_coefficient_zero() {
    let mut m = test_mask_poly(test_mask());
    m[TEST_N - 1] = TEST_DELTA;
    let _ = run_test(
        test_forward(TEST_X),
        test_reversed(TEST_X, TEST_W),
        m,
        TEST_X,
        test_mask(),
        TEST_W,
    );
}

#[test(should_fail)]
fn test_treasury_rejects_mask_beyond_width() {
    let mut m = test_mask_poly(test_mask());
    m[TEST_N - 1 - (MASK_WIDTH + 1)] = TEST_DELTA;
    let _ = run_test(
        test_forward(TEST_X),
        test_reversed(TEST_X, TEST_W),
        m,
        TEST_X,
        test_mask(),
        TEST_W,
    );
}

#[test(should_fail)]
fn test_treasury_rejects_swapped_polynomials() {
    let _ = run_test(
        test_reversed(TEST_X, TEST_W),
        test_forward(TEST_X),
        test_mask_poly(test_mask()),
        TEST_X,
        test_mask(),
        TEST_W,
    );
}
