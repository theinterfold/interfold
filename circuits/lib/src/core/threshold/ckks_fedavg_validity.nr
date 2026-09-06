// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS private federated-averaging validity leg (client-side submission
//! predicate, ParamSet 5). One client update is TWO encryptions proven in
//! FIVE legs bound by shared commitments: Greco ct0 + ct1 for the
//! GRADIENT ciphertext, Greco ct0 + ct1 for the COUNT ciphertext, and this
//! ONE leg, which takes both message polynomials privately, recomputes
//! both `m_commitment`s (same packing width `BIT_M` / domain separator as
//! the ct0 legs — see `ckks_app_validity::commit_message`) and proves the
//! update predicate.
//!
//! ## Coefficient layout (the policy's contract — `federated_average_policy`)
//!
//! Client `index` encrypts, COEFFICIENT-encoded at scale `delta`
//! (`e3_trckks::policy::coefficient_layout`):
//!
//! - `m_grad = gradient_block(g)`: coefficient `j + 1` = `g_j` for `j < D`,
//!   coefficient `D + 1` = `1.0` (the count marker), every other
//!   coefficient 0. Entries are fixed point: `g_j = G_j / 2^WEIGHT_FRAC_BITS`
//!   with `|G_j| <= 2^WEIGHT_FRAC_BITS` (`|g_j| <= 1`; negative words are
//!   `p - |G|`).
//! - `m_count = constant(n)`: coefficient 0 = `n`, the client's PRIVATE
//!   integer sample count, `1 <= n < 2^COUNT_BITS`; every other
//!   coefficient 0.
//!
//! The network multiplies the two ciphertexts (scalar x vector: no cross
//! terms, no wrap, no masks), sums over clients and opens ONE ciphertext:
//! coefficient `j + 1` = `sum_i n_i g_{i,j}`, coefficient `D + 1` =
//! `sum_i n_i`. The app divides to get the sample-weighted mean.
//!
//! ## Encoding contract (pinned Rust <-> Noir <-> WASM)
//!
//! Coefficient encoding is a direct per-coefficient rounding:
//! `c_k = round(delta * v_k)`. With `v_k = G / 2^16` and `delta = 2^40` the
//! product is the exact integer `2^24 * G`, so the circuit checks, over
//! the integers, `|2^16 * c_k - delta * G_j| <= 2^15 + SLACK` (the
//! half-ulp window of the rounding plus the credit leg's slack pattern;
//! since one ulp of `c_k` is `2^16` in these units the check pins `c_k`
//! EXACTLY at delta = 2^40) on coefficient `j + 1`, `c_{D+1} == delta` exactly, `c_0 == delta * n`
//! exactly on the count message, and every other coefficient `== 0`.
//!
//! ## Predicate
//!
//! 1. `|G_j| <= 2^WEIGHT_FRAC_BITS` for every `j < D`;
//! 2. `sum_j G_j^2 <= norm_bound` over the integers (`norm_bound` is the
//!    round's PUBLIC poisoning bound in `2^32` fixed point, since it bounds
//!    `sum_j g_j^2` whose fixed point is `V^2 / 2^32`);
//! 3. `1 <= count < 2^COUNT_BITS`;
//! 4. `m_grad` is exactly `gradient_block(g)` (within the window above);
//! 5. `m_count` is exactly `constant(count)`;
//! 6. `address` and `index` are public words the on-chain gate equates to
//!    `msg.sender` and to the sender's registered slot (ownership binding).
//!
//! Returns `(m_commitment_grad, m_commitment_count)`.
//!
//! Layout reminder: `Polynomial<N>` stores descending degree, so
//! coefficient `k` is `coefficients[N - 1 - k]`.

use crate::core::threshold::ckks_app_validity::commit_message;
use crate::math::polynomial::Polynomial;

/// Fractional bits of an update entry: `g_j = G_j / 2^WEIGHT_FRAC_BITS`.
pub global WEIGHT_FRAC_BITS: u32 = 16;
/// `2^WEIGHT_FRAC_BITS`.
pub global WEIGHT_FRAC_SCALE: Field = 65536;
/// `|G_j| <= WEIGHT_LIMIT` (`|g_j| <= 1`).
pub global WEIGHT_LIMIT: Field = 65536;
/// Bit width of the shifted entry window `G + WEIGHT_LIMIT in [0, 2 * WEIGHT_LIMIT]`.
pub global WEIGHT_WIN_BITS: u32 = WEIGHT_FRAC_BITS + 2;
/// Fractional bits of the squared-norm bound: `B = norm_bound / 2^NORM_FRAC_BITS`.
pub global NORM_FRAC_BITS: u32 = 32;
/// Bit width the public `norm_bound` (and the squared norm) must fit:
/// `D * 2^32 < 2^NORM_BITS` for every `D <= 62`.
pub global NORM_BITS: u32 = 40;
/// Sample-count width: `1 <= count < 2^COUNT_BITS` (`< 1024`).
pub global COUNT_BITS: u32 = 10;
/// Half-ulp of the coefficient rounding in `2^16 * c - delta * G` units.
pub global HALF_ULP: Field = 32768;
/// Extra slack of the encoding window (credit-leg pattern; the encoding
/// is exact at `delta = 2^40`, so this is margin, not a requirement).
pub global SLACK: Field = 8;
/// `2 * (HALF_ULP + SLACK) < 2^ENC_WIN_BITS`.
pub global ENC_WIN_BITS: u32 = 17;
/// Upper bound on the public slot `index` (a registered-list position).
pub global MAX_INDEX: u32 = 65536;

/// Parameters of the federated-averaging leg (generated per ParamSet by
/// codegen).
pub struct Configs {
    /// The CKKS scale `delta` (exact integer, e.g. `2^40`).
    pub delta: Field,
    /// Symmetric bound on every message coefficient (the ct0 leg's
    /// `m_bound`), re-checked on the entry coefficients so the window
    /// arithmetic is exact.
    pub m_bound: Field,
}

impl Configs {
    pub fn new(delta: Field, m_bound: Field) -> Self {
        Configs { delta, m_bound }
    }
}

/// Asserts `|g| <= WEIGHT_LIMIT` for a signed field word (`p - |g|` when
/// negative).
fn assert_entry_range(g: Field) {
    let shifted = g + WEIGHT_LIMIT;
    shifted.assert_max_bit_size::<WEIGHT_WIN_BITS>();
    (2 * WEIGHT_LIMIT - shifted).assert_max_bit_size::<WEIGHT_WIN_BITS>();
}

/// Checks `|2^16 * c - delta * g| <= HALF_ULP + SLACK` over the integers
/// (`c` already range-checked to `m_bound`, `g` to `WEIGHT_LIMIT`).
fn assert_entry_encoding(delta: Field, c: Field, g: Field) {
    let tol = HALF_ULP + SLACK;
    let shifted = WEIGHT_FRAC_SCALE * c - delta * g + tol;
    shifted.assert_max_bit_size::<ENC_WIN_BITS>();
    (2 * tol - shifted).assert_max_bit_size::<ENC_WIN_BITS>();
}

/// Proves `m` is `gradient_block(g)`: `g_j` on coefficient `j + 1`, `1.0`
/// (`delta`) on coefficient `D + 1`, zero elsewhere.
pub fn check_gradient_block<let N: u32, let BIT_M: u32, let D: u32>(
    configs: Configs,
    m: Polynomial<N>,
    g: [Field; D],
) {
    // The D entry coefficients are the only ones whose value is a
    // window (not an exact equality); bound them so the window is exact.
    let mut entries: Polynomial<D> = Polynomial::new([0; D]);
    for j in 0..D {
        entries.coefficients[j] = m.coefficients[N - 1 - (j + 1)];
    }
    entries.range_check_2bounds::<BIT_M>(configs.m_bound, configs.m_bound);
    for j in 0..D {
        assert_entry_encoding(configs.delta, entries.coefficients[j], g[j]);
    }
    // Coefficient 0 is empty (the count marker lives at D + 1).
    assert(m.coefficients[N - 1] == 0, "gradient block: coefficient 0 must be zero");
    assert(m.coefficients[N - 1 - (D + 1)] == configs.delta, "gradient block: marker must be 1.0");
    for k in D + 2..N {
        assert(m.coefficients[N - 1 - k] == 0, "gradient block: tail must be zero");
    }
}

/// Proves `m` is `constant(count)`: `delta * count` on coefficient 0,
/// zero elsewhere.
pub fn check_constant<let N: u32>(configs: Configs, m: Polynomial<N>, count: Field) {
    assert(
        m.coefficients[N - 1] == configs.delta * count,
        "count: coefficient 0 must be delta * n",
    );
    for k in 1..N {
        assert(m.coefficients[N - 1 - k] == 0, "count: tail must be zero");
    }
}

/// Federated-averaging validity. Returns `(m_commitment_grad, m_commitment_count)`.
pub fn fedavg_validity<let N: u32, let BIT_M: u32, let D: u32>(
    configs: Configs,
    m_grad: Polynomial<N>,
    m_count: Polynomial<N>,
    g: [Field; D],
    count: Field,
    norm_bound: Field,
    address: Field,
    index: u32,
) -> (Field, Field) {
    // `address` is a free public word the chain equates to msg.sender; it
    // only needs to be a 160-bit value there. `index` is bounded so a
    // relayed proof cannot smuggle a huge slot word.
    let _ = address;
    assert(index < MAX_INDEX, "slot index out of range");

    // 1. Entry range and 2. squared norm.
    norm_bound.assert_max_bit_size::<NORM_BITS>();
    let mut norm: Field = 0;
    for j in 0..D {
        assert_entry_range(g[j]);
        norm += g[j] * g[j];
    }
    // norm <= D * 2^32 < 2^NORM_BITS, so the difference check is exact.
    (norm_bound - norm).assert_max_bit_size::<NORM_BITS>();

    // 3. Sample count.
    count.assert_max_bit_size::<COUNT_BITS>();
    assert(count != 0, "sample count must be positive");

    // 4. + 5. Layouts.
    check_gradient_block::<N, BIT_M, D>(configs, m_grad, g);
    check_constant::<N>(configs, m_count, count);

    (commit_message::<N, BIT_M>(m_grad), commit_message::<N, BIT_M>(m_count))
}

// ---------------------------------------------------------------------
// Tests (N = 32, D = 4 so they run fast under `nargo test`). The messages
// are the exact `round(2^40 * G / 2^16) = 2^24 * G` coefficients the
// fhe.rs `encode_coefficients` produces. Pinned against
// `crates/zk-helpers/.../ckks_fedavg_validity.rs`
// (`small_vectors_match_noir_test_vectors`).
// ---------------------------------------------------------------------

global TEST_N: u32 = 32;
global TEST_D: u32 = 4;
global TEST_DELTA: Field = 1099511627776; // 2^40
global TEST_M_BOUND: Field = 1125899906842625; // 2^40 * 1024 + 1
global TEST_BIT_M: u32 = 51;
global TEST_ADDRESS: Field = 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266;
global TEST_INDEX: u32 = 2;
global TEST_COUNT: Field = 137;
// g = [0.5, -0.25, 0.75, -1.0] * 2^16
global TEST_G: [Field; TEST_D] = [32768, -16384, 49152, -65536];
// sum G^2 = 2^30 + 2^28 + 9*2^28 + 2^32 = 8053063680
global TEST_NORM: Field = 8053063680;
global TEST_NORM_BOUND: Field = 8589934592; // 2.0 * 2^32

fn test_configs() -> Configs {
    Configs::new(TEST_DELTA, TEST_M_BOUND)
}

/// `gradient_block(g)` at scale 2^40 in the circuit layout (reversed).
fn test_grad_poly(g: [Field; TEST_D]) -> Polynomial<TEST_N> {
    let mut m = [0; TEST_N];
    for j in 0..TEST_D {
        m[TEST_N - 1 - (j + 1)] = g[j] * 16777216; // 2^24 * G
    }
    m[TEST_N - 1 - (TEST_D + 1)] = TEST_DELTA;
    Polynomial::new(m)
}

/// `constant(count)` at scale 2^40 in the circuit layout.
fn test_count_poly(count: Field) -> Polynomial<TEST_N> {
    let mut m = [0; TEST_N];
    m[TEST_N - 1] = TEST_DELTA * count;
    Polynomial::new(m)
}

fn run_test(
    m_grad: Polynomial<TEST_N>,
    m_count: Polynomial<TEST_N>,
    g: [Field; TEST_D],
    count: Field,
    norm_bound: Field,
) -> (Field, Field) {
    fedavg_validity::<TEST_N, TEST_BIT_M, TEST_D>(
        test_configs(),
        m_grad,
        m_count,
        g,
        count,
        norm_bound,
        TEST_ADDRESS,
        TEST_INDEX,
    )
}

#[test]
fn test_fedavg_accepts_the_encoder_vectors() {
    let (cg, cc) = run_test(
        test_grad_poly(TEST_G),
        test_count_poly(TEST_COUNT),
        TEST_G,
        TEST_COUNT,
        TEST_NORM_BOUND,
    );
    assert(cg != cc);
    assert(cg == commit_message::<TEST_N, TEST_BIT_M>(test_grad_poly(TEST_G)));
    assert(cc == commit_message::<TEST_N, TEST_BIT_M>(test_count_poly(TEST_COUNT)));
}

#[test]
fn test_fedavg_accepts_a_tight_norm_bound() {
    let _ = run_test(
        test_grad_poly(TEST_G),
        test_count_poly(TEST_COUNT),
        TEST_G,
        TEST_COUNT,
        TEST_NORM,
    );
}

#[test]
fn test_fedavg_accepts_the_max_count() {
    let _ = run_test(
        test_grad_poly(TEST_G),
        test_count_poly(1023),
        TEST_G,
        1023,
        TEST_NORM_BOUND,
    );
}

#[test(should_fail)]
fn test_fedavg_rejects_entry_coefficient_off_by_one() {
    // The window is `2^15 + SLACK` in `2^16 * c` units: a whole ulp of `c`
    // (2^16) is outside it, so the encoding is pinned exactly.
    let mut m = test_grad_poly(TEST_G);
    m.coefficients[TEST_N - 2] += 1;
    let _ = run_test(
        m,
        test_count_poly(TEST_COUNT),
        TEST_G,
        TEST_COUNT,
        TEST_NORM_BOUND,
    );
}

#[test(should_fail)]
fn test_fedavg_rejects_over_norm_bound() {
    let _ = run_test(
        test_grad_poly(TEST_G),
        test_count_poly(TEST_COUNT),
        TEST_G,
        TEST_COUNT,
        TEST_NORM - 1,
    );
}

#[test(should_fail)]
fn test_fedavg_rejects_entry_over_one() {
    let mut g = TEST_G;
    g[0] = 65537;
    let _ = run_test(
        test_grad_poly(g),
        test_count_poly(TEST_COUNT),
        g,
        TEST_COUNT,
        1099511627776,
    );
}

#[test(should_fail)]
fn test_fedavg_rejects_wrong_entry_claim() {
    // The message encodes TEST_G but the prover claims a different g_1.
    let mut g = TEST_G;
    g[1] = -16383;
    let _ = run_test(
        test_grad_poly(TEST_G),
        test_count_poly(TEST_COUNT),
        g,
        TEST_COUNT,
        TEST_NORM_BOUND,
    );
}

#[test(should_fail)]
fn test_fedavg_rejects_missing_marker() {
    let mut m = test_grad_poly(TEST_G);
    m.coefficients[TEST_N - 1 - (TEST_D + 1)] = 0;
    let _ = run_test(
        m,
        test_count_poly(TEST_COUNT),
        TEST_G,
        TEST_COUNT,
        TEST_NORM_BOUND,
    );
}

#[test(should_fail)]
fn test_fedavg_rejects_extra_coefficient() {
    let mut m = test_grad_poly(TEST_G);
    m.coefficients[0] = 1;
    let _ = run_test(
        m,
        test_count_poly(TEST_COUNT),
        TEST_G,
        TEST_COUNT,
        TEST_NORM_BOUND,
    );
}

#[test(should_fail)]
fn test_fedavg_rejects_zero_count() {
    let _ = run_test(
        test_grad_poly(TEST_G),
        test_count_poly(0),
        TEST_G,
        0,
        TEST_NORM_BOUND,
    );
}

#[test(should_fail)]
fn test_fedavg_rejects_count_over_1024() {
    let _ = run_test(
        test_grad_poly(TEST_G),
        test_count_poly(1024),
        TEST_G,
        1024,
        TEST_NORM_BOUND,
    );
}

#[test(should_fail)]
fn test_fedavg_rejects_wrong_count_claim() {
    let _ = run_test(
        test_grad_poly(TEST_G),
        test_count_poly(TEST_COUNT),
        TEST_G,
        138,
        TEST_NORM_BOUND,
    );
}

#[test(should_fail)]
fn test_fedavg_rejects_count_tail() {
    let mut m = test_count_poly(TEST_COUNT);
    m.coefficients[TEST_N - 2] = TEST_DELTA;
    let _ = run_test(
        test_grad_poly(TEST_G),
        m,
        TEST_G,
        TEST_COUNT,
        TEST_NORM_BOUND,
    );
}
