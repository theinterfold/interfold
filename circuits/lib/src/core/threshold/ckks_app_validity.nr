// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS application-validity legs (client-side submission predicates).
//!
//! A CKKS submission is proven in THREE legs bound by shared commitments:
//!
//! - `user_data_encryption_ckks_ct0` — Greco ct0 leg, outputs
//!   `(pk0_c, ct0_c, m_commitment, u_commitment)`.
//! - `user_data_encryption_ct1` — Greco ct1 leg, outputs
//!   `(pk1_c, ct1_c, u_commitment)`.
//! - this leg — takes the SAME message polynomial `m` as a private input,
//!   recomputes `m_commitment` with the SAME packing width `BIT_M` and
//!   domain separator as the ct0 leg (so the on-chain gate can equate the
//!   two), and proves the application predicate about the value `m`
//!   encodes.
//!
//! ## Encoding predicate (both apps)
//!
//! Every app encrypts a slot-REPLICATED constant `c = v_raw / cap` (see
//! `ckks_participant --replicate-slots`). For a replicated constant the
//! fhe.rs canonical-embedding encoder
//! (`crates/fhe/src/ckks/encoder.rs`, `encode_with_scale`) produces
//!
//! `m_0 = round(delta * c)` and `m_k = 0` for `k >= 1` (mathematically:
//! the power sums of the primitive `2N`-th roots vanish for `0 < k < N`).
//!
//! In floating point the tail is not exactly zero (|m_k| up to a few tens
//! at delta = 2^40, B = 1000), so this leg checks
//!
//! - `|m_0 * cap - delta * v_raw| <= 2 * cap`  (exact rounding is
//!   `<= cap/2`; the slack absorbs a +-1 rounding flip of the float sum),
//! - `|m_k| <= tail_bound` for every `k >= 1`.
//!
//! Both are sound for the app predicate: the decoded value in EVERY slot
//! is `m_0/delta +- (N-1)*tail_bound/delta`, i.e. `v_raw/cap` up to a
//! negligible error, so a bound proven on `v_raw` holds for the encrypted
//! value and the ciphertext IS slot-replicated (a non-replicated message
//! has a large tail and is rejected).
//!
//! Layout reminder: `Polynomial<N>` stores descending degree, so the
//! constant term `m_0` is `coefficients[N - 1]` and the tail is
//! `coefficients[0 .. N - 1]`.

use crate::math::commitments::compute_single_polynomial_commitment;
use crate::math::commitments::DS_USER_DATA_ENCRYPTION_COMMITMENT;
use crate::math::polynomial::Polynomial;
use binary_merkle_root::binary_merkle_root;
use poseidon::poseidon::bn254::hash_2 as poseidon;

/// Parameters shared by both app legs.
pub struct Configs {
    /// The CKKS scale `delta` (exact integer, e.g. `2^40`).
    pub delta: Field,
    /// Symmetric bound on the constant coefficient `m_0` (the ct0 leg's
    /// `m_bound`). Re-checked here so `m_0 * cap` is a bounded INTEGER
    /// (no field wrap) before the head window is pinned.
    pub m_bound: Field,
    /// Symmetric bound on every non-constant message coefficient.
    pub tail_bound: Field,
}

impl Configs {
    pub fn new(delta: Field, m_bound: Field, tail_bound: Field) -> Self {
        Configs { delta, m_bound, tail_bound }
    }
}

/// Bit width used for the `[0, 2^64)` range checks on values and caps.
global VALUE_BITS: u32 = 64;
/// `4 * cap < 2^(VALUE_BITS + 2)`, the width of the head-check window.
global HEAD_WINDOW_BITS: u32 = VALUE_BITS + 2;

/// Asserts `0 <= x < 2^64`.
fn assert_u64(x: Field) {
    x.assert_max_bit_size::<VALUE_BITS>();
}

/// Asserts `lo <= hi` for two values already known to be `< 2^64`.
fn assert_le_u64(lo: Field, hi: Field) {
    (hi - lo).assert_max_bit_size::<VALUE_BITS>();
}

/// Recomputes the ct0 leg's `m_commitment` (same packing width and
/// domain separator).
pub fn commit_message<let N: u32, let BIT_M: u32>(m: Polynomial<N>) -> Field {
    compute_single_polynomial_commitment::<N, BIT_M>(m, DS_USER_DATA_ENCRYPTION_COMMITMENT)
}

/// Proves that `m` is the slot-replicated encoding of `v_raw / cap`.
///
/// Requires `v_raw < 2^64`, `0 < cap < 2^64`, `|m_0| <= m_bound < 2^BIT_M`
/// with `BIT_M + 64 < 254` so every intermediate is an exact integer.
pub fn check_replicated_encoding<let N: u32, let BIT_M: u32, let BIT_TAIL: u32>(
    configs: Configs,
    m: Polynomial<N>,
    v_raw: Field,
    cap: Field,
) {
    assert_u64(v_raw);
    assert_u64(cap);
    assert(cap != 0, "cap must be nonzero");

    let m0 = m.coefficients[N - 1];
    let head_poly: Polynomial<1> = Polynomial::new([m0]);
    head_poly.range_check_2bounds::<BIT_M>(configs.m_bound, configs.m_bound);

    // Head: |m_0 * cap - delta * v_raw| <= 2 * cap, checked as
    // 0 <= (m_0*cap - delta*v_raw) + 2*cap <= 4*cap over the integers.
    // Both sides are < 2^66, so the two bit-size checks pin the window.
    let head = m0 * cap - configs.delta * v_raw;
    let window = 4 * cap;
    let shifted = head + 2 * cap;
    shifted.assert_max_bit_size::<HEAD_WINDOW_BITS>();
    (window - shifted).assert_max_bit_size::<HEAD_WINDOW_BITS>();

    // Tail: every non-constant coefficient is small.
    let mut tail: Polynomial<N - 1> = Polynomial::new([0; N - 1]);
    for k in 0..N - 1 {
        tail.coefficients[k] = m.coefficients[k];
    }
    tail.range_check_2bounds::<BIT_TAIL>(configs.tail_bound, configs.tail_bound);
}

/// Salary-survey validity: `0 <= salary_raw <= cap` and `m` encodes the
/// replicated `salary_raw / cap`. Returns `m_commitment`.
pub fn salary_validity<let N: u32, let BIT_M: u32, let BIT_TAIL: u32>(
    configs: Configs,
    m: Polynomial<N>,
    salary_raw: Field,
    cap: Field,
) -> Field {
    check_replicated_encoding::<N, BIT_M, BIT_TAIL>(configs, m, salary_raw, cap);
    assert_le_u64(salary_raw, cap);
    commit_message::<N, BIT_M>(m)
}

/// Auction validity: `m` encodes the replicated `bid_raw / cap`,
/// `0 <= bid_raw <= balance`, and `(address, balance)` is a leaf of the
/// balance tree under `merkle_root` (CRISP token-holder model: leaf =
/// `poseidon([address, balance])`). `address` is a public input the
/// on-chain gate equates to `msg.sender`, which is the ownership binding.
/// Returns `m_commitment`.
pub fn auction_validity<let N: u32, let BIT_M: u32, let BIT_TAIL: u32, let MAX_DEPTH: u32>(
    configs: Configs,
    m: Polynomial<N>,
    bid_raw: Field,
    cap: Field,
    balance: Field,
    address: Field,
    merkle_root: Field,
    depth: u32,
    indices: [bool; MAX_DEPTH],
    siblings: [Field; MAX_DEPTH],
) -> Field {
    check_replicated_encoding::<N, BIT_M, BIT_TAIL>(configs, m, bid_raw, cap);

    assert_u64(balance);
    assert_le_u64(bid_raw, balance);

    let leaf = poseidon([address, balance]);
    let root = binary_merkle_root(poseidon, leaf, depth, indices, siblings);
    assert(root == merkle_root, "balance leaf not under the published root");

    commit_message::<N, BIT_M>(m)
}

// ---------------------------------------------------------------------
// Tests (small N so they run fast under `nargo test`).
// ---------------------------------------------------------------------

global TEST_DELTA: Field = 1099511627776; // 2^40
global TEST_M_BOUND: Field = 1099511627776001; // ceil(2^40 * 1000) + 1 (ps2, 50 bits)
global TEST_M_BOUND_PS3: Field = 1099511627777; // ceil(2^40 * 1) + 1 (ps3, 41 bits)

fn test_message<let N: u32>(m0: Field, tail: Field) -> Polynomial<N> {
    let mut coeffs = [tail; N];
    coeffs[N - 1] = m0;
    Polynomial::new(coeffs)
}

#[test]
fn test_salary_accepts_exact_encoding() {
    // 52000 / 100000 at delta 2^40: round(0.52 * 2^40) = 571746046443
    let m: Polynomial<8> = test_message(571746046443, 0);
    let _ = salary_validity::<8, 41, 8>(
        Configs::new(TEST_DELTA, TEST_M_BOUND_PS3, 64),
        m,
        52000,
        100000,
    );
}

#[test]
fn test_salary_accepts_small_tail_and_head_slack() {
    // head off by one, tail at the bound: still accepted.
    let m: Polynomial<8> = test_message(571746046444, 64);
    let _ = salary_validity::<8, 41, 8>(
        Configs::new(TEST_DELTA, TEST_M_BOUND_PS3, 64),
        m,
        52000,
        100000,
    );
}

#[test(should_fail)]
fn test_salary_rejects_over_cap() {
    // 120000 / 100000 = 1.2 -> 1319413953331; encoding is consistent but
    // salary_raw > cap.
    let m: Polynomial<8> = test_message(1319413953331, 0);
    let _ = salary_validity::<8, 41, 8>(
        Configs::new(TEST_DELTA, TEST_M_BOUND, 64),
        m,
        120000,
        100000,
    );
}

#[test(should_fail)]
fn test_salary_rejects_wrong_value_claim() {
    // m encodes 0.52 but the prover claims 0.10.
    let m: Polynomial<8> = test_message(571746046443, 0);
    let _ = salary_validity::<8, 41, 8>(
        Configs::new(TEST_DELTA, TEST_M_BOUND_PS3, 64),
        m,
        10000,
        100000,
    );
}

#[test(should_fail)]
fn test_salary_rejects_non_replicated_tail() {
    let m: Polynomial<8> = test_message(571746046443, 65);
    let _ = salary_validity::<8, 41, 8>(
        Configs::new(TEST_DELTA, TEST_M_BOUND_PS3, 64),
        m,
        52000,
        100000,
    );
}

#[test(should_fail)]
fn test_salary_rejects_negative_value() {
    let m: Polynomial<8> = test_message(-571746046443, 0);
    let _ = salary_validity::<8, 41, 8>(
        Configs::new(TEST_DELTA, TEST_M_BOUND, 64),
        m,
        -52000,
        100000,
    );
}

#[test]
fn test_auction_accepts_leaf_under_root() {
    // Bid 700 (cap 1) with balance 1000; depth-2 tree, zero siblings.
    let address = 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266;
    let balance = 1000;
    let leaf = poseidon([address, balance]);
    let root = poseidon([poseidon([leaf, 0]), 0]);
    let m: Polynomial<8> = test_message(700 * TEST_DELTA, 3);
    let _ = auction_validity::<8, 50, 8, 20>(
        Configs::new(TEST_DELTA, TEST_M_BOUND, 64),
        m,
        700,
        1,
        balance,
        address,
        root,
        2,
        [false; 20],
        [0; 20],
    );
}

#[test(should_fail)]
fn test_auction_rejects_over_balance() {
    let address = 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266;
    let balance = 500;
    let leaf = poseidon([address, balance]);
    let root = poseidon([poseidon([leaf, 0]), 0]);
    let m: Polynomial<8> = test_message(700 * TEST_DELTA, 0);
    let _ = auction_validity::<8, 50, 8, 20>(
        Configs::new(TEST_DELTA, TEST_M_BOUND, 64),
        m,
        700,
        1,
        balance,
        address,
        root,
        2,
        [false; 20],
        [0; 20],
    );
}

#[test(should_fail)]
fn test_auction_rejects_wrong_root() {
    let address = 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266;
    let balance = 1000;
    let leaf = poseidon([address, balance + 1]);
    let root = poseidon([poseidon([leaf, 0]), 0]);
    let m: Polynomial<8> = test_message(700 * TEST_DELTA, 0);
    let _ = auction_validity::<8, 50, 8, 20>(
        Configs::new(TEST_DELTA, TEST_M_BOUND, 64),
        m,
        700,
        1,
        balance,
        address,
        root,
        2,
        [false; 20],
        [0; 20],
    );
}
