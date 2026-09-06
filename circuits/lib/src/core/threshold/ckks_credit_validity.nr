// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS private-credit-scoring v2 validity leg (client-side submission
//! predicate). A credit application is TWO encryptions proven in FIVE
//! legs bound by shared commitments: Greco ct0 + ct1 for the LOGIT
//! ciphertext, Greco ct0 + ct1 for the MASK ciphertext, and this ONE
//! leg, which takes both message polynomials privately, recomputes both
//! `m_commitment`s (same packing width `BIT_M` / domain separator as the
//! ct0 legs — see `ckks_app_validity::commit_message`) and proves the
//! application predicate.
//!
//! ## Slot layout (the policy's contract — `credit_sigmoid_policy`)
//!
//! Applicant `index` encrypts, SLOT-encoded at scale `delta`:
//!
//! - `m_z`: slot `index` = `z = <w, x>/cap + b` (the PUBLIC model's
//!   logit over the applicant's Merkle-attested features), every other
//!   slot 0. Weights and bias are fixed point: `w_j = weights[j] /
//!   2^WEIGHT_FRAC_BITS` with `|weights[j]| <= 2^WEIGHT_MAG_BITS`
//!   (negative words are `p - |W|`), likewise `bias`.
//! - `m_m`: slot `index` = `m = mask / 2^MASK_FRAC_BITS in [0, 1024)`,
//!   the applicant's OUTPUT mask, every other slot 0.
//!
//! The network computes `sigma(z_i) + m_i` in slot `i` (two ct x ct
//! products under the committee's relin keys); the applicant unmasks.
//!
//! ## Encoding contract (pinned Rust <-> Noir <-> WASM)
//!
//! For one non-zero slot the canonical-embedding encoder gives, for
//! every `k < N`, `m_k = round(delta * (2/N) * v * cos(pi * e * k / N))`
//! with `e = 5^index mod 2N`. With `v = V / D` (integer numerator over
//! integer denominator) and the fixed-point table `C_t = round(2^COS_FRAC_BITS
//! * cos(pi * t / N))`, the circuit checks, over the integers,
//!
//! `|Q * m_k - 2 * delta * V * C_{(e*k) mod 2N}| <= SLACK * Q`,
//! `Q = N * D * 2^COS_FRAC_BITS`,
//!
//! for EVERY coefficient. `SLACK = 8` covers 1/2 from the encoder's
//! rounding, `|v|/N` from the table quantisation (`|v| < 1024`,
//! `N = 512` → 2) and a 1-ulp platform `cos` difference. Pinning all
//! `N` coefficients against ONE declared slot value forces every other
//! slot to 0 (a residual of `<= 8` per coefficient decodes to
//! `< 8N / delta ≈ 2^-28` in any slot).
//!
//! ## Predicate
//!
//! 1. `0 < cap < 2^CAP_BITS`, `features[j] <= cap`;
//! 2. `|weights[j]|, |bias| <= 2^WEIGHT_MAG_BITS`; `mask < 2^MASK_BITS`;
//!    `index < N/2`;
//! 3. `|m_k| <= m_bound` for both messages (the ct0 legs' bound, re-checked
//!    so every product below is an exact integer);
//! 4. `m_z` is the slot-`index` encoding of `(sum_j weights[j] * features[j]
//!    + bias * cap) / (2^WEIGHT_FRAC_BITS * cap)` within `SLACK`;
//! 5. `m_m` is the slot-`index` encoding of `mask / 2^MASK_FRAC_BITS`
//!    within `SLACK`;
//! 6. `poseidon([address, x_0, .., x_7])` is a leaf under `merkle_root`
//!    (issuer snapshot; `address` is a public input the on-chain gate
//!    equates to `msg.sender` — the ownership binding; `index` is the
//!    applicant's position in the round's registered list).
//!
//! Returns `(m_commitment_z, m_commitment_m)`.
//!
//! Layout reminder: `Polynomial<N>` stores descending degree, so `m_k` is
//! `coefficients[N - 1 - k]`.

use crate::core::threshold::ckks_app_validity::commit_message;
use crate::math::polynomial::Polynomial;
use binary_merkle_root::binary_merkle_root;
use poseidon::poseidon::bn254::{hash_2, hash_9};

/// Number of issuer-attested features.
pub global FEATURES: u32 = 8;
/// Fractional bits of the output mask: `m = mask / 2^MASK_FRAC_BITS`.
pub global MASK_FRAC_BITS: u32 = 10;
/// Total mask width: `mask < 2^MASK_BITS`, i.e. `m in [0, 1024)`.
pub global MASK_BITS: u32 = 20;
/// Fractional bits of a weight / the bias.
pub global WEIGHT_FRAC_BITS: u32 = 16;
/// `|weights[j]| <= 2^WEIGHT_MAG_BITS` (`|w_j| <= 8`).
pub global WEIGHT_MAG_BITS: u32 = WEIGHT_FRAC_BITS + 3;
/// Bit width of `cap` and every feature numerator.
pub global CAP_BITS: u32 = 32;
/// Fixed-point bits of the cosine table.
pub global COS_FRAC_BITS: u32 = 40;
/// Per-coefficient slack of the encoding check, in units of `Q`.
pub global SLACK: Field = 8;
/// `log2(N)` of the pinned degree (`N = 512`).
pub global LOG_N: u32 = 9;
/// Window bits of the logit check: `2 * SLACK * Q < 2^LOGIT_WIN_BITS` with
/// `Q = N * 2^WEIGHT_FRAC_BITS * cap * 2^COS_FRAC_BITS`.
pub global LOGIT_WIN_BITS: u32 = LOG_N + WEIGHT_FRAC_BITS + CAP_BITS + COS_FRAC_BITS + 5;
/// Window bits of the mask check: `2 * SLACK * Q < 2^MASK_WIN_BITS` with
/// `Q = N * 2^MASK_FRAC_BITS * 2^COS_FRAC_BITS`.
pub global MASK_WIN_BITS: u32 = LOG_N + MASK_FRAC_BITS + COS_FRAC_BITS + 5;
/// `2^WEIGHT_FRAC_BITS`.
pub global WEIGHT_FRAC_SCALE: Field = 65536;
/// `2^WEIGHT_MAG_BITS`.
pub global WEIGHT_MAG_LIMIT: Field = 524288;
/// `2^MASK_FRAC_BITS`.
pub global MASK_FRAC_SCALE: Field = 1024;
/// `2^COS_FRAC_BITS`.
pub global COS_SCALE: Field = 1099511627776;

/// Parameters of the credit leg (generated per ParamSet by codegen).
pub struct Configs<let N: u32> {
    /// The CKKS scale `delta` (exact integer, e.g. `2^40`).
    pub delta: Field,
    /// Symmetric bound on every message coefficient (the ct0 leg's
    /// `m_bound`).
    pub m_bound: Field,
    /// `round(2^COS_FRAC_BITS * cos(pi * t / N))` for `t in 0..2N`.
    pub cos: [Field; 2 * N],
    /// `5^i mod 2N` for `i in 0..N/2` (the slot exponents).
    pub exp5: [u32; N / 2],
}

impl<let N: u32> Configs<N> {
    pub fn new(delta: Field, m_bound: Field, cos: [Field; 2 * N], exp5: [u32; N / 2]) -> Self {
        Configs { delta, m_bound, cos, exp5 }
    }
}

/// Asserts `0 <= x < 2^CAP_BITS`.
fn assert_cap_range(x: Field) {
    x.assert_max_bit_size::<CAP_BITS>();
}

/// Asserts `|w| <= 2^WEIGHT_MAG_BITS` for a signed field word
/// (`p - |w|` when negative).
fn assert_weight_range(w: Field) {
    let shifted = w + WEIGHT_MAG_LIMIT;
    shifted.assert_max_bit_size::<WEIGHT_MAG_BITS + 2>();
    (2 * WEIGHT_MAG_LIMIT - shifted).assert_max_bit_size::<WEIGHT_MAG_BITS + 2>();
}

/// Checks that `m` is the slot-`index` encoding of `numerator /
/// denominator` (every other slot 0) within `SLACK` — the integer
/// window above, for EVERY coefficient.
///
/// Requires `BIT_M + log2(Q) + 2 < 254` and `2 * SLACK * Q < 2^WIN_BITS`
/// so every product is an exact integer and the two bit-size checks pin
/// the window.
pub fn check_slot_encoding<let N: u32, let BIT_M: u32, let WIN_BITS: u32>(
    configs: Configs<N>,
    m: Polynomial<N>,
    numerator: Field,
    denominator: Field,
    index: u32,
) {
    m.range_check_2bounds::<BIT_M>(configs.m_bound, configs.m_bound);
    assert(index < N / 2, "slot index out of range");

    let q = (N as Field) * denominator * COS_SCALE;
    let two_delta_v = 2 * configs.delta * numerator;
    let slack = SLACK * q;
    let window = 2 * slack;
    let e = configs.exp5[index];
    let mut t: u32 = 0;
    for k in 0..N {
        let m_k = m.coefficients[N - 1 - k];
        // 0 <= Q*m_k - 2*delta*V*C_t + SLACK*Q <= 2*SLACK*Q
        let shifted = q * m_k - two_delta_v * configs.cos[t] + slack;
        shifted.assert_max_bit_size::<WIN_BITS>();
        (window - shifted).assert_max_bit_size::<WIN_BITS>();
        t = (t + e) % (2 * N);
    }
}

/// Credit-scoring v2 validity. Returns `(m_commitment_z, m_commitment_m)`.
pub fn credit_validity<let N: u32, let BIT_M: u32, let MAX_DEPTH: u32>(
    configs: Configs<N>,
    m_z: Polynomial<N>,
    m_m: Polynomial<N>,
    features: [Field; FEATURES],
    depth: u32,
    indices: [bool; MAX_DEPTH],
    siblings: [Field; MAX_DEPTH],
    mask: Field,
    cap: Field,
    address: Field,
    merkle_root: Field,
    index: u32,
    weights: [Field; FEATURES],
    bias: Field,
) -> (Field, Field) {
    assert_cap_range(cap);
    assert(cap != 0, "cap must be nonzero");
    for j in 0..FEATURES {
        assert_cap_range(features[j]);
        assert_cap_range(cap - features[j]);
        assert_weight_range(weights[j]);
    }
    assert_weight_range(bias);
    mask.assert_max_bit_size::<MASK_BITS>();

    // Logit: slot `index` = (sum_j W_j x_j + B * cap) / (2^16 * cap).
    let mut z_num = bias * cap;
    for j in 0..FEATURES {
        z_num += weights[j] * features[j];
    }
    check_slot_encoding::<N, BIT_M, LOGIT_WIN_BITS>(
        configs,
        m_z,
        z_num,
        cap * WEIGHT_FRAC_SCALE,
        index,
    );
    // Mask: slot `index` = mask / 2^10.
    check_slot_encoding::<N, BIT_M, MASK_WIN_BITS>(configs, m_m, mask, MASK_FRAC_SCALE, index);

    let leaf = hash_9([
        address,
        features[0],
        features[1],
        features[2],
        features[3],
        features[4],
        features[5],
        features[6],
        features[7],
    ]);
    let root = binary_merkle_root(hash_2, leaf, depth, indices, siblings);
    assert(root == merkle_root, "feature leaf not under the published root");

    (commit_message::<N, BIT_M>(m_z), commit_message::<N, BIT_M>(m_m))
}

// ---------------------------------------------------------------------
// Tests (N = 32 so they run fast under `nargo test`). The messages are
// `round(2^40 * (2/32) * v * cos(pi * e * k / 32))` with `e = 5^2 mod 64
// = 25` for v = z = 10753580 / (1000 * 2^16) (the demo model over
// features [520, 130, 350, 999, 0, 1, 777, 42], cap 1000) and
// v = 205312 / 2^10 = 200.5 (a mask small enough that the N = 32 table
// quantisation `|v|/N` stays inside SLACK; at N = 512 the full range
// does). Pinned against `crates/zk-helpers/.../ckks_credit_validity.rs`
// (`small_tables_match_noir_test_vectors`).
// ---------------------------------------------------------------------

global TEST_N: u32 = 32;
global TEST_DELTA: Field = 1099511627776; // 2^40
global TEST_M_BOUND: Field = 1125899906842625; // 2^40 * 1024 + 1
global TEST_BIT_M: u32 = 51;
global TEST_ADDRESS: Field = 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266;
global TEST_FEATURES: [Field; FEATURES] = [520, 130, 350, 999, 0, 1, 777, 42];
global TEST_CAP: Field = 1000;
global TEST_INDEX: u32 = 2;
global TEST_MASK: Field = 205312; // 200.5
// [1.7, -2.3, 0.9, 0.4, -1.1, 2.6, -0.5, 1.2] * 2^16, bias -0.8 * 2^16.
global TEST_WEIGHTS: [Field; FEATURES] =
    [111411, -150733, 58982, 26214, -72090, 170394, -32768, 78643];
global TEST_BIAS: Field = -52429;
global TEST_COS: [Field; 2 * TEST_N] = [
    1099511627776,
    1094217178761,
    1078384820155,
    1052167026225,
    1015816288660,
    969682684934,
    914210506869,
    849933981865,
    777472127994,
    697522792521,
    610855931251,
    518306193436,
    420764883643,
    319171378006,
    214504077523,
    107770985514,
    0,
    -107770985514,
    -214504077523,
    -319171378006,
    -420764883643,
    -518306193436,
    -610855931251,
    -697522792521,
    -777472127994,
    -849933981865,
    -914210506869,
    -969682684934,
    -1015816288660,
    -1052167026225,
    -1078384820155,
    -1094217178761,
    -1099511627776,
    -1094217178761,
    -1078384820155,
    -1052167026225,
    -1015816288660,
    -969682684934,
    -914210506869,
    -849933981865,
    -777472127994,
    -697522792521,
    -610855931251,
    -518306193436,
    -420764883643,
    -319171378006,
    -214504077523,
    -107770985514,
    0,
    107770985514,
    214504077523,
    319171378006,
    420764883643,
    518306193436,
    610855931251,
    697522792521,
    777472127994,
    849933981865,
    914210506869,
    969682684934,
    1015816288660,
    1052167026225,
    1078384820155,
    1094217178761,
];
global TEST_EXP5: [u32; TEST_N / 2] = [1, 5, 25, 61, 49, 53, 9, 45, 33, 37, 57, 29, 17, 21, 41, 13];
// m_k for k = 0..32 (natural order); the polynomial stores them reversed.
global TEST_MZ: [Field; TEST_N] = [
    11275945902,
    -8716424054,
    2199827917,
    5315444103,
    -10417615629,
    10790407457,
    -6264579892,
    -1105235972,
    7973297812,
    -11221649141,
    9375606368,
    -3273234317,
    -4315117681,
    9944496467,
    -11059281763,
    7153384353,
    0,
    -7153384353,
    11059281763,
    -9944496467,
    4315117681,
    3273234317,
    -9375606368,
    11221649141,
    -7973297812,
    1105235972,
    6264579892,
    -10790407457,
    10417615629,
    -5315444103,
    -2199827917,
    8716424054,
];
global TEST_MM: [Field; TEST_N] = [
    13778255085568,
    -10650735210242,
    2688004221464,
    6495024486493,
    -12729447867276,
    13184968047387,
    -7654788388493,
    -1350505162219,
    9742697603923,
    -13711909021351,
    11456200414203,
    -3999616330644,
    -5272709948147,
    12151336145578,
    -13513509777566,
    8740832493778,
    0,
    -8740832493778,
    13513509777566,
    -12151336145578,
    5272709948147,
    3999616330644,
    -11456200414203,
    13711909021351,
    -9742697603923,
    1350505162219,
    7654788388493,
    -13184968047387,
    12729447867276,
    -6495024486493,
    -2688004221464,
    10650735210242,
];

fn test_configs() -> Configs<TEST_N> {
    Configs::new(TEST_DELTA, TEST_M_BOUND, TEST_COS, TEST_EXP5)
}

fn test_poly(natural: [Field; TEST_N]) -> [Field; TEST_N] {
    let mut m = [0; TEST_N];
    for k in 0..TEST_N {
        m[TEST_N - 1 - k] = natural[k];
    }
    m
}

fn test_root(features: [Field; FEATURES]) -> Field {
    let leaf = hash_9([
        TEST_ADDRESS,
        features[0],
        features[1],
        features[2],
        features[3],
        features[4],
        features[5],
        features[6],
        features[7],
    ]);
    hash_2([hash_2([leaf, 0]), 0])
}

fn run_test(
    m_z: [Field; TEST_N],
    m_m: [Field; TEST_N],
    features: [Field; FEATURES],
    root: Field,
    mask: Field,
    index: u32,
    weights: [Field; FEATURES],
) -> (Field, Field) {
    credit_validity::<TEST_N, TEST_BIT_M, 20>(
        test_configs(),
        Polynomial::new(m_z),
        Polynomial::new(m_m),
        features,
        2,
        [false; 20],
        [0; 20],
        mask,
        TEST_CAP,
        TEST_ADDRESS,
        root,
        index,
        weights,
        TEST_BIAS,
    )
}

fn run_default() -> (Field, Field) {
    run_test(
        test_poly(TEST_MZ),
        test_poly(TEST_MM),
        TEST_FEATURES,
        test_root(TEST_FEATURES),
        TEST_MASK,
        TEST_INDEX,
        TEST_WEIGHTS,
    )
}

#[test]
fn test_credit_accepts_the_encoder_vectors() {
    let (cz, cm) = run_default();
    assert(cz != cm);
    assert(cz == commit_message::<TEST_N, TEST_BIT_M>(Polynomial::new(test_poly(TEST_MZ))));
    assert(cm == commit_message::<TEST_N, TEST_BIT_M>(Polynomial::new(test_poly(TEST_MM))));
}

#[test(should_fail)]
fn test_credit_rejects_wrong_logit() {
    // The leaf matches the (tampered) claim, but m_z encodes the logit
    // of the REAL features.
    let mut features = TEST_FEATURES;
    features[0] = 521;
    let _ = run_test(
        test_poly(TEST_MZ),
        test_poly(TEST_MM),
        features,
        test_root(features),
        TEST_MASK,
        TEST_INDEX,
        TEST_WEIGHTS,
    );
}

#[test(should_fail)]
fn test_credit_rejects_wrong_weights() {
    let mut weights = TEST_WEIGHTS;
    weights[1] += 1;
    let _ = run_test(
        test_poly(TEST_MZ),
        test_poly(TEST_MM),
        TEST_FEATURES,
        test_root(TEST_FEATURES),
        TEST_MASK,
        TEST_INDEX,
        weights,
    );
}

#[test(should_fail)]
fn test_credit_rejects_wrong_mask() {
    let _ = run_test(
        test_poly(TEST_MZ),
        test_poly(TEST_MM),
        TEST_FEATURES,
        test_root(TEST_FEATURES),
        TEST_MASK + 1,
        TEST_INDEX,
        TEST_WEIGHTS,
    );
}

#[test(should_fail)]
fn test_credit_rejects_wrong_index() {
    let _ = run_test(
        test_poly(TEST_MZ),
        test_poly(TEST_MM),
        TEST_FEATURES,
        test_root(TEST_FEATURES),
        TEST_MASK,
        TEST_INDEX + 1,
        TEST_WEIGHTS,
    );
}

#[test(should_fail)]
fn test_credit_rejects_extra_slot() {
    // A second non-zero slot perturbs every coefficient far beyond SLACK.
    let mut m_z = TEST_MZ;
    for k in 0..TEST_N {
        m_z[k] += 1000000;
    }
    let _ = run_test(
        test_poly(m_z),
        test_poly(TEST_MM),
        TEST_FEATURES,
        test_root(TEST_FEATURES),
        TEST_MASK,
        TEST_INDEX,
        TEST_WEIGHTS,
    );
}

#[test(should_fail)]
fn test_credit_rejects_off_by_slack_coefficient() {
    // One coefficient moved by more than SLACK (in units of the decoded
    // slot value): 2^20 >> 8.
    let mut m_m = TEST_MM;
    m_m[5] += 1048576;
    let _ = run_test(
        test_poly(TEST_MZ),
        test_poly(m_m),
        TEST_FEATURES,
        test_root(TEST_FEATURES),
        TEST_MASK,
        TEST_INDEX,
        TEST_WEIGHTS,
    );
}

#[test(should_fail)]
fn test_credit_rejects_wrong_root() {
    let mut features = TEST_FEATURES;
    features[7] = 43;
    let _ = run_test(
        test_poly(TEST_MZ),
        test_poly(TEST_MM),
        TEST_FEATURES,
        test_root(features),
        TEST_MASK,
        TEST_INDEX,
        TEST_WEIGHTS,
    );
}

#[test(should_fail)]
fn test_credit_rejects_feature_over_cap() {
    let mut features = TEST_FEATURES;
    features[3] = 1001;
    let _ = run_test(
        test_poly(TEST_MZ),
        test_poly(TEST_MM),
        features,
        test_root(features),
        TEST_MASK,
        TEST_INDEX,
        TEST_WEIGHTS,
    );
}

#[test(should_fail)]
fn test_credit_rejects_mask_out_of_range() {
    let _ = run_test(
        test_poly(TEST_MZ),
        test_poly(TEST_MM),
        TEST_FEATURES,
        test_root(TEST_FEATURES),
        1048576,
        TEST_INDEX,
        TEST_WEIGHTS,
    );
}

#[test(should_fail)]
fn test_credit_rejects_weight_out_of_range() {
    let mut weights = TEST_WEIGHTS;
    weights[4] = 524289;
    let _ = run_test(
        test_poly(TEST_MZ),
        test_poly(TEST_MM),
        TEST_FEATURES,
        test_root(TEST_FEATURES),
        TEST_MASK,
        TEST_INDEX,
        weights,
    );
}

#[test]
fn test_feature_leaf_vector() {
    // Pinned against the Rust `poseidon9_matches_noir_vector` test.
    let leaf = hash_9([TEST_ADDRESS, 520, 130, 350, 999, 0, 1, 777, 42]);
    assert(leaf == 0x2e70bfe6109556e0a2a8885470e8fdb18abb76d03a135766b644ab2bd2ad0c0e);
}
