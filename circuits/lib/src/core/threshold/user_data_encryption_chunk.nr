// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! User-data encryption, coefficient-level chunk leaves (P3).
//!
//! Proving a whole ciphertext leg in one circuit does not fit the browser's ~2M gate ceiling at
//! N=16384, L=5, so each leg's witness is split into `N_CHUNKS` coefficient slices, each slice is
//! proved in its own leaf circuit, and the leaves are recombined through a small recursive tree.
//! This module holds the per-slice logic those leaves run, so the checks that actually protect
//! the protocol live somewhere `nargo test` can reach them and read their bounds from one
//! generated `Configs` rather than from loose globals at each call site.
//!
//! Each leg's grid is *merged*: `r1is`/`p1is` are padded to `2N` where every other polynomial is
//! padded to `N`, so at a shared chunk count their slices are exactly twice as wide
//! (`R1_CHUNK_SIZE == 2 * CHUNK_SIZE`) and the same `chunk_idx` addresses both.
//!
//! Two rounds run over the same slices. Round A range-checks them and commits; Round B
//! re-supplies them, re-derives the identical commitments for cross-round binding, and evaluates
//! at the Fiat-Shamir challenge. Both rounds build the same `Ct0ChunkLeaf`/`Ct1ChunkLeaf` - Round
//! A additionally calls `check_range_bounds` and `check_padding`, Round B additionally calls
//! `check_e0_chunk_crt_consistency` (ct0 only) and `chunk_gamma_pow`.

use crate::math::commitments::{
    compute_ude_chunk_commitment, compute_ude_chunk_root_commitment,
    compute_ude_multi_chunk_commitment, UDE_KIND_CT0_E0, UDE_KIND_CT0_K1, UDE_KIND_CT0_R1,
    UDE_KIND_CT0_R2, UDE_KIND_CT1_E1, UDE_KIND_CT1_P1, UDE_KIND_CT1_P2, UDE_KIND_U,
};
use crate::math::polynomial::Polynomial;

/// Bounds a ct0 chunk leaf checks against. `k0is` is absent because no leaf needs it - only the
/// identity check in `ct0_eval_chunk_identity` does - while `qis` is present because Round B's
/// CRT-consistency check needs it.
pub struct Ct0ChunkConfigs<let L: u32> {
    pub qis: [Field; L],
    pub u_bound: Field,
    pub e0_bound: Field,
    pub k1_low_bound: Field,
    pub k1_up_bound: Field,
    pub r1_low_bounds: [Field; L],
    pub r1_up_bounds: [Field; L],
    pub r2_bounds: [Field; L],
    /// Per-limb bound on the honest `e0_quotients[i]` magnitude - see
    /// `check_e0_chunk_crt_consistency`.
    pub e0_quotient_bounds: [Field; L],
}

impl<let L: u32> Ct0ChunkConfigs<L> {
    pub fn new(
        qis: [Field; L],
        u_bound: Field,
        e0_bound: Field,
        k1_low_bound: Field,
        k1_up_bound: Field,
        r1_low_bounds: [Field; L],
        r1_up_bounds: [Field; L],
        r2_bounds: [Field; L],
        e0_quotient_bounds: [Field; L],
    ) -> Self {
        Ct0ChunkConfigs {
            qis,
            u_bound,
            e0_bound,
            k1_low_bound,
            k1_up_bound,
            r1_low_bounds,
            r1_up_bounds,
            r2_bounds,
            e0_quotient_bounds,
        }
    }
}

/// Bounds a ct1 chunk leaf checks against. ct1 has no `e1is`/`e1_quotients` equivalent, so unlike
/// `Ct0ChunkConfigs` it needs no `qis` and no quotient bounds.
pub struct Ct1ChunkConfigs<let L: u32> {
    pub u_bound: Field,
    pub e1_bound: Field,
    pub p1_bounds: [Field; L],
    pub p2_bounds: [Field; L],
}

impl<let L: u32> Ct1ChunkConfigs<L> {
    pub fn new(
        u_bound: Field,
        e1_bound: Field,
        p1_bounds: [Field; L],
        p2_bounds: [Field; L],
    ) -> Self {
        Ct1ChunkConfigs { u_bound, e1_bound, p1_bounds, p2_bounds }
    }
}

/// One `chunk_idx` slice of ct0's merged main+r1 grid: `u`, `e0`, `k1`, `r2is` at `CHUNK_SIZE`
/// coefficients each, plus `r1is` at `R1_CHUNK_SIZE == 2 * CHUNK_SIZE`.
///
/// `n` is the *full* polynomial length (N), not the slice width - it is hashed into every chunk
/// commitment so a slice can never be reinterpreted as belonging to a different-sized run.
pub struct Ct0ChunkLeaf<let CHUNK_SIZE: u32, let R1_CHUNK_SIZE: u32, let L: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_K: u32, let BIT_R2: u32, let BIT_R1: u32> {
    configs: Ct0ChunkConfigs<L>,
    chunk_idx: u32,
    n: u32,
    u_chunk: Polynomial<CHUNK_SIZE>,
    e0_chunk: Polynomial<CHUNK_SIZE>,
    k1_chunk: Polynomial<CHUNK_SIZE>,
    r2is_chunk: [Polynomial<CHUNK_SIZE>; L],
    r1is_chunk: [Polynomial<R1_CHUNK_SIZE>; L],
}

impl<let CHUNK_SIZE: u32, let R1_CHUNK_SIZE: u32, let L: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_K: u32, let BIT_R2: u32, let BIT_R1: u32> Ct0ChunkLeaf<CHUNK_SIZE, R1_CHUNK_SIZE, L, BIT_U, BIT_E0, BIT_K, BIT_R2, BIT_R1> {
    pub fn new(
        configs: Ct0ChunkConfigs<L>,
        chunk_idx: u32,
        n: u32,
        u_chunk: Polynomial<CHUNK_SIZE>,
        e0_chunk: Polynomial<CHUNK_SIZE>,
        k1_chunk: Polynomial<CHUNK_SIZE>,
        r2is_chunk: [Polynomial<CHUNK_SIZE>; L],
        r1is_chunk: [Polynomial<R1_CHUNK_SIZE>; L],
    ) -> Self {
        Ct0ChunkLeaf { configs, chunk_idx, n, u_chunk, e0_chunk, k1_chunk, r2is_chunk, r1is_chunk }
    }

    /// `r2is` and `r1is` are padded from their native degrees (`N-1` and `2N-1`) to `N` and `2N`
    /// by one leading zero (see `Polynomial`'s descending-degree convention). That padding slot
    /// lives at global index 0, i.e. chunk 0's local offset 0, so only chunk 0 checks it.
    pub fn check_padding(self) {
        if self.chunk_idx == 0 {
            for i in 0..L {
                assert(
                    self.r2is_chunk[i].coefficients[0] == 0,
                    "r2is padding coefficient must be zero",
                );
                assert(
                    self.r1is_chunk[i].coefficients[0] == 0,
                    "r1is padding coefficient must be zero",
                );
            }
        }
    }

    /// Round A only. Every coefficient in this slice is range-checked here and nowhere else, so
    /// the union over all `chunk_idx` in `0..N_CHUNKS` covers each polynomial exactly once - a
    /// chunk that is never proved is a coefficient range that is never checked.
    pub fn check_range_bounds(self) {
        self.u_chunk.range_check_2bounds::<BIT_U>(self.configs.u_bound, self.configs.u_bound);
        self.e0_chunk.range_check_2bounds::<BIT_E0>(self.configs.e0_bound, self.configs.e0_bound);
        self.k1_chunk.range_check_2bounds::<BIT_K>(
            self.configs.k1_up_bound,
            self.configs.k1_low_bound,
        );
        for i in 0..L {
            self.r2is_chunk[i].range_check_2bounds::<BIT_R2>(
                self.configs.r2_bounds[i],
                self.configs.r2_bounds[i],
            );
            self.r1is_chunk[i].range_check_2bounds::<BIT_R1>(
                self.configs.r1_up_bounds[i],
                self.configs.r1_low_bounds[i],
            );
        }
    }

    /// One commitment *per polynomial*, never bundled: the `user_data_encryption` wrapper
    /// cross-checks ct0's and ct1's `u` commitment directly, and `k1`'s survives into ct0's final
    /// output tuple, so both must stay independently recoverable.
    ///
    /// Returns `(u, e0, k1, r2, r1)`. Both rounds call this and the top-level circuit asserts the
    /// resulting roots match - that equality is what stops a prover from range-checking one
    /// witness in Round A and evaluating a different one in Round B.
    pub fn commitments(self) -> (Field, Field, Field, Field, Field) {
        let u_commit = compute_ude_chunk_commitment::<CHUNK_SIZE, BIT_U>(
            UDE_KIND_U,
            self.chunk_idx,
            self.n,
            self.u_chunk,
        );
        let e0_commit = compute_ude_chunk_commitment::<CHUNK_SIZE, BIT_E0>(
            UDE_KIND_CT0_E0,
            self.chunk_idx,
            self.n,
            self.e0_chunk,
        );
        let k1_commit = compute_ude_chunk_commitment::<CHUNK_SIZE, BIT_K>(
            UDE_KIND_CT0_K1,
            self.chunk_idx,
            self.n,
            self.k1_chunk,
        );
        let r2_commit = compute_ude_multi_chunk_commitment::<CHUNK_SIZE, L, BIT_R2>(
            UDE_KIND_CT0_R2,
            self.chunk_idx,
            self.n,
            self.r2is_chunk,
        );
        let r1_commit = compute_ude_multi_chunk_commitment::<R1_CHUNK_SIZE, L, BIT_R1>(
            UDE_KIND_CT0_R1,
            self.chunk_idx,
            self.n,
            self.r1is_chunk,
        );

        (u_commit, e0_commit, k1_commit, r2_commit, r1_commit)
    }
}

/// One `chunk_idx` slice of ct1's merged main+p1 grid: `u`, `e1`, `p2is` at `CHUNK_SIZE`
/// coefficients each, plus `p1is` at `R1_CHUNK_SIZE == 2 * CHUNK_SIZE`.
pub struct Ct1ChunkLeaf<let CHUNK_SIZE: u32, let R1_CHUNK_SIZE: u32, let L: u32, let BIT_U: u32, let BIT_E1: u32, let BIT_P2: u32, let BIT_P1: u32> {
    configs: Ct1ChunkConfigs<L>,
    chunk_idx: u32,
    n: u32,
    u_chunk: Polynomial<CHUNK_SIZE>,
    e1_chunk: Polynomial<CHUNK_SIZE>,
    p2is_chunk: [Polynomial<CHUNK_SIZE>; L],
    p1is_chunk: [Polynomial<R1_CHUNK_SIZE>; L],
}

impl<let CHUNK_SIZE: u32, let R1_CHUNK_SIZE: u32, let L: u32, let BIT_U: u32, let BIT_E1: u32, let BIT_P2: u32, let BIT_P1: u32> Ct1ChunkLeaf<CHUNK_SIZE, R1_CHUNK_SIZE, L, BIT_U, BIT_E1, BIT_P2, BIT_P1> {
    pub fn new(
        configs: Ct1ChunkConfigs<L>,
        chunk_idx: u32,
        n: u32,
        u_chunk: Polynomial<CHUNK_SIZE>,
        e1_chunk: Polynomial<CHUNK_SIZE>,
        p2is_chunk: [Polynomial<CHUNK_SIZE>; L],
        p1is_chunk: [Polynomial<R1_CHUNK_SIZE>; L],
    ) -> Self {
        Ct1ChunkLeaf { configs, chunk_idx, n, u_chunk, e1_chunk, p2is_chunk, p1is_chunk }
    }

    /// See `Ct0ChunkLeaf::check_padding` - `p2is`/`p1is` carry the same leading zero.
    pub fn check_padding(self) {
        if self.chunk_idx == 0 {
            for i in 0..L {
                assert(
                    self.p2is_chunk[i].coefficients[0] == 0,
                    "p2is padding coefficient must be zero",
                );
                assert(
                    self.p1is_chunk[i].coefficients[0] == 0,
                    "p1is padding coefficient must be zero",
                );
            }
        }
    }

    /// Round A only. Note `p1is` is checked with the same bound in both directions, unlike ct0's
    /// `r1is`, which has a separate low and up bound per limb.
    pub fn check_range_bounds(self) {
        self.u_chunk.range_check_2bounds::<BIT_U>(self.configs.u_bound, self.configs.u_bound);
        self.e1_chunk.range_check_2bounds::<BIT_E1>(self.configs.e1_bound, self.configs.e1_bound);
        for i in 0..L {
            self.p2is_chunk[i].range_check_2bounds::<BIT_P2>(
                self.configs.p2_bounds[i],
                self.configs.p2_bounds[i],
            );
            self.p1is_chunk[i].range_check_2bounds::<BIT_P1>(
                self.configs.p1_bounds[i],
                self.configs.p1_bounds[i],
            );
        }
    }

    /// Returns `(u, e1, p2, p1)`. See `Ct0ChunkLeaf::commitments`.
    pub fn commitments(self) -> (Field, Field, Field, Field) {
        let u_commit = compute_ude_chunk_commitment::<CHUNK_SIZE, BIT_U>(
            UDE_KIND_U,
            self.chunk_idx,
            self.n,
            self.u_chunk,
        );
        let e1_commit = compute_ude_chunk_commitment::<CHUNK_SIZE, BIT_E1>(
            UDE_KIND_CT1_E1,
            self.chunk_idx,
            self.n,
            self.e1_chunk,
        );
        let p2_commit = compute_ude_multi_chunk_commitment::<CHUNK_SIZE, L, BIT_P2>(
            UDE_KIND_CT1_P2,
            self.chunk_idx,
            self.n,
            self.p2is_chunk,
        );
        let p1_commit = compute_ude_multi_chunk_commitment::<R1_CHUNK_SIZE, L, BIT_P1>(
            UDE_KIND_CT1_P1,
            self.chunk_idx,
            self.n,
            self.p1is_chunk,
        );

        (u_commit, e1_commit, p2_commit, p1_commit)
    }
}

/// Ties each CRT residue `e0is[i]` to the integer `e0` through a bounded quotient, for one chunk.
///
/// **Round B only.** Round A never commits to `e0is`, so a copy of this check there would
/// constrain nothing observable: the binding runs entirely through Round B, where `e0is` is tied
/// to `e0_chunk` here and `e0_chunk` is in turn tied to Round A's `e0` by the top-level circuit's
/// `e0_root` equality assert.
///
/// The quotient range check is not optional. The equation below holds in `F_p`, not in `Z`: with
/// an unbounded `e0_quotients[i]` a prover satisfies it for an *arbitrary* `e0is[i]` by solving
/// `e0_quotients[i] := (e0 - e0is[i]) / qis[i]` through the modular inverse, and that forged
/// residue then reaches the identity check unmediated. Bounding the quotient to the honest range
/// closes the gap.
///
/// `e0is` itself is deliberately *not* bounded here - that would be redundant, since any multiple
/// of `qis[i]` absorbed into `e0is` is absorbed one-for-one by `r1is` and leaves the identity
/// unchanged mod `qis[i]`. Per-limb bounds could not substitute for the integer bound anyway: L
/// residues each under `q_i/2` CRT-reconstruct to anything up to `q/2`, which would destroy the
/// smudging bound decryption correctness depends on.
pub fn check_e0_chunk_crt_consistency<let CHUNK_SIZE: u32, let L: u32, let BIT_E0_QUOTIENT: u32>(
    configs: Ct0ChunkConfigs<L>,
    e0_chunk: Polynomial<CHUNK_SIZE>,
    e0is_chunk: [Polynomial<CHUNK_SIZE>; L],
    e0_quotients_chunk: [Polynomial<CHUNK_SIZE>; L],
) {
    for i in 0..L {
        e0_quotients_chunk[i].range_check_2bounds::<BIT_E0_QUOTIENT>(
            configs.e0_quotient_bounds[i],
            configs.e0_quotient_bounds[i],
        );
        for j in 0..CHUNK_SIZE {
            assert(
                e0_chunk.coefficients[j]
                    == e0is_chunk[i].coefficients[j]
                        + e0_quotients_chunk[i].coefficients[j] * configs.qis[i],
            );
        }
    }
}

/// The `gamma` power that lifts a chunk's *local* Horner evaluation into its contribution to the
/// full-length one.
///
/// `Polynomial::eval` treats a `chunk_size`-length slice as its own complete polynomial, so the
/// slice's real contribution is `local_eval * gamma^offset`, where `offset` is the degree of the
/// chunk's lowest coefficient. In the descending-coefficient layout that is
/// `total_len - (chunk_idx + 1) * chunk_size`. Summing every chunk's contribution reconstructs
/// the full evaluation exactly.
///
/// `total_len` is `N` for the main grid and `2 * N` for `r1is`/`p1is`, which is the whole reason
/// this is a parameter rather than a constant - passing the wrong one silently produces a valid
/// proof of the wrong polynomial.
pub fn chunk_gamma_pow(total_len: u32, chunk_size: u32, chunk_idx: u32, gamma: Field) -> Field {
    let offset = total_len - ((chunk_idx + 1) * chunk_size);
    gamma.pow_32(offset as Field)
}

/// Fold every chunk's ct0 commitments into the five per-polynomial roots, in the order
/// `(u, e0, k1, r2, r1)`.
///
/// `r1` is rooted under `r1_chunk_size`, not `chunk_size` - the chunk width is hashed into the
/// root, so using the main width there would produce a root the leaves can never match.
pub fn ct0_chunk_roots(
    n: u32,
    chunk_size: u32,
    r1_chunk_size: u32,
    u_commitments: [Field],
    e0_commitments: [Field],
    k1_commitments: [Field],
    r2_commitments: [Field],
    r1_commitments: [Field],
) -> (Field, Field, Field, Field, Field) {
    let u_root = compute_ude_chunk_root_commitment(UDE_KIND_U, n, chunk_size, u_commitments);
    let e0_root = compute_ude_chunk_root_commitment(UDE_KIND_CT0_E0, n, chunk_size, e0_commitments);
    let k1_root = compute_ude_chunk_root_commitment(UDE_KIND_CT0_K1, n, chunk_size, k1_commitments);
    let r2_root = compute_ude_chunk_root_commitment(UDE_KIND_CT0_R2, n, chunk_size, r2_commitments);
    let r1_root =
        compute_ude_chunk_root_commitment(UDE_KIND_CT0_R1, n, r1_chunk_size, r1_commitments);

    (u_root, e0_root, k1_root, r2_root, r1_root)
}

/// Fold every chunk's ct1 commitments into the four per-polynomial roots, in the order
/// `(u, e1, p2, p1)`. See `ct0_chunk_roots` for the `p1_chunk_size` caveat.
pub fn ct1_chunk_roots(
    n: u32,
    chunk_size: u32,
    p1_chunk_size: u32,
    u_commitments: [Field],
    e1_commitments: [Field],
    p2_commitments: [Field],
    p1_commitments: [Field],
) -> (Field, Field, Field, Field) {
    let u_root = compute_ude_chunk_root_commitment(UDE_KIND_U, n, chunk_size, u_commitments);
    let e1_root = compute_ude_chunk_root_commitment(UDE_KIND_CT1_E1, n, chunk_size, e1_commitments);
    let p2_root = compute_ude_chunk_root_commitment(UDE_KIND_CT1_P2, n, chunk_size, p2_commitments);
    let p1_root =
        compute_ude_chunk_root_commitment(UDE_KIND_CT1_P1, n, p1_chunk_size, p1_commitments);

    (u_root, e1_root, p2_root, p1_root)
}

// ---------------------------------------------------------------------------------------------
// Tests
//
// These cover the logic the deployed leaf circuits actually run: the soundness-critical checks
// (`check_e0_chunk_crt_consistency`, `check_range_bounds`, `check_padding`) and the two places a
// silent wrong answer is possible rather than a failed assert - the gamma offset convention and
// the per-polynomial chunk width used to root a commitment.
// ---------------------------------------------------------------------------------------------

// e0_bound=100 and BIT_E0=8 (9-bit capacity) comfortably cover the small honest coefficients used
// below; e0_quotient_bound=32 with BIT_E0_QUOTIENT=6 (7-bit capacity, range_size=2*bound) mirrors
// the real fix's margin over the ~25.5 honest maximum at the real secure_16384 preset.
#[test]
fn test_chunk_configs_new_roundtrip() {
    let configs = test_ct0_configs(7, 100, 32);
    assert(configs.qis[0] == 7);
    assert(configs.e0_bound == 100);
    assert(configs.e0_quotient_bounds[0] == 32);
}

fn test_ct0_configs(qis0: Field, e0_bound: Field, e0_quotient_bound: Field) -> Ct0ChunkConfigs<1> {
    Ct0ChunkConfigs::new(
        [qis0],
        1,
        e0_bound,
        0,
        1,
        [0],
        [0],
        [0],
        [e0_quotient_bound],
    )
}

/// The gap the `e0_quotients` range check closes. `check_e0_chunk_crt_consistency`'s equation
/// holds in F_p, so a prover can back-solve `e0_quotients[i] := (e0 - e0is[i]) / qis[i]` through
/// the modular inverse and satisfy it for an arbitrary forged `e0is[i]`. Without the bound this
/// witness would be accepted; with it, the wildly out-of-range quotient is rejected.
#[test(should_fail)]
fn test_e0_chunk_crt_consistency_rejects_out_of_range_quotient() {
    let honest_e0_coeff: Field = 5;
    let qis0: Field = 1125899917262849;
    let forged_e0is_coeff: Field = 999999999999;
    let forged_quotient: Field = (honest_e0_coeff - forged_e0is_coeff) / qis0;

    check_e0_chunk_crt_consistency::<2, 1, 6>(
        test_ct0_configs(qis0, 100, 32),
        Polynomial::new([honest_e0_coeff, 0]),
        [Polynomial::new([forged_e0is_coeff, 0])],
        [Polynomial::new([forged_quotient, 0])],
    );
}

/// Sanity check: an honest witness (quotient within the configured bound) still passes, so the
/// bound does not reject legitimate provers.
#[test]
fn test_e0_chunk_crt_consistency_accepts_honest_witness() {
    let honest_e0_coeff: Field = 5;
    let qis0: Field = 1125899917262849;

    check_e0_chunk_crt_consistency::<2, 1, 6>(
        test_ct0_configs(qis0, 100, 32),
        Polynomial::new([honest_e0_coeff, 0]),
        [Polynomial::new([honest_e0_coeff, 0])], // e0is == e0, so the honest quotient is 0
        [Polynomial::new([0, 0])],
    );
}

/// A residue that does not reconcile with `e0` under *any* in-range quotient must be rejected on
/// the equation itself, not just the bound.
#[test(should_fail)]
fn test_e0_chunk_crt_consistency_rejects_mismatched_residue() {
    check_e0_chunk_crt_consistency::<2, 1, 6>(
        test_ct0_configs(1125899917262849, 100, 32),
        Polynomial::new([5, 0]),
        [Polynomial::new([6, 0])], // off by one, and no in-range quotient can absorb it
        [Polynomial::new([0, 0])],
    );
}

fn test_ct0_leaf(
    chunk_idx: u32,
    u_coeffs: [Field; 2],
    r2_coeffs: [Field; 2],
    r1_coeffs: [Field; 4],
) -> Ct0ChunkLeaf<2, 4, 1, 1, 8, 1, 1, 1> {
    Ct0ChunkLeaf::new(
        test_ct0_configs(1125899917262849, 100, 32),
        chunk_idx,
        4,
        Polynomial::new(u_coeffs),
        Polynomial::new([0, 0]),
        Polynomial::new([0, 0]),
        [Polynomial::new(r2_coeffs)],
        [Polynomial::new(r1_coeffs)],
    )
}

/// `u_bound` is 1 in `test_ct0_configs` (as at every real preset - `u` is trinary), so a
/// coefficient of 2 is out of range.
#[test(should_fail)]
fn test_ct0_chunk_range_bounds_rejects_out_of_range_u() {
    test_ct0_leaf(0, [2, 0], [0, 0], [0, 0, 0, 0]).check_range_bounds();
}

#[test]
fn test_ct0_chunk_range_bounds_accepts_in_range_u() {
    test_ct0_leaf(0, [1, 0], [0, 0], [0, 0, 0, 0]).check_range_bounds();
}

/// The `r2is`/`r1is` padding slot sits at global index 0, i.e. chunk 0's local offset 0.
#[test(should_fail)]
fn test_ct0_chunk_padding_rejects_nonzero_r2_pad() {
    test_ct0_leaf(0, [0, 0], [1, 0], [0, 0, 0, 0]).check_padding();
}

#[test(should_fail)]
fn test_ct0_chunk_padding_rejects_nonzero_r1_pad() {
    test_ct0_leaf(0, [0, 0], [0, 0], [1, 0, 0, 0]).check_padding();
}

/// Only chunk 0 owns the padding slot, so the same coefficient is unremarkable in chunk 1.
#[test]
fn test_ct0_chunk_padding_ignores_later_chunks() {
    test_ct0_leaf(1, [0, 0], [1, 0], [1, 0, 0, 0]).check_padding();
}

/// The whole point of the offset convention: summing each chunk's `local_eval * gamma^offset`
/// must reproduce the full-length Horner evaluation exactly.
#[test]
fn test_chunk_gamma_pow_reconstructs_full_evaluation() {
    let gamma: Field = 7;
    let full = Polynomial::new([3, 5, 11, 2]); // descending: 3g^3 + 5g^2 + 11g + 2
    let expected = full.eval(gamma);

    let chunk0 = Polynomial::new([3, 5]);
    let chunk1 = Polynomial::new([11, 2]);

    let partial0 = chunk0.eval(gamma) * chunk_gamma_pow(4, 2, 0, gamma);
    let partial1 = chunk1.eval(gamma) * chunk_gamma_pow(4, 2, 1, gamma);

    assert(partial0 + partial1 == expected);
}

/// `r1is`/`p1is` are padded to `2N`, so their offsets are computed against the doubled length -
/// passing `N` there would silently prove the wrong polynomial.
#[test]
fn test_chunk_gamma_pow_uses_the_grid_it_is_given() {
    let gamma: Field = 7;

    // Last chunk always contributes at offset 0, whichever grid it belongs to.
    assert(chunk_gamma_pow(4, 2, 1, gamma) == 1);
    assert(chunk_gamma_pow(8, 4, 1, gamma) == 1);

    // Chunk 0 of the main grid sits at offset 2; of the doubled grid, at offset 4.
    assert(chunk_gamma_pow(4, 2, 0, gamma) == gamma.pow_32(2));
    assert(chunk_gamma_pow(8, 4, 0, gamma) == gamma.pow_32(4));
}

/// `r1` must be rooted under its own chunk width. Using the main width would produce a root the
/// leaves can never match, so the two must differ for the same commitments.
#[test]
fn test_ct0_chunk_roots_separate_r1_by_chunk_width() {
    let commitments = [1, 2];
    let (u_root, e0_root, k1_root, r2_root, r1_root) = ct0_chunk_roots(
        4,
        2,
        4,
        commitments,
        commitments,
        commitments,
        commitments,
        commitments,
    );

    // Same inputs, different domain tags: every root must differ.
    assert(u_root != e0_root);
    assert(e0_root != k1_root);
    assert(k1_root != r2_root);
    assert(r2_root != r1_root);

    // And r1 rooted at the main width is a different value than at its own width.
    let (_, _, _, _, r1_root_wrong_width) = ct0_chunk_roots(
        4,
        2,
        2,
        commitments,
        commitments,
        commitments,
        commitments,
        commitments,
    );
    assert(r1_root != r1_root_wrong_width);
}

/// ct0's and ct1's `u` share one domain tag - the `user_data_encryption` wrapper asserts the two
/// legs' `u` commitments are equal, which a per-leg tag would make unsatisfiable.
#[test]
fn test_chunk_roots_agree_on_u_across_legs() {
    let commitments = [1, 2];
    let (ct0_u_root, _, _, _, _) = ct0_chunk_roots(
        4,
        2,
        4,
        commitments,
        commitments,
        commitments,
        commitments,
        commitments,
    );
    let (ct1_u_root, ct1_e1_root, _, _) =
        ct1_chunk_roots(4, 2, 4, commitments, commitments, commitments, commitments);

    assert(ct0_u_root == ct1_u_root);
    // Everything else stays separated.
    assert(ct1_u_root != ct1_e1_root);
}
