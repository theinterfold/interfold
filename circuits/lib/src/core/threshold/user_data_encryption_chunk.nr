// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! User-data encryption, coefficient-level chunk leaves (P3).
//!
//! Each ciphertext leg (ct0, ct1) is checked reduced modulo `X^N + 1`, so it has no cyclotomic
//! quotient and its modulus-switch quotient (`r1is` / `p1is`) has `N` coefficients; the whole
//! witness fits one browser leaf. This module holds the leaf logic, so the checks that protect the
//! protocol live somewhere `nargo test` can reach them and read their bounds from one generated
//! `Configs`.
//!
//! The leaf range-checks and commits the witness, derives the challenge from those commitments and
//! the public-key and ciphertext commitments, and evaluates at it. The product
//! `pk * u mod X^N + 1` is evaluated in `ct*_eval_pk_ct` through `negacyclic_kernel`, so it never
//! enters a witness.

use crate::math::commitments::{
    compute_ude_chunk_commitment, compute_ude_chunk_root_commitment,
    compute_ude_multi_chunk_commitment, compute_vk_hash, UDE_KIND_CT0_E0, UDE_KIND_CT0_K1,
    UDE_KIND_CT0_R1, UDE_KIND_CT1_E1, UDE_KIND_CT1_P1, UDE_KIND_U,
};
use crate::math::polynomial::Polynomial;

/// Bounds a ct0 chunk leaf checks against. `k0is` is absent because no leaf needs it - only the
/// identity check in `ct0_eval_chunk_identity` does.
pub struct Ct0ChunkConfigs<let L: u32> {
    pub qis: [Field; L],
    pub u_bound: Field,
    pub e0_bound: Field,
    pub k1_low_bound: Field,
    pub k1_up_bound: Field,
    pub r1_low_bounds: [Field; L],
    pub r1_up_bounds: [Field; L],
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
    ) -> Self {
        Ct0ChunkConfigs {
            qis,
            u_bound,
            e0_bound,
            k1_low_bound,
            k1_up_bound,
            r1_low_bounds,
            r1_up_bounds,
        }
    }
}

/// Bounds a ct1 chunk leaf checks against. ct1 has no `e1is`/`e1_quotients` equivalent, so unlike
/// `Ct0ChunkConfigs` it needs no `qis` and no quotient bounds.
pub struct Ct1ChunkConfigs<let L: u32> {
    pub u_bound: Field,
    pub e1_bound: Field,
    pub p1_bounds: [Field; L],
}

impl<let L: u32> Ct1ChunkConfigs<L> {
    pub fn new(u_bound: Field, e1_bound: Field, p1_bounds: [Field; L]) -> Self {
        Ct1ChunkConfigs { u_bound, e1_bound, p1_bounds }
    }
}

/// Each ciphertext leg is proved as a single leaf per round over the whole polynomials: the reduced
/// identities (`ct0 = (pk0 * u mod X^N + 1) + e0 + k0 * k1 + q * r1` and
/// `ct1 = (pk1 * u mod X^N + 1) + e1 + q * p1`) have no cyclotomic quotient and `N`-coefficient
/// `r1`/`p1`, so the full witness fits one browser leaf and no chunk-root level is needed. The
/// commitments keep the chunk format with this single chunk.
pub global UDE_N_CHUNKS: u32 = 1;

/// ct0's witness for one round: `u`, `e0`, `k1` and the reduced quotients `r1is`, all `N` wide.
///
/// `n` is the full polynomial length, hashed into every commitment so a commitment can never be
/// reinterpreted as belonging to a different-sized run.
pub struct Ct0ChunkLeaf<let CHUNK_SIZE: u32, let L: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_K: u32, let BIT_R1: u32> {
    configs: Ct0ChunkConfigs<L>,
    chunk_idx: u32,
    n: u32,
    u_chunk: Polynomial<CHUNK_SIZE>,
    e0_chunk: Polynomial<CHUNK_SIZE>,
    k1_chunk: Polynomial<CHUNK_SIZE>,
    r1is_chunk: [Polynomial<CHUNK_SIZE>; L],
}

impl<let CHUNK_SIZE: u32, let L: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_K: u32, let BIT_R1: u32> Ct0ChunkLeaf<CHUNK_SIZE, L, BIT_U, BIT_E0, BIT_K, BIT_R1> {
    pub fn new(
        configs: Ct0ChunkConfigs<L>,
        chunk_idx: u32,
        n: u32,
        u_chunk: Polynomial<CHUNK_SIZE>,
        e0_chunk: Polynomial<CHUNK_SIZE>,
        k1_chunk: Polynomial<CHUNK_SIZE>,
        r1is_chunk: [Polynomial<CHUNK_SIZE>; L],
    ) -> Self {
        Ct0ChunkLeaf { configs, chunk_idx, n, u_chunk, e0_chunk, k1_chunk, r1is_chunk }
    }

    /// Every coefficient is range-checked here and nowhere else; the commitments below pin any
    /// later opening (such as `u` in `ct*_eval_pk_ct`) to these bounded values.
    pub fn check_range_bounds(self) {
        self.u_chunk.range_check_2bounds::<BIT_U>(self.configs.u_bound, self.configs.u_bound);
        self.e0_chunk.range_check_2bounds::<BIT_E0>(self.configs.e0_bound, self.configs.e0_bound);
        self.k1_chunk.range_check_2bounds::<BIT_K>(
            self.configs.k1_up_bound,
            self.configs.k1_low_bound,
        );
        for i in 0..L {
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
    /// Returns `(u, e0, k1, r1)`, computed from the same witness the leaf range-checks and
    /// evaluates.
    pub fn commitments(self) -> (Field, Field, Field, Field) {
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
        let r1_commit = compute_ude_multi_chunk_commitment::<CHUNK_SIZE, L, BIT_R1>(
            UDE_KIND_CT0_R1,
            self.chunk_idx,
            self.n,
            self.r1is_chunk,
        );

        (u_commit, e0_commit, k1_commit, r1_commit)
    }
}

/// ct1's witness for one round: `u`, `e1` and the reduced quotients `p1is`, all `N` wide.
pub struct Ct1ChunkLeaf<let CHUNK_SIZE: u32, let L: u32, let BIT_U: u32, let BIT_E1: u32, let BIT_P1: u32> {
    configs: Ct1ChunkConfigs<L>,
    chunk_idx: u32,
    n: u32,
    u_chunk: Polynomial<CHUNK_SIZE>,
    e1_chunk: Polynomial<CHUNK_SIZE>,
    p1is_chunk: [Polynomial<CHUNK_SIZE>; L],
}

impl<let CHUNK_SIZE: u32, let L: u32, let BIT_U: u32, let BIT_E1: u32, let BIT_P1: u32> Ct1ChunkLeaf<CHUNK_SIZE, L, BIT_U, BIT_E1, BIT_P1> {
    pub fn new(
        configs: Ct1ChunkConfigs<L>,
        chunk_idx: u32,
        n: u32,
        u_chunk: Polynomial<CHUNK_SIZE>,
        e1_chunk: Polynomial<CHUNK_SIZE>,
        p1is_chunk: [Polynomial<CHUNK_SIZE>; L],
    ) -> Self {
        Ct1ChunkLeaf { configs, chunk_idx, n, u_chunk, e1_chunk, p1is_chunk }
    }

    /// See `Ct0ChunkLeaf::check_range_bounds`.
    pub fn check_range_bounds(self) {
        self.u_chunk.range_check_2bounds::<BIT_U>(self.configs.u_bound, self.configs.u_bound);
        self.e1_chunk.range_check_2bounds::<BIT_E1>(self.configs.e1_bound, self.configs.e1_bound);
        for i in 0..L {
            self.p1is_chunk[i].range_check_2bounds::<BIT_P1>(
                self.configs.p1_bounds[i],
                self.configs.p1_bounds[i],
            );
        }
    }

    /// Returns `(u, e1, p1)`, one commitment per polynomial; see `Ct0ChunkLeaf::commitments`.
    pub fn commitments(self) -> (Field, Field, Field) {
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
        let p1_commit = compute_ude_multi_chunk_commitment::<CHUNK_SIZE, L, BIT_P1>(
            UDE_KIND_CT1_P1,
            self.chunk_idx,
            self.n,
            self.p1is_chunk,
        );

        (u_commit, e1_commit, p1_commit)
    }
}

/// Pin every ciphertext limb to its centered residue `[-(q_i-1)/2, (q_i-1)/2]`.
///
/// The commit circuits create the ciphertext commitment, and the chunk identities only check the
/// ciphertext modulo `q_i` (`r1` absorbs any multiple of it), so without this bound `ct + k*q_i`
/// is a second opening of the same ciphertext. Main's monolithic ct0/ct1 circuits apply the same
/// bound.
pub fn assert_centered_ciphertext<let N: u32, let L: u32, let BIT_CT: u32>(
    cts: [Polynomial<N>; L],
    qis: [Field; L],
) {
    for i in 0..L {
        let half = (qis[i] - 1) / 2;
        cts[i].range_check_2bounds::<BIT_CT>(half, half);
    }
}

/// Compute a single-polynomial chunk root from the complete polynomial.
///
/// The top-level ct0 circuit uses this function to bind the complete `k1` witness to the `k1`
/// root from both recursive rounds. The coefficients use the same descending-degree chunk order
/// as the leaf circuits.
pub fn ude_single_root_from_polynomial<let N: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32, let BIT: u32>(
    kind_tag: Field,
    polynomial: Polynomial<N>,
) -> Field {
    assert(N == N_CHUNKS * CHUNK_SIZE);

    let mut chunks: [Field; N_CHUNKS] = [0; N_CHUNKS];
    for chunk_idx in 0..N_CHUNKS {
        let mut coefficients: [Field; CHUNK_SIZE] = [0; CHUNK_SIZE];
        for offset in 0..CHUNK_SIZE {
            coefficients[offset] = polynomial.coefficients[(chunk_idx * CHUNK_SIZE) + offset];
        }
        chunks[chunk_idx] = compute_ude_chunk_commitment::<CHUNK_SIZE, BIT>(
            kind_tag,
            chunk_idx,
            N,
            Polynomial::new(coefficients),
        );
    }

    compute_ude_chunk_root_commitment(kind_tag, N, CHUNK_SIZE, chunks)
}

/// Fold every chunk's ct0 commitments into the five per-polynomial roots, in the order
/// `(u, e0, k1, r2, r1)`.
///
/// `r1` is rooted under `r1_chunk_size`, not `chunk_size` - the chunk width is hashed into the
/// root, so using the main width there would produce a root the leaves can never match.
pub fn ct0_chunk_roots(
    n: u32,
    chunk_size: u32,
    u_commitments: [Field],
    e0_commitments: [Field],
    k1_commitments: [Field],
    r1_commitments: [Field],
) -> (Field, Field, Field, Field) {
    let u_root = compute_ude_chunk_root_commitment(UDE_KIND_U, n, chunk_size, u_commitments);
    let e0_root = compute_ude_chunk_root_commitment(UDE_KIND_CT0_E0, n, chunk_size, e0_commitments);
    let k1_root = compute_ude_chunk_root_commitment(UDE_KIND_CT0_K1, n, chunk_size, k1_commitments);
    let r1_root = compute_ude_chunk_root_commitment(UDE_KIND_CT0_R1, n, chunk_size, r1_commitments);

    (u_root, e0_root, k1_root, r1_root)
}

/// Fold every chunk's ct1 commitments into the four per-polynomial roots, in the order
/// `(u, e1, p2, p1)`. See `ct0_chunk_roots` for the `p1_chunk_size` caveat.
pub fn ct1_chunk_roots(
    n: u32,
    chunk_size: u32,
    u_commitments: [Field],
    e1_commitments: [Field],
    p1_commitments: [Field],
) -> (Field, Field, Field) {
    let u_root = compute_ude_chunk_root_commitment(UDE_KIND_U, n, chunk_size, u_commitments);
    let e1_root = compute_ude_chunk_root_commitment(UDE_KIND_CT1_E1, n, chunk_size, e1_commitments);
    let p1_root = compute_ude_chunk_root_commitment(UDE_KIND_CT1_P1, n, chunk_size, p1_commitments);

    (u_root, e1_root, p1_root)
}

/// The VK manifest for one ciphertext leg: the key hash of every circuit below the top-level
/// circuit, as one value.
///
/// `verify_honk_proof` only proves that a proof verifies under a VK with the given key hash. A key
/// hash that no layer compares to an expected value lets a prover use any circuit with the same
/// public-input shape - for example a leaf without its range checks. The identity circuit outputs
/// its leaf's and pk circuit's key hashes, and the top-level circuit calls this function with them,
/// the identity circuit's own key hash and the ciphertext circuit's. The wrapper then folds the
/// result into `compute_ude_vk_chain`, and the verifier compares that value to a deployment anchor.
///
/// The order is part of the anchor. Keep it identical in any off-chain code that computes the
/// expected value: identity, leaf, pk, ct.
pub fn compute_ude_vk_manifest(
    identity_key_hash: Field,
    leaf_key_hash: Field,
    pk_key_hash: Field,
    ct_key_hash: Field,
) -> Field {
    compute_vk_hash(
        [identity_key_hash, leaf_key_hash, pk_key_hash, ct_key_hash].as_vector(),
    )
}

/// The complete VK chain for one ciphertext leg: the top-level circuit's key hash, then the
/// manifest of every circuit below it (see `compute_ude_vk_manifest`). The `user_data_encryption`
/// wrapper outputs one of these per leg in the positions that used to hold the bare ct0 and ct1 key
/// hashes.
pub fn compute_ude_vk_chain(top_level_key_hash: Field, vk_manifest: Field) -> Field {
    compute_vk_hash([top_level_key_hash, vk_manifest].as_vector())
}

// ---------------------------------------------------------------------------------------------
// Tests
//
// These cover the logic the deployed leaf circuits actually run: the soundness-critical checks
// (`check_range_bounds`, `check_padding`) and the two places a
// silent wrong answer is possible rather than a failed assert - the gamma offset convention and
// the per-polynomial chunk width used to root a commitment.
// ---------------------------------------------------------------------------------------------

// e0_bound=100 and BIT_E0=8 (9-bit capacity) comfortably cover the small honest coefficients used
// below.
#[test]
fn test_chunk_configs_new_roundtrip() {
    let configs = test_ct0_configs(7, 100);
    assert(configs.qis[0] == 7);
    assert(configs.e0_bound == 100);
}

fn test_ct0_configs(qis0: Field, e0_bound: Field) -> Ct0ChunkConfigs<1> {
    Ct0ChunkConfigs::new([qis0], 1, e0_bound, 0, 1, [0], [0])
}

fn test_ct0_leaf(u_coeffs: [Field; 2], r1_coeffs: [Field; 2]) -> Ct0ChunkLeaf<2, 1, 1, 8, 1, 1> {
    Ct0ChunkLeaf::new(
        test_ct0_configs(1125899917262849, 100),
        0,
        2,
        Polynomial::new(u_coeffs),
        Polynomial::new([0, 0]),
        Polynomial::new([0, 0]),
        [Polynomial::new(r1_coeffs)],
    )
}

/// `u_bound` is 1 in `test_ct0_configs` (as at every real preset - `u` is trinary), so a
/// coefficient of 2 is out of range.
#[test(should_fail)]
fn test_ct0_chunk_range_bounds_rejects_out_of_range_u() {
    test_ct0_leaf([2, 0], [0, 0]).check_range_bounds();
}

#[test]
fn test_ct0_chunk_range_bounds_accepts_in_range_u() {
    test_ct0_leaf([1, 0], [0, 0]).check_range_bounds();
}

/// `r1` is bounded too: its up bound is 0 in `test_ct0_configs`.
#[test(should_fail)]
fn test_ct0_chunk_range_bounds_rejects_out_of_range_r1() {
    test_ct0_leaf([0, 0], [1, 0]).check_range_bounds();
}

#[test]
fn test_ude_single_root_from_polynomial_matches_leaf_order() {
    let polynomial = Polynomial::new([3, 5, 11, 2]);
    let chunk0 =
        compute_ude_chunk_commitment::<2, 8>(UDE_KIND_CT0_K1, 0, 4, Polynomial::new([3, 5]));
    let chunk1 =
        compute_ude_chunk_commitment::<2, 8>(UDE_KIND_CT0_K1, 1, 4, Polynomial::new([11, 2]));
    let expected = compute_ude_chunk_root_commitment(UDE_KIND_CT0_K1, 4, 2, [chunk0, chunk1]);

    assert(ude_single_root_from_polynomial::<4, 2, 2, 8>(UDE_KIND_CT0_K1, polynomial) == expected);
}

/// Every ct0 root has its own domain tag, so the same commitments give four different roots.
#[test]
fn test_ct0_chunk_roots_separate_kinds() {
    let commitments = [1];
    let (u_root, e0_root, k1_root, r1_root) =
        ct0_chunk_roots(4, 4, commitments, commitments, commitments, commitments);
    assert(u_root != e0_root);
    assert(e0_root != k1_root);
    assert(k1_root != r1_root);
}

/// ct0's and ct1's `u` share one domain tag - the `user_data_encryption` wrapper asserts the two
/// legs' `u` commitments are equal, which a per-leg tag would make unsatisfiable.
#[test]
fn test_chunk_roots_agree_on_u_across_legs() {
    let commitments = [1, 2];
    let (ct0_u_root, _, _, _) =
        ct0_chunk_roots(4, 2, commitments, commitments, commitments, commitments);
    let (ct1_u_root, ct1_e1_root, _) = ct1_chunk_roots(4, 2, commitments, commitments, commitments);

    assert(ct0_u_root == ct1_u_root);
    // Everything else stays separated.
    assert(ct1_u_root != ct1_e1_root);
}

/// Every slot in the manifest must change the result, and the order matters, so no circuit in the
/// tree can be swapped for another with the same public-input shape.
#[test]
fn test_ude_vk_manifest_depends_on_every_key_hash_in_order() {
    let base = compute_ude_vk_manifest(1, 2, 3, 4);
    assert(base == compute_vk_hash([1, 2, 3, 4].as_vector()));
    assert(compute_ude_vk_manifest(9, 2, 3, 4) != base);
    assert(compute_ude_vk_manifest(1, 9, 3, 4) != base);
    assert(compute_ude_vk_manifest(1, 2, 9, 4) != base);
    assert(compute_ude_vk_manifest(1, 2, 3, 9) != base);
    assert(compute_ude_vk_manifest(2, 1, 3, 4) != base);
    assert(compute_ude_vk_chain(10, 11) == compute_vk_hash([10, 11].as_vector()));
}

#[test]
fn test_centered_ciphertext_accepts_both_edges() {
    assert_centered_ciphertext::<2, 2, 4>(
        [Polynomial::new([8, -8]), Polynomial::new([0, 6])],
        [17, 13],
    );
}

#[test(should_fail)]
fn test_centered_ciphertext_rejects_a_shifted_residue() {
    // 9 == -8 mod 17, but it is not the centered representative.
    assert_centered_ciphertext::<2, 2, 4>(
        [Polynomial::new([9, 0]), Polynomial::new([0, 0])],
        [17, 13],
    );
}

#[test(should_fail)]
fn test_centered_ciphertext_checks_every_limb() {
    // 7 is centered mod 17 but not mod 13.
    assert_centered_ciphertext::<2, 2, 4>(
        [Polynomial::new([0, 0]), Polynomial::new([7, 0])],
        [17, 13],
    );
}
