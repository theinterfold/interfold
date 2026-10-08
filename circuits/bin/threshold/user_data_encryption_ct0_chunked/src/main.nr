// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Top-level ct0 (P3). Round A: `ct0_chunk_main` (one ZK leaf over the whole witness,
//! `u`/`e0`/`k1`/`r1is`) and `ct0_pk_ct_commit` (range-checks and commits `ct0is`, passes the
//! `pk0is` commitment through) feed `ct0_chunk_gamma`, which derives gamma. Round B:
//! `ct0_eval_chunk_main` and `ct0_eval_pk_ct` (which evaluates the reduced `pk0 * u` product)
//! feed `ct0_eval_chunk_identity`, which checks the identity reduced modulo `X^N + 1`. The
//! reduced identity has no cyclotomic quotient, so one leaf per round fits the browser budget.
//!
//! This circuit verifies both round proofs and checks every commitment and batching coefficient
//! they produced agree - closing the binding that stops a prover from range-checking one witness
//! in Round A and evaluating a different, unconstrained one in Round B.
//!
//! It also closes VK binding for the tree. Each round outputs the key hashes of its leaf and
//! pk/ct circuits. This circuit folds those four values and its own two child key hashes into one
//! VK manifest, and outputs the manifest first. The wrapper folds the manifest into the value that
//! the verifier checks against a deployment anchor. Without the manifest, a prover could replace
//! any circuit below this one - for example a leaf without its range checks - with a different
//! circuit that has the same public-input shape.
//!
//! Outputs: `vk_manifest`, `pk0_commitment`, `ct0_commitment`, `k1_commitment`, `u_root`.
//! Prove this circuit with the ZK recursive target because its witness contains the private `k1`
//! polynomial.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::configs::default::threshold::{L, N, USER_DATA_ENCRYPTION_CHUNKED_BIT_K};
use lib::core::threshold::user_data_encryption_chunk::{
    compute_ude_vk_manifest, UDE_N_CHUNKS as N_CHUNKS,
    UDE_ROUND_CHILD_KEY_HASHES as ROUND_CHILD_KEY_HASHES, ude_single_root_from_polynomial,
};
use lib::math::commitments::{
    compute_single_polynomial_commitment, DS_USER_DATA_ENCRYPTION_COMMITMENT, UDE_KIND_CT0_K1,
};
use lib::math::polynomial::Polynomial;

global CHUNK_SIZE: u32 = N / N_CHUNKS;

// Both rounds share one output layout: leaf and pk/ct key hashes, pk0 and ct0 commitments, k1/u/e0/r1 roots, then the
// batching coefficients.
global ROUND_LEN: u32 = 8 + L;
global PK0: u32 = 2;
global CT0: u32 = 3;
global K1: u32 = 4;
global U: u32 = 5;
global E0: u32 = 6;
global R1: u32 = 7;
global BATCHING: u32 = 8;

fn main(
    a_vk: UltraHonkVerificationKey,
    a_key_hash: Field,
    a_proof: UltraHonkProof,
    a_public_inputs: [Field; ROUND_LEN],
    b_vk: UltraHonkVerificationKey,
    b_key_hash: Field,
    b_proof: UltraHonkProof,
    b_public_inputs: [Field; ROUND_LEN],
    k1: Polynomial<N>,
) -> pub (Field, Field, Field, Field, Field) {
    verify_honk_proof_non_zk(a_vk, a_proof, a_public_inputs, a_key_hash);
    verify_honk_proof_non_zk(b_vk, b_proof, b_public_inputs, b_key_hash);

    let a = a_public_inputs;
    let b = b_public_inputs;

    assert(a[PK0] == b[PK0], "pk0_commitment mismatch between rounds");
    assert(a[CT0] == b[CT0], "ct0_commitment mismatch between rounds");
    assert(a[K1] == b[K1], "k1 root mismatch between rounds");
    assert(a[U] == b[U], "u root mismatch between rounds");
    assert(a[E0] == b[E0], "e0 root mismatch between rounds");
    assert(a[R1] == b[R1], "r1 root mismatch between rounds");
    // Index 0 is gamma itself: Round A's `ct0_gammas[0]` is gamma, and Round B asserts its
    // `ct0_batching_coeffs[0] == gamma`.
    for i in 0..L {
        assert(a[BATCHING + i] == b[BATCHING + i], "batching-coefficient mismatch between rounds");
    }

    let mut a_children: [Field; ROUND_CHILD_KEY_HASHES] = [0; ROUND_CHILD_KEY_HASHES];
    let mut b_children: [Field; ROUND_CHILD_KEY_HASHES] = [0; ROUND_CHILD_KEY_HASHES];
    for i in 0..ROUND_CHILD_KEY_HASHES {
        a_children[i] = a[i];
        b_children[i] = b[i];
    }
    let vk_manifest = compute_ude_vk_manifest(a_key_hash, a_children, b_key_hash, b_children);

    // Bind the complete polynomial to both recursive rounds before restoring the commitment that
    // CRISP publishes. A chunk root and a whole-polynomial commitment use different transcripts.
    let k1_root = ude_single_root_from_polynomial::<N, N_CHUNKS, CHUNK_SIZE, USER_DATA_ENCRYPTION_CHUNKED_BIT_K>(
        UDE_KIND_CT0_K1,
        k1,
    );
    assert(k1_root == a[K1], "k1 polynomial does not match chunk root");
    let k1_commitment = compute_single_polynomial_commitment::<N, USER_DATA_ENCRYPTION_CHUNKED_BIT_K>(
        k1,
        DS_USER_DATA_ENCRYPTION_COMMITMENT,
    );

    (vk_manifest, a[PK0], a[CT0], k1_commitment, a[U])
}
