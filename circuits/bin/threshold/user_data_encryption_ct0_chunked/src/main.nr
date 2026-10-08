// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Top-level ct0 (P3). The leg is five proofs:
//! - `ct0_chunk_main` (leaf): range-checks and commits `u`/`e0`/`k1`/`r1is`, derives the challenge
//!   from those commitments and the `pk0`/`ct0` commitments, and evaluates the witness at it;
//! - `ct0_pk_ct_commit`: pins `ct0is` to centered residues, commits it, evaluates it;
//! - `ct0_eval_pk_ct`: commits `pk0is` and evaluates `pk0 * u mod X^N + 1` via `negacyclic_kernel`;
//! - `ct0_eval_chunk_identity`: verifies the leaf and the pk circuit, binds `pk0` and `u`, and
//!   evaluates the batched right-hand side of the reduced identity;
//! - this circuit: verifies the identity and ciphertext proofs, requires the ciphertext circuit's
//!   commitment and challenge to be the leaf's, and checks the batched identity
//!   `sum_i gamma_i * ct0[i](gamma) == rhs`.
//!
//! Every term of the reduced identity is bounded (ct0 and pk0 centered, u trinary, e0 and k1 by
//! their leaf bounds, r1 by its reduced bound), so the field equality implies the integer one.
//!
//! It also closes VK binding for the leg: it folds the identity, leaf, pk and ciphertext key
//! hashes into one manifest and outputs it first. The wrapper folds the manifest into the value
//! that the verifier checks against a deployment anchor. Without it, a prover could replace any
//! circuit below this one - for example a leaf without its range checks - with a different circuit
//! that has the same public-input shape.
//!
//! Outputs: `vk_manifest`, `pk0_commitment`, `ct0_commitment`, `k1_commitment`, `u_root`.
//! Prove this circuit with the ZK recursive target because its witness contains the private `k1`
//! polynomial.

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
    verify_honk_proof_non_zk,
};
use lib::configs::default::threshold::{L, N, USER_DATA_ENCRYPTION_CHUNKED_BIT_K};
use lib::core::threshold::user_data_encryption_chunk::{
    compute_ude_vk_manifest, UDE_N_CHUNKS, ude_single_root_from_polynomial,
};
use lib::math::commitments::{
    compute_single_polynomial_commitment, DS_USER_DATA_ENCRYPTION_COMMITMENT, UDE_KIND_CT0_K1,
};
use lib::math::polynomial::Polynomial;

// Identity outputs: leaf and pk key hashes, pk0 and ct0 commitments, k1/u/e0/r1 roots, gammas[L],
// the batched right-hand side.
global IDENTITY_LEN: u32 = 9 + L;
global LEAF_KEY_HASH: u32 = 0;
global PK_KEY_HASH: u32 = 1;
global PK0: u32 = 2;
global CT0: u32 = 3;
global K1: u32 = 4;
global U: u32 = 5;
global GAMMAS: u32 = 8;
global RHS: u32 = 8 + L;
// Ciphertext circuit public inputs: gamma, ct0 commitment, ct0(gamma)[L].
global CT_LEN: u32 = 2 + L;

fn main(
    identity_vk: UltraHonkVerificationKey,
    identity_key_hash: Field,
    identity_proof: UltraHonkProof,
    identity_public_inputs: [Field; IDENTITY_LEN],
    ct_vk: UltraHonkVerificationKey,
    ct_key_hash: Field,
    ct_proof: UltraHonkZKProof,
    ct_public_inputs: [Field; CT_LEN],
    k1: Polynomial<N>,
) -> pub (Field, Field, Field, Field, Field) {
    verify_honk_proof_non_zk(
        identity_vk,
        identity_proof,
        identity_public_inputs,
        identity_key_hash,
    );
    verify_honk_proof(ct_vk, ct_proof, ct_public_inputs, ct_key_hash);

    let id = identity_public_inputs;
    assert(ct_public_inputs[0] == id[GAMMAS], "gamma mismatch between leaf and ciphertext");
    assert(ct_public_inputs[1] == id[CT0], "ct0_commitment mismatch between leaf and ciphertext");

    let mut lhs = 0;
    for i in 0..L {
        let gamma_i = if i == 0 { 1 } else { id[GAMMAS + i] };
        lhs += ct_public_inputs[2 + i] * gamma_i;
    }
    assert(lhs == id[RHS], "ct0 encryption check failed");

    let vk_manifest = compute_ude_vk_manifest(
        identity_key_hash,
        id[LEAF_KEY_HASH],
        id[PK_KEY_HASH],
        ct_key_hash,
    );

    // Bind the complete polynomial to the leaf's root before restoring the commitment that the
    // wrapper publishes. A chunk root and a whole-polynomial commitment use different transcripts.
    let k1_root = ude_single_root_from_polynomial::<N, UDE_N_CHUNKS, N, USER_DATA_ENCRYPTION_CHUNKED_BIT_K>(
        UDE_KIND_CT0_K1,
        k1,
    );
    assert(k1_root == id[K1], "k1 polynomial does not match the leaf's root");
    let k1_commitment = compute_single_polynomial_commitment::<N, USER_DATA_ENCRYPTION_CHUNKED_BIT_K>(
        k1,
        DS_USER_DATA_ENCRYPTION_COMMITMENT,
    );

    (vk_manifest, id[PK0], id[CT0], k1_commitment, id[U])
}
