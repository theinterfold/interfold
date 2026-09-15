// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Top-level ct0 (P3). Proving ct0 in a single circuit does not fit the browser's ~2M gate
//! ceiling at N=16384, L=5, so its work is split by coefficient-level chunking into one merged
//! grid - `u`/`e0`/`k1`/`r2is`/`r1is` together, 2 chunks - each chunk range-checked independently
//! and combined through a two-level tree (max 2 recursive verifications per circuit):
//! `ct0_chunk_main` (leaves, 2 instances) -> `ct0_chunk_main_root` (verifies both leaves
//! directly, no intermediate pair level) + separate `ct0_pk_ct_commit` (commits `pk0is` and
//! `ct0is` together) -> `ct0_chunk_gamma` (verifies `ct0_chunk_main_root` and
//! `ct0_pk_ct_commit`, derives gamma). Round B (`ct0_eval_chunk_*`) mirrors this shape to
//! evaluate every chunk at gamma and sum the partial evaluations, converging on
//! `ct0_eval_chunk_identity` (the actual Schwartz-Zippel identity check).
//!
//! This circuit verifies both final proofs and checks every commitment and batching coefficient
//! they produced agree - closing the binding that stops a prover from range-checking one witness
//! in Round A and evaluating a different, unconstrained one in Round B.
//!
//! It also closes VK binding for the tree. Each round outputs the key hashes of its root, leaf,
//! and pk/ct circuits. This circuit folds those six values and its own two child key hashes into
//! one VK manifest, and outputs the manifest first. The wrapper folds the manifest into the value
//! that the verifier checks against a deployment anchor. Without the manifest, a prover could
//! replace any circuit below this one - for example a leaf without its range checks - with a
//! different circuit that has the same public-input shape.
//!
//! Outputs: `vk_manifest`, `pk0_commitment`, `ct0_commitment`, `k1_root`, `u_root`.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::configs::default::threshold::L;
use lib::core::threshold::user_data_encryption_chunk::{
    compute_ude_vk_manifest, UDE_ROUND_CHILD_KEY_HASHES,
};

// Both rounds share one output layout: 3 key hashes (root, leaf, pk/ct), `pk0`, `ct0`, `k1`, `u`,
// `e0`, `r2`, `r1`, then the L batching coefficients (Round A: `ct0_gammas`).
global ROUND_LEN: u32 = 10 + L;
global PK0: u32 = 3;
global CT0: u32 = 4;
global K1: u32 = 5;
global U: u32 = 6;
global E0: u32 = 7;
global R2: u32 = 8;
global R1: u32 = 9;
global BATCHING: u32 = 10;

fn main(
    a_vk: UltraHonkVerificationKey,
    a_key_hash: Field,
    a_proof: UltraHonkProof,
    a_public_inputs: [Field; ROUND_LEN],
    b_vk: UltraHonkVerificationKey,
    b_key_hash: Field,
    b_proof: UltraHonkProof,
    b_public_inputs: [Field; ROUND_LEN],
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
    assert(a[R2] == b[R2], "r2 root mismatch between rounds");
    assert(a[R1] == b[R1], "r1 root mismatch between rounds");
    // Index 0 is gamma itself: Round A's `ct0_gammas[0]` is gamma, and Round B asserts its
    // `ct0_batching_coeffs[0] == gamma`.
    for i in 0..L {
        assert(a[BATCHING + i] == b[BATCHING + i], "batching-coefficient mismatch between rounds");
    }

    let mut a_children: [Field; UDE_ROUND_CHILD_KEY_HASHES] = [0; UDE_ROUND_CHILD_KEY_HASHES];
    let mut b_children: [Field; UDE_ROUND_CHILD_KEY_HASHES] = [0; UDE_ROUND_CHILD_KEY_HASHES];
    for i in 0..UDE_ROUND_CHILD_KEY_HASHES {
        a_children[i] = a[i];
        b_children[i] = b[i];
    }
    let vk_manifest = compute_ude_vk_manifest(a_key_hash, a_children, b_key_hash, b_children);

    (vk_manifest, a[PK0], a[CT0], a[K1], a[U])
}
