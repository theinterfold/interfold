// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Per-node fold: C0, C1, `c2ab_fold`, `c3ab_fold`, `c4ab_fold` with same-party assertions.

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
    verify_honk_proof_non_zk,
};
use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::{H, N_PARTIES};
use lib::math::commitments::compute_vk_hash;

pub global C2_PUBLIC_LEN: u32 = 1 + (N_PARTIES * L_THRESHOLD);
pub global C2AB_FOLD_PUBLIC_LEN: u32 = 3 + (2 * C2_PUBLIC_LEN);
/// One slot per (party, threshold-modulus) pair - must match `c3ab_fold::C3AB_FOLD_PUBLIC_LEN`.
pub global C3_SLOTS: u32 = N_PARTIES * L_THRESHOLD;
pub global C3AB_FOLD_PUBLIC_LEN: u32 = 2 + 1 + (6 * C3_SLOTS);
/// Prefix (two inner key hashes + combined hash) before six `C3_SLOTS` columns in `c3ab_fold` public IO.
pub global C3AB_PREFIX_LEN: u32 = C3AB_FOLD_PUBLIC_LEN - (6 * C3_SLOTS);
pub global C4_PUBLIC_LEN: u32 = (H * L_THRESHOLD) + 1;
pub global C4AB_FOLD_PUBLIC_LEN: u32 = 3 + (2 * C4_PUBLIC_LEN);

/// Key-hash prefix length in `c2ab_fold` / `c4ab_fold` flattened public IO.
pub global C2AB_PREFIX_LEN: u32 = C2AB_FOLD_PUBLIC_LEN - (2 * C2_PUBLIC_LEN);
pub global C4AB_PREFIX_LEN: u32 = C4AB_FOLD_PUBLIC_LEN - (2 * C4_PUBLIC_LEN);

/// Inner C2 / C4 column offsets inside `c2ab_public` / `c4ab_public`
/// (parallel to `NF_*` in `dkg_aggregator`; keep in sync).
pub global C2A_INNER_START: u32 = C2AB_PREFIX_LEN;
pub global C2B_INNER_START: u32 = C2AB_PREFIX_LEN + C2_PUBLIC_LEN;
pub global C2A_SHARES_START: u32 = C2A_INNER_START + 1;
pub global C2B_SHARES_START: u32 = C2B_INNER_START + 1;

pub global C4A_INNER_START: u32 = C4AB_PREFIX_LEN;
pub global C4B_INNER_START: u32 = C4AB_PREFIX_LEN + C4_PUBLIC_LEN;
pub global SK_AGG_INDEX: u32 = C4A_INNER_START + (H * L_THRESHOLD);
pub global ESM_AGG_INDEX: u32 = C4B_INNER_START + (H * L_THRESHOLD);

/// `c3ab_fold` flattened tail: pk_a, msg_a, ct_a, pk_b, msg_b, ct_b - each `C3_SLOTS` long.
pub global C3AB_PK_A_START: u32 = C3AB_PREFIX_LEN;
pub global C3AB_MSG_A_START: u32 = C3AB_PREFIX_LEN + C3_SLOTS;
pub global C3AB_PK_B_START: u32 = C3AB_PREFIX_LEN + (3 * C3_SLOTS);
pub global C3AB_MSG_B_START: u32 = C3AB_PREFIX_LEN + (4 * C3_SLOTS);

/// Total public parameters + outputs for `node_fold`.
pub global NODE_FOLD_PUBLIC_LEN: u32 = 11 + N_PARTIES + (2 * (N_PARTIES + H) * L_THRESHOLD);

/// Constrains the C3 recipient keys that the fold later reduces to one key per recipient.
///
/// Two things must hold. `pk_a[j*L+l] == pk_b[j*L+l]` keeps the key consistent across both folded C3
/// chains, and every limb of a recipient's key must equal its **limb-zero** key — because limb zero
/// is the only one exported below, and `dkg_aggregator` links just that one to the recipient's C0
/// key.
///
/// Without the second check a prover puts the correct key in limb zero and a different key in a
/// later limb, matching in C3a and C3b so the first check still passes. The exported key would then
/// not represent what the other limbs encrypted to, and the recursive statement would not establish
/// that every encrypted limb targets the intended recipient. Both presets have more than one
/// threshold limb, so neither is exempt.
///
/// The node's own slot is excluded for the same reason as the C2-to-C3 binding: it is not
/// C3-encrypted, and its key is taken from C0 rather than from these slots.
fn assert_c3_recipient_keys(party_id: Field, c3ab_public: [Field; C3AB_FOLD_PUBLIC_LEN]) {
    for j in 0..N_PARTIES {
        for l in 0..L_THRESHOLD {
            let slot = j * L_THRESHOLD + l;
            assert(c3ab_public[C3AB_PK_A_START + slot] == c3ab_public[C3AB_PK_B_START + slot]);

            if (party_id != (j as Field)) & (l != 0) {
                assert(
                    c3ab_public[C3AB_PK_A_START + slot]
                        == c3ab_public[C3AB_PK_A_START + j * L_THRESHOLD],
                );
            }
        }
    }
}

fn main(
    c0_vk: UltraHonkVerificationKey,
    c0_proof: UltraHonkZKProof,
    c0_public: [Field; 1],
    c1_vk: UltraHonkVerificationKey,
    c1_proof: UltraHonkZKProof,
    c1_public: [Field; 3],
    c2ab_vk: UltraHonkVerificationKey,
    c2ab_proof: UltraHonkProof,
    c2ab_public: [Field; C2AB_FOLD_PUBLIC_LEN],
    c3ab_vk: UltraHonkVerificationKey,
    c3ab_proof: UltraHonkProof,
    c3ab_public: [Field; C3AB_FOLD_PUBLIC_LEN],
    c4ab_vk: UltraHonkVerificationKey,
    c4ab_proof: UltraHonkProof,
    c4ab_public: [Field; C4AB_FOLD_PUBLIC_LEN],
    // Bound to sortition slot via `NF_PARTY_ID_IDX` in `dkg_aggregator`; do not rename.
    party_id: pub Field,
    c0_key_hash: pub Field,
    c1_key_hash: pub Field,
    c2ab_key_hash: pub Field,
    c3ab_key_hash: pub Field,
    c4ab_key_hash: pub Field,
    ) -> pub (Field, Field, Field, [Field; N_PARTIES], [[Field; L_THRESHOLD]; N_PARTIES], [[Field; L_THRESHOLD]; N_PARTIES], [[Field; L_THRESHOLD]; H], [[Field; L_THRESHOLD]; H], Field, Field) {
    verify_honk_proof(c0_vk, c0_proof, c0_public, c0_key_hash);
    verify_honk_proof(c1_vk, c1_proof, c1_public, c1_key_hash);
    verify_honk_proof_non_zk(c2ab_vk, c2ab_proof, c2ab_public, c2ab_key_hash);
    verify_honk_proof_non_zk(c3ab_vk, c3ab_proof, c3ab_public, c3ab_key_hash);
    verify_honk_proof_non_zk(c4ab_vk, c4ab_proof, c4ab_public, c4ab_key_hash);

    let vk_hashes =
        [c0_key_hash, c1_key_hash, c2ab_key_hash, c3ab_key_hash, c4ab_key_hash].as_vector();
    let key_hash = compute_vk_hash(vk_hashes);

    // C0: `commit(pk_dkg)` (DKG key for C3). C1[1]: `commit(pk_trbfv)` (threshold key); not equal to C0.
    let c0_pk = c0_public[0];
    let c1_pk = c1_public[1];

    // Same-party C1 to C2: `c2ab_public` lays out two full C2 public vectors after a 3-field
    // prefix (`C2AB_FOLD_PUBLIC_LEN` = 3 + 2 * `C2_PUBLIC_LEN`). For each inner C2 block, index 0
    // is `expected_secret_commitment`; these equal C1's sk- and e_sm-side public inputs [0] and [2].
    assert(c1_public[0] == c2ab_public[C2A_INNER_START]);
    assert(c1_public[2] == c2ab_public[C2B_INNER_START]);

    assert_c3_recipient_keys(party_id, c3ab_public);

    // C2 to C3: encrypted recipient slots must be bound - msg_a[j*L+l] == c2a_shares[j][l]
    // and msg_b[j*L+l] == c2b_shares[j][l]. The node's own slot is intentionally not
    // C3-encrypted; it is bound through the C4 plaintext/decryption path instead.
    // c3ab layout: key-hash prefix, then pk_a, msg_a, ct_a, pk_b, msg_b, ct_b (`C3_SLOTS` each).
    // c2ab layout: see `C2AB_PREFIX_LEN` / `C2_PUBLIC_LEN`.
    for j in 0..N_PARTIES {
        for l in 0..L_THRESHOLD {
            if party_id != (j as Field) {
                let slot = j * L_THRESHOLD + l;
                assert(
                    c2ab_public[C2A_SHARES_START + slot] == c3ab_public[C3AB_MSG_A_START + slot],
                );
                assert(
                    c2ab_public[C2B_SHARES_START + slot] == c3ab_public[C3AB_MSG_B_START + slot],
                );
            }
        }
    }

    let mut c3_pk: [Field; N_PARTIES] = [0; N_PARTIES];
    for j in 0..N_PARTIES {
        if party_id == (j as Field) {
            c3_pk[j] = c0_pk;
        } else {
            // pk is per-party (same DKG key across all moduli of the same recipient): use slot j*L+0.
            c3_pk[j] = c3ab_public[C3AB_PK_A_START + j * L_THRESHOLD];
        }
    }

    let mut c2a: [[Field; L_THRESHOLD]; N_PARTIES] = [[0; L_THRESHOLD]; N_PARTIES];
    let mut c2b: [[Field; L_THRESHOLD]; N_PARTIES] = [[0; L_THRESHOLD]; N_PARTIES];
    for j in 0..N_PARTIES {
        for l in 0..L_THRESHOLD {
            c2a[j][l] = c2ab_public[C2A_SHARES_START + j * L_THRESHOLD + l];
            c2b[j][l] = c2ab_public[C2B_SHARES_START + j * L_THRESHOLD + l];
        }
    }

    let mut c4a_exp: [[Field; L_THRESHOLD]; H] = [[0; L_THRESHOLD]; H];
    let mut c4b_exp: [[Field; L_THRESHOLD]; H] = [[0; L_THRESHOLD]; H];
    for h in 0..H {
        for l in 0..L_THRESHOLD {
            c4a_exp[h][l] = c4ab_public[C4A_INNER_START + h * L_THRESHOLD + l];
            c4b_exp[h][l] = c4ab_public[C4B_INNER_START + h * L_THRESHOLD + l];
        }
    }
    let sk_agg = c4ab_public[SK_AGG_INDEX];
    let esm_agg = c4ab_public[ESM_AGG_INDEX];

    (key_hash, c0_pk, c1_pk, c3_pk, c2a, c2b, c4a_exp, c4b_exp, sk_agg, esm_agg)
}

/// Builds C3 public inputs where every recipient key is limb-consistent, as an honest prover's are.
#[test]
fn consistent_c3_recipient_keys_are_accepted() {
    let mut c3ab: [Field; C3AB_FOLD_PUBLIC_LEN] = [0; C3AB_FOLD_PUBLIC_LEN];
    for j in 0..N_PARTIES {
        for l in 0..L_THRESHOLD {
            let slot = j * L_THRESHOLD + l;
            // One key per recipient, repeated across that recipient's limbs.
            c3ab[C3AB_PK_A_START + slot] = (j as Field) + 1000;
            c3ab[C3AB_PK_B_START + slot] = (j as Field) + 1000;
        }
    }
    assert_c3_recipient_keys(0, c3ab);
}

/// A different key in a nonzero limb is rejected, even though it matches between C3a and C3b.
///
/// This is the substitution the fold previously accepted: limb zero carries the recipient's real
/// key — the only one exported and linked to their C0 key — while a later limb encrypts to a key of
/// the prover's choosing. Matching it across C3a and C3b satisfied the one check that existed.
#[test(should_fail)]
fn divergent_nonzero_limb_c3_key_is_rejected() {
    let mut c3ab: [Field; C3AB_FOLD_PUBLIC_LEN] = [0; C3AB_FOLD_PUBLIC_LEN];
    for j in 0..N_PARTIES {
        for l in 0..L_THRESHOLD {
            let slot = j * L_THRESHOLD + l;
            c3ab[C3AB_PK_A_START + slot] = (j as Field) + 1000;
            c3ab[C3AB_PK_B_START + slot] = (j as Field) + 1000;
        }
    }
    // Recipient 1, limb 1: swapped in both chains so the C3a/C3b check still passes.
    let tampered = C3AB_PK_A_START + 1 * L_THRESHOLD + 1;
    let tampered_b = C3AB_PK_B_START + 1 * L_THRESHOLD + 1;
    c3ab[tampered] = 999999;
    c3ab[tampered_b] = 999999;

    assert_c3_recipient_keys(0, c3ab);
}

/// The node's own slot stays unconstrained, since its key comes from C0 rather than these slots.
#[test]
fn self_recipient_limbs_may_differ() {
    let mut c3ab: [Field; C3AB_FOLD_PUBLIC_LEN] = [0; C3AB_FOLD_PUBLIC_LEN];
    for j in 0..N_PARTIES {
        for l in 0..L_THRESHOLD {
            let slot = j * L_THRESHOLD + l;
            c3ab[C3AB_PK_A_START + slot] = (j as Field) + 1000;
            c3ab[C3AB_PK_B_START + slot] = (j as Field) + 1000;
        }
    }
    // Party 2 is the node itself here; its own slots are not C3-encrypted.
    c3ab[C3AB_PK_A_START + 2 * L_THRESHOLD + 1] = 7;
    c3ab[C3AB_PK_B_START + 2 * L_THRESHOLD + 1] = 7;

    assert_c3_recipient_keys(2, c3ab);
}
