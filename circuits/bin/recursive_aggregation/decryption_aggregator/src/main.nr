// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Decryption aggregator: non-ZK `c6_fold` (folded C6 column) + non-ZK `decrypted_shares_aggregation`
//! (C7, both `noir-recursive-no-zk`). The final `bb prove -t evm` proof of this circuit is what the
//! contract verifies on-chain.
//! `committee_hash_hi` / `committee_hash_lo` bind the proof to the full on-chain committee ordering.
//!
//! Committee sizing: `committee_members` covers the **full registered committee** of size
//! `N_PARTIES`, matching `topNodes` on-chain. The `T + 1` participating `party_ids` (extracted
//! from the inner C7 proof) are indices into that full committee. `committee_members` must be
//! supplied in the same order as on-chain `topNodes`; the hash equality pins that order.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::configs::default::MAX_MSG_NON_ZERO_COEFFS;
use lib::configs::default::N_PARTIES;
use lib::configs::default::T;
use lib::math::commitments::compute_vk_hash;
use lib::math::committee_hash::committee_hash_limbs;

/// Must match `c6_fold::C6_FOLD_PUBLIC_LEN`: pub params, common domain limbs,
/// and flattened `(out_sk, out_esm, out_ct, out_d)`.
pub global C6_KEY_SLOTS: u32 = (T + 1) * N_PARTIES;
pub global C6_FOLD_PUBLIC_LEN: u32 = 6 + (5 * (T + 1)) + (2 * C6_KEY_SLOTS);

pub global C6_FOLD_PREFIX_LEN: u32 = 6;

/// Column offsets inside the `c6_fold` flattened tail (after `C6_FOLD_PREFIX_LEN`):
/// `(out_sk, out_esm, out_ct, out_d)`, each `C6_FOLD_COL_WIDTH = T + 1` long.
pub global C6_FOLD_COL_WIDTH: u32 = T + 1;
pub global C6_FOLD_SK_COL_OFFSET: u32 = 0;
pub global C6_FOLD_ESM_COL_OFFSET: u32 = C6_FOLD_COL_WIDTH;
pub global C6_FOLD_CT_COL_OFFSET: u32 = 2 * C6_FOLD_COL_WIDTH;
pub global C6_FOLD_D_COL_OFFSET: u32 = 3 * C6_FOLD_COL_WIDTH;

/// `c7_public` layout: `[expected_d_commitments | party_ids | message]`.
pub global C7_D_COMMITMENT_OFFSET: u32 = 0;
pub global C7_PARTY_ID_OFFSET: u32 = T + 1;
pub global C7_MESSAGE_OFFSET: u32 = 2 * (T + 1);

pub global C7_PUBLIC_LEN: u32 = (2 * (T + 1)) + MAX_MSG_NON_ZERO_COEFFS + 1;

/// Validates a single circuit-side `party_id`: must be a 1-indexed Shamir x-coordinate
/// in `[1, N_PARTIES]`. `x=0` is reserved for the secret itself (see DKG
/// `share_computation.nr`'s `y[...][party_idx + 1]`) and must never be accepted as a
/// participating share. Returns the `u32` cast for reuse by the caller (e.g. the
/// strictly-increasing check below), avoiding a second `Field -> u32` cast.
fn assert_valid_party_id(id: Field) -> u32 {
    let id_u32 = id as u32;
    assert(id_u32 >= 1);
    assert(id_u32 <= N_PARTIES);
    id_u32
}

/// Asserts `curr > prev`. Used to force the `T + 1` reconstructing `party_ids` to be
/// strictly increasing, which (a) implies distinctness -- no party's share can occupy
/// two reconstruction slots, which would let a single real share masquerade as T+1
/// independent contributions and silently defeat the T+1 honest-party threshold -- and
/// (b) matches the ordering `decrypted_shares_aggregation.nr`'s own Lagrange
/// sign-computation already assumes but never enforced.
fn assert_strictly_increasing(prev: u32, curr: u32) {
    assert(curr > prev);
}

fn main(
    c6_fold_vk: UltraHonkVerificationKey,
    c6_fold_proof: UltraHonkProof,
    c6_fold_public: [Field; C6_FOLD_PUBLIC_LEN],
    c7_vk: UltraHonkVerificationKey,
    c7_proof: UltraHonkProof,
    c7_public: [Field; C7_PUBLIC_LEN],
    c6_fold_key_hash: pub Field,
    c7_key_hash: pub Field,
    committee_members: [Field; N_PARTIES],
    committee_hash_hi: pub Field,
    committee_hash_lo: pub Field,
    domain_hi: pub Field,
    domain_lo: pub Field,
    ciphertext_commitment: pub Field,
) -> pub (Field, [Field; T + 1], [Field; T + 1], [Field; T + 1], [Field; MAX_MSG_NON_ZERO_COEFFS], [Field; C6_KEY_SLOTS], [Field; C6_KEY_SLOTS]) {
    let (expected_hi, expected_lo) = committee_hash_limbs(committee_members);
    assert(expected_hi == committee_hash_hi);
    assert(expected_lo == committee_hash_lo);

    verify_honk_proof_non_zk(c6_fold_vk, c6_fold_proof, c6_fold_public, c6_fold_key_hash);
    verify_honk_proof_non_zk(c7_vk, c7_proof, c7_public, c7_key_hash);

    // The C6 fold only accepts secret-bearing leaf proofs carrying one common
    // domain. Expose that domain in the final EVM proof for on-chain checking.
    assert(c6_fold_public[4] == domain_hi);
    assert(c6_fold_public[5] == domain_lo);

    // Every C6 leaf commits to the same decoded BFV ciphertext. Expose that
    // canonical commitment as a final public input for the EVM wrapper.
    let c0_commitment = c7_public[C7_PUBLIC_LEN - 1];
    for i in 0..(T + 1) {
        assert(
            c6_fold_public[C6_FOLD_PREFIX_LEN + C6_FOLD_CT_COL_OFFSET + i] == ciphertext_commitment,
        );
        assert(
            c6_fold_public[C6_FOLD_PREFIX_LEN + C6_FOLD_ESM_COL_OFFSET + i] == c0_commitment,
        );
    }

    // Cross-circuit C6 to C7: each folded `d_commitment` column entry must match `c7_public[i]`
    // (leading `T + 1` words of `c7_public`).
    for i in 0..(T + 1) {
        assert(
            c6_fold_public[C6_FOLD_PREFIX_LEN + C6_FOLD_D_COL_OFFSET + i]
                == c7_public[C7_D_COMMITMENT_OFFSET + i],
        );
    }

    let vk_hashes = [c6_fold_key_hash, c7_key_hash].as_vector();
    let key_hash = compute_vk_hash(vk_hashes);

    let mut party_ids: [Field; T + 1] = [0; T + 1];
    let mut expected_sk: [Field; T + 1] = [0; T + 1];
    let mut expected_esm: [Field; T + 1] = [0; T + 1];
    let mut prev_party_id: u32 = 0;
    for i in 0..(T + 1) {
        party_ids[i] = c7_public[C7_PARTY_ID_OFFSET + i];
        expected_sk[i] = c6_fold_public[C6_FOLD_PREFIX_LEN + C6_FOLD_SK_COL_OFFSET + i];
        expected_esm[i] = c6_fold_public[C6_FOLD_PREFIX_LEN + C6_FOLD_ESM_COL_OFFSET + i];

        // `committee_members` and `topNodes` are 0-indexed; a future per-party
        // signer/identity check must index them with `committee_members[party_ids[i] - 1]`,
        // not `party_ids[i]` (which is a 1-indexed Shamir x-coordinate -- see
        // `assert_valid_party_id`).
        let id_u32 = assert_valid_party_id(party_ids[i]);
        if i > 0 {
            assert_strictly_increasing(prev_party_id, id_u32);
        }
        prev_party_id = id_u32;
    }

    let mut message: [Field; MAX_MSG_NON_ZERO_COEFFS] = [0; MAX_MSG_NON_ZERO_COEFFS];
    for k in 0..MAX_MSG_NON_ZERO_COEFFS {
        message[k] = c7_public[C7_MESSAGE_OFFSET + k];
    }

    let key_base = C6_FOLD_PREFIX_LEN + (4 * (T + 1));
    let mut outgoing_keys: [Field; C6_KEY_SLOTS] = [0; C6_KEY_SLOTS];
    let mut incoming_keys: [Field; C6_KEY_SLOTS] = [0; C6_KEY_SLOTS];
    for i in 0..C6_KEY_SLOTS {
        outgoing_keys[i] = c6_fold_public[key_base + i];
        incoming_keys[i] = c6_fold_public[key_base + C6_KEY_SLOTS + i];
    }
    let decryptor_base = key_base + (2 * C6_KEY_SLOTS);
    for i in 0..(T + 1) {
        assert(c6_fold_public[decryptor_base + i] == party_ids[i]);
    }

    (
        key_hash, party_ids, expected_sk, expected_esm, message, outgoing_keys, incoming_keys,
    )
}

// ------------------------------ TESTS ------------------------------

#[test]
fn test_party_id_min_valid() {
    let _ = assert_valid_party_id(1);
}

#[test]
fn test_party_id_max_valid() {
    let _ = assert_valid_party_id(N_PARTIES as Field);
}

#[test(should_fail)]
fn test_party_id_zero_rejected() {
    // x=0 is the secret's own evaluation point, never a valid share -- this is the
    // exact value the old `id < N_PARTIES` bound wrongly admitted.
    let _ = assert_valid_party_id(0);
}

#[test(should_fail)]
fn test_party_id_above_n_parties_rejected() {
    let _ = assert_valid_party_id((N_PARTIES + 1) as Field);
}

#[test]
fn test_strictly_increasing_accepts_ascending_pair() {
    assert_strictly_increasing(1, 2);
}

#[test(should_fail)]
fn test_strictly_increasing_rejects_duplicate() {
    // The exact attack this closes: the same party's share occupying two
    // reconstruction slots, letting one real share masquerade as two.
    assert_strictly_increasing(3, 3);
}

#[test(should_fail)]
fn test_strictly_increasing_rejects_descending_pair() {
    assert_strictly_increasing(5, 2);
}
