// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! DKG aggregator: non-ZK `nodes_fold` and non-ZK `pk_aggregation` (both `noir-recursive-no-zk`).
//! The final `bb prove -t evm` proof of this circuit is what the contract verifies on-chain.
//! `committee_hash_hi` / `committee_hash_lo` bind the proof to `keccak256(abi.encodePacked(topNodes))`
//! (128-bit limbs); the contract recomputes the hash from on-chain `topNodes`.
//!
//! Committee sizing: `committee_members` covers the **full registered committee** of size
//! `N_PARTIES`, matching `topNodes` on-chain. The H folded `party_ids` are indices into that
//! full committee. `H` may be smaller than `N_PARTIES`. Supply `committee_members` in the same
//! order as on-chain `topNodes`; the hash equality pins that order.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::{H, N_PARTIES};
use lib::math::commitments::compute_vk_hash;
use lib::math::committee_hash::committee_hash_limbs;

/// Must match `node_fold::NODE_FOLD_PUBLIC_LEN`.
pub global NODE_FOLD_PUBLIC_LEN: u32 = 11 + N_PARTIES + (2 * (N_PARTIES + H) * L_THRESHOLD);

/// Must match `nodes_fold::NODES_FOLD_PUBLIC_LEN` (pub params + flattened `H` node-fold rows).
pub global NODES_FOLD_PUBLIC_LEN: u32 = 4 + (H * NODE_FOLD_PUBLIC_LEN);

/// Flattened `node_fold` return tuple length (key hash + pks + share grids + agg commits).
pub global NODE_FOLD_RETURN_PUBLIC_LEN: u32 =
    5 + N_PARTIES + (2 * N_PARTIES * L_THRESHOLD) + (2 * H * L_THRESHOLD);

/// Leading `node_fold` public inputs (party id + five key hashes) before the return tuple.
pub global NODE_FOLD_PARAM_PUBLIC_LEN: u32 = NODE_FOLD_PUBLIC_LEN - NODE_FOLD_RETURN_PUBLIC_LEN;

/// Leading `nodes_fold` public inputs before the `H` full `node_fold` rows.
pub global NODES_FOLD_PARAM_PUBLIC_LEN: u32 = NODES_FOLD_PUBLIC_LEN - (H * NODE_FOLD_PUBLIC_LEN);

/// Indices within one `node_fold` public row (length `NODE_FOLD_PUBLIC_LEN`).
pub global NF_PARTY_ID_IDX: u32 = 0;
pub global NF_C0_PK_IDX: u32 = NODE_FOLD_PARAM_PUBLIC_LEN + 1;
pub global NF_C1_PK_IDX: u32 = NODE_FOLD_PARAM_PUBLIC_LEN + 2;
pub global NF_C3_PK_BASE_IDX: u32 = NODE_FOLD_PARAM_PUBLIC_LEN + 3;
pub global NF_C2A_BASE_IDX: u32 = NODE_FOLD_PARAM_PUBLIC_LEN + 3 + N_PARTIES;
pub global NF_C2B_BASE_IDX: u32 = NF_C2A_BASE_IDX + (N_PARTIES * L_THRESHOLD);
pub global NF_C4A_BASE_IDX: u32 = NF_C2B_BASE_IDX + (N_PARTIES * L_THRESHOLD);
pub global NF_C4B_BASE_IDX: u32 = NF_C4A_BASE_IDX + (H * L_THRESHOLD);
pub global NF_SK_AGG_IDX: u32 = NF_C4B_BASE_IDX + (H * L_THRESHOLD);
pub global NF_ESM_AGG_IDX: u32 = NF_SK_AGG_IDX + 1;

fn main(
    nodes_fold_vk: UltraHonkVerificationKey,
    nodes_fold_proof: UltraHonkProof,
    nodes_fold_public: [Field; NODES_FOLD_PUBLIC_LEN],
    c5_vk: UltraHonkVerificationKey,
    c5_proof: UltraHonkProof,
    c5_public: [Field; H + 1],
    nodes_fold_key_hash: pub Field,
    c5_key_hash: pub Field,
    party_ids: pub [Field; H],
    committee_members: [Field; N_PARTIES],
    committee_hash_hi: pub Field,
    committee_hash_lo: pub Field,
) -> pub (Field, [Field; H], [Field; H], Field) {
    let (expected_hi, expected_lo) = committee_hash_limbs(committee_members);
    assert(expected_hi == committee_hash_hi);
    assert(expected_lo == committee_hash_lo);

    // Range-check each folded `party_ids[i]` against the full committee size `N_PARTIES`.
    // This makes `committee_members[party_ids[i]]` a well-defined committee slot and is the
    // structural pre-condition for future per-party signer/identity constraints.
    for i in 0..H {
        let id = party_ids[i] as u32;
        assert(id < N_PARTIES);
    }

    verify_honk_proof_non_zk(
        nodes_fold_vk,
        nodes_fold_proof,
        nodes_fold_public,
        nodes_fold_key_hash,
    );
    verify_honk_proof_non_zk(c5_vk, c5_proof, c5_public, c5_key_hash);

    // Bind each folded `node_fold` row to the aggregator-supplied honest-set ordering: slot 0 per row
    // is the party id (matches `party_ids[i]`).
    for i in 0..H {
        assert(
            nodes_fold_public[NODES_FOLD_PARAM_PUBLIC_LEN
                + i * NODE_FOLD_PUBLIC_LEN
                + NF_PARTY_ID_IDX]
                == party_ids[i],
        );
    }

    assert_selected_c0_c3_links(nodes_fold_public, party_ids);
    assert_selected_c2_c4_links(nodes_fold_public, party_ids);

    // Cross-circuit C5 to `node_fold`: C5 row `i` matches that node's `c1_pk` public field.
    for i in 0..H {
        assert(
            c5_public[i]
                == nodes_fold_public[NODES_FOLD_PARAM_PUBLIC_LEN
                    + i * NODE_FOLD_PUBLIC_LEN
                    + NF_C1_PK_IDX],
        );
    }

    let vk_hashes = [nodes_fold_key_hash, c5_key_hash].as_vector();
    let key_hash = compute_vk_hash(vk_hashes);

    let mut sk_agg_commits: [Field; H] = [0; H];
    let mut esm_agg_commits: [Field; H] = [0; H];
    for i in 0..H {
        sk_agg_commits[i] = nodes_fold_public[NODES_FOLD_PARAM_PUBLIC_LEN
            + i * NODE_FOLD_PUBLIC_LEN
            + NF_SK_AGG_IDX];
        esm_agg_commits[i] = nodes_fold_public[NODES_FOLD_PARAM_PUBLIC_LEN
            + i * NODE_FOLD_PUBLIC_LEN
            + NF_ESM_AGG_IDX];
    }
    let aggregated_pk_commit = c5_public[H];

    (key_hash, sk_agg_commits, esm_agg_commits, aggregated_pk_commit)
}

fn assert_selected_c0_c3_links(
    nodes_fold_public: [Field; NODES_FOLD_PUBLIC_LEN],
    party_ids: [Field; H],
) {
    // C3 recipient slots use full-committee party IDs, not folded row positions.
    for i in 0..H {
        for j in 0..H {
            let recipient_id = party_ids[j] as u32;
            assert(
                nodes_fold_public[NODES_FOLD_PARAM_PUBLIC_LEN
                    + i * NODE_FOLD_PUBLIC_LEN
                    + NF_C3_PK_BASE_IDX
                    + recipient_id]
                    == nodes_fold_public[NODES_FOLD_PARAM_PUBLIC_LEN
                        + j * NODE_FOLD_PUBLIC_LEN
                        + NF_C0_PK_IDX],
            );
        }
    }
}

fn assert_selected_c2_c4_links(
    nodes_fold_public: [Field; NODES_FOLD_PUBLIC_LEN],
    party_ids: [Field; H],
) {
    // C2 recipient slots use full-committee party IDs. C4 sender slots use folded row positions.
    for i in 0..H {
        for j in 0..H {
            let recipient_id = party_ids[j] as u32;
            for l in 0..L_THRESHOLD {
                assert(
                    nodes_fold_public[NODES_FOLD_PARAM_PUBLIC_LEN
                        + j * NODE_FOLD_PUBLIC_LEN
                        + NF_C4A_BASE_IDX
                        + i * L_THRESHOLD
                        + l]
                        == nodes_fold_public[NODES_FOLD_PARAM_PUBLIC_LEN
                            + i * NODE_FOLD_PUBLIC_LEN
                            + NF_C2A_BASE_IDX
                            + recipient_id * L_THRESHOLD
                            + l],
                );
            }
        }
    }

    // Cross-party C2 to C4 (second chain).
    for i in 0..H {
        for j in 0..H {
            let recipient_id = party_ids[j] as u32;
            for l in 0..L_THRESHOLD {
                assert(
                    nodes_fold_public[NODES_FOLD_PARAM_PUBLIC_LEN
                        + j * NODE_FOLD_PUBLIC_LEN
                        + NF_C4B_BASE_IDX
                        + i * L_THRESHOLD
                        + l]
                        == nodes_fold_public[NODES_FOLD_PARAM_PUBLIC_LEN
                            + i * NODE_FOLD_PUBLIC_LEN
                            + NF_C2B_BASE_IDX
                            + recipient_id * L_THRESHOLD
                            + l],
                );
            }
        }
    }
}

#[test]
fn test_non_prefix_c0_c3_links() {
    let (nodes_fold_public, party_ids) = non_prefix_fixture();
    assert_selected_c0_c3_links(nodes_fold_public, party_ids);
}

#[test]
fn test_non_prefix_c2_c4_links() {
    let (nodes_fold_public, party_ids) = non_prefix_fixture();
    assert_selected_c2_c4_links(nodes_fold_public, party_ids);
}

#[test(should_fail)]
fn test_non_prefix_c0_c3_rejects_wrong_recipient() {
    let (mut nodes_fold_public, party_ids) = non_prefix_fixture();
    let recipient_id = party_ids[H - 1] as u32;
    nodes_fold_public[NODES_FOLD_PARAM_PUBLIC_LEN + NF_C3_PK_BASE_IDX + recipient_id] = 0;
    assert_selected_c0_c3_links(nodes_fold_public, party_ids);
}

#[test(should_fail)]
fn test_non_prefix_c2_c4_rejects_wrong_recipient() {
    let (mut nodes_fold_public, party_ids) = non_prefix_fixture();
    let recipient_id = party_ids[H - 1] as u32;
    nodes_fold_public[NODES_FOLD_PARAM_PUBLIC_LEN + NF_C2A_BASE_IDX + recipient_id * L_THRESHOLD] =
        0;
    assert_selected_c2_c4_links(nodes_fold_public, party_ids);
}

fn non_prefix_fixture() -> ([Field; NODES_FOLD_PUBLIC_LEN], [Field; H]) {
    assert(H < N_PARTIES);
    let mut party_ids: [Field; H] = [0; H];
    for row in 0..H {
        party_ids[row] = row as Field;
    }
    party_ids[H - 1] = (N_PARTIES - 1) as Field;

    let mut nodes_fold_public: [Field; NODES_FOLD_PUBLIC_LEN] = [0; NODES_FOLD_PUBLIC_LEN];
    for row in 0..H {
        let base = NODES_FOLD_PARAM_PUBLIC_LEN + row * NODE_FOLD_PUBLIC_LEN;
        nodes_fold_public[base + NF_PARTY_ID_IDX] = party_ids[row];
        nodes_fold_public[base + NF_C0_PK_IDX] = 100 + party_ids[row];
    }

    for sender_row in 0..H {
        let sender_base = NODES_FOLD_PARAM_PUBLIC_LEN + sender_row * NODE_FOLD_PUBLIC_LEN;
        for recipient_row in 0..H {
            let recipient_id = party_ids[recipient_row] as u32;
            let recipient_base = NODES_FOLD_PARAM_PUBLIC_LEN + recipient_row * NODE_FOLD_PUBLIC_LEN;
            nodes_fold_public[sender_base + NF_C3_PK_BASE_IDX + recipient_id] =
                nodes_fold_public[recipient_base + NF_C0_PK_IDX];

            for l in 0..L_THRESHOLD {
                let c2_slot = recipient_id * L_THRESHOLD + l;
                let c4_slot = sender_row * L_THRESHOLD + l;
                let value = (1000 + sender_row * N_PARTIES * L_THRESHOLD + c2_slot) as Field;
                nodes_fold_public[sender_base + NF_C2A_BASE_IDX + c2_slot] = value;
                nodes_fold_public[recipient_base + NF_C4A_BASE_IDX + c4_slot] = value;
                nodes_fold_public[sender_base + NF_C2B_BASE_IDX + c2_slot] = value + 1000;
                nodes_fold_public[recipient_base + NF_C4B_BASE_IDX + c4_slot] = value + 1000;
            }
        }
    }

    (nodes_fold_public, party_ids)
}
