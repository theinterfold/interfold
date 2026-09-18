// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Verify the V2 node fold, legacy C5, and secure-16384 l-BFV aggregation fold.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use keccak256::keccak256;
use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::{H, N_PARTIES};
use lib::math::commitments::compute_vk_hash;
use lib::math::committee_hash::committee_hash_limbs;

pub global LBFV_ROWS: u32 = 5;

pub global NODE_FOLD_PUBLIC_LEN: u32 = 14 + N_PARTIES + (2 * (N_PARTIES + H) * L_THRESHOLD);
pub global NODE_FOLD_V2_APPEND_LEN: u32 = 3 + (3 * LBFV_ROWS);
pub global NODE_FOLD_V2_PREFIX_LEN: u32 = 4;
pub global NODE_FOLD_V2_PUBLIC_LEN: u32 =
    NODE_FOLD_V2_PREFIX_LEN + NODE_FOLD_PUBLIC_LEN + NODE_FOLD_V2_APPEND_LEN;
pub global NODES_FOLD_V2_PREFIX_LEN: u32 = 6;
pub global NODES_FOLD_V2_PUBLIC_LEN: u32 = NODES_FOLD_V2_PREFIX_LEN + (H * NODE_FOLD_V2_PUBLIC_LEN);

pub global NODE_FOLD_RETURN_PUBLIC_LEN: u32 =
    8 + N_PARTIES + (2 * N_PARTIES * L_THRESHOLD) + (2 * H * L_THRESHOLD);
pub global NODE_FOLD_PARAM_PUBLIC_LEN: u32 = NODE_FOLD_PUBLIC_LEN - NODE_FOLD_RETURN_PUBLIC_LEN;

pub global NF_PARTY_ID_IDX: u32 = NODE_FOLD_V2_PREFIX_LEN;
pub global NF_C2A_CHUNK_HASH_IDX: u32 = NODE_FOLD_V2_PREFIX_LEN + NODE_FOLD_PARAM_PUBLIC_LEN + 1;
pub global NF_C2B_CHUNK_HASH_IDX: u32 = NODE_FOLD_V2_PREFIX_LEN + NODE_FOLD_PARAM_PUBLIC_LEN + 2;
pub global NF_C0_PK_IDX: u32 = NODE_FOLD_V2_PREFIX_LEN + NODE_FOLD_PARAM_PUBLIC_LEN + 3;
pub global NF_C1_PK_IDX: u32 = NODE_FOLD_V2_PREFIX_LEN + NODE_FOLD_PARAM_PUBLIC_LEN + 4;
pub global NF_C3_PK_BASE_IDX: u32 = NODE_FOLD_V2_PREFIX_LEN + NODE_FOLD_PARAM_PUBLIC_LEN + 5;
pub global NF_C2A_BASE_IDX: u32 =
    NODE_FOLD_V2_PREFIX_LEN + NODE_FOLD_PARAM_PUBLIC_LEN + 5 + N_PARTIES;
pub global NF_C2B_BASE_IDX: u32 = NF_C2A_BASE_IDX + (N_PARTIES * L_THRESHOLD);
pub global NF_C4A_BASE_IDX: u32 = NF_C2B_BASE_IDX + (N_PARTIES * L_THRESHOLD);
pub global NF_C4B_BASE_IDX: u32 = NF_C4A_BASE_IDX + (H * L_THRESHOLD);
pub global NF_SK_AGG_IDX: u32 = NF_C4B_BASE_IDX + (H * L_THRESHOLD);
pub global NF_ESM_AGG_IDX: u32 = NF_SK_AGG_IDX + 1;
pub global NF_NODE_VK_MANIFEST_IDX: u32 = NODE_FOLD_V2_PREFIX_LEN + NODE_FOLD_PUBLIC_LEN - 1;

pub global NF_SESSION_HI_IDX: u32 = NODE_FOLD_V2_PREFIX_LEN + NODE_FOLD_PUBLIC_LEN;
pub global NF_SESSION_LO_IDX: u32 = NF_SESSION_HI_IDX + 1;
pub global NF_LBFV_PK_BASE_IDX: u32 = NF_SESSION_HI_IDX + 2;
pub global NF_LBFV_D0_BASE_IDX: u32 = NF_LBFV_PK_BASE_IDX + LBFV_ROWS;
pub global NF_LBFV_D2_BASE_IDX: u32 = NF_LBFV_D0_BASE_IDX + LBFV_ROWS;
pub global NF_LBFV_VK_MANIFEST_IDX: u32 = NF_LBFV_D2_BASE_IDX + LBFV_ROWS;

pub global AGGREGATION_FOLD_PREFIX_LEN: u32 = 7;
pub global AGGREGATION_FOLD_PUBLIC_LEN: u32 =
    AGGREGATION_FOLD_PREFIX_LEN + 5 + (3 * LBFV_ROWS * H) + (3 * LBFV_ROWS);
pub global AF_PK_VK_IDX: u32 = 0;
pub global AF_RLK_VK_IDX: u32 = 1;
pub global AF_ACC_VK_IDX: u32 = 2;
pub global AF_IS_FIRST_STEP_IDX: u32 = 3;
pub global AF_ROW_INDEX_IDX: u32 = 4;
pub global AF_EXPECTED_KERNEL_IDX: u32 = 5;
pub global AF_EXPECTED_FOLD_IDX: u32 = 6;
pub global AF_SESSION_HI_IDX: u32 = AGGREGATION_FOLD_PREFIX_LEN;
pub global AF_SESSION_LO_IDX: u32 = AF_SESSION_HI_IDX + 1;
pub global AF_AGGREGATOR_ID_IDX: u32 = AF_SESSION_HI_IDX + 2;
pub global AF_ACCEPTED_SET_HI_IDX: u32 = AF_SESSION_HI_IDX + 3;
pub global AF_ACCEPTED_SET_LO_IDX: u32 = AF_SESSION_HI_IDX + 4;
pub global AF_EXPECTED_PK_START: u32 = AF_SESSION_HI_IDX + 5;
pub global AF_EXPECTED_D0_START: u32 = AF_EXPECTED_PK_START + (LBFV_ROWS * H);
pub global AF_EXPECTED_D2_START: u32 = AF_EXPECTED_D0_START + (LBFV_ROWS * H);
pub global AF_AGGREGATE_PK_START: u32 = AF_EXPECTED_D2_START + (LBFV_ROWS * H);
pub global AF_AGGREGATE_D0_START: u32 = AF_AGGREGATE_PK_START + LBFV_ROWS;
pub global AF_AGGREGATE_D2_START: u32 = AF_AGGREGATE_D0_START + LBFV_ROWS;

pub global VK_BINDING_LEN: u32 = 16;
pub global VK_NODE_FOLD: u32 = 0;
pub global VK_C0: u32 = 1;
pub global VK_C1: u32 = 2;
pub global VK_C2AB: u32 = 3;
pub global VK_C3AB: u32 = 4;
pub global VK_C4AB: u32 = 5;
pub global VK_C2A_FINALIZE: u32 = 6;
pub global VK_C2B_FINALIZE: u32 = 7;
pub global VK_C2_BATCH: u32 = 8;
pub global VK_C2A_CHUNK: u32 = 9;
pub global VK_C2B_CHUNK: u32 = 10;
pub global VK_C3_FOLD: u32 = 11;
pub global VK_SHARE_ENCRYPTION: u32 = 12;
pub global VK_C4: u32 = 13;
pub global VK_C3_FOLD_KERNEL: u32 = 14;
pub global VK_NODES_FOLD_KERNEL: u32 = 15;

pub global V2_VK_BINDING_LEN: u32 = 13;
pub global V2_VK_NODE_FOLD: u32 = 0;
pub global V2_VK_NODES_FOLD: u32 = 1;
pub global V2_VK_NODES_FOLD_KERNEL: u32 = 2;
pub global V2_VK_GENERATION_FOLD: u32 = 3;
pub global V2_VK_GENERATION_FOLD_KERNEL: u32 = 4;
pub global V2_VK_PK_GENERATION: u32 = 5;
pub global V2_VK_RLK_GENERATION: u32 = 6;
pub global V2_VK_RLK_GENERATION_LIMB: u32 = 7;
pub global V2_VK_AGGREGATION_FOLD: u32 = 8;
pub global V2_VK_AGGREGATION_FOLD_KERNEL: u32 = 9;
pub global V2_VK_PK_AGGREGATION: u32 = 10;
pub global V2_VK_RLK_AGGREGATION: u32 = 11;
pub global V2_VK_PK_GENERATION_LIMB: u32 = 12;

pub global ACCEPTED_SET_PREIMAGE_LEN: u32 = 36 + (4 * H);

fn accepted_party_set_hash_limbs(party_ids: [u32; H]) -> (Field, Field) {
    // keccak256("interfold.lbfv.accepted-party-set:v1")
    let label_hash: [u8; 32] = [
        170, 188, 144, 1, 45, 94, 56, 175, 230, 124, 29, 74, 116, 168, 26, 99, 171, 246, 85, 102,
        241, 165, 99, 134, 54, 62, 188, 11, 62, 132, 194, 158,
    ];
    let mut preimage = [0u8; ACCEPTED_SET_PREIMAGE_LEN];
    for i in 0..32 {
        preimage[i] = label_hash[i];
    }

    let count_bytes: [u8; 32] = (H as Field).to_be_bytes();
    for i in 0..4 {
        preimage[32 + i] = count_bytes[28 + i];
    }
    for party in 0..H {
        let party_bytes: [u8; 32] = (party_ids[party] as Field).to_be_bytes();
        for i in 0..4 {
            preimage[36 + party * 4 + i] = party_bytes[28 + i];
        }
    }

    let hash = keccak256(preimage, ACCEPTED_SET_PREIMAGE_LEN);
    let mut hi: Field = 0;
    let mut lo: Field = 0;
    for i in 0..16 {
        hi = hi * 256 + hash[i] as Field;
        lo = lo * 256 + hash[16 + i] as Field;
    }
    (hi, lo)
}

fn assert_expected_commitment(expected: Field, folded: Field) {
    assert(expected == folded);
}

fn assert_node_vk_binding(
    nodes_fold_public: [Field; NODES_FOLD_V2_PUBLIC_LEN],
    row: u32,
    vk_binding: [Field; VK_BINDING_LEN],
    v2_vk_binding: [Field; V2_VK_BINDING_LEN],
    expected_node_manifest: Field,
    expected_generation_manifest: Field,
) {
    assert(nodes_fold_public[row] == v2_vk_binding[V2_VK_GENERATION_FOLD]);
    assert(nodes_fold_public[row + 1] == vk_binding[VK_NODE_FOLD]);
    assert(nodes_fold_public[row + 2] == vk_binding[VK_C1]);
    assert(nodes_fold_public[row + 5] == vk_binding[VK_C0]);
    assert(nodes_fold_public[row + 6] == vk_binding[VK_C1]);
    assert(nodes_fold_public[row + 7] == vk_binding[VK_C2AB]);
    assert(nodes_fold_public[row + 8] == vk_binding[VK_C3AB]);
    assert(nodes_fold_public[row + 9] == vk_binding[VK_C4AB]);
    assert(nodes_fold_public[row + NF_NODE_VK_MANIFEST_IDX] == expected_node_manifest);
    assert(nodes_fold_public[row + NF_LBFV_VK_MANIFEST_IDX] == expected_generation_manifest);
}

fn main(
    nodes_fold_vk: UltraHonkVerificationKey,
    nodes_fold_proof: UltraHonkProof,
    nodes_fold_public: [Field; NODES_FOLD_V2_PUBLIC_LEN],
    c5_vk: UltraHonkVerificationKey,
    c5_proof: UltraHonkProof,
    c5_public: [Field; H + 1],
    nodes_fold_key_hash: pub Field,
    c5_key_hash: pub Field,
    party_ids: pub [Field; H],
    committee_members: [Field; N_PARTIES],
    committee_hash_hi: pub Field,
    committee_hash_lo: pub Field,
    vk_binding: pub [Field; VK_BINDING_LEN],
    aggregation_fold_vk: UltraHonkVerificationKey,
    aggregation_fold_proof: UltraHonkProof,
    aggregation_fold_public: [Field; AGGREGATION_FOLD_PUBLIC_LEN],
    aggregation_fold_key_hash: Field,
    v2_vk_binding: [Field; V2_VK_BINDING_LEN],
    ) -> pub (Field, Field, Field, [Field; H], [Field; H], Field, Field, Field, Field, Field, Field, Field, [Field; LBFV_ROWS], [Field; LBFV_ROWS], [Field; LBFV_ROWS], [Field; V2_VK_BINDING_LEN]) {
    let (expected_hi, expected_lo) = committee_hash_limbs(committee_members);
    assert(expected_hi == committee_hash_hi);
    assert(expected_lo == committee_hash_lo);

    verify_honk_proof_non_zk(
        nodes_fold_vk,
        nodes_fold_proof,
        nodes_fold_public,
        nodes_fold_key_hash,
    );
    verify_honk_proof_non_zk(c5_vk, c5_proof, c5_public, c5_key_hash);
    verify_honk_proof_non_zk(
        aggregation_fold_vk,
        aggregation_fold_proof,
        aggregation_fold_public,
        aggregation_fold_key_hash,
    );

    assert(nodes_fold_key_hash == v2_vk_binding[V2_VK_NODES_FOLD]);
    assert(nodes_fold_public[0] == v2_vk_binding[V2_VK_NODE_FOLD]);
    assert(nodes_fold_public[2] == 0);
    assert(nodes_fold_public[3] == (H - 1) as Field);
    assert(nodes_fold_public[4] == v2_vk_binding[V2_VK_NODES_FOLD_KERNEL]);
    assert(nodes_fold_public[5] == v2_vk_binding[V2_VK_NODES_FOLD]);
    if H == 2 {
        assert(nodes_fold_public[1] == v2_vk_binding[V2_VK_NODES_FOLD_KERNEL]);
    } else {
        assert(nodes_fold_public[1] == v2_vk_binding[V2_VK_NODES_FOLD]);
    }

    assert(aggregation_fold_key_hash == v2_vk_binding[V2_VK_AGGREGATION_FOLD]);
    assert(aggregation_fold_public[AF_PK_VK_IDX] == v2_vk_binding[V2_VK_PK_AGGREGATION]);
    assert(aggregation_fold_public[AF_RLK_VK_IDX] == v2_vk_binding[V2_VK_RLK_AGGREGATION]);
    assert(aggregation_fold_public[AF_ACC_VK_IDX] == v2_vk_binding[V2_VK_AGGREGATION_FOLD]);
    assert(aggregation_fold_public[AF_IS_FIRST_STEP_IDX] == 0);
    assert(aggregation_fold_public[AF_ROW_INDEX_IDX] == (LBFV_ROWS - 1) as Field);
    assert(
        aggregation_fold_public[AF_EXPECTED_KERNEL_IDX]
            == v2_vk_binding[V2_VK_AGGREGATION_FOLD_KERNEL],
    );
    assert(aggregation_fold_public[AF_EXPECTED_FOLD_IDX] == v2_vk_binding[V2_VK_AGGREGATION_FOLD]);

    let expected_c2_manifest = compute_vk_hash([
        vk_binding[VK_C2A_FINALIZE],
        vk_binding[VK_C2B_FINALIZE],
        vk_binding[VK_C2_BATCH],
        vk_binding[VK_C2_BATCH],
        vk_binding[VK_C2A_CHUNK],
        vk_binding[VK_C2B_CHUNK],
    ]
        .as_vector());
    let expected_c3_manifest = compute_vk_hash([
        vk_binding[VK_C3_FOLD],
        vk_binding[VK_C3_FOLD],
        vk_binding[VK_SHARE_ENCRYPTION],
        vk_binding[VK_SHARE_ENCRYPTION],
        vk_binding[VK_C3_FOLD],
        vk_binding[VK_C3_FOLD],
        vk_binding[VK_C3_FOLD_KERNEL],
        vk_binding[VK_C3_FOLD_KERNEL],
        vk_binding[VK_C3_FOLD],
        vk_binding[VK_C3_FOLD],
    ]
        .as_vector());
    let expected_c4_manifest = compute_vk_hash([vk_binding[VK_C4], vk_binding[VK_C4]].as_vector());
    let expected_node_manifest = compute_vk_hash([
        vk_binding[VK_C0],
        vk_binding[VK_C1],
        vk_binding[VK_C2AB],
        vk_binding[VK_C3AB],
        vk_binding[VK_C4AB],
        expected_c2_manifest,
        expected_c3_manifest,
        expected_c4_manifest,
    ]
        .as_vector());
    let expected_generation_manifest = compute_vk_hash([
        v2_vk_binding[V2_VK_GENERATION_FOLD],
        v2_vk_binding[V2_VK_GENERATION_FOLD_KERNEL],
        v2_vk_binding[V2_VK_PK_GENERATION],
        v2_vk_binding[V2_VK_RLK_GENERATION],
        v2_vk_binding[V2_VK_RLK_GENERATION_LIMB],
        v2_vk_binding[V2_VK_PK_GENERATION_LIMB],
    ]
        .as_vector());

    for i in 0..H {
        let row = NODES_FOLD_V2_PREFIX_LEN + i * NODE_FOLD_V2_PUBLIC_LEN;
        assert_node_vk_binding(
            nodes_fold_public,
            row,
            vk_binding,
            v2_vk_binding,
            expected_node_manifest,
            expected_generation_manifest,
        );
    }

    for i in 0..H {
        let row = NODES_FOLD_V2_PREFIX_LEN + i * NODE_FOLD_V2_PUBLIC_LEN;
        assert(
            nodes_fold_public[row + NF_C2A_CHUNK_HASH_IDX]
                == nodes_fold_public[NODES_FOLD_V2_PREFIX_LEN + NF_C2A_CHUNK_HASH_IDX],
        );
        assert(
            nodes_fold_public[row + NF_C2B_CHUNK_HASH_IDX]
                == nodes_fold_public[NODES_FOLD_V2_PREFIX_LEN + NF_C2B_CHUNK_HASH_IDX],
        );
        assert(
            nodes_fold_public[row + NF_SESSION_HI_IDX]
                == aggregation_fold_public[AF_SESSION_HI_IDX],
        );
        assert(
            nodes_fold_public[row + NF_SESSION_LO_IDX]
                == aggregation_fold_public[AF_SESSION_LO_IDX],
        );
    }

    let mut canonical_party_ids: [u32; H] = [0; H];
    for i in 0..H {
        let id = party_ids[i] as u32;
        assert(party_ids[i] == id as Field);
        assert(id < N_PARTIES);
        if i > 0 {
            assert((party_ids[i - 1] as u32) < id);
        }
        assert(
            nodes_fold_public[NODES_FOLD_V2_PREFIX_LEN
                + i * NODE_FOLD_V2_PUBLIC_LEN
                + NF_PARTY_ID_IDX]
                == party_ids[i],
        );
        canonical_party_ids[i] = id;
    }
    let (accepted_set_hi, accepted_set_lo) = accepted_party_set_hash_limbs(canonical_party_ids);
    assert(aggregation_fold_public[AF_ACCEPTED_SET_HI_IDX] == accepted_set_hi);
    assert(aggregation_fold_public[AF_ACCEPTED_SET_LO_IDX] == accepted_set_lo);

    for i in 0..H {
        for j in 0..H {
            let recipient_id = party_ids[j] as u32;
            assert(
                nodes_fold_public[NODES_FOLD_V2_PREFIX_LEN
                    + i * NODE_FOLD_V2_PUBLIC_LEN
                    + NF_C3_PK_BASE_IDX
                    + recipient_id]
                    == nodes_fold_public[NODES_FOLD_V2_PREFIX_LEN
                        + j * NODE_FOLD_V2_PUBLIC_LEN
                        + NF_C0_PK_IDX],
            );
        }
    }

    for i in 0..H {
        for j in 0..H {
            let recipient_id = party_ids[j] as u32;
            for l in 0..L_THRESHOLD {
                assert(
                    nodes_fold_public[NODES_FOLD_V2_PREFIX_LEN
                        + j * NODE_FOLD_V2_PUBLIC_LEN
                        + NF_C4A_BASE_IDX
                        + i * L_THRESHOLD
                        + l]
                        == nodes_fold_public[NODES_FOLD_V2_PREFIX_LEN
                            + i * NODE_FOLD_V2_PUBLIC_LEN
                            + NF_C2A_BASE_IDX
                            + recipient_id * L_THRESHOLD
                            + l],
                );
                assert(
                    nodes_fold_public[NODES_FOLD_V2_PREFIX_LEN
                        + j * NODE_FOLD_V2_PUBLIC_LEN
                        + NF_C4B_BASE_IDX
                        + i * L_THRESHOLD
                        + l]
                        == nodes_fold_public[NODES_FOLD_V2_PREFIX_LEN
                            + i * NODE_FOLD_V2_PUBLIC_LEN
                            + NF_C2B_BASE_IDX
                            + recipient_id * L_THRESHOLD
                            + l],
                );
            }
        }
    }

    for i in 0..H {
        assert(
            c5_public[i]
                == nodes_fold_public[NODES_FOLD_V2_PREFIX_LEN
                    + i * NODE_FOLD_V2_PUBLIC_LEN
                    + NF_C1_PK_IDX],
        );
    }

    for row in 0..LBFV_ROWS {
        for party in 0..H {
            let node_row = NODES_FOLD_V2_PREFIX_LEN + party * NODE_FOLD_V2_PUBLIC_LEN;
            assert_expected_commitment(
                aggregation_fold_public[AF_EXPECTED_PK_START + row * H + party],
                nodes_fold_public[node_row + NF_LBFV_PK_BASE_IDX + row],
            );
            assert_expected_commitment(
                aggregation_fold_public[AF_EXPECTED_D0_START + row * H + party],
                nodes_fold_public[node_row + NF_LBFV_D0_BASE_IDX + row],
            );
            assert_expected_commitment(
                aggregation_fold_public[AF_EXPECTED_D2_START + row * H + party],
                nodes_fold_public[node_row + NF_LBFV_D2_BASE_IDX + row],
            );
        }
    }

    let legacy_key_hash = compute_vk_hash([nodes_fold_key_hash, c5_key_hash].as_vector());
    let v2_key_hash = compute_vk_hash([nodes_fold_key_hash, c5_key_hash, aggregation_fold_key_hash]
        .as_vector());
    let mut sk_agg_commits: [Field; H] = [0; H];
    let mut esm_agg_commits: [Field; H] = [0; H];
    for i in 0..H {
        sk_agg_commits[i] = nodes_fold_public[NODES_FOLD_V2_PREFIX_LEN
            + i * NODE_FOLD_V2_PUBLIC_LEN
            + NF_SK_AGG_IDX];
        esm_agg_commits[i] = nodes_fold_public[NODES_FOLD_V2_PREFIX_LEN
            + i * NODE_FOLD_V2_PUBLIC_LEN
            + NF_ESM_AGG_IDX];
    }

    let mut aggregate_pk: [Field; LBFV_ROWS] = [0; LBFV_ROWS];
    let mut aggregate_d0: [Field; LBFV_ROWS] = [0; LBFV_ROWS];
    let mut aggregate_d2: [Field; LBFV_ROWS] = [0; LBFV_ROWS];
    for row in 0..LBFV_ROWS {
        aggregate_pk[row] = aggregation_fold_public[AF_AGGREGATE_PK_START + row];
        aggregate_d0[row] = aggregation_fold_public[AF_AGGREGATE_D0_START + row];
        aggregate_d2[row] = aggregation_fold_public[AF_AGGREGATE_D2_START + row];
    }

    (
        legacy_key_hash, nodes_fold_public[NODES_FOLD_V2_PREFIX_LEN + NF_C2A_CHUNK_HASH_IDX],
        nodes_fold_public[NODES_FOLD_V2_PREFIX_LEN + NF_C2B_CHUNK_HASH_IDX], sk_agg_commits,
        esm_agg_commits, c5_public[H], v2_key_hash, aggregation_fold_public[AF_SESSION_HI_IDX],
        aggregation_fold_public[AF_SESSION_LO_IDX], aggregation_fold_public[AF_AGGREGATOR_ID_IDX],
        aggregation_fold_public[AF_ACCEPTED_SET_HI_IDX],
        aggregation_fold_public[AF_ACCEPTED_SET_LO_IDX], aggregate_pk, aggregate_d0, aggregate_d2,
        v2_vk_binding,
    )
}

#[test]
fn test_expected_commitment_accepts_equal_values() {
    assert_expected_commitment(17, 17);
}

#[test(should_fail)]
fn test_expected_commitment_rejects_mismatch() {
    assert_expected_commitment(17, 18);
}

#[test]
fn test_accepted_party_set_hash_matches_rust_vector() {
    let mut party_ids: [u32; H] = [0; H];
    for i in 0..H {
        party_ids[i] = i;
    }
    if H == 2 {
        party_ids[1] = 2;
        let (hi, lo) = accepted_party_set_hash_limbs(party_ids);
        assert(hi == 0x1331941941e2bdb6998a5b4676e3adbb);
        assert(lo == 0x9dcc20d884d5b54129886199ff0b7e9a);
    }
}

#[test]
fn test_node_vk_binding_accepts_distinct_legacy_and_v2_hashes() {
    let mut nodes_public: [Field; NODES_FOLD_V2_PUBLIC_LEN] = [0; NODES_FOLD_V2_PUBLIC_LEN];
    let mut legacy: [Field; VK_BINDING_LEN] = [0; VK_BINDING_LEN];
    let mut v2: [Field; V2_VK_BINDING_LEN] = [0; V2_VK_BINDING_LEN];
    let row = NODES_FOLD_V2_PREFIX_LEN;
    legacy[VK_NODE_FOLD] = 101;
    legacy[VK_C0] = 102;
    legacy[VK_C1] = 103;
    legacy[VK_C2AB] = 104;
    legacy[VK_C3AB] = 105;
    legacy[VK_C4AB] = 106;
    v2[V2_VK_NODE_FOLD] = 202;
    v2[V2_VK_GENERATION_FOLD] = 201;
    nodes_public[row] = 201;
    nodes_public[row + 1] = 101;
    nodes_public[row + 2] = 103;
    nodes_public[row + 5] = 102;
    nodes_public[row + 6] = 103;
    nodes_public[row + 7] = 104;
    nodes_public[row + 8] = 105;
    nodes_public[row + 9] = 106;
    nodes_public[row + NF_NODE_VK_MANIFEST_IDX] = 301;
    nodes_public[row + NF_LBFV_VK_MANIFEST_IDX] = 302;

    assert_node_vk_binding(nodes_public, row, legacy, v2, 301, 302);
}

#[test(should_fail)]
fn test_node_vk_binding_rejects_wrong_embedded_c0_hash() {
    let mut nodes_public: [Field; NODES_FOLD_V2_PUBLIC_LEN] = [0; NODES_FOLD_V2_PUBLIC_LEN];
    let mut legacy: [Field; VK_BINDING_LEN] = [0; VK_BINDING_LEN];
    let mut v2: [Field; V2_VK_BINDING_LEN] = [0; V2_VK_BINDING_LEN];
    let row = NODES_FOLD_V2_PREFIX_LEN;
    legacy[VK_NODE_FOLD] = 101;
    legacy[VK_C0] = 102;
    legacy[VK_C1] = 103;
    legacy[VK_C2AB] = 104;
    legacy[VK_C3AB] = 105;
    legacy[VK_C4AB] = 106;
    v2[V2_VK_NODE_FOLD] = 202;
    v2[V2_VK_GENERATION_FOLD] = 201;
    nodes_public[row] = 201;
    nodes_public[row + 1] = 101;
    nodes_public[row + 2] = 103;
    nodes_public[row + 5] = 999;
    nodes_public[row + 6] = 103;
    nodes_public[row + 7] = 104;
    nodes_public[row + 8] = 105;
    nodes_public[row + 9] = 106;
    nodes_public[row + NF_NODE_VK_MANIFEST_IDX] = 301;
    nodes_public[row + NF_LBFV_VK_MANIFEST_IDX] = 302;

    assert_node_vk_binding(nodes_public, row, legacy, v2, 301, 302);
}
