// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Placement for the C6 Chonk app (`c6_chonk_app`). Its leaves fill every slot; the decryption
//! aggregator requires the ciphertext commitment in each.

/// Fields of a C6 public transcript: sk, esm and ct commitments, the domain limbs, then d.
pub global C6_PUBLIC_LEN: u32 = 6;

/// Writes each leaf's sk, esm, ct and d commitments into its slot. A slot must be empty before it
/// is written; the sentinel slot `SLOTS` writes nothing.
pub fn place_c6_leaves<let SLOTS: u32, let K: u32>(
    sk: [Field; SLOTS],
    esm: [Field; SLOTS],
    ct: [Field; SLOTS],
    d: [Field; SLOTS],
    leaves: [[Field; C6_PUBLIC_LEN]; K],
    slot_indices: [u32; K],
) -> ([Field; SLOTS], [Field; SLOTS], [Field; SLOTS], [Field; SLOTS]) {
    let mut sk = sk;
    let mut esm = esm;
    let mut ct = ct;
    let mut d = d;
    for k in 0..K {
        let slot = slot_indices[k];
        assert(slot <= SLOTS, "slot index out of range");
        for i in 0..SLOTS {
            if slot == i {
                assert(sk[i] == 0, "slot already filled");
                assert(esm[i] == 0, "slot already filled");
                assert(ct[i] == 0, "slot already filled");
                assert(d[i] == 0, "slot already filled");
                sk[i] = leaves[k][0];
                esm[i] = leaves[k][1];
                ct[i] = leaves[k][2];
                d[i] = leaves[k][5];
            }
        }
    }
    (sk, esm, ct, d)
}

/// Every leaf must carry the chain's domain limbs.
pub fn assert_c6_domain<let K: u32>(
    leaves: [[Field; C6_PUBLIC_LEN]; K],
    domain_hi: Field,
    domain_lo: Field,
) {
    for k in 0..K {
        assert(leaves[k][3] == domain_hi, "C6 leaf domain differs");
        assert(leaves[k][4] == domain_lo, "C6 leaf domain differs");
    }
}

#[test]
fn c6_leaves_land_in_their_slots_and_the_sentinel_writes_nothing() {
    let (sk, esm, ct, d) = place_c6_leaves::<3, 3>(
        [0; 3],
        [0; 3],
        [0; 3],
        [0; 3],
        [[1, 2, 3, 9, 9, 4], [5, 6, 7, 9, 9, 8], [1, 2, 3, 9, 9, 4]],
        [2, 0, 3],
    );
    assert(sk == [5, 0, 1]);
    assert(esm == [6, 0, 2]);
    assert(ct == [7, 0, 3]);
    assert(d == [8, 0, 4]);
}

#[test(should_fail_with = "slot already filled")]
fn a_c6_leaf_cannot_overwrite_a_filled_slot() {
    let _ = place_c6_leaves::<2, 1>([0, 1], [0; 2], [0; 2], [0; 2], [[1, 2, 3, 0, 0, 4]], [1]);
}

#[test(should_fail_with = "slot index out of range")]
fn a_c6_slot_past_the_sentinel_is_rejected() {
    let _ = place_c6_leaves::<2, 1>([0; 2], [0; 2], [0; 2], [0; 2], [[1, 2, 3, 0, 0, 4]], [3]);
}

#[test(should_fail_with = "C6 leaf domain differs")]
fn a_c6_leaf_from_another_domain_is_rejected() {
    assert_c6_domain([[1, 2, 3, 7, 8, 4], [1, 2, 3, 7, 9, 4]], 7, 8);
}
