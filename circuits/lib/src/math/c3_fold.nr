// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Row placement shared by `c3_fold_kernel` and `c3_fold`.
//!
//! Each kernel or fold step verifies `C3_FOLD_LEAVES` C3 proofs. Four leaves plus the accumulator
//! fill 2^22 (about 87%), which costs half as much per leaf as one leaf per 2^21 step. A chain may
//! be shorter than a whole number of steps, so a place can be empty: its slot index is the
//! sentinel `SLOTS` and it writes nothing (its proof position repeats a real leaf of the step).

/// Leaves each `c3_fold_kernel` or `c3_fold` step verifies.
pub global C3_FOLD_LEAVES: u32 = 4;

/// Writes each leaf's `(pk, msg, ct)` row into its slot, which must be empty. A slot index of
/// `SLOTS` marks an empty place and writes nothing; any other index must be in range.
pub fn place_leaves<let SLOTS: u32, let K: u32>(
    pk: [Field; SLOTS],
    msg: [Field; SLOTS],
    ct: [Field; SLOTS],
    rows: [[Field; 3]; K],
    slot_indices: [u32; K],
) -> ([Field; SLOTS], [Field; SLOTS], [Field; SLOTS]) {
    let mut pk = pk;
    let mut msg = msg;
    let mut ct = ct;
    for k in 0..K {
        let slot = slot_indices[k];
        assert(slot <= SLOTS, "slot index out of range");
        for i in 0..SLOTS {
            if slot == i {
                assert(pk[i] == 0, "slot already filled");
                assert(msg[i] == 0, "slot already filled");
                assert(ct[i] == 0, "slot already filled");
                pk[i] = rows[k][0];
                msg[i] = rows[k][1];
                ct[i] = rows[k][2];
            }
        }
    }
    (pk, msg, ct)
}

#[test]
fn leaves_land_in_their_slots_and_empty_places_write_nothing() {
    let (pk, msg, ct) = place_leaves::<4, 3>(
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [[1, 2, 3], [4, 5, 6], [7, 8, 9]],
        [2, 4, 0],
    );
    assert(pk == [7, 0, 1, 0]);
    assert(msg == [8, 0, 2, 0]);
    assert(ct == [9, 0, 3, 0]);
}

#[test(should_fail_with = "slot already filled")]
fn a_leaf_cannot_overwrite_a_filled_slot() {
    let _ = place_leaves::<4, 2>(
        [0, 5, 0, 0],
        [0, 6, 0, 0],
        [0, 7, 0, 0],
        [[1, 2, 3], [4, 5, 6]],
        [1, 4],
    );
}

#[test(should_fail_with = "slot already filled")]
fn two_leaves_cannot_share_a_slot() {
    let _ = place_leaves::<4, 2>([0; 4], [0; 4], [0; 4], [[1, 2, 3], [4, 5, 6]], [3, 3]);
}

#[test(should_fail_with = "slot index out of range")]
fn a_slot_past_the_sentinel_is_rejected() {
    let _ = place_leaves::<4, 1>([0; 4], [0; 4], [0; 4], [[1, 2, 3]], [5]);
}
