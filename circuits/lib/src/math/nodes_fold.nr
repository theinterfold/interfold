// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Multi-leaf placement shared by `nodes_fold_kernel` and `nodes_fold`.
//!
//! A step verifies [`NODES_FOLD_LEAVES`] `node_fold` proofs, so each node costs a share of one
//! larger proof instead of a whole step. A step with fewer nodes repeats one of them under the
//! sentinel slot `H`, which writes nothing. The DKG aggregator binds every row to a selected party,
//! so a chain cannot end with a row left empty.

/// `node_fold` proofs one kernel or fold step verifies.
pub global NODES_FOLD_LEAVES: u32 = 4;

/// Writes each node's statement into its row. A row must be all zero before it is written; the
/// sentinel slot `H` writes nothing.
pub fn place_nodes<let LEN: u32, let H: u32, let K: u32>(
    rows: [[Field; LEN]; H],
    nodes: [[Field; LEN]; K],
    slot_indices: [u32; K],
) -> [[Field; LEN]; H] {
    let mut rows = rows;
    for k in 0..K {
        let slot = slot_indices[k];
        assert(slot <= H, "slot index out of range");
        for i in 0..H {
            if slot == i {
                for j in 0..LEN {
                    assert(rows[i][j] == 0, "slot already filled");
                }
                rows[i] = nodes[k];
            }
        }
    }
    rows
}

#[test]
fn nodes_land_in_their_rows_and_the_sentinel_writes_nothing() {
    let rows = place_nodes::<2, 3, 3>([[0; 2]; 3], [[1, 2], [3, 4], [1, 2]], [2, 0, 3]);
    assert(rows == [[3, 4], [0, 0], [1, 2]]);
}

#[test(should_fail_with = "slot already filled")]
fn a_node_cannot_overwrite_a_filled_row() {
    let _ = place_nodes::<2, 2, 1>([[0, 0], [0, 5]], [[1, 2]], [1]);
}

#[test(should_fail_with = "slot index out of range")]
fn a_node_slot_past_the_sentinel_is_rejected() {
    let _ = place_nodes::<2, 2, 1>([[0; 2]; 2], [[1, 2]], [3]);
}
