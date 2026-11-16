// SPDX-License-Identifier: LGPL-3.0-only

//! Draft DKG joins. A recipient proof opens one canonical caller-supplied setup/H-roster; neither
//! this module nor C4 authenticates chain selection or proves a BFV decryption equation.

use super::commitments::{assert_context, commit};

/// Commit the complete ordered dealer statements, including every C2/C3 recipient/CRT slot.
/// Matching threshold PKs alone would allow different valid randomized C2 batches per recipient.
pub fn dealer_batch<let N: u32, let L: u32, let H: u32>(
    profile: [Field; 2],
    setup_binding: [Field; 2],
    key_bits: u32,
    nodes: [[Field; 6 + N + 2 * N * L]; H],
) -> Field {
    assert_context(profile, setup_binding);
    let mut payload = [
        5,
        profile[0],
        profile[1],
        setup_binding[0],
        setup_binding[1],
        N as Field,
        key_bits as Field,
        H as Field,
        L as Field,
    ]
        .as_vector();
    for row in nodes {
        for value in row {
            payload = payload.push_back(value);
        }
    }
    commit(payload)
}

/// Join one dealer's C1/C2 and its complete non-self C3 fan-out, in recipient/CRT order.
pub fn join_dealer<let N: u32, let L: u32>(
    setup_binding: [Field; 2],
    dealer: u32,
    c1: [Field; 5],
    c2: [Field; 5 + N * L],
    c3: [[Field; 3]; (N - 1) * L],
) -> (Field, Field, [[Field; L]; N], [Field; N], [[Field; L]; N]) {
    assert(N > 1);
    assert(L > 0);
    assert(dealer < N);
    assert_context([0, 0], setup_binding);
    for i in 0..2 {
        assert(c1[i] == setup_binding[i]);
        assert(c2[i] == setup_binding[i]);
    }
    assert(c1[2] == dealer as Field);
    assert(c2[2] == dealer as Field);
    assert(c1[3] == c2[3], "C1/C2 secret differs");

    let mut messages = [[0; L]; N];
    let mut keys = [0; N];
    let mut ciphertexts = [[0; L]; N];
    for recipient in 0..N {
        for limb in 0..L {
            messages[recipient][limb] = c2[4 + recipient * L + limb];
            if recipient != dealer {
                let row = if recipient < dealer {
                    recipient
                } else {
                    recipient - 1
                };
                let slot = row * L + limb;
                assert(c3[slot][1] == messages[recipient][limb], "C2/C3 message differs");
                assert(c3[slot][0] == c3[row * L][0], "C3 recipient key differs across CRT rows");
                keys[recipient] = c3[slot][0];
                ciphertexts[recipient][limb] = c3[slot][2];
            }
        }
    }
    (c1[4], c2[4 + N * L], messages, keys, ciphertexts)
}

/// Node public IO: context[2], dealer, descendant hash, threshold PK, outgoing root,
/// N×L messages, N recipient keys, N×L ciphertexts. Self C3 slots are zero, not dummy proofs.
pub fn join_recipient<let N: u32, let L: u32, let H: u32>(
    setup_binding: [Field; 2],
    recipient: u32,
    dealers: [u32; H],
    c0: Field,
    own_c2: [Field; 5 + N * L],
    c4: [Field; 6 + H + H * L],
    nodes: [[Field; 6 + N + 2 * N * L]; H],
) -> ([Field; H], Field, Field, Field) {
    assert(H > 0);
    assert(H < N);
    assert(L > 0);
    assert(recipient < N);
    assert_context([0, 0], setup_binding);
    for i in 0..2 {
        assert(own_c2[i] == setup_binding[i]);
        assert(c4[i] == setup_binding[i]);
    }
    assert(own_c2[2] == recipient as Field);
    assert(c4[2] == recipient as Field);
    assert(own_c2[4 + N * L] == c4[3 + H], "C4 outgoing root differs from owner's C2");
    let mut threshold_keys = [0; H];
    for row in 0..H {
        let dealer = dealers[row];
        assert(dealer < N);
        if row > 0 {
            assert(dealers[row - 1] < dealer, "Dealers must strictly increase");
        }
        assert(c4[3 + row] == dealer as Field, "C4 roster differs");
        for i in 0..2 {
            assert(nodes[row][i] == setup_binding[i], "Dealer setup differs");
        }
        assert(nodes[row][2] == dealer as Field, "Dealer slot differs");
        assert(nodes[row][3] == nodes[0][3], "Dealer VK genealogy differs");
        threshold_keys[row] = nodes[row][4];
        for limb in 0..L {
            assert(
                c4[4 + H + row * L + limb] == nodes[row][6 + recipient * L + limb],
                "C2/C4 message differs",
            );
        }
        if dealer == recipient {
            assert(nodes[row][5] == own_c2[4 + N * L]);
            for slot in 0..(N * L) {
                assert(nodes[row][6 + slot] == own_c2[4 + slot], "Own C2 contribution differs");
            }
        } else {
            // join_dealer constrained every CRT row to this key, not only the exported first row.
            assert(nodes[row][6 + N * L + recipient] == c0, "C3 key differs from recipient C0");
        }
    }
    (threshold_keys, c4[4 + H + H * L], c4[5 + H + H * L], nodes[0][3])
}

fn dealer_fixture() -> ([Field; 5], [Field; 14], [[Field; 3]; 6]) {
    // Dealer 2: self is omitted, not a zero proof occupying a fan-out slot.
    let c1 = [10, 20, 2, 7, 8];
    let c2 = [10, 20, 2, 7, 1, 2, 3, 4, 5, 6, 7, 8, 9, 99];
    let c3 = [[11, 1, 21], [11, 2, 22], [11, 3, 23], [12, 4, 24], [12, 5, 25], [12, 6, 26]];
    (c1, c2, c3)
}

#[test]
fn full_committee_slots_do_not_shift_at_the_self_slot() {
    let (c1, c2, c3) = dealer_fixture();
    let (pk, root, messages, keys, ciphertexts) = join_dealer::<3, 3>([10, 20], 2, c1, c2, c3);
    assert(pk == 8);
    assert(root == 99);
    assert(messages == [[1, 2, 3], [4, 5, 6], [7, 8, 9]]);
    assert(keys == [11, 12, 0]);
    assert(ciphertexts == [[21, 22, 23], [24, 25, 26], [0, 0, 0]]);
}

#[test(should_fail_with = "C3 recipient key differs across CRT rows")]
fn the_last_crt_row_cannot_inherit_the_first_rows_key() {
    let (c1, c2, mut c3) = dealer_fixture();
    c3[5][0] = 999;
    let _ = join_dealer::<3, 3>([10, 20], 2, c1, c2, c3);
}

#[test(should_fail_with = "C1/C2 secret differs")]
fn independent_valid_sk_statements_do_not_join() {
    let (mut c1, c2, c3) = dealer_fixture();
    c1[3] = 999;
    let _ = join_dealer::<3, 3>([10, 20], 2, c1, c2, c3);
}

fn recipient_fixture() -> ([Field; 14], [Field; 14], [[Field; 27]; 2]) {
    // Non-prefix H=[0,2], recipient 1 outside H. Every incoming row is encrypted.
    let own = [10, 20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99];
    let c4 = [10, 20, 1, 0, 2, 99, 1, 2, 3, 4, 5, 6, 90, 91];
    let mut nodes = [[0; 27]; 2];
    for row in 0..2 {
        nodes[row][0] = 10;
        nodes[row][1] = 20;
        nodes[row][2] = (row * 2) as Field;
        nodes[row][3] = 100; // Descendant VK genealogy.
        nodes[row][4] = (200 + row) as Field;
        nodes[row][16] = 7; // Recipient 1's C0, after the N×L messages.
        for limb in 0..3 {
            nodes[row][9 + limb] = (row * 3 + limb + 1) as Field;
        }
    }
    (own, c4, nodes)
}

#[test]
fn an_outside_h_recipient_keeps_exact_nonprefix_dealer_rows() {
    let (own, c4, nodes) = recipient_fixture();
    let (pk, sk, bundle, tree) = join_recipient::<3, 3, 2>([10, 20], 1, [0, 2], 7, own, c4, nodes);
    assert(pk == [200, 201]);
    assert(sk == 90);
    assert(bundle == 91);
    assert(tree == 100);
}

#[test(should_fail_with = "C2/C4 message differs")]
fn every_incoming_crt_row_is_joined() {
    let (own, mut c4, nodes) = recipient_fixture();
    c4[11] = 999;
    let _ = join_recipient::<3, 3, 2>([10, 20], 1, [0, 2], 7, own, c4, nodes);
}

#[test(should_fail_with = "C4 outgoing root differs from owner's C2")]
fn outside_h_owners_still_need_their_own_outgoing_root() {
    let (mut own, c4, nodes) = recipient_fixture();
    own[13] = 999;
    let _ = join_recipient::<3, 3, 2>([10, 20], 1, [0, 2], 7, own, c4, nodes);
}

#[test(should_fail_with = "Dealer VK genealogy differs")]
fn different_valid_descendant_trees_cannot_mix() {
    let (own, c4, mut nodes) = recipient_fixture();
    nodes[1][3] = 999;
    let _ = join_recipient::<3, 3, 2>([10, 20], 1, [0, 2], 7, own, c4, nodes);
}
