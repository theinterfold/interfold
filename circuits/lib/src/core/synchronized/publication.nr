// SPDX-License-Identifier: LGPL-3.0-only

//! Consistency boundary only. The verifier's caller supplies canonical request/roster authority.

use super::commitments::assert_context;

pub fn join_publication<let N: u32, let H: u32>(
    setup_binding: [Field; 2],
    dealers: [u32; H],
    expected_descendants: Field,
    recipients: [[Field; 7 + 2 * H]; H],
    c5: [Field; H + 1],
) -> (Field, [Field; H], [Field; H], [Field; H], Field) {
    assert(H > 0);
    assert(H < N);
    assert_context([0, 0], setup_binding);
    let mut sk = [0; H];
    let mut bundles = [0; H];
    let mut keys = [0; H];
    let batch = recipients[0][4 + 2 * H];
    for row in 0..H {
        assert(dealers[row] < N);
        if row > 0 {
            assert(dealers[row - 1] < dealers[row]);
        }
        assert(recipients[row][0] == expected_descendants, "Setup VK descendants differ");
        assert(recipients[row][1] == setup_binding[0], "Recipient setup differs");
        assert(recipients[row][2] == setup_binding[1], "Recipient setup differs");
        assert(recipients[row][3] == dealers[row] as Field, "Recipient slot differs");
        for slot in 0..H {
            assert(recipients[row][4 + slot] == dealers[slot] as Field, "Recipient roster differs");
            assert(recipients[row][4 + H + slot] == c5[slot], "C5 contribution differs");
        }
        assert(recipients[row][4 + 2 * H] == batch, "Dealer batch differs");
        keys[row] = c5[row];
        sk[row] = recipients[row][5 + 2 * H];
        bundles[row] = recipients[row][6 + 2 * H];
    }
    (batch, keys, sk, bundles, c5[H])
}

fn fixture() -> [[Field; 11]; 2] {
    [[100, 10, 20, 0, 0, 2, 5, 6, 7, 8, 9], [100, 10, 20, 2, 0, 2, 5, 6, 7, 18, 19]]
}

#[test]
fn publication_preserves_nonprefix_recipient_anchors() {
    let (batch, keys, sk, bundles, pk) =
        join_publication::<3, 2>([10, 20], [0, 2], 100, fixture(), [5, 6, 99]);
    assert(batch == 7);
    assert(keys == [5, 6]);
    assert(sk == [8, 18]);
    assert(bundles == [9, 19]);
    assert(pk == 99);
}

#[test(should_fail_with = "Dealer batch differs")]
fn equal_public_keys_do_not_authorize_different_randomized_dealer_batches() {
    let mut recipients = fixture();
    recipients[1][8] = 999;
    let _ = join_publication::<3, 2>([10, 20], [0, 2], 100, recipients, [5, 6, 99]);
}

#[test(should_fail_with = "C5 contribution differs")]
fn c5_must_open_the_same_ordered_public_keys() {
    let _ = join_publication::<3, 2>([10, 20], [0, 2], 100, fixture(), [6, 5, 99]);
}

#[test(should_fail_with = "Recipient setup differs")]
fn another_request_cannot_supply_a_recipient() {
    let mut recipients = fixture();
    recipients[1][1] = 999;
    let _ = join_publication::<3, 2>([10, 20], [0, 2], 100, recipients, [5, 6, 99]);
}

#[test(should_fail_with = "Recipient slot differs")]
fn selected_dealer_slots_cannot_be_reordered() {
    let recipients = fixture();
    let _ = join_publication::<3, 2>(
        [10, 20],
        [0, 2],
        100,
        [recipients[1], recipients[0]],
        [5, 6, 99],
    );
}

#[test(should_fail_with = "Setup VK descendants differ")]
fn a_uniform_tree_pin_is_required() {
    let mut recipients = fixture();
    recipients[1][0] = 999;
    let _ = join_publication::<3, 2>([10, 20], [0, 2], 100, recipients, [5, 6, 99]);
}
