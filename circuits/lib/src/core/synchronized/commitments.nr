// SPDX-License-Identifier: LGPL-3.0-only

//! Private-key provenance, separate from the unchanged fhe.rs PRF transcript.
//! A leaf does not authenticate `setup_binding`: recursive parents and canonical E3 admission must
//! supply and join it, along with the exact dealer/recipient IDs and profile.

use crate::math::commitments::compute_commitment;

// "interfold:sync-dkg:v1", zero padded. The first absorbed field separates each statement role.
global DOMAIN: [u8; 64] = [
    105, 110, 116, 101, 114, 102, 111, 108, 100, 58, 115, 121, 110, 99, 45, 100, 107, 103, 58, 118,
    49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

pub fn commit(payload: [Field]) -> Field {
    compute_commitment(payload, DOMAIN)
}

pub fn assert_context(profile: [Field; 2], setup_binding: [Field; 2]) {
    for index in 0..2 {
        profile[index].assert_max_bit_size::<128>();
        setup_binding[index].assert_max_bit_size::<128>();
    }
}

pub fn assert_key<let KEY_BITS: u32>(key: [u8; 32]) {
    assert(KEY_BITS > 0);
    assert(KEY_BITS <= 256);
    assert(KEY_BITS % 8 == 0);
    for byte in (KEY_BITS / 8)..32 {
        assert(key[byte] == 0, "PRF key exceeds the profile width");
    }
}

pub fn key_bit(key: [u8; 32], index: u32) -> Field {
    ((key[index / 8] >> ((index % 8) as u8)) & 1) as Field
}

pub fn directed_key<let N_PARTIES: u32, let KEY_BITS: u32>(
    profile: [Field; 2],
    setup_binding: [Field; 2],
    dealer: u32,
    recipient: u32,
    key: [u8; 32],
) -> Field {
    assert_context(profile, setup_binding);
    assert(dealer < N_PARTIES, "Dealer outside committee");
    assert(recipient < N_PARTIES, "Recipient outside committee");
    assert_key::<KEY_BITS>(key);
    let mut payload = [
        1,
        profile[0],
        profile[1],
        setup_binding[0],
        setup_binding[1],
        N_PARTIES as Field,
        KEY_BITS as Field,
        dealer as Field,
        recipient as Field,
    ]
        .as_vector();
    // Byte fields are injective, including keys above the scalar modulus. Do not hash a lossy
    // key_to_field representation here; that map belongs only to the upstream PRF.
    for byte in key {
        payload = payload.push_back(byte as Field);
    }
    commit(payload)
}

pub fn outgoing_root<let N_PARTIES: u32, let KEY_BITS: u32>(
    profile: [Field; 2],
    setup_binding: [Field; 2],
    owner: u32,
    keys: [[u8; 32]; N_PARTIES],
) -> Field {
    let mut payload = [
        2,
        profile[0],
        profile[1],
        setup_binding[0],
        setup_binding[1],
        N_PARTIES as Field,
        KEY_BITS as Field,
        owner as Field,
    ]
        .as_vector();
    for recipient in 0..N_PARTIES {
        payload = payload.push_back(directed_key::<N_PARTIES, KEY_BITS>(
            profile,
            setup_binding,
            owner,
            recipient,
            keys[recipient],
        ));
    }
    commit(payload)
}

pub fn key_bundle<let N_PARTIES: u32, let H: u32, let KEY_BITS: u32>(
    profile: [Field; 2],
    setup_binding: [Field; 2],
    owner: u32,
    dealers: [u32; H],
    sk_commitment: Field,
    outgoing: [[u8; 32]; N_PARTIES],
    incoming: [[u8; 32]; H],
) -> Field {
    let mut payload = [
        3,
        profile[0],
        profile[1],
        setup_binding[0],
        setup_binding[1],
        N_PARTIES as Field,
        KEY_BITS as Field,
        owner as Field,
        H as Field,
        sk_commitment,
    ]
        .as_vector();
    for row in 0..H {
        let dealer = dealers[row];
        assert(dealer < N_PARTIES, "Dealer outside committee");
        if row > 0 {
            assert(dealers[row - 1] < dealer, "Dealers must strictly increase");
        }
        let out = directed_key::<N_PARTIES, KEY_BITS>(
            profile,
            setup_binding,
            owner,
            dealer,
            outgoing[dealer],
        );
        let received = directed_key::<N_PARTIES, KEY_BITS>(
            profile,
            setup_binding,
            dealer,
            owner,
            incoming[row],
        );
        if dealer == owner {
            assert(out == received, "Own key directions differ");
        }
        payload = payload.push_back(dealer as Field);
        payload = payload.push_back(out);
        payload = payload.push_back(received);
    }
    commit(payload)
}

#[test]
fn direction_owner_profile_and_setup_are_distinct() {
    let key = [7; 32];
    let expected = directed_key::<3, 256>([1, 2], [3, 4], 0, 2, key);
    assert(expected != directed_key::<3, 256>([1, 2], [3, 4], 2, 0, key));
    assert(expected != directed_key::<3, 256>([1, 3], [3, 4], 0, 2, key));
    assert(expected != directed_key::<3, 256>([1, 2], [3, 5], 0, 2, key));
}

#[test(should_fail_with = "PRF key exceeds the profile width")]
fn high_key_bytes_are_not_ignored() {
    let mut key: [u8; 32] = [0; 32];
    key[8] = 1;
    let _ = directed_key::<3, 64>([1, 2], [3, 4], 0, 2, key);
}
