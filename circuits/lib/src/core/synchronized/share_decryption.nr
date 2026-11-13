// SPDX-License-Identifier: LGPL-3.0-only

use crate::core::dkg::share_decryption::aggregate_canonical_shares;
use crate::math::commitments::compute_share_encryption_commitment_from_message_checked;
use crate::math::polynomial::Polynomial;
use super::commitments::{assert_key, key_bit, key_bundle, outgoing_root};

/// C4 opens C2's packed plaintexts, not a BFV decryption equation. C2/C3 and recursive joins must
/// anchor every expected message, the owner's outgoing root, context and canonical H-roster.
pub fn execute<let N: u32, let L: u32, let N_PARTIES: u32, let H: u32, let KEY_BITS: u32, let BIT_SHARE: u32, let BIT_MSG: u32, let BIT_AGG: u32>(
    profile: [Field; 2],
    setup_binding: [Field; 2],
    recipient: u32,
    dealers: [u32; H],
    expected_outgoing_root: Field,
    expected_commitments: [[Field; L]; H],
    moduli: [Field; L],
    packed_shares: [[Polynomial<N>; L]; H],
    outgoing: [[u8; 32]; N_PARTIES],
    incoming: [[u8; 32]; H],
) -> (Field, Field) {
    assert(KEY_BITS <= N);
    assert(H > 0);
    assert(H <= N_PARTIES);
    assert(
        outgoing_root::<N_PARTIES, KEY_BITS>(profile, setup_binding, recipient, outgoing)
            == expected_outgoing_root,
        "Outgoing root mismatch",
    );
    let mut shares = [[Polynomial::new([0; N]); L]; H];
    for row in 0..H {
        assert_key::<KEY_BITS>(incoming[row]);
        for limb in 0..L {
            let packed = packed_shares[row][limb];
            let mut reversed = [0; N];
            let mut residues = [0; N];
            for coefficient in 0..N {
                let bit = if (limb == 0) & (coefficient < KEY_BITS) {
                    key_bit(incoming[row], coefficient)
                } else {
                    0
                };
                let residue = packed.coefficients[coefficient] - bit * moduli[limb];
                Polynomial::new([residue]).range_check_standard::<BIT_SHARE>(moduli[limb]);
                residues[coefficient] = residue;
                reversed[N - 1 - coefficient] = packed.coefficients[coefficient];
            }
            assert(
                compute_share_encryption_commitment_from_message_checked::<N, BIT_MSG>(
                    Polynomial::new(reversed),
                )
                    == expected_commitments[row][limb],
                "Packed commitment mismatch",
            );
            shares[row][limb] = Polynomial::new(residues);
        }
    }
    let sk_commitment = aggregate_canonical_shares::<N, L, H, BIT_SHARE, BIT_AGG>(shares, moduli);
    let bundle = key_bundle::<N_PARTIES, H, KEY_BITS>(
        profile,
        setup_binding,
        recipient,
        dealers,
        sk_commitment,
        outgoing,
        incoming,
    );
    (sk_commitment, bundle)
}
