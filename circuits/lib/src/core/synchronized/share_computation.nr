// SPDX-License-Identifier: LGPL-3.0-only

use crate::core::dkg::share_computation::{Configs, SecretKeyShareComputation};
use crate::math::commitments::compute_share_encryption_commitment_from_message;
use crate::math::polynomial::Polynomial;
use super::commitments::{key_bit, outgoing_root};

pub fn packed_messages<let N: u32, let L: u32, let N_PARTIES: u32, let KEY_BITS: u32>(
    moduli: [Field; L],
    y: [[[Field; N_PARTIES + 1]; L]; N],
    keys: [[u8; 32]; N_PARTIES],
) -> [[Polynomial<N>; L]; N_PARTIES] {
    assert(KEY_BITS <= N, "PRF keys must fit in limb zero");
    let mut messages = [[Polynomial::new([0; N]); L]; N_PARTIES];
    for recipient in 0..N_PARTIES {
        for limb in 0..L {
            let mut coefficients = [0; N];
            for coefficient in 0..N {
                let bit = if (limb == 0) & (coefficient < KEY_BITS) {
                    key_bit(keys[recipient], coefficient)
                } else {
                    0
                };
                coefficients[N - 1 - coefficient] =
                    y[coefficient][limb][recipient + 1] + bit * moduli[limb];
            }
            messages[recipient][limb] = Polynomial::new(coefficients);
        }
    }
    messages
}

pub fn execute<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32, let KEY_BITS: u32, let BIT_SECRET: u32, let BIT_SHARE: u32, let BIT_MSG: u32>(
    profile: [Field; 2],
    setup_binding: [Field; 2],
    dealer: u32,
    expected_secret_commitment: Field,
    moduli: [Field; L],
    secret: Polynomial<N>,
    y: [[[Field; N_PARTIES + 1]; L]; N],
    keys: [[u8; 32]; N_PARTIES],
) -> ([[Field; L]; N_PARTIES], Field) {
    // Reuse the post-copt checked opening, canonical rows and bounded finite differences.
    let sharing: SecretKeyShareComputation<N, L, N_PARTIES, T, BIT_SECRET, BIT_SHARE> =
        SecretKeyShareComputation::new(Configs::new(moduli), expected_secret_commitment, secret, y);
    let _ = sharing.execute();
    let root = outgoing_root::<N_PARTIES, KEY_BITS>(profile, setup_binding, dealer, keys);
    let messages = packed_messages::<N, L, N_PARTIES, KEY_BITS>(moduli, y, keys);
    let mut commitments = [[0; L]; N_PARTIES];
    for recipient in 0..N_PARTIES {
        for limb in 0..L {
            // C3 opens this exact packed polynomial at the transport message width.
            commitments[recipient][limb] = compute_share_encryption_commitment_from_message::<N, BIT_MSG>(
                messages[recipient][limb],
            );
        }
    }
    (commitments, root)
}
