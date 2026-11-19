// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Limb 2 of chunked C4: C4's statement for CRT limb 2, continuing the aggregate commitment's
//! sponge from `h_in`. See `lib::core::dkg::share_decryption_chain`.

use lib::configs::default::dkg::{
    L_THRESHOLD, N, QIS_THRESHOLD, SHARE_DECRYPTION_BIT_AGG, SHARE_DECRYPTION_BIT_MSG,
};
use lib::configs::default::H;
use lib::core::dkg::share_decryption_chain::share_decryption_limb;
use lib::math::polynomial::Polynomial;
use lib::math::safe::STATE_SIZE;

fn main(
    expected_commitments: pub [Field; H],
    h_in: pub Field,
    decrypted_shares: [Polynomial<N>; H],
    state_in: [Field; STATE_SIZE],
) -> pub Field {
    share_decryption_limb::<2, N, L_THRESHOLD, H, SHARE_DECRYPTION_BIT_MSG, SHARE_DECRYPTION_BIT_AGG>(
        QIS_THRESHOLD,
        expected_commitments,
        decrypted_shares,
        h_in,
        state_in,
    )
}
