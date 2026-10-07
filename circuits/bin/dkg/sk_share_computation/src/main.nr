// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::dkg::{
    L_THRESHOLD, N, PARITY_MATRIX, SHARE_COMPUTATION_BIT_SHARE, SHARE_COMPUTATION_SK_BIT_SECRET,
    SHARE_COMPUTATION_SK_CONFIGS,
};
use lib::configs::default::{N_PARTIES, T};
use lib::core::dkg::share_computation::SecretKeyShareComputation;
use lib::math::polynomial::Polynomial;

fn main(
    expected_secret_commitment: pub Field,
    sk_secret: Polynomial<N>,
    y: [[[Field; N_PARTIES + 1]; L_THRESHOLD]; N],
) -> pub [[Field; L_THRESHOLD]; N_PARTIES] {
    let sk_share_computation: SecretKeyShareComputation<N, L_THRESHOLD, N_PARTIES, T, SHARE_COMPUTATION_SK_BIT_SECRET, SHARE_COMPUTATION_BIT_SHARE> = SecretKeyShareComputation::new(
        SHARE_COMPUTATION_SK_CONFIGS,
        expected_secret_commitment,
        sk_secret,
        y,
        PARITY_MATRIX,
    );

    sk_share_computation.execute()
}
