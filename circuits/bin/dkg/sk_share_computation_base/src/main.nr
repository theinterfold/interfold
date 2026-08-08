// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::dkg::{
    L_THRESHOLD, N, SHARE_COMPUTATION_BIT_SHARE, SHARE_COMPUTATION_CHUNK_SIZE,
    SHARE_COMPUTATION_N_CHUNKS, SHARE_COMPUTATION_SK_BIT_SECRET,
};
use lib::configs::default::N_PARTIES;
use lib::core::dkg::share_computation_base::SecretKeyShareComputationBase;
use lib::math::polynomial::Polynomial;

fn main(
    expected_secret_commitment: pub Field,
    sk_secret: Polynomial<N>,
    y: [[[Field; N_PARTIES + 1]; L_THRESHOLD]; N],
) -> pub ([Field; SHARE_COMPUTATION_N_CHUNKS], [[Field; L_THRESHOLD]; N_PARTIES]) {
    let circuit: SecretKeyShareComputationBase<N, L_THRESHOLD, N_PARTIES, SHARE_COMPUTATION_SK_BIT_SECRET, SHARE_COMPUTATION_BIT_SHARE, SHARE_COMPUTATION_CHUNK_SIZE, SHARE_COMPUTATION_N_CHUNKS> =
        SecretKeyShareComputationBase::new(expected_secret_commitment, sk_secret, y);
    circuit.execute()
}
