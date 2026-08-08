// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::dkg::{
    L_THRESHOLD, N, QIS_THRESHOLD, SHARE_COMPUTATION_BIT_SHARE, SHARE_COMPUTATION_CHUNK_SIZE,
    SHARE_COMPUTATION_E_SM_BIT_SECRET, SHARE_COMPUTATION_N_CHUNKS,
};
use lib::configs::default::N_PARTIES;
use lib::core::dkg::share_computation_base::SmudgingNoiseShareComputationBase;
use lib::math::polynomial::Polynomial;

fn main(
    expected_secret_commitment: pub Field,
    e_sm_secret: [Polynomial<N>; L_THRESHOLD],
    y: [[[Field; N_PARTIES + 1]; L_THRESHOLD]; N],
) -> pub ([Field; SHARE_COMPUTATION_N_CHUNKS], [[Field; L_THRESHOLD]; N_PARTIES]) {
    let circuit: SmudgingNoiseShareComputationBase<N, L_THRESHOLD, N_PARTIES, SHARE_COMPUTATION_E_SM_BIT_SECRET, SHARE_COMPUTATION_BIT_SHARE, SHARE_COMPUTATION_CHUNK_SIZE, SHARE_COMPUTATION_N_CHUNKS> = SmudgingNoiseShareComputationBase::new(
        expected_secret_commitment,
        e_sm_secret,
        y,
        QIS_THRESHOLD,
    );
    circuit.execute()
}
