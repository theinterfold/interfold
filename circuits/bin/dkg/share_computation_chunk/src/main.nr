// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::dkg::{
    L_THRESHOLD, PARITY_MATRIX, QIS_THRESHOLD, SHARE_COMPUTATION_BIT_SHARE,
    SHARE_COMPUTATION_CHUNK_SIZE, SHARE_COMPUTATION_N_CHUNKS,
};
use lib::configs::default::{N_PARTIES, T};
use lib::core::dkg::share_computation_chunk::{Configs, ShareComputationChunk};

fn main(
    chunk_commitment: pub Field,
    chunk_idx: pub u32,
    y_chunk: [[[Field; N_PARTIES + 1]; L_THRESHOLD]; SHARE_COMPUTATION_CHUNK_SIZE],
) {
    let configs = Configs::<L_THRESHOLD>::new(QIS_THRESHOLD);
    let circuit: ShareComputationChunk<L_THRESHOLD, N_PARTIES, T, SHARE_COMPUTATION_BIT_SHARE, SHARE_COMPUTATION_CHUNK_SIZE, SHARE_COMPUTATION_N_CHUNKS> =
        ShareComputationChunk::new(configs, chunk_commitment, chunk_idx, y_chunk, PARITY_MATRIX);
    circuit.execute()
}
