// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::compute_share_computation_chunk_commitment;
use crate::math::modulo::U64::ModU64;
use crate::math::polynomial::Polynomial;

pub struct Configs<let L: u32> {
    pub qis: [Field; L],
}

impl<let L: u32> Configs<L> {
    pub fn new(qis: [Field; L]) -> Self {
        Configs { qis }
    }
}

pub struct ShareComputationChunk<let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SHARE: u32, let CHUNK_SIZE: u32, let N_CHUNKS: u32> {
    configs: Configs<L>,
    chunk_commitment: Field,
    chunk_idx: u32,
    y_chunk: [[[Field; N_PARTIES + 1]; L]; CHUNK_SIZE],
    h: [[[Field; N_PARTIES + 1]; N_PARTIES - T]; L],
}

impl<let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SHARE: u32, let CHUNK_SIZE: u32, let N_CHUNKS: u32> ShareComputationChunk<L, N_PARTIES, T, BIT_SHARE, CHUNK_SIZE, N_CHUNKS> {
    pub fn new(
        configs: Configs<L>,
        chunk_commitment: Field,
        chunk_idx: u32,
        y_chunk: [[[Field; N_PARTIES + 1]; L]; CHUNK_SIZE],
        h: [[[Field; N_PARTIES + 1]; N_PARTIES - T]; L],
    ) -> Self {
        ShareComputationChunk { configs, chunk_commitment, chunk_idx, y_chunk, h }
    }

    pub fn execute(self) {
        assert(self.chunk_idx < N_CHUNKS);
        assert(
            compute_share_computation_chunk_commitment::<N_PARTIES, L, CHUNK_SIZE>(
                self.y_chunk,
                self.chunk_idx,
            )
                == self.chunk_commitment,
            "chunk commitment mismatch",
        );

        for mod_idx in 0..L {
            let q_j = self.configs.qis[mod_idx];
            for coeff_idx in 0..CHUNK_SIZE {
                for party_idx in 1..(N_PARTIES + 1) {
                    Polynomial::new([self.y_chunk[coeff_idx][mod_idx][party_idx]])
                        .range_check_standard::<BIT_SHARE>(q_j);
                }
                for row in 0..(N_PARTIES - T) {
                    let mut sum: Field = 0;
                    for col in 0..(N_PARTIES + 1) {
                        sum =
                            sum + self.h[mod_idx][row][col] * self.y_chunk[coeff_idx][mod_idx][col];
                    }
                    ModU64::new(q_j as u64).assert_zero_mod(sum);
                }
            }
        }
    }
}
