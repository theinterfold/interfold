// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::core::dkg::share_computation::commit_to_party_shares;
use crate::math::commitments::{
    compute_share_computation_chunk_commitment, compute_share_computation_e_sm_commitment,
    compute_share_computation_sk_commitment,
};
use crate::math::polynomial::Polynomial;

pub struct SecretKeyShareComputationBase<let N: u32, let L: u32, let N_PARTIES: u32, let BIT_SECRET: u32, let BIT_SHARE: u32, let CHUNK_SIZE: u32, let N_CHUNKS: u32> {
    expected_secret_commitment: Field,
    sk_secret: Polynomial<N>,
    y: [[[Field; N_PARTIES + 1]; L]; N],
}

impl<let N: u32, let L: u32, let N_PARTIES: u32, let BIT_SECRET: u32, let BIT_SHARE: u32, let CHUNK_SIZE: u32, let N_CHUNKS: u32> SecretKeyShareComputationBase<N, L, N_PARTIES, BIT_SECRET, BIT_SHARE, CHUNK_SIZE, N_CHUNKS> {
    pub fn new(
        expected_secret_commitment: Field,
        sk_secret: Polynomial<N>,
        y: [[[Field; N_PARTIES + 1]; L]; N],
    ) -> Self {
        SecretKeyShareComputationBase { expected_secret_commitment, sk_secret, y }
    }

    fn verify_secret_commitment(self) {
        let mut reversed_coeffs: [Field; N] = [0; N];
        for i in 0..N {
            reversed_coeffs[i] = self.sk_secret.coefficients[N - 1 - i];
        }
        assert(
            compute_share_computation_sk_commitment::<N, BIT_SECRET>(Polynomial::new(
                reversed_coeffs,
            ))
                == self.expected_secret_commitment,
            "SK commitment mismatch",
        );
    }

    fn verify_secret_consistency(self) {
        for coeff_idx in 0..N {
            for mod_idx in 0..L {
                assert(self.y[coeff_idx][mod_idx][0] == self.sk_secret.coefficients[coeff_idx]);
            }
        }
    }

    fn compute_chunk_commitments(self) -> [Field; N_CHUNKS] {
        let mut commitments: [Field; N_CHUNKS] = [0; N_CHUNKS];
        for chunk_idx in 0..N_CHUNKS {
            let start = chunk_idx * CHUNK_SIZE;
            let mut y_chunk: [[[Field; N_PARTIES + 1]; L]; CHUNK_SIZE] =
                [[[0; N_PARTIES + 1]; L]; CHUNK_SIZE];
            for i in 0..CHUNK_SIZE {
                y_chunk[i] = self.y[start + i];
            }
            commitments[chunk_idx] = compute_share_computation_chunk_commitment::<N_PARTIES, L, CHUNK_SIZE>(
                y_chunk,
                chunk_idx,
            );
        }
        commitments
    }

    pub fn execute(self) -> ([Field; N_CHUNKS], [[Field; L]; N_PARTIES]) {
        self.verify_secret_commitment();
        self.verify_secret_consistency();
        (
            self.compute_chunk_commitments(),
            commit_to_party_shares::<N, L, N_PARTIES, BIT_SHARE, N_CHUNKS, CHUNK_SIZE>(self.y),
        )
    }
}

pub struct SmudgingNoiseShareComputationBase<let N: u32, let L: u32, let N_PARTIES: u32, let BIT_SECRET: u32, let BIT_SHARE: u32, let CHUNK_SIZE: u32, let N_CHUNKS: u32> {
    expected_secret_commitment: Field,
    e_sm_secret: [Polynomial<N>; L],
    y: [[[Field; N_PARTIES + 1]; L]; N],
    qis: [Field; L],
}

impl<let N: u32, let L: u32, let N_PARTIES: u32, let BIT_SECRET: u32, let BIT_SHARE: u32, let CHUNK_SIZE: u32, let N_CHUNKS: u32> SmudgingNoiseShareComputationBase<N, L, N_PARTIES, BIT_SECRET, BIT_SHARE, CHUNK_SIZE, N_CHUNKS> {
    pub fn new(
        expected_secret_commitment: Field,
        e_sm_secret: [Polynomial<N>; L],
        y: [[[Field; N_PARTIES + 1]; L]; N],
        qis: [Field; L],
    ) -> Self {
        SmudgingNoiseShareComputationBase { expected_secret_commitment, e_sm_secret, y, qis }
    }

    fn verify_secret_commitment(self) {
        let mut normalized: [Polynomial<N>; L] = [Polynomial::new([0; N]); L];
        for j in 0..L {
            let q = self.qis[j];
            let half = (q - 1) / 2;
            let mut coeffs: [Field; N] = [0; N];
            for i in 0..N {
                let c = self.e_sm_secret[j].coefficients[N - 1 - i];
                coeffs[i] = if (c as u64) > (half as u64) { c - q } else { c };
            }
            normalized[j] = Polynomial::new(coeffs);
        }
        assert(
            compute_share_computation_e_sm_commitment::<N, L, BIT_SECRET>(normalized)
                == self.expected_secret_commitment,
            "ESM commitment mismatch",
        );
    }

    fn verify_secret_consistency(self) {
        for coeff_idx in 0..N {
            for mod_idx in 0..L {
                assert(
                    self.y[coeff_idx][mod_idx][0]
                        == self.e_sm_secret[mod_idx].coefficients[coeff_idx],
                );
            }
        }
    }

    fn compute_chunk_commitments(self) -> [Field; N_CHUNKS] {
        let mut commitments: [Field; N_CHUNKS] = [0; N_CHUNKS];
        for chunk_idx in 0..N_CHUNKS {
            let start = chunk_idx * CHUNK_SIZE;
            let mut y_chunk: [[[Field; N_PARTIES + 1]; L]; CHUNK_SIZE] =
                [[[0; N_PARTIES + 1]; L]; CHUNK_SIZE];
            for i in 0..CHUNK_SIZE {
                y_chunk[i] = self.y[start + i];
            }
            commitments[chunk_idx] = compute_share_computation_chunk_commitment::<N_PARTIES, L, CHUNK_SIZE>(
                y_chunk,
                chunk_idx,
            );
        }
        commitments
    }

    pub fn execute(self) -> ([Field; N_CHUNKS], [[Field; L]; N_PARTIES]) {
        self.verify_secret_commitment();
        self.verify_secret_consistency();
        (
            self.compute_chunk_commitments(),
            commit_to_party_shares::<N, L, N_PARTIES, BIT_SHARE, N_CHUNKS, CHUNK_SIZE>(self.y),
        )
    }
}
