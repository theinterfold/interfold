// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY

use crate::core::threshold::pk_generation::{Configs, PkGeneration};
use crate::math::polynomial::Polynomial;

/// Proves one row of an l-BFV public-key contribution.
///
/// The circuit reuses the C1 relation with zero smudging noise. It returns the
/// secret-key commitment and the commitment to the selected public-key row.
pub struct LbfvPkGeneration<let N: u32, let L: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_E_SM: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_PK: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> {
    configs: Configs<N, L>,
    a: [Polynomial<N>; L],
    eek: Polynomial<N>,
    sk: Polynomial<N>,
    r1: [Polynomial<2 * N - 1>; L],
    r2: [Polynomial<N - 1>; L],
    pk0: [Polynomial<N>; L],
}

impl<let N: u32, let L: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_E_SM: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_PK: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> LbfvPkGeneration<N, L, BIT_EEK, BIT_SK, BIT_E_SM, BIT_R1, BIT_R2, BIT_PK, N_CHUNKS, CHUNK_SIZE> {
    pub fn new(
        configs: Configs<N, L>,
        a: [Polynomial<N>; L],
        eek: Polynomial<N>,
        sk: Polynomial<N>,
        r1: [Polynomial<2 * N - 1>; L],
        r2: [Polynomial<N - 1>; L],
        pk0: [Polynomial<N>; L],
    ) -> Self {
        LbfvPkGeneration { configs, a, eek, sk, r1, r2, pk0 }
    }

    pub fn execute(self) -> (Field, Field) {
        let e_sm: [Polynomial<N>; L] = [Polynomial::new([0; N]); L];
        let circuit: PkGeneration<N, L, BIT_EEK, BIT_SK, BIT_E_SM, BIT_R1, BIT_R2, BIT_PK, N_CHUNKS, CHUNK_SIZE> = PkGeneration::new(
            self.configs,
            self.a,
            self.eek,
            self.sk,
            e_sm,
            self.r1,
            self.r2,
            self.pk0,
        );
        let (sk_commitment, pk_commitment, _) = circuit.execute();
        (sk_commitment, pk_commitment)
    }
}
