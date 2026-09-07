// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_multiple_polynomial_commitment, compute_rlk_d0_commitment, compute_rlk_d2_commitment,
    DS_RLK_AGGREGATION,
};
use crate::math::modulo::U64::ModU64;
use crate::math::polynomial::Polynomial;

/// Parameters for l-BFV relinearization key aggregation (new circuit, row-level).
pub struct Configs<let L: u32> {
    /// CRT moduli for each basis: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
}

impl<let L: u32> Configs<L> {
    pub fn new(qis: [Field; L]) -> Self {
        Configs { qis }
    }
}

/// l-BFV relinearization key aggregation for one gadget row (new circuit,
/// analogous to `pk_aggregation` (C5) but for the RLK's `(d0, d2)` pair).
///
/// **Role:** Sum honest parties' `d0`/`d2` row limbs into `d0_agg`/`d2_agg` and
/// commit each for downstream use (e.g. final RLK assembly / on-chain
/// verification). `d1`/`a` are not part of this circuit: both are compile-time
/// constants already pinned by the verification key (same mechanism `CRP`
/// relies on for `pk_generation`/`pk_aggregation`), so hashing them here would
/// be redundant - any consumer that needs their values reads them directly
/// from the same `D1_GADGET_ROWS`/`CRP_GADGET_ROWS` constants.
///
/// **Consumes:** `commit(d0[h])`/`commit(d2[h])` from RLK generation per honest party `h`.
///
/// **Produces:** `(commit(d0_agg), commit(d2_agg))`.
///
/// **Verifies:** For each limb and coefficient, `d0_agg`/`d2_agg` match the
/// mod-q_l sum of party `d0`/`d2` (centered coefficients) - same technique as
/// `pk_aggregation`, applied twice.
pub struct RlkAggregation<let N: u32, let H: u32, let L: u32, let BIT_D: u32> {
    /// Circuit parameters including CRT moduli.
    configs: Configs<L>,

    /// Expected commitments to each honest party's `d0` for this row.
    /// (public witnesses)
    expected_d0_commitments: [Field; H],
    /// Expected commitments to each honest party's `d2` for this row.
    /// (public witnesses)
    expected_d2_commitments: [Field; H],

    /// Individual `d0` components from H honest parties for this row.
    /// (committed witnesses)
    d0: [[Polynomial<N>; L]; H],
    /// Individual `d2` components from H honest parties for this row.
    /// (committed witnesses)
    d2: [[Polynomial<N>; L]; H],

    /// Claimed aggregated `d0` for each CRT basis. Must equal sum(d0[h][l]) mod q_l.
    /// (committed witness)
    d0_agg: [Polynomial<N>; L],
    /// Claimed aggregated `d2` for each CRT basis. Must equal sum(d2[h][l]) mod q_l.
    /// (committed witness)
    d2_agg: [Polynomial<N>; L],
}

impl<let N: u32, let H: u32, let L: u32, let BIT_D: u32> RlkAggregation<N, H, L, BIT_D> {
    pub fn new(
        configs: Configs<L>,
        expected_d0_commitments: [Field; H],
        expected_d2_commitments: [Field; H],
        d0: [[Polynomial<N>; L]; H],
        d2: [[Polynomial<N>; L]; H],
        d0_agg: [Polynomial<N>; L],
        d2_agg: [Polynomial<N>; L],
    ) -> Self {
        RlkAggregation {
            configs,
            expected_d0_commitments,
            expected_d2_commitments,
            d0,
            d2,
            d0_agg,
            d2_agg,
        }
    }

    /// Verifies that each honest party's d0/d2 hashes to its expected
    /// commitment from RLK generation.
    fn verify_commitments(self) {
        for i in 0..H {
            assert(
                compute_rlk_d0_commitment::<N, L, BIT_D>(self.d0[i])
                    == self.expected_d0_commitments[i],
                "RLK d0 commitment mismatch",
            );
            assert(
                compute_rlk_d2_commitment::<N, L, BIT_D>(self.d2[i])
                    == self.expected_d2_commitments[i],
                "RLK d2 commitment mismatch",
            );
        }
    }

    /// Verifies aggregation correctness for one component (d0 or d2) at a given CRT basis.
    /// Same modular-sum technique as `pk_aggregation::verify_pk_for_basis`.
    fn verify_sum_for_basis(
        self,
        values: [[Polynomial<N>; L]; H],
        agg: [Polynomial<N>; L],
        basis_idx: u32,
    ) {
        let q_l = self.configs.qis[basis_idx];
        let mod_q_l = ModU64::new(q_l as u64);

        let half_qi: Field = (q_l - 1) / 2;
        let h_half_qi: Field = H as Field * half_qi;
        let offset: Field = H as Field * q_l;

        for coeff_idx in 0..N {
            let mut sum_shifted: Field = 0;
            for party_idx in 0..H {
                sum_shifted =
                    sum_shifted + values[party_idx][basis_idx].coefficients[coeff_idx] + half_qi;
            }
            mod_q_l.assert_zero_mod(
                sum_shifted + offset - agg[basis_idx].coefficients[coeff_idx] - h_half_qi,
            );
        }
    }

    /// Returns `(commit(d0_agg), commit(d2_agg))` for downstream consumption.
    pub fn execute(self) -> (Field, Field) {
        // Step 1: Bind each party's d0/d2 to its RLK generation commitment.
        self.verify_commitments();

        // Step 2: Check `d0_agg`/`d2_agg` are the mod-q_l sum of party limbs.
        for basis_idx in 0..L {
            self.verify_sum_for_basis(self.d0, self.d0_agg, basis_idx);
            self.verify_sum_for_basis(self.d2, self.d2_agg, basis_idx);
        }

        // Step 3: Commit to d0_agg and d2_agg separately.
        let d0_agg_commitment =
            compute_multiple_polynomial_commitment::<N, L, BIT_D>(self.d0_agg, DS_RLK_AGGREGATION);
        let d2_agg_commitment =
            compute_multiple_polynomial_commitment::<N, L, BIT_D>(self.d2_agg, DS_RLK_AGGREGATION);

        (d0_agg_commitment, d2_agg_commitment)
    }
}
