// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/// Parameters for l-BFV relinearization-key generation.
pub struct Configs<let N: u32, let L: u32> {
    /// CRT moduli: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
    /// Bound for the ephemeral `r` polynomial coefficients (same distribution as `sk`).
    pub r_bound: Field,
    /// Bound for secret key polynomial (`sk`) coefficients.
    pub sk_bound: Field,
    /// Bound for `e0` (d0's error) coefficients.
    pub e0_bound: Field,
    /// Bound for `e2` (d2's error) coefficients.
    pub e2_bound: Field,
    /// Bounds for r1_d0 (d0 modulus-switching quotients) for each CRT basis.
    pub r1_d0_bounds: [Field; L],
    /// Bounds for r2_d0 (d0 cyclotomic-reduction quotients) for each CRT basis.
    pub r2_d0_bounds: [Field; L],
    /// Bounds for r1_d2 (d2 modulus-switching quotients) for each CRT basis.
    pub r1_d2_bounds: [Field; L],
    /// Bounds for r2_d2 (d2 cyclotomic-reduction quotients) for each CRT basis.
    pub r2_d2_bounds: [Field; L],
}

impl<let N: u32, let L: u32> Configs<N, L> {
    pub fn new(
        qis: [Field; L],
        r_bound: Field,
        sk_bound: Field,
        e0_bound: Field,
        e2_bound: Field,
        r1_d0_bounds: [Field; L],
        r2_d0_bounds: [Field; L],
        r1_d2_bounds: [Field; L],
        r2_d2_bounds: [Field; L],
    ) -> Self {
        Configs {
            qis,
            r_bound,
            sk_bound,
            e0_bound,
            e2_bound,
            r1_d0_bounds,
            r2_d0_bounds,
            r1_d2_bounds,
            r2_d2_bounds,
        }
    }
}
