// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::compute_sc_party_share_root_from_polynomial;
use crate::math::polynomial::Polynomial;

/// Cryptographic parameters for Threshold secret share verification circuit.
pub struct Configs<let L: u32> {
    /// CRT moduli: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
}

impl<let L: u32> Configs<L> {
    pub fn new(qis: [Field; L]) -> Self {
        Configs { qis }
    }
}

/// Correct Threshold Secret Key Share Computation (Circuit 2a).
///
/// Verifies:
/// 1. secret commitment: verify secret hashes to expected_secret_commitment
/// 2. secret consistency: y[i][j][0] == sk_secret[i] for all i, j
/// 3. Range check: shares are in [0, q_j)
/// 4. Parity check: H[j] * y[i][j]^T == 0 mod q_j for all i, j
///
/// For SK: sk_secret is the trinary coefficients
pub struct SecretKeyShareComputation<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SECRET: u32, let BIT_SHARE: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> {
    configs: Configs<L>,
    /// Expected commitment to secret (from C1)
    /// (public witness)
    expected_secret_commitment: Field,
    /// Secret key polynomial: Polynomial<N>
    /// trinary coefficients
    /// (secret witness)
    sk_secret: Polynomial<N>,
    /// Shares: y[coeff_idx][mod_idx][0..N_PARTIES+1]
    /// y[i][j][0] = sk_secret[i] = f(0), y[i][j][k] = f(k) for k = 1..N_PARTIES
    /// (secret witnesses)
    y: [[[Field; N_PARTIES + 1]; L]; N],
    /// Parity check matrices: H[mod_idx][row][col]
    /// Size per modulus: (N_PARTIES - T) * (N_PARTIES + 1)
    /// H * y^T = 0 mod q_j
    /// (public constants)
    h: [[[Field; N_PARTIES + 1]; N_PARTIES - T]; L],
}


/// Commits to shares for each party and modulus.
///
/// Returns `[[Field; L]; N_PARTIES]` where `commitments[party_idx][mod_idx]`
/// equals the root commitment for the reversed share polynomial.
pub fn commit_to_party_shares<let N: u32, let L: u32, let N_PARTIES: u32, let BIT_SHARE: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32>(
    y: [[[Field; N_PARTIES + 1]; L]; N],
) -> [[Field; L]; N_PARTIES] {
    let mut commitments: [[Field; L]; N_PARTIES] = [[0; L]; N_PARTIES];

    for party_idx in 0..N_PARTIES {
        for mod_idx in 0..L {
            // Build the share polynomial for this (party, modulus) pair.
            // Coefficients are stored in reversed order to match C3 / C4 `message` witness,
            // which is constructed as `pt.value.reversed()` before committing.
            let mut share_coeffs: [Field; N] = [0; N];
            for coeff_idx in 0..N {
                share_coeffs[N - 1 - coeff_idx] = y[coeff_idx][mod_idx][party_idx + 1];
            }

            let share_poly = Polynomial::new(share_coeffs);
            commitments[party_idx][mod_idx] = compute_sc_party_share_root_from_polynomial::<N, N_CHUNKS, CHUNK_SIZE, BIT_SHARE>(
                party_idx,
                mod_idx,
                share_poly,
            );
        }
    }

    commitments
}
