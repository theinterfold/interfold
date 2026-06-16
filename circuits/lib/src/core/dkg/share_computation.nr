// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_share_computation_e_sm_commitment, compute_share_computation_sk_commitment,
    compute_share_encryption_commitment_from_message,
};
use crate::math::modulo::U64::ModU64;
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
pub struct SecretKeyShareComputation<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SECRET: u32, let BIT_SHARE: u32> {
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

/// Correct Threshold Smudging Noise Share Computation (Circuit 2b).
///
/// Verifies:
/// 1. secret commitment: verify secret hashes to expected_secret_commitment
/// 2. secret consistency: y[i][j][0] == e_sm[j][i] for all i, j
/// 3. Range check: shares are in [0, q_j)
/// 4. Parity check: H[j] * y[i][j]^T == 0 mod q_j for all i, j
///
/// For ESM: e_sm[j] is the RNS representation at modulus j
pub struct SmudgingNoiseShareComputation<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SECRET: u32, let BIT_SHARE: u32> {
    configs: Configs<L>,
    /// Expected commitment to secret (from C1)
    /// This is computed from all L RNS polynomials (matching
    /// multiple_polynomial_payload's behavior which hashes all L modulus polynomials)
    expected_secret_commitment: Field,
    /// Smudging noise polynomial per modulus: [Polynomial<N>; L]
    /// For ESM: each modulus has its own polynomial (RNS representation)
    e_sm_secret: [Polynomial<N>; L],
    /// Shares: y[coeff_idx][mod_idx][0..N_PARTIES+1]
    /// y[i][j][0] = e_sm[j][i] = f(0), y[i][j][k] = f(k) for k = 1..N_PARTIES
    y: [[[Field; N_PARTIES + 1]; L]; N],
    /// Parity check matrices: H[mod_idx][row][col]
    /// Size per modulus: (N_PARTIES - T) * (N_PARTIES + 1)
    /// H * y^T = 0 mod q_j
    h: [[[Field; N_PARTIES + 1]; N_PARTIES - T]; L],
}

impl<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SECRET: u32, let BIT_SHARE: u32> SecretKeyShareComputation<N, L, N_PARTIES, T, BIT_SECRET, BIT_SHARE> {
    pub fn new(
        configs: Configs<L>,
        expected_secret_commitment: Field,
        sk_secret: Polynomial<N>,
        y: [[[Field; N_PARTIES + 1]; L]; N],
        h: [[[Field; N_PARTIES + 1]; N_PARTIES - T]; L],
    ) -> Self {
        SecretKeyShareComputation { configs, expected_secret_commitment, sk_secret, y, h }
    }

    /// Main verification function
    pub fn execute(self) -> [[Field; L]; N_PARTIES] {
        // Step 1: Verify secret commitment matches expected
        self.verify_secret_commitment();

        // Step 2: Verify secret consistency
        self.verify_secret_consistency();

        // Step 3: Range checks
        check_range_bounds::<N, L, N_PARTIES, BIT_SHARE>(self.configs.qis, self.y);

        // Step 4: Verify parity check
        verify_parity_check::<N, L, N_PARTIES, T>(self.configs.qis, self.h, self.y);

        // Step 5: Commit to shares for each party and modulus
        commit_to_party_shares::<N, L, N_PARTIES, BIT_SHARE>(self.y)
    }

    /// Verifies that secret hashes to expected_secret_commitment.
    ///
    /// Reverses `sk_secret` coefficients before hashing to match C1 (PkGeneration)'s
    /// convention, which passes sk in highest-degree-first order. This ensures
    /// `C1.sk_commitment == C2a.expected_secret_commitment` for the same sk.
    fn verify_secret_commitment(self) {
        let mut reversed_coeffs: [Field; N] = [0; N];
        for i in 0..N {
            reversed_coeffs[i] = self.sk_secret.coefficients[N - 1 - i];
        }
        let reversed_sk = Polynomial::new(reversed_coeffs);
        assert(
            compute_share_computation_sk_commitment::<N, BIT_SECRET>(reversed_sk)
                == self.expected_secret_commitment,
            "SK commitment mismatch",
        );
    }

    /// Verifies secret consistency: `y[i][j][0] == sk_secret[i]` for all i, j.
    ///
    /// This function ensures that for each coefficient i and CRT basis j, the share
    /// at party ID 0 equals the corresponding secret coefficient for that modulus.
    /// This is a fundamental property of Shamir secret sharing where the secret is the
    /// evaluation of the sharing polynomial at point 0.
    ///
    /// sk_secret is the trinary coefficients, so y[i][j][0] is the same for all j.
    ///
    /// # Panics
    /// The circuit will fail if secret consistency doesn't hold for any
    /// coefficient or CRT basis.
    fn verify_secret_consistency(self) {
        for coeff_idx in 0..N {
            let secret_coeff = self.sk_secret.coefficients[coeff_idx];

            for mod_idx in 0..L {
                assert(self.y[coeff_idx][mod_idx][0] == secret_coeff);
            }
        }
    }
}

impl<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SECRET: u32, let BIT_SHARE: u32> SmudgingNoiseShareComputation<N, L, N_PARTIES, T, BIT_SECRET, BIT_SHARE> {
    pub fn new(
        configs: Configs<L>,
        expected_secret_commitment: Field,
        e_sm_secret: [Polynomial<N>; L],
        y: [[[Field; N_PARTIES + 1]; L]; N],
        h: [[[Field; N_PARTIES + 1]; N_PARTIES - T]; L],
    ) -> Self {
        SmudgingNoiseShareComputation { configs, expected_secret_commitment, e_sm_secret, y, h }
    }

    /// Main verification function
    pub fn execute(self) -> [[Field; L]; N_PARTIES] {
        // Step 1: Verify secret commitment matches expected
        self.verify_secret_commitment();

        // Step 2: Verify secret consistency
        self.verify_secret_consistency();

        // Step 3: Range checks
        check_range_bounds::<N, L, N_PARTIES, BIT_SHARE>(self.configs.qis, self.y);

        // Step 4: Verify parity check
        verify_parity_check::<N, L, N_PARTIES, T>(self.configs.qis, self.h, self.y);

        // Step 5: Commit to shares for each party and modulus
        commit_to_party_shares::<N, L, N_PARTIES, BIT_SHARE>(self.y)
    }

    /// Verifies that secret hashes to expected_secret_commitment.
    ///
    /// Reverses and centers each `e_sm_secret` limb before hashing to match C1 (PkGeneration)'s
    /// convention: C1 passes e_sm reversed+centered (highest-degree-first, coefficients in
    /// `[-(q-1)/2, (q-1)/2]`). `e_sm_secret` here is in `[0, q)`, so we apply the same
    /// reverse+center transform before hashing.
    fn verify_secret_commitment(self) {
        let mut normalized: [Polynomial<N>; L] = [Polynomial::new([0; N]); L];
        for j in 0..L {
            let q = self.configs.qis[j];
            let half = (q - 1) / 2;
            let mut coeffs: [Field; N] = [0; N];
            for i in 0..N {
                // Reverse: position i gets the coefficient from N-1-i.
                let c = self.e_sm_secret[j].coefficients[N - 1 - i];
                // Center: shift [0, q) to [-(q-1)/2, (q-1)/2].
                // c = e_sm_secret coeff in [0, q) < 2^62; half < 2^61: u64 saves 22 gates.
                let centered = if (c as u64) > (half as u64) { c - q } else { c };
                coeffs[i] = centered;
            }
            normalized[j] = Polynomial::new(coeffs);
        }
        assert(
            compute_share_computation_e_sm_commitment::<N, L, BIT_SECRET>(normalized)
                == self.expected_secret_commitment,
            "ESM commitment mismatch",
        );
    }

    /// Verifies secret consistency: `y[i][j][0] == e_sm_secret[j][i]` for all i, j.
    ///
    /// This function ensures that for each coefficient i and CRT basis j, the share
    /// at party ID 0 equals the corresponding secret coefficient for that modulus.
    /// This is a fundamental property of Shamir secret sharing where the secret is the
    /// evaluation of the sharing polynomial at point 0.
    ///
    /// e_sm_secret[j] is the RNS representation at modulus j, so y[i][j][0] varies per modulus.
    ///
    /// # Panics
    /// The circuit will fail if secret consistency doesn't hold for any
    /// coefficient or CRT basis.
    fn verify_secret_consistency(self) {
        for coeff_idx in 0..N {
            for mod_idx in 0..L {
                let secret_coeff = self.e_sm_secret[mod_idx].coefficients[coeff_idx];
                assert(
                    self.y[coeff_idx][mod_idx][0] == secret_coeff,
                    "Secret consistency check failed",
                );
            }
        }
    }
}

/// Performs range checks on secret key and share values.
///
/// This function constrains all values to be within their expected bounds:
/// - Share values for parties k >= 1 must be in [0, q_j) for each CRT modulus q_j
///
/// These bounds are critical for security and correctness of the Threshold scheme.
///
/// # Panics
/// This function will cause the circuit to fail if any value is outside
/// its expected bounds.
pub fn check_range_bounds<let N: u32, let L: u32, let N_PARTIES: u32, let BIT_SHARE: u32>(
    qis: [Field; L],
    y: [[[Field; N_PARTIES + 1]; L]; N],
) {
    // Shares y[i][j][k] for k >= 1 should be in [0, q_j)
    for mod_idx in 0..L {
        let q_j = qis[mod_idx];

        for coeff_idx in 0..N {
            for party_idx in 1..(N_PARTIES + 1) {
                // Use range_check_standard from Polynomial by creating a single-coefficient polynomial
                Polynomial::new([y[coeff_idx][mod_idx][party_idx]])
                    .range_check_standard::<BIT_SHARE>(q_j);
            }
        }
    }
}

/// Verifies Reed-Solomon parity check: `H[j] * y[i][j]^T == 0 mod q_j` for all i, j.
///
/// This function verifies that for each coefficient i and CRT basis j, the share
/// vector `y[i][j]` forms a valid Reed-Solomon codeword by satisfying the parity
/// check equation with the parity check matrix `H[j]`.
///
/// The parity check matrix H[j] has dimensions `(N_PARTIES - T) * (N_PARTIES + 1)`,
/// and the share vector `y[i][j]` has length `N_PARTIES + 1`. The parity check
/// ensures that any T+1 shares can correctly reconstruct the secret key via
/// Lagrange interpolation.
///
/// # Panics
/// The circuit will fail if the parity check doesn't hold for any coefficient,
/// CRT basis, or parity check row.
pub fn verify_parity_check<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32>(
    qis: [Field; L],
    h: [[[Field; N_PARTIES + 1]; N_PARTIES - T]; L],
    y: [[[Field; N_PARTIES + 1]; L]; N],
) {
    for coeff_idx in 0..N {
        for mod_idx in 0..L {
            let q_j = qis[mod_idx];

            // For each row of H, compute dot product with y and verify == 0
            for row in 0..(N_PARTIES - T) {
                let mut sum: Field = 0;

                for col in 0..(N_PARTIES + 1) {
                    sum = sum + h[mod_idx][row][col] * y[coeff_idx][mod_idx][col];
                }

                // Assert sum divisible by q_j: ~12 gates vs reduce_mod's ~24 gates.
                // Safe: sum < (N_PARTIES+1)*max(h)*q_j < 2^122 << field prime, no Field wrap.
                ModU64::new(q_j as u64).assert_zero_mod(sum);
            }
        }
    }
}

/// Commits to shares for each party and modulus.
///
/// Returns `[[Field; L]; N_PARTIES]` where `commitments[party_idx][mod_idx]`
/// equals `compute_share_encryption_commitment_from_message(share_polynomial)`.
pub fn commit_to_party_shares<let N: u32, let L: u32, let N_PARTIES: u32, let BIT_SHARE: u32>(
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
            commitments[party_idx][mod_idx] =
                compute_share_encryption_commitment_from_message::<N, BIT_SHARE>(share_poly);
        }
    }

    commitments
}
