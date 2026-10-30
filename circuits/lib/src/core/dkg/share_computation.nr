// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_share_computation_e_sm_commitment_checked,
    compute_share_computation_sk_commitment_checked,
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
/// 4. Shamir check: y[i][j][0..=N_PARTIES] lie on one polynomial of degree <= T mod q_j
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
}

/// Correct Threshold Smudging Noise Share Computation (Circuit 2b).
///
/// Verifies:
/// 1. secret commitment: verify secret hashes to expected_secret_commitment
/// 2. secret consistency: y[i][j][0] == e_sm[j][i] for all i, j
/// 3. Range check: shares are in [0, q_j)
/// 4. Shamir check: y[i][j][0..=N_PARTIES] lie on one polynomial of degree <= T mod q_j
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
}

impl<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SECRET: u32, let BIT_SHARE: u32> SecretKeyShareComputation<N, L, N_PARTIES, T, BIT_SECRET, BIT_SHARE> {
    pub fn new(
        configs: Configs<L>,
        expected_secret_commitment: Field,
        sk_secret: Polynomial<N>,
        y: [[[Field; N_PARTIES + 1]; L]; N],
    ) -> Self {
        SecretKeyShareComputation { configs, expected_secret_commitment, sk_secret, y }
    }

    /// Main verification function
    pub fn execute(self) -> [[Field; L]; N_PARTIES] {
        // Step 1: Verify secret commitment matches expected
        self.verify_secret_commitment();

        // Step 2: Verify secret consistency
        self.verify_secret_consistency();

        // Step 3: Range checks
        check_range_bounds::<N, L, N_PARTIES, BIT_SHARE>(self.configs.qis, self.y);

        // Step 4: Verify the shares lie on one degree-T polynomial
        verify_shamir_finite_differences::<N, L, N_PARTIES, T>(self.configs.qis, self.y);

        // Step 5: Commit to shares for each party and modulus
        commit_to_party_shares::<N, L, N_PARTIES, BIT_SHARE>(self.y)
    }

    /// Verifies that secret hashes to expected_secret_commitment.
    ///
    /// Reverses `sk_secret` coefficients before hashing to match C1 (PkGeneration)'s
    /// convention, which passes sk in highest-degree-first order. This ensures
    /// `C1.sk_commitment == C2a.expected_secret_commitment` for the same sk.
    ///
    /// Opens with the checked packing helper. `sk_secret` carries no range check of its own here:
    /// `check_range_bounds` covers the shares (`party_idx >= 1`), not the secret. Asserting each
    /// packed digit fits its slot makes the opening unique, so the witness must equal the trinary
    /// `sk` C1 committed. Without it the slot at `BIT_SECRET = 1` is only `radix = 2^8`, so a
    /// coefficient of 240 or more overflows into the next and gives the commitment a second
    /// opening -- the prover could Shamir-split a secret other than the one in the public key.
    fn verify_secret_commitment(self) {
        let mut reversed_coeffs: [Field; N] = [0; N];
        for i in 0..N {
            reversed_coeffs[i] = self.sk_secret.coefficients[N - 1 - i];
        }
        let reversed_sk = Polynomial::new(reversed_coeffs);
        assert(
            compute_share_computation_sk_commitment_checked::<N, BIT_SECRET>(reversed_sk)
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
    ) -> Self {
        SmudgingNoiseShareComputation { configs, expected_secret_commitment, e_sm_secret, y }
    }

    /// Main verification function
    pub fn execute(self) -> [[Field; L]; N_PARTIES] {
        // Step 1: Verify secret commitment matches expected
        self.verify_secret_commitment();

        // Step 2: Verify secret consistency
        self.verify_secret_consistency();

        // Step 3: Range checks
        check_range_bounds::<N, L, N_PARTIES, BIT_SHARE>(self.configs.qis, self.y);

        // Step 4: Verify the shares lie on one degree-T polynomial
        verify_shamir_finite_differences::<N, L, N_PARTIES, T>(self.configs.qis, self.y);

        // Step 5: Commit to shares for each party and modulus
        commit_to_party_shares::<N, L, N_PARTIES, BIT_SHARE>(self.y)
    }

    /// Verifies that secret hashes to expected_secret_commitment.
    ///
    /// Reverses and centers each `e_sm_secret` limb before hashing to match C1 (PkGeneration)'s
    /// convention: C1 passes e_sm reversed+centered (highest-degree-first, coefficients in
    /// `[-(q-1)/2, (q-1)/2]`). `e_sm_secret` here is in `[0, q)`, so we apply the same
    /// reverse+center transform before hashing.
    ///
    /// Opens with the checked packing helper. The `as u64` cast below bounds each coefficient to
    /// `2^64`, which is not tight enough for injectivity: at `BIT_SECRET = 57` the slot is
    /// `radix = 2^64` and `base = 2^60`, so a digit can exceed it. Asserting the digit fits forces
    /// the witness to equal the centered residues C1 committed and bounded.
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
            compute_share_computation_e_sm_commitment_checked::<N, L, BIT_SECRET>(normalized)
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

/// Verifies that each share vector is a Shamir sharing of degree `T`: for every coefficient `i` and
/// modulus `j`, the values `y[i][j][0..=N_PARTIES]` (the secret at `x = 0`, party `k` at `x = k`) agree
/// modulo `q_j` with one polynomial of degree at most `T`.
///
/// The evaluation points are consecutive, so a sequence comes from a degree-`T` polynomial exactly
/// when its `(T + 1)`-th finite differences vanish. Each check is one window of `T + 2` consecutive
/// values with the signed binomial weights `(-1)^k * C(T + 1, k)`; the `N_PARTIES - T` windows starting
/// at `0..N_PARTIES - T` span the same space as the Reed-Solomon parity rows (over `F_{q_j}`, whose
/// characteristic exceeds `T + 1`). Against a reduced-mod-`q` parity matrix this reads `T + 2` values
/// per row instead of `N_PARTIES + 1`, and the weights are small integers, so each divisibility
/// quotient is `T + 3` bits instead of a full `u64`.
///
/// Bounds: the caller range-checks the shares to `[0, q_j)` and pins the secret column below `2 q_j`
/// in magnitude (each C2 circuit opens it through a checked commitment). The weights sum to
/// `2^(T + 1)` in absolute value, so a window's integer sum lies in `(-2^(T + 2) q_j, 2^(T + 2) q_j)`;
/// the offset `2^(T + 2) q_j` makes it non-negative and its quotient below `2^(T + 3)`. Every term stays
/// far below the field prime, so the field equation `sum + offset == quotient * q_j` is the integer
/// one, and `q_j` divides the window's finite difference.
///
/// # Panics
/// The circuit fails if any window's finite difference is non-zero modulo `q_j`.
pub fn verify_shamir_finite_differences<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32>(
    qis: [Field; L],
    y: [[[Field; N_PARTIES + 1]; L]; N],
) {
    // Keeps 2^(T + 3) * q_j (q_j < 2^64) far below the field prime.
    assert(T < 120);
    // Pascal's rule yields the public weights C(T + 1, k) without division.
    let mut binomial: [Field; T + 2] = [0; T + 2];
    binomial[0] = 1;
    for row in 1..(T + 2) {
        for k in 0..row {
            let col = row - k;
            binomial[col] += binomial[col - 1];
        }
    }
    for mod_idx in 0..L {
        let q_j = ModU64::new(qis[mod_idx] as u64);
        let offset = 2.pow_32((T + 2) as Field) * qis[mod_idx];
        for coeff_idx in 0..N {
            for start in 0..(N_PARTIES - T) {
                let mut sum = offset;
                for k in 0..(T + 2) {
                    let term = binomial[k] * y[coeff_idx][mod_idx][start + k];
                    if k % 2 == 0 {
                        sum += term;
                    } else {
                        sum -= term;
                    }
                }
                q_j.assert_zero_mod_bounded::<T + 3>(sum);
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

/// Shares of the secret 5 over q = 97 on `y(x) = 5 + 3x` at `x = 0..=3` (one coefficient, one modulus).
global TEST_Q: [Field; 1] = [97];

#[test]
fn test_finite_differences_accept_a_degree_one_sharing() {
    verify_shamir_finite_differences::<1, 1, 3, 1>(TEST_Q, [[[5, 8, 11, 14]]]);
}

#[test]
fn test_finite_differences_accept_values_reduced_mod_q() {
    // y(x) = 60 + 50x + 40x^2 mod 97 at x = 0..=4: 60, 53, 29, 85, 27.
    verify_shamir_finite_differences::<1, 1, 4, 2>(TEST_Q, [[[60, 53, 29, 85, 27]]]);
}

#[test]
fn test_finite_differences_accept_a_negative_secret() {
    // y(x) = -1 + 2x with the secret as the field element -1 and shares reduced: -1, 1, 3, 5.
    verify_shamir_finite_differences::<1, 1, 3, 1>(TEST_Q, [[[-1, 1, 3, 5]]]);
}

#[test(should_fail_with = "Divisibility check failed")]
fn test_finite_differences_reject_a_corrupted_share() {
    verify_shamir_finite_differences::<1, 1, 3, 1>(TEST_Q, [[[5, 8, 12, 14]]]);
}

#[test(should_fail_with = "Divisibility check failed")]
fn test_finite_differences_reject_a_degree_above_t() {
    // y(x) = x^2 at x = 0..=3 has degree 2 > T = 1.
    verify_shamir_finite_differences::<1, 1, 3, 1>(TEST_Q, [[[0, 1, 4, 9]]]);
}

#[test(should_fail_with = "Divisibility check failed")]
fn test_finite_differences_reject_a_corrupted_last_share() {
    // The last window alone covers party N_PARTIES.
    verify_shamir_finite_differences::<1, 1, 4, 2>(TEST_Q, [[[60, 53, 29, 85, 28]]]);
}
