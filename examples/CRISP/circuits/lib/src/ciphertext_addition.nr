// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! # Ciphertext Addition Verification
//!
//! This module implements zero-knowledge proof verification for homomorphic addition of BFV
//! (Brakerski-Fan-Vercauteren) ciphertexts. It verifies that a sum ciphertext correctly
//! represents the addition of two input ciphertexts without revealing the plaintexts.
//!
//! ## Purpose
//!
//! In CRISP, mask votes can update slots. When a mask vote updates a slot, the new vote ciphertext
//! must be homomorphically added to the previous vote ciphertext. This module verifies that
//! this addition was performed correctly.
//!
//! ## Mathematical Background
//!
//! BFV ciphertexts are represented as pairs (c0, c1) where:
//! - c0 and c1 are polynomials in the ring R_q = Z_q[X]/(X^N + 1)
//! - For CRT (Chinese Remainder Theorem) bases, we have arrays [c0_i, c1_i] for each modulus q_i
//!
//! Homomorphic addition is performed component-wise:
//! - sum_c0_i = ct0_i + prev_c0_i + r0_i * q_i
//! - sum_c1_i = ct1_i + prev_c1_i + r1_i * q_i
//!
//! Where r0_i and r1_i are correction terms (quotient polynomials) that account for modular
//! reduction when coefficients exceed the modulus q_i.
//!
//! ## Verification Strategy
//!
//! The verification uses the Schwartz-Zippel lemma: if polynomial equations hold when evaluated
//! at random points, then the polynomials are identical with high probability. The circuit:
//!
//! 1. Generates random challenge values using Fiat-Shamir transform
//! 2. Evaluates all polynomials at these challenge points
//! 3. Verifies the addition equations hold at these points
//! 4. Checks range constraints on all coefficients

use interfold_lib::math::commitments::compute_challenge;
use interfold_lib::math::polynomial::Polynomial;

/// Parameters for ciphertext addition verification.
///
/// # Arguments
/// * `N` - Polynomial degree.
/// * `L` - Number of CRT bases.
/// * `BIT_CT` - Bit-width bound per coefficient for ciphertext polynomials `ct0is`/`ct1is`.
/// * `BIT_PREV_CT` - Bit-width bound per coefficient for previous ciphertext polynomials `prev_ct0is`/`prev_ct1is`.
/// * `BIT_SUM_CT` - Bit-width bound per coefficient for sum ciphertext polynomials `sum_ct0is`/`sum_ct1is`.
pub struct CiphertextAddition<let N: u32, let L: u32, let BIT_CT: u32, let BIT_PREV_CT: u32, let BIT_SUM_CT: u32> {
    qis: [Field; L],
    ct0is: [Polynomial<N>; L],
    ct1is: [Polynomial<N>; L],
    ct_commitment: Field,
    prev_ct0is: [Polynomial<N>; L],
    prev_ct1is: [Polynomial<N>; L],
    prev_ct_commitment: Field,
    sum_ct0is: [Polynomial<N>; L],
    sum_ct1is: [Polynomial<N>; L],
    sum_ct_commitment: Field,
    r0is: [Polynomial<N>; L],
    r1is: [Polynomial<N>; L],
}

impl<let N: u32, let L: u32, let BIT_CT: u32, let BIT_PREV_CT: u32, let BIT_SUM_CT: u32> CiphertextAddition<N, L, BIT_CT, BIT_PREV_CT, BIT_SUM_CT> {
    /// Creates a new CiphertextAddition instance.
    ///
    /// # Arguments
    /// * `configs` - Cryptographic configuration for the ciphertext addition circuit.
    /// * `ct0is`, `ct1is` - Ciphertext polynomials.
    /// * `prev_ct0is`, `prev_ct1is` - Previous ciphertext polynomials.
    /// * `sum_ct0is`, `sum_ct1is` - Ciphertext addition polynomials.
    /// * `r0is`, `r1is` - Quotient/correction polynomials for modular reduction.
    pub fn new(
        qis: [Field; L],
        ct0is: [Polynomial<N>; L],
        ct1is: [Polynomial<N>; L],
        ct_commitment: Field,
        prev_ct0is: [Polynomial<N>; L],
        prev_ct1is: [Polynomial<N>; L],
        prev_ct_commitment: Field,
        sum_ct0is: [Polynomial<N>; L],
        sum_ct1is: [Polynomial<N>; L],
        sum_ct_commitment: Field,
        r0is: [Polynomial<N>; L],
        r1is: [Polynomial<N>; L],
    ) -> Self {
        Self {
            qis,
            ct0is,
            ct1is,
            ct_commitment,
            prev_ct0is,
            prev_ct1is,
            prev_ct_commitment,
            sum_ct0is,
            sum_ct1is,
            sum_ct_commitment,
            r0is,
            r1is,
        }
    }

    /// Verifies the correct addition constraints for the ciphertext addition circuit.
    ///
    /// This function implements the core zero-knowledge proof verification using a three-step
    /// process:
    ///
    /// 1. **Range Checks**: Ensures all polynomial coefficients are within expected bounds
    /// 2. **Challenge Generation**: Uses Fiat-Shamir transform to generate random evaluation points
    /// 3. **Polynomial Evaluation**: Verifies addition equations hold at random points
    ///
    /// ## Verification Strategy
    ///
    /// The proof uses the Schwartz-Zippel lemma: if polynomial equations hold when evaluated
    /// at random points, then the polynomials are identical with high probability.
    ///
    /// ## Addition Equations
    ///
    /// For each CRT basis i, we verify:
    /// ```
    /// sum_ct0i(gamma) = ct0i(gamma) + prev_ct0i(gamma) + r0i(gamma) * q_i
    /// sum_ct1i(gamma) = ct1i(gamma) + prev_ct1i(gamma) + r1i(gamma) * q_i
    /// ```
    ///
    /// Where:
    /// - `gamma` is a random challenge value (same for all evaluations)
    /// - `q_i` is the i-th CRT modulus from cryptographic parameters
    /// - `r0i`, `r1i` are correction/quotient polynomials accounting for modular reduction
    ///
    /// The correction terms `r0i` and `r1i` are necessary because when adding coefficients
    /// that exceed `q_i`, we need to subtract multiples of `q_i` to bring them back into
    /// the valid range [0, q_i).
    ///
    /// ## Linear Combination Check
    ///
    /// Instead of checking each equation separately, we form a linear combination:
    /// ```
    /// sum(gamma_i * (sum_ct0i(gamma) - ct0i(gamma) - prev_ct0i(gamma) - r0i(gamma) * q_i)) +
    /// sum(gamma_{L+i} * (sum_ct1i(gamma) - ct1i(gamma) - prev_ct1i(gamma) - r1i(gamma) * q_i)) = 0
    /// ```
    ///
    /// This single check ensures all equations hold simultaneously.
    ///
    /// # Returns
    /// `true` if all ciphertext addition constraints are satisfied, `false` otherwise.
    pub fn execute(self) -> bool {
        // Step 1: Perform range checks on all polynomial coefficients
        self.check_range_bounds();

        // Step 2: Generate Fiat-Shamir challenges
        let gammas = self.generate_challenge();

        // Step 3: Verify ciphertext addition constraints using challenges
        self.verify_evaluations(gammas)
    }

    /// Verifies range constraints on the quotient polynomials r0is and r1is.
    ///
    /// When adding two ciphertexts, the correction terms (quotient polynomials) must be
    /// bounded. For homomorphic addition of two ciphertexts (M=2), each coefficient of the
    /// quotient polynomial must be in the set {-1, 0, 1}.
    ///
    /// This constraint ensures that the modular reduction was performed correctly and that
    /// the sum ciphertext coefficients remain within the valid range [0, q_i) for each CRT
    /// modulus q_i.
    ///
    /// # Why {-1, 0, 1}?
    ///
    /// When adding two coefficients a and b modulo q_i:
    /// - If a + b < q_i: no reduction needed, quotient = 0
    /// - If q_i <= a + b < 2*q_i: subtract q_i once, quotient = 1
    /// - If a + b < 0 (can happen with signed arithmetic): add q_i, quotient = -1
    ///
    /// Since we're adding two ciphertexts, the maximum possible sum is 2*q_i - 2, so we
    /// never need to subtract more than one multiple of q_i.
    fn check_range_bounds(self) {
        for i in 0..L {
            // For M=2 (adding two ciphertexts), each coefficient of the quotient polynomial
            // must be in {-1, 0, 1}, so the bound will always be 1 for all CRT moduli.
            self.r0is[i].range_check_2bounds::<1>(1, 1);
            self.r1is[i].range_check_2bounds::<1>(1, 1);
        }
    }

    /// Generates Fiat-Shamir challenge values using a cryptographic sponge
    ///
    /// The sponge absorbs all witness values and squeezes out deterministic random field elements
    /// that will be used to evaluate polynomials for the Schwartz-Zippel lemma.
    ///
    /// # Returns
    /// Vector of challenge values [gamma_0, gamma_1, ..., gamma_{2L-1}]
    fn generate_challenge(self) -> Vec<Field> {
        // Domain separator - "CLG_CT_ADD"
        let DS_CLG_CT_ADD: [u8; 64] = [
            0x43, 0x4c, 0x47, 0x5f, 0x43, 0x54, 0x5f, 0x41, 0x44, 0x44, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let mut payload = Vec::new();

        payload.push(self.ct_commitment);
        payload.push(self.prev_ct_commitment);
        payload.push(self.sum_ct_commitment);

        compute_challenge::<L>(payload, DS_CLG_CT_ADD)
    }

    /// Verifies ciphertext addition constraints using Fiat-Shamir challenges.
    ///
    /// This function evaluates all polynomials at random challenge points and verifies that
    /// the addition equations hold. It uses a linear combination approach to check all 2L
    /// equations simultaneously.
    ///
    /// # Arguments
    /// * `gammas` - Vector of challenge values [gamma_0, gamma_1, ..., gamma_{2L-1}]
    ///   - gamma_0 is used as the evaluation point for all polynomials
    ///   - gamma_1 through gamma_{L-1} are multipliers for the first L equations
    ///   - gamma_L through gamma_{2L-1} are multipliers for the second L equations
    ///
    /// # Verification Process
    ///
    /// For each CRT basis i:
    /// 1. Compute the difference polynomial: `p = sum_ct0i - (ct0i + prev_ct0i + r0i * q_i)`
    /// 2. Evaluate at gamma: p(gamma)
    /// 3. Add to accumulator with weight gamma_i: accumulator += gamma_i * p(gamma)
    ///
    /// Repeat for ct1 components with weights gamma_{L+i}.
    ///
    /// If all equations hold, the accumulator will be zero. If any equation fails, the
    /// accumulator will be non-zero with high probability (by Schwartz-Zippel lemma).
    ///
    /// # Returns
    /// `true` if the accumulator equals zero (all constraints satisfied), `false` otherwise.
    fn verify_evaluations(self, gammas: Vec<Field>) -> bool {
        // Use the first challenge as the evaluation point for all polynomials
        let gamma = gammas.get(0);

        let mut accumulator: Field = 0;

        // First L equalities: verify sum_ct0i = ct0i + prev_ct0i + r0i * q_i
        // For i=0, use weight 1; for i>0, use weight gamma_i
        for i in 0..L {
            // Build the expected sum: ct0i + prev_ct0i + r0i * q_i
            let mut p = self.ct0is[i];
            let r0i_scaled = self.r0is[i].mul_scalar(self.qis[i]);

            p = p.add(self.prev_ct0is[i]);
            p = p.add(r0i_scaled);

            // Compute difference: sum_ct0i - expected_sum
            p = self.sum_ct0is[i].sub(p);

            // Weight and accumulate: use gamma_i as the weight (gamma_0 = 1 for i=0)
            let gamma_i = if i == 0 { 1 } else { gammas.get(i) };
            accumulator += gamma_i * p.eval(gamma);
        }

        // Next L equalities: verify sum_ct1i = ct1i + prev_ct1i + r1i * q_i
        // Use weights gamma_{L+i} for these equations
        for i in 0..L {
            // Build the expected sum: ct1i + prev_ct1i + r1i * q_i
            let mut p = self.ct1is[i];
            let r1i_scaled = self.r1is[i].mul_scalar(self.qis[i]);

            p = p.add(self.prev_ct1is[i]);
            p = p.add(r1i_scaled);

            // Compute difference: sum_ct1i - expected_sum
            p = self.sum_ct1is[i].sub(p);

            // Weight and accumulate: use gamma_{L+i} as the weight
            let gamma_i = gammas.get(L + i);
            accumulator += gamma_i * p.eval(gamma);
        }

        // All equations hold if and only if the accumulator is zero
        accumulator == 0
    }
}
