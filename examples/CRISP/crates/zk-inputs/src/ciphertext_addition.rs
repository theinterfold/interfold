// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_polynomial::{CrtPolynomial, Polynomial};
use e3_zk_helpers::commitments::compute_ciphertext_commitment;
use e3_zk_helpers::crt_polynomial_to_toml_json;
use e3_zk_helpers::utils::compute_modulus_bit;
use eyre::{Context, Result};
use fhe::bfv::BfvParameters;
use fhe::bfv::Ciphertext;
use num_bigint::BigInt;

/// Set of inputs for validation of a ciphertext addition.
///
/// This struct contains all the necessary data to prove that a ciphertext addition
/// was performed correctly in the zero-knowledge proof system.
#[derive(Clone, Debug)]
pub struct CiphertextAdditionWitness {
    pub prev_ct0is: CrtPolynomial,
    pub prev_ct1is: CrtPolynomial,
    pub sum_ct0is: CrtPolynomial,
    pub sum_ct1is: CrtPolynomial,
    pub r0is: CrtPolynomial,
    pub r1is: CrtPolynomial,
    pub prev_ct_commitment: BigInt,
}

impl CiphertextAdditionWitness {
    /// Computes the ciphertext addition inputs for zero-knowledge proof validation.
    ///
    /// # Arguments
    /// * `params` - BFV parameters
    /// * `prev_ct` - The existing ciphertext to add to
    /// * `ct` - The ciphertext being added
    /// * `sum_ct` - The result of the ciphertext addition
    ///
    /// # Returns
    /// CiphertextAdditionInputs containing all necessary proof data
    pub fn compute(
        params: &BfvParameters,
        prev_ct: &Ciphertext,
        ct: &Ciphertext,
        sum_ct: &Ciphertext,
    ) -> Result<CiphertextAdditionWitness> {
        let moduli = params.moduli();

        let mut crt_polynomials = [
            CrtPolynomial::from_fhe_polynomial(&prev_ct[0]),
            CrtPolynomial::from_fhe_polynomial(&prev_ct[1]),
            CrtPolynomial::from_fhe_polynomial(&ct[0]),
            CrtPolynomial::from_fhe_polynomial(&ct[1]),
            CrtPolynomial::from_fhe_polynomial(&sum_ct[0]),
            CrtPolynomial::from_fhe_polynomial(&sum_ct[1]),
        ];

        // fhe-math stores coefficients in ascending degree (c_0, c_1, …). But here we want
        // that each limb is stored in **descending** order (a_n, …, a_0) so circuit evaluation can use Horner's
        // method in one forward pass: `result = result * x + coefficients[i]` from i = 0,
        // i.e. P(x) = ((…((a_n·x + a_{n-1})·x + …)·x + a_0), with no extra reversing or reindexing.
        //
        // We center so the quotient r = (sum − (prev + ct)) / q_i lies in {-1, 0, 1}.
        // BFV/fhe-math already gives coefficients in [0, q_i), so reduce is redundant. We need centering
        // into (-q/2, q/2]: then the difference per coefficient is small in absolute value, and for valid
        // ciphertext addition that difference is a multiple of q_i, so the quotient is in {-1, 0, 1},
        // which the circuit and compute_quotient expect.
        for c in &mut crt_polynomials {
            c.reverse();
            c.center(moduli)?;
        }

        let [prev_ct0, prev_ct1, ct0, ct1, sum_ct0, sum_ct1] = crt_polynomials;

        // Compute quotient polynomials: r = (sum_centered - (ct_centered + prev_ct_centered)) / qi.
        // For ciphertext addition: sum_centered = ct_centered + prev_ct_centered + r * qi.
        // So: r = (sum_centered - (ct_centered + prev_ct_centered)) / qi.
        let r0 = Self::compute_quotient(&sum_ct0, &ct0, &prev_ct0, moduli)
            .with_context(|| "Failed to compute r0 quotient")?;
        let r1 = Self::compute_quotient(&sum_ct1, &ct1, &prev_ct1, moduli)
            .with_context(|| "Failed to compute r1 quotient")?;

        // Coefficients are centered per modulus; no zkp reduce. The circuit reduces mod r when needed.
        let pk_bit = compute_modulus_bit(params);
        let prev_ct_commitment = compute_ciphertext_commitment(&prev_ct0, &prev_ct1, pk_bit);

        Ok(CiphertextAdditionWitness {
            prev_ct0is: prev_ct0,
            prev_ct1is: prev_ct1,
            sum_ct0is: sum_ct0,
            sum_ct1is: sum_ct1,
            r0is: r0,
            r1is: r1,
            prev_ct_commitment,
        })
    }

    /// Computes the quotient CRT polynomial `(sum - (a + b)) / q_i` per modulus.
    ///
    /// For each limb index `i`, divides `sum_i - (a_i + b_i)` by the modulus `q_i`.
    /// Used when verifying that sum ciphertext equals a + b and recovering the
    /// quotient (small integer) from the difference.
    ///
    /// # Arguments
    ///
    /// * `sum` - CRT polynomial of the sum ciphertext
    /// * `a` - CRT polynomial of the first ciphertext
    /// * `b` - CRT polynomial of the second ciphertext
    /// * `n` - polynomial degree (number of coefficients per limb)
    /// * `moduli` - moduli for each CRT limb
    ///
    /// # Returns
    ///
    /// The quotient CRT polynomial, or an error if division is not exact or the
    /// quotient is not in `{-1, 0, 1}`.
    fn compute_quotient(
        sum: &CrtPolynomial,
        a: &CrtPolynomial,
        b: &CrtPolynomial,
        moduli: &[u64],
    ) -> Result<CrtPolynomial> {
        let num_moduli = moduli.len();

        let mut quotient_limbs = Vec::with_capacity(num_moduli);

        for (i, &modulus) in moduli.iter().enumerate().take(num_moduli) {
            let sum_limb = sum.limb(i);
            let a_limb = a.limb(i);
            let b_limb = b.limb(i);
            let qi = Polynomial::constant(BigInt::from(modulus));

            let diff = sum_limb.sub(&a_limb.add(b_limb));
            let (q_poly, remainder) = diff
                .div(&qi)
                .map_err(|e| eyre::eyre!("division by modulus q_i at index {}: {}", i, e))?;

            if !remainder.is_zero() {
                return Err(eyre::eyre!(
                    "Division by q_i at modulus index {} was not exact; non-zero remainder",
                    i
                ));
            }

            for (j, q) in q_poly.coefficients().iter().enumerate() {
                if *q < (-1).into() || *q > 1.into() {
                    return Err(eyre::eyre!(
                        "Quotient out of range [-1, 1] at modulus index {}, coeff {}: quotient = {}",
                        i,
                        j,
                        q
                    ));
                }
            }

            quotient_limbs.push(q_poly);
        }

        Ok(CrtPolynomial::new(quotient_limbs))
    }

    /// Serializes the witness to a JSON string.
    ///
    /// # Returns
    /// The JSON string representation of the witness.
    pub fn to_json(&self) -> Result<serde_json::Value> {
        let prev_ct0is = crt_polynomial_to_toml_json(&self.prev_ct0is);
        let prev_ct1is = crt_polynomial_to_toml_json(&self.prev_ct1is);
        let sum_ct0is = crt_polynomial_to_toml_json(&self.sum_ct0is);
        let sum_ct1is = crt_polynomial_to_toml_json(&self.sum_ct1is);
        let r0is = crt_polynomial_to_toml_json(&self.r0is);
        let r1is = crt_polynomial_to_toml_json(&self.r1is);
        let prev_ct_commitment = self.prev_ct_commitment.to_string();

        let json = serde_json::json!({
            "prev_ct0is": prev_ct0is,
            "prev_ct1is": prev_ct1is,
            "sum_ct0is": sum_ct0is,
            "sum_ct1is": sum_ct1is,
            "sum_r0is": r0is,
            "sum_r1is": r1is,
            "prev_ct_commitment": prev_ct_commitment,
        });

        Ok(json)
    }
}
