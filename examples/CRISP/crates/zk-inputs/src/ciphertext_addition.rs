// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_polynomial::{CrtPolynomial, Polynomial};
use e3_zk_helpers::commitments::compute_ciphertext_commitment;
use e3_zk_helpers::encoding::crt_polynomial_to_toml_json;
use e3_bfv_math::compute_modulus_bit;
use eyre::{Context, Result};
use fhe::bfv::BfvParameters;
use fhe::bfv::Ciphertext;
use num_bigint::BigInt;
use num_traits::Zero;

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
    /// Commitment to the ciphertext being added, which is the ballot itself.
    ///
    /// Exported to break a cycle in the voting flow. The voter signs a digest that commits to the
    /// ballot, and that signature is then an input to the crisp circuit — so the commitment has to
    /// be known *before* the circuit runs. The circuit computes the same value internally and
    /// returns it, but by then it is too late to sign.
    ///
    /// The alternative is recomputing it in TypeScript, which would have to reproduce
    /// `compute_ciphertext_commitment` exactly. A mismatch there is silent: the ballot proves
    /// fine and is rejected on chain, because the digest the contract rebuilds does not match the
    /// one that was signed.
    pub ct_commitment: BigInt,
    /// Commitment to the ciphertext that becomes the slot, which is what gets published.
    ///
    /// The circuit returns this value, `CRISPProgram` stores it, and `CRISPProgram.ballotDigest`
    /// builds the digest the voter signs over it. Exported for the same reason as `ct_commitment`:
    /// the digest is itself a circuit input, so the value has to be known before proving. It
    /// equals `ct_commitment` whenever the ballot replaces the slot rather than adding to it.
    pub sum_ct_commitment: BigInt,
}

impl CiphertextAdditionWitness {
    /// Computes the ciphertext addition inputs for zero-knowledge proof validation.
    ///
    /// The circuit always proves `sum_ct = addend + ct`, and picks the addend itself from the
    /// private mask flag: the ciphertext already in the slot for a mask, the zero ciphertext for a
    /// vote, an update, or any input to an empty slot. This witness has to be built for the same
    /// addend, which is what `keep_previous` selects.
    ///
    /// The previous ciphertext is exported and committed to whichever addend is used, because the
    /// circuit checks it against the commitment `CRISPProgram` stored for the slot. Only the
    /// quotient polynomials depend on the addend.
    ///
    /// An empty slot has no previous ciphertext and no stored commitment. It gets zero limbs and a
    /// zero commitment, which is what the contract passes the circuit for such a slot.
    ///
    /// # Arguments
    /// * `params` - BFV parameters
    /// * `previous_ct` - The ciphertext currently in the slot, or `None` when the slot is empty
    /// * `ct` - The ballot ciphertext
    /// * `sum_ct` - The ciphertext that becomes the slot
    /// * `keep_previous` - Whether `sum_ct` adds to the previous ciphertext rather than replacing it
    ///
    /// # Returns
    /// CiphertextAdditionInputs containing all necessary proof data
    pub fn compute(
        params: &BfvParameters,
        previous_ct: Option<&Ciphertext>,
        ct: &Ciphertext,
        sum_ct: &Ciphertext,
        keep_previous: bool,
    ) -> Result<CiphertextAdditionWitness> {
        let moduli = params.moduli();
        let pk_bit = compute_modulus_bit(params);

        // fhe-math stores coefficients in ascending degree (c_0, c_1, …). But here we want
        // that each limb is stored in **descending** order (a_n, …, a_0) so circuit evaluation can use Horner's
        // method in one forward pass: `result = result * x + coefficients[i]` from i = 0,
        // i.e. P(x) = ((…((a_n·x + a_{n-1})·x + …)·x + a_0), with no extra reversing or reindexing.
        //
        // We center so the quotient r = (sum − (addend + ct)) / q_i lies in {-1, 0, 1}.
        // BFV/fhe-math already gives coefficients in [0, q_i), so reduce is redundant. We need centering
        // into (-q/2, q/2]: then the difference per coefficient is small in absolute value, and for valid
        // ciphertext addition that difference is a multiple of q_i, so the quotient is in {-1, 0, 1},
        // which the circuit and compute_quotient expect.
        let mut crt_polynomials = [
            CrtPolynomial::from_fhe_polynomial(&ct[0]),
            CrtPolynomial::from_fhe_polynomial(&ct[1]),
            CrtPolynomial::from_fhe_polynomial(&sum_ct[0]),
            CrtPolynomial::from_fhe_polynomial(&sum_ct[1]),
        ];

        for c in &mut crt_polynomials {
            c.reverse();
            c.center(moduli)?;
        }

        let [ct0, ct1, sum_ct0, sum_ct1] = crt_polynomials;

        let (prev_ct0, prev_ct1, prev_ct_commitment) = match previous_ct {
            Some(previous) => {
                let mut limbs = [
                    CrtPolynomial::from_fhe_polynomial(&previous[0]),
                    CrtPolynomial::from_fhe_polynomial(&previous[1]),
                ];

                for c in &mut limbs {
                    c.reverse();
                    c.center(moduli)?;
                }

                let [p0, p1] = limbs;
                let commitment = compute_ciphertext_commitment(&p0, &p1, pk_bit);

                (p0, p1, commitment)
            }
            // Shaped from the ballot limbs, so the degree and the number of moduli follow the
            // parameters rather than being restated here.
            None => (
                Self::select_addend(&ct0, false),
                Self::select_addend(&ct1, false),
                BigInt::zero(),
            ),
        };

        // What the circuit adds the ballot to, which is the slot's ciphertext only for a mask over
        // an occupied slot. An empty slot has nothing to keep, whatever the caller asked for.
        let keep = keep_previous && previous_ct.is_some();
        let addend_ct0 = Self::select_addend(&prev_ct0, keep);
        let addend_ct1 = Self::select_addend(&prev_ct1, keep);

        // Compute quotient polynomials: r = (sum_centered - (ct_centered + addend_centered)) / qi.
        // For ciphertext addition: sum_centered = ct_centered + addend_centered + r * qi.
        // So: r = (sum_centered - (ct_centered + addend_centered)) / qi.
        let r0 = Self::compute_quotient(&sum_ct0, &ct0, &addend_ct0, moduli)
            .with_context(|| "Failed to compute r0 quotient")?;
        let r1 = Self::compute_quotient(&sum_ct1, &ct1, &addend_ct1, moduli)
            .with_context(|| "Failed to compute r1 quotient")?;

        // Coefficients are centered per modulus; no zkp reduce. The circuit reduces mod r when needed.
        let ct_commitment = compute_ciphertext_commitment(&ct0, &ct1, pk_bit);
        let sum_ct_commitment = compute_ciphertext_commitment(&sum_ct0, &sum_ct1, pk_bit);

        Ok(CiphertextAdditionWitness {
            prev_ct0is: prev_ct0,
            prev_ct1is: prev_ct1,
            sum_ct0is: sum_ct0,
            sum_ct1is: sum_ct1,
            r0is: r0,
            r1is: r1,
            prev_ct_commitment,
            ct_commitment,
            sum_ct_commitment,
        })
    }

    /// The limbs the ballot is added to, mirroring `crisp_lib::ciphertext_addition::select_addend`.
    ///
    /// Zeroed rather than dropped so the quotient computation keeps the shape of the ciphertext it
    /// replaces, whatever the degree and the number of moduli.
    ///
    /// # Arguments
    ///
    /// * `previous` - The limbs of the ciphertext currently in the slot
    /// * `keep_previous` - Whether the ballot adds to them
    fn select_addend(previous: &CrtPolynomial, keep_previous: bool) -> CrtPolynomial {
        if keep_previous {
            return previous.clone();
        }

        let mut zeroed = previous.clone();
        zeroed.scalar_mul(&BigInt::zero());

        zeroed
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
        let ct_commitment = self.ct_commitment.to_string();
        let sum_ct_commitment = self.sum_ct_commitment.to_string();

        let json = serde_json::json!({
            "prev_ct0is": prev_ct0is,
            "prev_ct1is": prev_ct1is,
            "sum_ct0is": sum_ct0is,
            "sum_ct1is": sum_ct1is,
            "sum_r0is": r0is,
            "sum_r1is": r1is,
            "prev_ct_commitment": prev_ct_commitment,
            // Neither of these is a crisp circuit input. The caller needs `sum_ct_commitment` to
            // build the ballot digest before signing, so both ride along with the witness rather
            // than being recomputed.
            "ct_commitment": ct_commitment,
            "sum_ct_commitment": sum_ct_commitment,
        });

        Ok(json)
    }
}
