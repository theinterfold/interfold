// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Circuit input data, witness preparation, and canonical Noir encoding.

use crate::commitments::compute_aggregated_shares_commitment;
use crate::commitments::compute_ciphertext_commitment;
use crate::encoding::crt_polynomial_to_toml_json;
use crate::negacyclic::{exact_reduction_quotient, product_for_fold};
use crate::WitnessError;
use e3_polynomial::CrtPolynomial;
use e3_polynomial::Polynomial;
use e3_polynomial_fhe::FromFhePolynomial as _;
use e3_zk_config::threshold::share_decryption::Configs;
use fhe::bfv::Ciphertext;
use num_bigint::BigInt;
use num_traits::Zero;
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use serde::Deserialize;
use serde::Serialize;

/// Threshold share decryption circuit (PVSS #6).
///
/// Verifies correct computation of a party's decryption share with respect to
/// committed aggregated secret and smudging-error shares.

/// Input to the share decryption circuit: ciphertext and the party's
/// aggregated secret share (s), smudging error (e), and computed decryption share (d_share).
pub struct ShareDecryptionCircuitData {
    pub ciphertext: Ciphertext,
    pub s: CrtPolynomial,
    pub e: CrtPolynomial,
    pub d_share: CrtPolynomial,
    /// High and low 128-bit limbs of the E3 decryption domain.
    pub domain_hi: u128,
    pub domain_lo: u128,
}

/// Low-degree native \([0, q)\) CRT limbs for `d_commitment`, matching C7's `from_fhe` truncation.
/// In each limb, `d` is reversed+centered (witness layout); native coeff `j` is `uncenter(d[N-1-j])`.
fn d_native_trunc_from_centered_d(
    d: &CrtPolynomial,
    moduli: &[u64],
    degree: usize,
    max_k: usize,
) -> CrtPolynomial {
    let mut limbs = Vec::with_capacity(d.limbs.len());
    for (limb_idx, limb) in d.limbs.iter().enumerate() {
        let q = BigInt::from(moduli[limb_idx]);
        let coeffs = limb.coefficients();
        let mut asc = Vec::with_capacity(max_k);
        for j in 0..max_k {
            let w = &coeffs[degree - 1 - j];
            let u = if w < &BigInt::zero() {
                w + &q
            } else {
                w.clone()
            };
            asc.push(u);
        }
        limbs.push(Polynomial::new(asc));
    }
    CrtPolynomial::new(limbs)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    pub ct0: CrtPolynomial,
    pub ct1: CrtPolynomial,
    pub sk: CrtPolynomial,
    pub e_sm: CrtPolynomial,
    pub r: CrtPolynomial,
    pub d: CrtPolynomial,
    /// Native truncated `d` per limb (C7-compatible); hashed for public `d_commitment`.
    pub d_native_trunc: CrtPolynomial,
    pub expected_sk_commitment: BigInt,
    pub expected_e_sm_commitment: BigInt,
    pub ct_commitment: BigInt,
    pub domain_hi: BigInt,
    pub domain_lo: BigInt,
}

impl Inputs {
    pub fn compute(
        config: &Configs,
        data: &ShareDecryptionCircuitData,
    ) -> Result<Self, WitnessError> {
        let threshold_params = &config.params;
        if data.ciphertext.len() != 2 {
            return Err(WitnessError::UnexpectedCiphertextComponents(
                data.ciphertext.len(),
            ));
        }
        for (index, component) in data.ciphertext.iter().enumerate() {
            let coefficients = component.coefficients();
            crate::validation::context(
                &format!("ciphertext[{index}]"),
                component.ctx(),
                coefficients.nrows(),
                coefficients.ncols(),
                threshold_params,
            )?;
        }
        for (name, value) in [("s", &data.s), ("e", &data.e), ("d_share", &data.d_share)] {
            crate::validation::crt(name, value, threshold_params)?;
        }
        if config.max_msg_non_zero_coeffs > threshold_params.degree() {
            return Err(WitnessError::Other(
                "max_msg_non_zero_coeffs exceeds the polynomial degree".into(),
            ));
        }

        let moduli = threshold_params.moduli();
        let n = threshold_params.degree() as u64;

        // Extract and convert ciphertext polynomials
        let ct0 = CrtPolynomial::from_fhe_polynomial(&data.ciphertext[0]);
        let ct1 = CrtPolynomial::from_fhe_polynomial(&data.ciphertext[1]);

        // Perform the main computation logic
        #[allow(clippy::type_complexity)]
        let results: Vec<(
            Polynomial,
            Polynomial,
            Polynomial,
            Polynomial,
            Polynomial,
            Polynomial,
        )> = (
            moduli,
            ct0.limbs,
            ct1.limbs,
            &data.s.limbs,
            &data.e.limbs,
            &data.d_share.limbs,
        )
            .into_par_iter()
            .map(|(qi, mut ct0, mut ct1, s, e, d_share)| {
                let qi = BigInt::from(*qi);
                let mut s = s.clone();
                let mut e = e.clone();
                let mut d_share = d_share.clone();
                ct0.reverse();
                ct0.center(&qi);

                ct1.reverse();
                ct1.center(&qi);

                s.reverse();
                s.center(&qi);

                e.reverse();
                e.center(&qi);

                d_share.reverse();
                d_share.center(&qi);

                // Compute d_share_hat = ct0 + ct1 * s + e
                // This is the expected value before lifting to Z
                let d_share_hat = {
                    // ct1 * s (degree 2*(n-1))
                    let ct1_s_times = product_for_fold(&ct1, &s, n as usize);
                    assert_eq!((ct1_s_times.coefficients().len() as u64) - 1, 2 * (n - 1));

                    // ct0 + ct1 * s + e
                    ct0.add(&ct1_s_times).add(&e)
                };
                assert_eq!((d_share_hat.coefficients().len() as u64) - 1, 2 * (n - 1));

                // The circuit checks the identity reduced modulo X^N + 1, so the cyclotomic
                // quotient's term is identically zero and `r2` is gone. `r` is then pinned by the
                // identity itself:
                //   d = (ct0 + ct1 * s + e mod X^N + 1) + q * r
                // so folding the `d_share_hat` already computed above and dividing by q gives it.
                let (reduced_hat, r) =
                    exact_reduction_quotient(&d_share, &d_share_hat, n as usize, &qi)?;

                // Check the derived witness against the integer identity.
                assert!(
                    d_share.sub(&reduced_hat.add(&r.scalar_mul(&qi))).is_zero(),
                    "reduced identity must hold: d == ct0 + ct1 * sk + e_sm + qi * r (mod X^N + 1)"
                );

                Ok((ct0, ct1, s, e, d_share, r))
            })
            .collect::<Result<Vec<_>, WitnessError>>()?;

        let mut ct0 = CrtPolynomial::new(vec![]);
        let mut ct1 = CrtPolynomial::new(vec![]);
        let mut sk = CrtPolynomial::new(vec![]);
        let mut e_sm = CrtPolynomial::new(vec![]);
        let mut r = CrtPolynomial::new(vec![]);
        let mut d = CrtPolynomial::new(vec![]);

        for (ct0i, ct1i, si, ei, d_sharei, ri) in results {
            ct0.add_limb(ct0i);
            ct1.add_limb(ct1i);
            sk.add_limb(si);
            e_sm.add_limb(ei);
            r.add_limb(ri);
            d.add_limb(d_sharei);
        }

        // Compute commitments to s and e (matches circuit's commitment functions)
        let modulus_bit = config.bits.sk_bit;
        let expected_sk_commitment = compute_aggregated_shares_commitment(&sk, modulus_bit);
        let expected_e_sm_commitment = compute_aggregated_shares_commitment(&e_sm, modulus_bit);
        let bits = &config.bits;
        let ct_commitment = compute_ciphertext_commitment(&ct0, &ct1, bits.ct_bit);

        let d_native_trunc =
            d_native_trunc_from_centered_d(&d, moduli, n as usize, config.max_msg_non_zero_coeffs);

        Ok(Inputs {
            ct0,
            ct1,
            sk,
            e_sm,
            r,
            d,
            d_native_trunc,
            expected_sk_commitment,
            expected_e_sm_commitment,
            ct_commitment,
            domain_hi: BigInt::from(data.domain_hi),
            domain_lo: BigInt::from(data.domain_lo),
        })
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "ct0": crt_polynomial_to_toml_json(&self.ct0),
            "ct1": crt_polynomial_to_toml_json(&self.ct1),
            "sk": crt_polynomial_to_toml_json(&self.sk),
            "e_sm": crt_polynomial_to_toml_json(&self.e_sm),
            "r": crt_polynomial_to_toml_json(&self.r),
            "d": crt_polynomial_to_toml_json(&self.d),
            "d_native_trunc": crt_polynomial_to_toml_json(&self.d_native_trunc),
            "expected_sk_commitment": self.expected_sk_commitment.to_string(),
            "expected_e_sm_commitment": self.expected_e_sm_commitment.to_string(),
            "ct_commitment": self.ct_commitment.to_string(),
            "domain_hi": self.domain_hi.to_string(),
            "domain_lo": self.domain_lo.to_string(),
        })
    }
}
