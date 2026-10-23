// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Exact-ciphertext preparation for chunked user encryption.
use super::user_data_encryption::UserDataEncryptionCircuitData;
use crate::encoding::*;
use crate::negacyclic::{exact_quotient, negacyclic_mul};
use crate::EncryptionIntermediates;
use crate::WitnessError;
use e3_polynomial::{CrtPolynomial, Polynomial};
use e3_polynomial_fhe::FromFhePolynomial as _;
use e3_zk_config::field::get_zkp_modulus;
use e3_zk_config::threshold::user_data_encryption_chunked::Configs;
use fhe::bfv::Ciphertext;
use fhe_math::zq::Modulus;
use fhe_traits::Serialize as FheSerialize;
use itertools::izip;
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    pub pk0is: CrtPolynomial,
    pub pk1is: CrtPolynomial,
    pub ct0is: CrtPolynomial,
    pub ct1is: CrtPolynomial,
    /// Reduced modulus-switch quotients of ct0, `N` coefficients each: the identity is checked
    /// modulo `X^N + 1`, so there is no cyclotomic quotient.
    pub r1is: CrtPolynomial,
    /// Reduced modulus-switch quotients of ct1, as `r1is`.
    pub p1is: CrtPolynomial,
    pub e0: Polynomial,
    pub e1: Polynomial,
    pub u: Polynomial,
    pub k1: Polynomial,
    pub ciphertext: Vec<u8>,
    /// `commit(pk0is)` under `DS_PK_AGGREGATION`: round A passes it through instead of hashing
    /// the key, and round B checks it against `pk0is`.
    pub pk0_commitment: BigInt,
    /// `commit(pk1is)`, as `pk0_commitment`.
    pub pk1_commitment: BigInt,
    /// `commit(ct0is)` under `DS_CIPHERTEXT`. The leaf hashes it into the challenge before the
    /// ciphertext circuit, which needs that challenge, can be proved.
    pub ct0_commitment: BigInt,
    /// `commit(ct1is)`, as `ct0_commitment`.
    pub ct1_commitment: BigInt,
}
impl Inputs {
    pub fn compute(
        config: &Configs,
        data: &UserDataEncryptionCircuitData,
        ct: &Ciphertext,
        intermediates: &EncryptionIntermediates,
    ) -> Result<Self, WitnessError> {
        let threshold_params = &config.params;
        crate::validation::parameters("public_key", &data.public_key.params, threshold_params)?;
        if data.public_key.c.len() != 2 || ct.len() != 2 {
            return Err(WitnessError::Other(
                "encryption requires a two-component public key and ciphertext".into(),
            ));
        }
        for (name, poly) in [
            ("pk0", &data.public_key.c[0]),
            ("pk1", &data.public_key.c[1]),
            ("ct0", &ct[0]),
            ("ct1", &ct[1]),
            ("u", intermediates.randomness()),
            ("e0", intermediates.error_0()),
            ("e1", intermediates.error_1()),
        ] {
            let coefficients = poly.coefficients();
            crate::validation::context(
                name,
                poly.ctx(),
                coefficients.nrows(),
                coefficients.ncols(),
                threshold_params,
            )?;
        }

        let pk = data.public_key.clone();
        let pt = data.plaintext.clone();

        // Context and plaintext modulus (use same ctx for e0 reconstruction and loop).
        let ctx = threshold_params.context_at_level(0)?;

        #[allow(non_snake_case)]
        let modulus_q = BigInt::from(ctx.modulus().clone());
        let moduli = threshold_params.moduli();

        let t = threshold_params.plaintext();
        let n = threshold_params.degree() as u64;
        let q_mod_t = (&modulus_q % t)
            .to_u64()
            .ok_or_else(|| WitnessError::Other("Failed to convert q_mod_t to u64".into()))?; // [q]_t

        let u = intermediates.randomness();
        let e0 = intermediates.error_0().to_power_basis();
        let e1 = intermediates.error_1();

        // The lifted `e0`: the ct0 identity reads it directly in every CRT limb (IF-006).
        let mut e0_mod_q = Polynomial::from_fhe_polynomial(&e0);

        e0_mod_q.reverse();
        e0_mod_q.center(&modulus_q);

        // Reconstruct k1 from plaintext polynomial.
        let mut k1_u64 = plaintext_poly_u64(&pt, threshold_params)?; // m

        Modulus::new(t)
            .map_err(|e| WitnessError::Fhe(fhe::Error::from(e)))?
            .scalar_mul_vec(&mut k1_u64, q_mod_t); // k1 = [q*m]_t

        let mut k1 = Polynomial::from_u64_vector(k1_u64);

        k1.reverse();

        // Reconstruct u and e1 as polynomials (only the first limb is needed)
        let mut u = CrtPolynomial::from_fhe_polynomial(&u).limb(0).clone();
        let mut e1 = CrtPolynomial::from_fhe_polynomial(&e1).limb(0).clone();

        u.center(&BigInt::from(moduli[0]));
        u.reverse();

        e1.center(&BigInt::from(moduli[0]));
        e1.reverse();

        let mut ct0 = CrtPolynomial::from_fhe_polynomial(&ct[0]);
        let mut ct1 = CrtPolynomial::from_fhe_polynomial(&ct[1]);
        let mut pk0 = CrtPolynomial::from_fhe_polynomial(&pk.c[0]);
        let mut pk1 = CrtPolynomial::from_fhe_polynomial(&pk.c[1]);

        ct0.reverse();
        ct1.reverse();
        pk0.reverse();
        pk1.reverse();

        ct0.center(moduli)?;
        ct1.center(moduli)?;

        pk0.center(moduli)?;
        pk1.center(moduli)?;

        crate::encoding::verify_crt_shapes(&[&ct0, &ct1, &pk0, &pk1], moduli.len(), n as usize)
            .map_err(|e| {
                WitnessError::Other(format!("user-data-encryption CRT shape mismatch: {e}"))
            })?;

        let CrtPolynomial { limbs: ct0_limbs } = ct0;
        let CrtPolynomial { limbs: ct1_limbs } = ct1;
        let CrtPolynomial { limbs: pk0_limbs } = pk0;
        let CrtPolynomial { limbs: pk1_limbs } = pk1;

        // Perform the main computation logic
        let mut results = izip!(
            ctx.moduli_operators(),
            ct0_limbs,
            ct1_limbs,
            pk0_limbs,
            pk1_limbs,
        )
        .enumerate()
        .par_bridge()
        .map(|(i, (qi, ct0i, ct1i, pk0i, pk1i))| {
            let qi_bigint = BigInt::from(**qi);

            // k0qi = -t^{-1} mod qi
            let k0qi = BigInt::from(config.k0is[i]);

            // ki = k1 * k0qi
            let ki = k1.scalar_mul(&k0qi);

            // The circuits check both identities reduced modulo X^N + 1, so the products are folded
            // negacyclically and each quotient is an exact division by `qi`, `N` coefficients wide:
            //   ct0i = (pk0i * u mod X^N + 1) + e0 + ki + qi * r1i
            //   ct1i = (pk1i * u mod X^N + 1) + e1 + qi * p1i
            // `e0` is the committed, lifted error, so `r1i` absorbs its multiple of `qi` and no
            // per-limb split of `e0` is a witness (IF-006).
            let n_usize = n as usize;
            let ct0i_hat = negacyclic_mul(&pk0i, &u, n_usize)?.add(&e0_mod_q).add(&ki);
            let r1i = exact_quotient(&ct0i.sub(&ct0i_hat), &qi_bigint, "reduced ct0 residual")?;

            let ct1i_hat = negacyclic_mul(&pk1i, &u, n_usize)?.add(&e1);
            let p1i = exact_quotient(&ct1i.sub(&ct1i_hat), &qi_bigint, "reduced ct1 residual")?;

            Ok::<_, WitnessError>((i, r1i, k0qi, ct0i, ct1i, pk0i, pk1i, p1i))
        })
        .collect::<Result<Vec<_>, _>>()?;

        results.sort_by_key(|(i, ..)| *i);

        let mut pk0is = Vec::with_capacity(results.len());
        let mut pk1is = Vec::with_capacity(results.len());
        let mut ct0is = Vec::with_capacity(results.len());
        let mut ct1is = Vec::with_capacity(results.len());
        let mut r1is = Vec::with_capacity(results.len());
        let mut p1is = Vec::with_capacity(results.len());

        for (_, r1i, _, ct0i, ct1i, pk0i, pk1i, p1i) in results {
            pk0is.push(pk0i);
            pk1is.push(pk1i);
            ct0is.push(ct0i);
            ct1is.push(ct1i);
            r1is.push(r1i);
            p1is.push(p1i);
        }

        let pk0is = CrtPolynomial::new(pk0is);
        let pk1is = CrtPolynomial::new(pk1is);
        let ct0is = CrtPolynomial::new(ct0is);
        let ct1is = CrtPolynomial::new(ct1is);
        let r1is = CrtPolynomial::new(r1is);
        let p1is = CrtPolynomial::new(p1is);

        // e0 is mod Q (huge); reduce to zkp_modulus so it fits in the proof system field.
        let zkp_modulus = get_zkp_modulus();
        e0_mod_q.reduce(&zkp_modulus);

        let bits = &config.bits;
        let pk0_commitment = crate::compute_pk_aggregation_pk1_commitment(&pk0is, bits.pk_bit);
        let pk1_commitment = crate::compute_pk_aggregation_pk1_commitment(&pk1is, bits.pk_bit);
        let ct0_commitment = crate::compute_ciphertext_component_commitment(&ct0is, bits.ct_bit);
        let ct1_commitment = crate::compute_ciphertext_component_commitment(&ct1is, bits.ct_bit);

        Ok(Inputs {
            pk0is,
            pk1is,
            ct0is,
            ct1is,
            r1is,
            p1is,
            e0: e0_mod_q,
            e1,
            u,
            k1,
            ciphertext: ct.to_bytes(),
            pk0_commitment,
            pk1_commitment,
            ct0_commitment,
            ct1_commitment,
        })
    }

    // Used as input for Nargo execution. Coefficients are JSON numbers when they fit in i64, else strings.
    pub fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        use crate::crt_polynomial_to_toml_json;
        use crate::polynomial_to_toml_json;

        let pk0is = crt_polynomial_to_toml_json(&self.pk0is);
        let pk1is = crt_polynomial_to_toml_json(&self.pk1is);
        let ct0is = crt_polynomial_to_toml_json(&self.ct0is);
        let ct1is = crt_polynomial_to_toml_json(&self.ct1is);
        let u = polynomial_to_toml_json(&self.u);
        let e0 = polynomial_to_toml_json(&self.e0);
        let e1 = polynomial_to_toml_json(&self.e1);
        let k1 = polynomial_to_toml_json(&self.k1);
        let r1is = crt_polynomial_to_toml_json(&self.r1is);
        let p1is = crt_polynomial_to_toml_json(&self.p1is);

        let json = serde_json::json!({
            "pk0is": pk0is,
            "pk1is": pk1is,
            "ct0is": ct0is,
            "ct1is": ct1is,
            "u": u,
            "e0": e0,
            "e1": e1,
            "k1": k1,
            "r1is": r1is,
            "p1is": p1is,
            "pk0_commitment": self.pk0_commitment.to_string(),
            "pk1_commitment": self.pk1_commitment.to_string(),
            "ct0_commitment": self.ct0_commitment.to_string(),
            "ct1_commitment": self.ct1_commitment.to_string(),
        });

        Ok(json)
    }
}
pub mod utils;
