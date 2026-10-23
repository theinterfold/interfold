// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Circuit input data, witness preparation, and canonical Noir encoding.

use crate::commitments::compute_dkg_pk_commitment;
use crate::commitments::compute_share_encryption_commitment_from_message;
use crate::encoding::polynomial_to_toml_json;
use crate::encoding::{
    crt_polynomial_to_toml_json, fhe_poly_first_limb_centered, fhe_poly_to_crt_centered,
};
use crate::negacyclic::{exact_reduction_quotient, product_for_fold};
use crate::WitnessError;
use e3_polynomial::CrtPolynomial;
use e3_polynomial::Polynomial;
use e3_polynomial_fhe::FromFhePolynomial as _;
use e3_zk_config::dkg::share_encryption::Configs;
use fhe::bfv::Ciphertext;
use fhe::bfv::Encoding;
use fhe::bfv::Plaintext;
use fhe::bfv::PublicKey;
use fhe_math::rq::Ntt;
use fhe_math::rq::Poly;
use fhe_math::zq::Modulus;
use fhe_traits::FheDecoder;
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use rayon::prelude::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use serde::Deserialize;
use serde::Serialize;

/// Share-encryption circuit: proves correct encryption of a (secret or smudging) share under the DKG public key.

/// Input to the share-encryption circuit: plaintext, ciphertext, public key, and encryption randomness.
pub struct ShareEncryptionCircuitData {
    /// Plaintext (encoded share row).
    pub plaintext: Plaintext,
    /// Ciphertext (encryption under public_key).
    pub ciphertext: Ciphertext,
    /// DKG public key used to encrypt.
    pub public_key: PublicKey,
    /// Encryption randomness u in RNS form (from try_encrypt_with_intermediates).
    pub u_rns: Poly<Ntt>,
    /// Encryption error e0 in RNS form.
    pub e0_rns: Poly<Ntt>,
    /// Encryption error e1 in RNS form.
    pub e1_rns: Poly<Ntt>,
}

/// Input for the share-encryption circuit: CRT limbs for pk, ct, randomness, and message.
///
/// Coefficients are reduced to the ZKP field modulus for serialization. The circuit verifies
/// that the ciphertext and commitments match the public inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    /// Public key and ciphertext polynomials in CRT form (per modulus).
    pub pk0is: CrtPolynomial,
    pub pk1is: CrtPolynomial,
    pub ct0is: CrtPolynomial,
    pub ct1is: CrtPolynomial,
    /// ct0-leg reduction quotient, already reduced modulo `X^N + 1`.
    pub ct0_r: CrtPolynomial,
    /// ct1-leg reduction quotient, already reduced modulo `X^N + 1`.
    pub ct1_r: CrtPolynomial,
    /// Carries with `k1 == q_mod_t * m - t * z` and `k1` in `[0, t)`, so the circuit's scaled path
    /// never builds `k1`. A witness rather than an in-circuit hint, matching every other quotient
    /// here. Always produced; the direct path ignores it.
    pub z: CrtPolynomial,
    pub e0: Polynomial,
    pub e1: Polynomial,
    pub u: Polynomial,
    pub message: Polynomial,
    pub pk_commitment: BigInt,
    pub msg_commitment: BigInt,
}

impl Inputs {
    pub fn compute(
        config: &Configs,
        data: &ShareEncryptionCircuitData,
    ) -> Result<Self, WitnessError> {
        let dkg_params = &config.params;
        crate::validation::parameters("public_key", &data.public_key.params, dkg_params)?;
        if data.public_key.c.len() != 2 || data.ciphertext.len() != 2 {
            return Err(WitnessError::Other(
                "share encryption requires a two-component public key and ciphertext".into(),
            ));
        }
        for (name, poly) in [
            ("pk0", &data.public_key.c[0]),
            ("pk1", &data.public_key.c[1]),
            ("ct0", &data.ciphertext[0]),
            ("ct1", &data.ciphertext[1]),
            ("u", &data.u_rns),
            ("e0", &data.e0_rns),
            ("e1", &data.e1_rns),
        ] {
            let coefficients = poly.coefficients();
            crate::validation::context(
                name,
                poly.ctx(),
                coefficients.nrows(),
                coefficients.ncols(),
                dkg_params,
            )?;
        }

        let pk = &data.public_key;
        let pt = &data.plaintext;
        let ct = &data.ciphertext;
        let u = &data.u_rns;
        let e0 = &data.e0_rns;
        let e1 = &data.e1_rns;

        // The pk, ct, and error polynomials are pinned to the level-zero context above. A
        // plaintext above level zero would pair fewer context moduli with the full limb vectors
        // and silently truncate the witness.
        if pt.level() != 0 {
            return Err(WitnessError::Other(
                "share encryption plaintext must be at level zero".into(),
            ));
        }
        let ctx = dkg_params.context_at_level(0)?;
        let moduli = dkg_params.moduli();

        #[allow(non_snake_case)]
        let modulus_q = BigInt::from(ctx.modulus().clone());
        let t = dkg_params.plaintext();
        let k0is = &config.k0is;
        let n = dkg_params.degree() as u64;
        let q_mod_t = (&modulus_q % t)
            .to_u64()
            .ok_or_else(|| WitnessError::Other("Failed to convert q_mod_t to u64".into()))?;

        let e0_power = e0.to_power_basis();
        let mut e0_mod_q = Polynomial::from_fhe_polynomial(&e0_power);
        e0_mod_q.reverse();
        e0_mod_q.center(&modulus_q);

        let mut k1_u64 = Vec::<u64>::try_decode(pt, Encoding::poly())?;
        if k1_u64.len() != dkg_params.degree() {
            return Err(WitnessError::Other(
                "plaintext does not have the configured polynomial degree".into(),
            ));
        }
        Modulus::new(t)
            .map_err(|e| WitnessError::Fhe(fhe::Error::from(e)))?
            .scalar_mul_vec(&mut k1_u64, q_mod_t);

        let mut k1 = Polynomial::from_u64_vector(k1_u64);
        k1.reverse();

        let mut message =
            Polynomial::from_u64_vector(Vec::<u64>::try_decode(pt, Encoding::poly())?);
        message.reverse();

        let u = fhe_poly_first_limb_centered(u, moduli[0]);
        let e1 = fhe_poly_first_limb_centered(e1, moduli[0]);

        let ct0 = fhe_poly_to_crt_centered(&ct[0], moduli)?;
        let ct1 = fhe_poly_to_crt_centered(&ct[1], moduli)?;
        let pk0 = fhe_poly_to_crt_centered(&pk.c[0], moduli)?;
        let pk1 = fhe_poly_to_crt_centered(&pk.c[1], moduli)?;
        let e0_crt = fhe_poly_to_crt_centered(&e0_power, moduli)?;

        let CrtPolynomial { limbs: ct0_limbs } = ct0;
        let CrtPolynomial { limbs: ct1_limbs } = ct1;
        let CrtPolynomial { limbs: pk0_limbs } = pk0;
        let CrtPolynomial { limbs: pk1_limbs } = pk1;
        let CrtPolynomial { limbs: e0_limbs } = e0_crt;

        let results: Vec<_> = (
            ctx.moduli_operators(),
            ct0_limbs,
            ct1_limbs,
            pk0_limbs,
            pk1_limbs,
            e0_limbs,
        )
        .into_par_iter()
        .enumerate()
        .map(|(i, (qi, ct0i, ct1i, pk0i, pk1i, e0i))| {
            let qi_bigint = BigInt::from(**qi);

            // The circuit uses the lifted `e0` directly, with no CRT decomposition. That is only
            // correct while `e0_bound < q_i / 2`, which makes the centered residue equal to `e0`.
            // DKG keeps `error1_variance <= 16`, so the bound is `2 * variance`. If a parameter
            // change breaks that, fail here instead of emitting a witness the circuit misreads.
            assert!(
                e0_mod_q.sub(&e0i).is_zero(),
                "DKG e0 must fit in every modulus: e0 mod q_{i} differs from e0, so e0_bound >= q_i / 2"
            );

            let k0qi = BigInt::from(k0is[i]);
            let ki = k1.scalar_mul(&k0qi);

            let ct0i_hat = {
                let pk0i_u_times = product_for_fold(&pk0i, &u, n as usize);
                let e0_plus_ki = e0i.add(&ki);

                assert_eq!((pk0i_u_times.coefficients().len() as u64) - 1, 2 * (n - 1));
                assert_eq!((e0_plus_ki.coefficients().len() as u64) - 1, n - 1);

                pk0i_u_times.add(&e0_plus_ki)
            };

            assert_eq!((ct0i_hat.coefficients().len() as u64) - 1, 2 * (n - 1));

            let ct1i_hat = {
                let pk1i_u_times = product_for_fold(&pk1i, &u, n as usize);

                assert_eq!((pk1i_u_times.coefficients().len() as u64) - 1, 2 * (n - 1));

                pk1i_u_times.add(&e1)
            };
            assert_eq!((ct1i_hat.coefficients().len() as u64) - 1, 2 * (n - 1));

            // Both quotients are pinned by the reduced identities themselves:
            //   ct0i = (pk0i * u + e0 + k0qi * k1 mod X^N + 1) + qi * ct0_r
            //   ct1i = (pk1i * u + e1            mod X^N + 1) + qi * ct1_r
            // so folding the hats computed above and dividing by qi gives them. The hats already
            // hold the products, so nothing is recomputed and the cyclotomic quotients never exist.
            let (ct0_reduced_hat, ct0_r) =
                exact_reduction_quotient(&ct0i, &ct0i_hat, n as usize, &qi_bigint)?;
            let (ct1_reduced_hat, ct1_r) =
                exact_reduction_quotient(&ct1i, &ct1i_hat, n as usize, &qi_bigint)?;

            // Check both derived witnesses against their integer identities.
            assert!(
                ct0i
                    .sub(&ct0_reduced_hat.add(&ct0_r.scalar_mul(&qi_bigint)))
                    .is_zero(),
                "reduced C3 ct0 identity must hold: ct0i == pk0i * u + e0 + k0qi * k1 + qi * r (mod X^N + 1)"
            );
            assert!(
                ct1i
                    .sub(&ct1_reduced_hat.add(&ct1_r.scalar_mul(&qi_bigint)))
                    .is_zero(),
                "reduced C3 ct1 identity must hold: ct1i == pk1i * u + e1 + qi * r (mod X^N + 1)"
            );

            Ok((ct0i, ct1i, pk0i, pk1i, ct0_r, ct1_r))
        })
        .collect::<Result<Vec<_>, WitnessError>>()?;

        let mut pk0is = Vec::with_capacity(results.len());
        let mut pk1is = Vec::with_capacity(results.len());
        let mut ct0is = Vec::with_capacity(results.len());
        let mut ct1is = Vec::with_capacity(results.len());
        let mut ct0_r = Vec::with_capacity(results.len());
        let mut ct1_r = Vec::with_capacity(results.len());

        for (ct0i, ct1i, pk0i, pk1i, ct0_ri, ct1_ri) in results {
            pk0is.push(pk0i);
            pk1is.push(pk1i);
            ct0is.push(ct0i);
            ct1is.push(ct1i);
            ct0_r.push(ct0_ri);
            ct1_r.push(ct1_ri);
        }

        let pk0is = CrtPolynomial::new(pk0is);
        let pk1is = CrtPolynomial::new(pk1is);
        let ct0is = CrtPolynomial::new(ct0is);
        let ct1is = CrtPolynomial::new(ct1is);
        let ct0_r = CrtPolynomial::new(ct0_r);
        let ct1_r = CrtPolynomial::new(ct1_r);

        // z[j] = floor(q_mod_t * m[j] / t), i.e. the carry that puts `q_mod_t * m - t * z` in
        // `[0, t)`. The circuit pins it by asserting that window, so an off-by-one here fails there
        // rather than passing silently.
        let t_big = BigInt::from(dkg_params.plaintext());
        let scale_big =
            BigInt::from(dkg_params.context_at_level(0)?.modulus() % dkg_params.plaintext());
        let z_coeffs: Vec<BigInt> = message
            .coefficients()
            .iter()
            .map(|m| (&scale_big * m) / &t_big)
            .collect();
        let z = CrtPolynomial::new(vec![Polynomial::new(z_coeffs)]);

        let pk_bit = config.bits.pk_bit;
        let msg_bit = config.bits.msg_bit;
        let pk_commitment = compute_dkg_pk_commitment(&pk0is, &pk1is, pk_bit);
        let msg_commitment = compute_share_encryption_commitment_from_message(&message, msg_bit);

        Ok(Inputs {
            pk0is,
            pk1is,
            ct0is,
            ct1is,
            ct0_r,
            ct1_r,
            z,
            e0: e0_mod_q,
            e1,
            u,
            message,
            pk_commitment,
            msg_commitment,
        })
    }

    // Used as input for Nargo execution.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "pk0is": crt_polynomial_to_toml_json(&self.pk0is),
            "pk1is": crt_polynomial_to_toml_json(&self.pk1is),
            "ct0is": crt_polynomial_to_toml_json(&self.ct0is),
            "ct1is": crt_polynomial_to_toml_json(&self.ct1is),
            "u": polynomial_to_toml_json(&self.u),
            "e0": polynomial_to_toml_json(&self.e0),
            "e1": polynomial_to_toml_json(&self.e1),
            "message": polynomial_to_toml_json(&self.message),
            "ct0_r": crt_polynomial_to_toml_json(&self.ct0_r),
            "ct1_r": crt_polynomial_to_toml_json(&self.ct1_r),
            "z": crt_polynomial_to_toml_json(&self.z),
            "expected_pk_commitment": self.pk_commitment.to_string(),
            "expected_message_commitment": self.msg_commitment.to_string(),
        })
    }
}
