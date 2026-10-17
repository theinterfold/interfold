// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Circuit input data, witness preparation, and canonical Noir encoding.

use crate::encoding::{fhe_poly_first_limb_centered, fhe_poly_to_crt_centered};
use crate::negacyclic::{exact_reduction_quotient, product_for_fold};
use crate::WitnessError;
use e3_fhe_params::utils::compute_modulus_bit;
use e3_polynomial::CrtPolynomial;
use e3_polynomial::CrtPolynomialError;
use e3_polynomial::Polynomial;
use e3_polynomial_fhe::FromFhePolynomial as _;
use e3_zk_config::field::get_zkp_modulus;
use e3_zk_config::threshold::user_data_encryption::Configs;
use fhe::bfv::BfvParameters;
use fhe::bfv::Ciphertext;
use fhe::bfv::Encoding;
use fhe::bfv::EncryptionIntermediates;
use fhe::bfv::Plaintext;
use fhe::bfv::PublicKey;
use fhe_math::zq::Modulus;
use fhe_traits::FheDecoder;
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use rayon::prelude::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use serde::Deserialize;
use serde::Serialize;

pub struct UserDataEncryptionCircuitData {
    pub public_key: PublicKey,
    pub plaintext: Plaintext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    pub pk0is: CrtPolynomial,
    pub pk1is: CrtPolynomial,
    pub ct0is: CrtPolynomial,
    pub ct1is: CrtPolynomial,
    /// ct0's reduction quotient, already reduced modulo `X^N + 1`.
    pub ct0_r: CrtPolynomial,
    /// ct1's reduction quotient, already reduced modulo `X^N + 1`.
    pub ct1_r: CrtPolynomial,
    pub e0: Polynomial,
    pub e1: Polynomial,
    pub u: Polynomial,
    pub k1: Polynomial,
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

        let pk = &data.public_key;
        let pt = &data.plaintext;

        // Context and plaintext modulus (use same ctx for e0 reconstruction and loop).
        let ctx = threshold_params.context_at_level(0)?;

        #[allow(non_snake_case)]
        let modulus_q = BigInt::from(ctx.modulus().clone());
        let moduli = threshold_params.moduli();

        let t = threshold_params.plaintext();
        let k0is = &config.k0is;
        let n = threshold_params.degree() as u64;
        let q_mod_t = (&modulus_q % t)
            .to_u64()
            .ok_or_else(|| WitnessError::Other("Failed to convert q_mod_t to u64".into()))?; // [q]_t

        // Reconstruct e0 coefficients mod Q (CRT) for e0_quotient computation.
        let e0_power = intermediates.error_0().to_power_basis();
        let mut e0_mod_q = Polynomial::from_fhe_polynomial(&e0_power);

        e0_mod_q.reverse();
        e0_mod_q.center(&modulus_q);

        // Reconstruct k1 from plaintext polynomial.
        let mut k1_u64 = Vec::<u64>::try_decode(&pt, Encoding::poly())?; // m
        if k1_u64.len() != threshold_params.degree() {
            return Err(WitnessError::Other(
                "plaintext does not have the configured polynomial degree".into(),
            ));
        }

        Modulus::new(t)
            .map_err(|e| WitnessError::Fhe(fhe::Error::from(e)))?
            .scalar_mul_vec(&mut k1_u64, q_mod_t); // k1 = [q*m]_t

        let mut k1 = Polynomial::from_u64_vector(k1_u64);

        k1.reverse();

        // Reconstruct u and e1 as polynomials (only the first limb is needed)
        let u = fhe_poly_first_limb_centered(intermediates.randomness(), moduli[0]);
        let e1 = fhe_poly_first_limb_centered(intermediates.error_1(), moduli[0]);

        let ct0 = fhe_poly_to_crt_centered(&ct[0], moduli)?;
        let ct1 = fhe_poly_to_crt_centered(&ct[1], moduli)?;
        let pk0 = fhe_poly_to_crt_centered(&pk.c[0], moduli)?;
        let pk1 = fhe_poly_to_crt_centered(&pk.c[1], moduli)?;
        let e0 = fhe_poly_to_crt_centered(&e0_power, moduli)?;

        let CrtPolynomial { limbs: ct0_limbs } = ct0;
        let CrtPolynomial { limbs: ct1_limbs } = ct1;
        let CrtPolynomial { limbs: pk0_limbs } = pk0;
        let CrtPolynomial { limbs: pk1_limbs } = pk1;
        let CrtPolynomial { limbs: e0_limbs } = e0;

        // Perform the main computation logic
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

            // Compute e0_quotients[i] = (e0 - e0i) / qi for each coefficient
            // This is used for CRT consistency check: e0[j] = e0i[j] + e0_quotients[i][j] * qi
            // Each difference must be exactly divisible by qi.
            let diff = e0_mod_q.sub(&e0i);
            let e0_quotient = diff.div_exact(&qi_bigint)?;

            // k0qi = -t^{-1} mod qi
            let k0qi = BigInt::from(k0is[i]);

            // ki = k1 * k0qi
            let ki = k1.scalar_mul(&k0qi);

            // Calculate ct0i_hat = pk0 * ui + e0i + ki
            let ct0i_hat = {
                let pk0i_u_times = product_for_fold(&pk0i, &u, n as usize);
                let e0_plus_ki = e0i.add(&ki);

                assert_eq!((pk0i_u_times.coefficients().len() as u64) - 1, 2 * (n - 1));
                assert_eq!((e0_plus_ki.coefficients().len() as u64) - 1, n - 1);

                pk0i_u_times.add(&e0_plus_ki)
            };

            assert_eq!((ct0i_hat.coefficients().len() as u64) - 1, 2 * (n - 1));

            // Calculate ct1i_hat = pk1i * ui + e1
            let ct1i_hat = {
                let pk1i_u_times = product_for_fold(&pk1i, &u, n as usize);

                assert_eq!((pk1i_u_times.coefficients().len() as u64) - 1, 2 * (n - 1));

                pk1i_u_times.add(&e1)
            };
            assert_eq!((ct1i_hat.coefficients().len() as u64) - 1, 2 * (n - 1));

            // The circuit checks one degree-N identity per leg, reduced modulo X^N + 1:
            //   ct0i = (pk0i * u mod X^N + 1) + e0 + k0qi * k1 + qi * ct0_r
            //   ct1i = (pk1i * u mod X^N + 1) + e1            + qi * ct1_r
            // Each quotient is pinned by its own identity, so folding the hat computed above and
            // dividing by qi gives it. The hats already hold the products, so nothing is recomputed
            // and the cyclotomic quotients never exist.
            //
            // The ct0 hat carries the residue `e0i`, while the identity reads the lifted `e0`.
            // Substituting the CRT split `e0 = e0i + e0_quotient * qi` moves that difference into
            // the quotient, so `ct0_r` is the folded quotient minus `e0_quotient`.
            let (ct0_reduced_hat, ct0_folded_quotient) =
                exact_reduction_quotient(&ct0i, &ct0i_hat, n as usize, &qi_bigint)?;
            let ct0_r = ct0_folded_quotient.sub(&e0_quotient);

            let (ct1_reduced_hat, ct1_r) =
                exact_reduction_quotient(&ct1i, &ct1i_hat, n as usize, &qi_bigint)?;

            // Restate both identities on the derived witnesses, with the lifted `e0` the circuit
            // reads. This checks the derived quotients against the integer equations.
            let ct0_reduced = ct0_reduced_hat
                .sub(&e0i)
                .add(&e0_mod_q)
                .add(&ct0_r.scalar_mul(&qi_bigint));
            assert!(
                ct0i.sub(&ct0_reduced).is_zero(),
                "reduced ct0 identity must hold: ct0i == pk0i * u + e0 + k0qi * k1 + qi * r (mod X^N + 1)"
            );
            assert!(
                ct1i
                    .sub(&ct1_reduced_hat.add(&ct1_r.scalar_mul(&qi_bigint)))
                    .is_zero(),
                "reduced ct1 identity must hold: ct1i == pk1i * u + e1 + qi * r (mod X^N + 1)"
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

        // e0 is mod Q (huge); reduce to zkp_modulus so it fits in the proof system field.
        let zkp_modulus = get_zkp_modulus();
        e0_mod_q.reduce(&zkp_modulus);

        Ok(Inputs {
            pk0is,
            pk1is,
            ct0is,
            ct1is,
            ct0_r,
            ct1_r,
            e0: e0_mod_q,
            e1,
            u,
            k1,
        })
    }

    // Used as input for Nargo execution. Coefficients are JSON numbers when they fit in i64, else strings.
    pub fn to_json(&self) -> serde_json::Value {
        use crate::encoding::crt_polynomial_to_toml_json;
        use crate::encoding::polynomial_to_toml_json;

        // ct0 and ct1 share one Prover.toml, so each reduction quotient needs its own key. Both feed
        // a circuit field named `r`.
        serde_json::json!({
            "pk0is": crt_polynomial_to_toml_json(&self.pk0is),
            "pk1is": crt_polynomial_to_toml_json(&self.pk1is),
            "ct0is": crt_polynomial_to_toml_json(&self.ct0is),
            "ct1is": crt_polynomial_to_toml_json(&self.ct1is),
            "u": polynomial_to_toml_json(&self.u),
            "e0": polynomial_to_toml_json(&self.e0),
            "e1": polynomial_to_toml_json(&self.e1),
            "k1": polynomial_to_toml_json(&self.k1),
            "r": crt_polynomial_to_toml_json(&self.ct0_r),
            "r_ct1": crt_polynomial_to_toml_json(&self.ct1_r),
        })
    }
}

/// Encrypt once and prepare the witness from those exact encryption intermediates.
/// Callers serialize the typed ciphertext only at their public output boundary.
pub fn encrypt_and_prepare(
    config: &Configs,
    data: &UserDataEncryptionCircuitData,
) -> Result<(Ciphertext, Inputs), WitnessError> {
    crate::validation::parameters("public_key", &data.public_key.params, &config.params)?;
    let (ciphertext, intermediates) = data
        .public_key
        .try_encrypt_with_intermediates(&data.plaintext, &mut rand::rng())?;
    let inputs = Inputs::compute(config, data, &ciphertext, &intermediates)?;
    Ok((ciphertext, inputs))
}

/// Converts a BFV ciphertext to Greco format.
///
/// Takes a BFV ciphertext and converts it to Greco format, returning ct0is and ct1is
/// as CRT polynomials.
///
/// # Arguments
/// * `params` - BFV parameters
/// * `ct` - BFV ciphertext
///
/// # Returns
/// A tuple of (ct0is, ct1is) where each is CrtPolynomial
///
/// # Errors
/// Returns [`WitnessError::UnexpectedCiphertextComponents`] if the ciphertext does not have
/// exactly two components.
/// Returns [`WitnessError::ConversionError`] if `moduli.len() != self.limbs.len()`.
pub fn bfv_ciphertext_to_greco(
    params: &BfvParameters,
    ciphertext: &Ciphertext,
) -> Result<(CrtPolynomial, CrtPolynomial), WitnessError> {
    // The Greco form and the Noir circuit both cover c[0] and c[1] only. A ciphertext with more
    // components would commit to the same value as its own two-component prefix, so two different
    // ciphertexts would share one commitment. Reject the extra components instead.
    if ciphertext.len() != 2 {
        return Err(WitnessError::UnexpectedCiphertextComponents(
            ciphertext.len(),
        ));
    }

    let moduli = params.moduli();

    // Converted separately and directly, not through a shared closure. `fhe_poly_to_crt_centered`
    // takes the polynomial by reference and builds a fresh `CrtPolynomial` before reversing and
    // centering it, so each call starts from an untouched component and neither centering can
    // compound on the other. Spelling that out here rather than folding the two calls into one
    // helper, because a reused helper reads as though it might carry state across them.
    let wrap = |e: CrtPolynomialError| {
        WitnessError::ConversionError(format!("Failed to convert ciphertext polynomial: {e}"))
    };

    let ct0is = fhe_poly_to_crt_centered(&ciphertext[0], moduli).map_err(wrap)?;
    let ct1is = fhe_poly_to_crt_centered(&ciphertext[1], moduli).map_err(wrap)?;

    Ok((ct0is, ct1is))
}

/// Converts a BFV public key to Greco format for commitment computation.
///
/// Coefficients are reversed then centered per modulus, matching C1 / C5 threshold PK proofs.
///
/// # Arguments
/// * `params` - BFV parameters
/// * `public_key` - BFV public key
///
/// # Returns
/// A tuple of (pk0is, pk1is) where each is CrtPolynomial
///
/// # Errors
/// Returns [`CrtPolynomialError::ModuliLengthMismatch`] if `moduli.len() != self.limbs.len()`.
pub fn bfv_public_key_to_greco(
    params: &BfvParameters,
    public_key: &PublicKey,
) -> Result<(CrtPolynomial, CrtPolynomial), CrtPolynomialError> {
    let moduli = params.moduli();
    let mut pk0is = CrtPolynomial::from_fhe_polynomial(&public_key.c[0]);
    let mut pk1is = CrtPolynomial::from_fhe_polynomial(&public_key.c[1]);
    pk0is.reverse();
    pk1is.reverse();
    pk0is.center(moduli)?;
    pk1is.center(moduli)?;
    Ok((pk0is, pk1is))
}

/// Computes the commitment of the public key.
///
/// # Arguments
/// * `params` - BFV parameters
/// * `public_key` - BFV public key
///
/// # Returns
/// The commitment of the public key
///
/// # Errors
/// Returns [`WitnessError::ConversionError`] if the conversion fails.
/// Returns [`WitnessError::CommitmentTooLong`] if the commitment is too long.
pub fn compute_public_key_commitment(
    params: &BfvParameters,
    public_key: &PublicKey,
) -> Result<[u8; 32], WitnessError> {
    use crate::commitments::compute_pk_aggregation_commitment;

    let (pk0is, pk1is) = bfv_public_key_to_greco(params, public_key).map_err(|e| {
        WitnessError::ConversionError(format!("Failed to convert public key to greco: {}", e))
    })?;

    let pk_bit = compute_modulus_bit(params);
    let commitment = compute_pk_aggregation_commitment(&pk0is, &pk1is, pk_bit);

    let bytes = commitment.to_bytes_be().1;

    if bytes.len() > 32 {
        return Err(WitnessError::CommitmentTooLong(bytes.len()));
    }

    let mut padded_bytes = vec![0u8; 32];
    let start_idx = 32 - bytes.len();
    padded_bytes[start_idx..].copy_from_slice(&bytes);

    let public_key_hash: [u8; 32] = padded_bytes.try_into().map_err(|_| {
        WitnessError::ConversionError("Failed to convert padded bytes to array".into())
    })?;

    Ok(public_key_hash)
}

/// Computes the commitment of the ciphertext.
///
/// # Arguments
/// * `params` - BFV parameters
/// * `ciphertext` - BFV ciphertext
///
/// # Returns
/// The commitment of the ciphertext
///
/// # Errors
/// Returns [`WitnessError::UnexpectedCiphertextComponents`] if the ciphertext does not have
/// exactly two components.
/// Returns [`WitnessError::ConversionError`] if the conversion fails.
/// Returns [`WitnessError::CommitmentTooLong`] if the commitment is too long.
pub fn compute_ciphertext_commitment(
    params: &BfvParameters,
    ciphertext: &Ciphertext,
) -> Result<[u8; 32], WitnessError> {
    use crate::commitments::compute_ciphertext_commitment;

    let (ct0is, ct1is) = bfv_ciphertext_to_greco(params, ciphertext)?;

    let pk_bit = compute_modulus_bit(params);
    let commitment = compute_ciphertext_commitment(&ct0is, &ct1is, pk_bit);

    let bytes = commitment.to_bytes_be().1;

    if bytes.len() > 32 {
        return Err(WitnessError::CommitmentTooLong(bytes.len()));
    }

    let mut padded_bytes = vec![0u8; 32];
    let start_idx = 32 - bytes.len();
    padded_bytes[start_idx..].copy_from_slice(&bytes);

    let ciphertext_hash: [u8; 32] = padded_bytes.try_into().map_err(|_| {
        WitnessError::ConversionError("Failed to convert padded bytes to array".into())
    })?;

    Ok(ciphertext_hash)
}
