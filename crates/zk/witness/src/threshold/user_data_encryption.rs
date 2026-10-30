// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Circuit input data, witness preparation, and canonical Noir encoding.

use crate::encoding::{fhe_poly_first_limb_centered, fhe_poly_to_crt_centered};
use crate::negacyclic::negacyclic_mul_exact;
use crate::EncryptionIntermediates;
use crate::WitnessError;
use e3_fhe_params::create_deterministic_crp_from_default_seed;
use e3_fhe_params::utils::compute_modulus_bit;
use e3_polynomial::CrtPolynomial;
use e3_polynomial::CrtPolynomialError;
use e3_polynomial::Polynomial;
use e3_polynomial_fhe::FromFhePolynomial as _;
use e3_zk_config::field::get_zkp_modulus;
use e3_zk_config::threshold::pk_generation::crp::deterministic_crp_crt_polynomial;
use e3_zk_config::threshold::user_data_encryption::Configs;
use fhe::bfv::BfvParameters;
use fhe::bfv::Ciphertext;
use fhe::bfv::Encoding;
use fhe::bfv::Plaintext;
use fhe::bfv::PublicKey;
use fhe::bfv::SecretKey;
use fhe::mbfv::{Aggregate as _, PublicKeyShare};
use fhe_math::zq::Modulus;
use fhe_traits::FheDecoder;
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use rand::{CryptoRng, RngCore};
use rayon::prelude::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use serde::Deserialize;
use serde::Serialize;
use std::sync::Arc;

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

        // Reconstruct e0 coefficients mod Q; the reduced ct0 identity reads the lifted `e0`.
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

        // ct1 hard-codes the protocol CRS as `pk1`, as C5 does, so only keys built on it can be
        // proven. Committee keys always are; reject anything else here rather than in the prover.
        let crs = deterministic_crp_crt_polynomial(threshold_params)
            .map_err(|e| WitnessError::Other(e.to_string()))?;
        if pk1 != crs {
            return Err(WitnessError::Other(
                "user-data encryption proofs need a public key whose second component is the \
                 protocol CRS (committee keys, or keys built with the default-seed CRP)"
                    .into(),
            ));
        }

        let CrtPolynomial { limbs: ct0_limbs } = ct0;
        let CrtPolynomial { limbs: ct1_limbs } = ct1;
        let CrtPolynomial { limbs: pk0_limbs } = pk0;
        let CrtPolynomial { limbs: pk1_limbs } = pk1;

        // Perform the main computation logic
        let results: Vec<_> = (
            ctx.moduli_operators(),
            ct0_limbs,
            ct1_limbs,
            pk0_limbs,
            pk1_limbs,
        )
            .into_par_iter()
            .enumerate()
            .map(|(i, (qi, ct0i, ct1i, pk0i, pk1i))| {
                let qi_bigint = BigInt::from(**qi);

                // k0qi = -t^{-1} mod qi
                let k0qi = BigInt::from(k0is[i]);

                // ki = k1 * k0qi
                let ki = k1.scalar_mul(&k0qi);

                // The circuit checks one degree-N identity per leg, reduced modulo X^N + 1, over the
                // integers and with the lifted `e0`:
                //   ct0i = (pk0i * u mod X^N + 1) + e0 + k0qi * k1 + qi * ct0_r
                //   ct1i = (pk1i * u mod X^N + 1) + e1            + qi * ct1_r
                // so each quotient is the leg's residual divided by qi. The reduced products are exact
                // integer products, taken by NTT in O(N log N).
                let pk0_u = negacyclic_mul_exact(&pk0i, &u, n as usize);
                let pk1_u = negacyclic_mul_exact(&pk1i, &u, n as usize);

                // Exact division rejects any coefficient that is not a multiple of qi, so a successful
                // division proves an integer quotient closes the reduced equation, and a wrong product
                // surfaces as a divisibility failure.
                let ct0_r = ct0i
                    .sub(&pk0_u)
                    .sub(&e0_mod_q)
                    .sub(&ki)
                    .div_exact(&qi_bigint)?;
                let ct1_r = ct1i.sub(&pk1_u).sub(&e1).div_exact(&qi_bigint)?;

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
        // a circuit field named `r`. `pk1is` is not an input: ct1 hard-codes the CRS it must equal.
        serde_json::json!({
            "pk0is": crt_polynomial_to_toml_json(&self.pk0is),
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

/// A BFV public key built on the protocol CRS: `(-a * s + e, a)` with `a` the default-seed CRP,
/// the shape every committee key has.
///
/// ct1 hard-codes that `a` as `pk1`, as C5 does, so user-data encryption proofs can only be made
/// for keys like this one. Key generators for tests, demos and local runs use it instead of
/// `PublicKey::new`, whose `a` is random.
pub fn public_key_on_protocol_crs<R: RngCore + CryptoRng>(
    params: &Arc<BfvParameters>,
    secret_key: &SecretKey,
    rng: &mut R,
) -> Result<PublicKey, fhe::Error> {
    let crp = create_deterministic_crp_from_default_seed(params);
    PublicKey::from_shares(vec![PublicKeyShare::new(secret_key, crp, rng)?])
}

/// Encrypt once and prepare the witness from those exact encryption intermediates.
/// Callers serialize the typed ciphertext only at their public output boundary.
pub fn encrypt_and_prepare(
    config: &Configs,
    data: &UserDataEncryptionCircuitData,
) -> Result<(Ciphertext, Inputs), WitnessError> {
    crate::validation::parameters("public_key", &data.public_key.params, &config.params)?;
    let (ciphertext, intermediates) =
        crate::encrypt_with_intermediates(&data.public_key, &data.plaintext, &mut rand::rng())?;
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
