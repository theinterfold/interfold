// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::encoding::fhe_poly_to_crt_centered;
use crate::WitnessError;
use e3_fhe_params::utils::compute_modulus_bit;
use e3_polynomial::{CrtPolynomial, CrtPolynomialError};
use e3_polynomial_fhe::FromFhePolynomial as _;
use fhe::bfv::{BfvParameters, Ciphertext, PublicKey};

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
