// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::fhe_poly_to_crt_centered;
use crate::utils::{compute_modulus_bit, ZkHelpersUtilsError};
use e3_polynomial::{CrtPolynomial, CrtPolynomialError};
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
/// Returns [`ZkHelpersUtilsError::UnexpectedCiphertextComponents`] if the ciphertext does not have
/// exactly two components.
/// Returns [`ZkHelpersUtilsError::ConversionError`] if `moduli.len() != self.limbs.len()`.
pub fn bfv_ciphertext_to_greco(
    params: &BfvParameters,
    ciphertext: &Ciphertext,
) -> Result<(CrtPolynomial, CrtPolynomial), ZkHelpersUtilsError> {
    // The Greco form and the Noir circuit both cover c[0] and c[1] only. A ciphertext with more
    // components would commit to the same value as its own two-component prefix, so two different
    // ciphertexts would share one commitment. Reject the extra components instead.
    if ciphertext.len() != 2 {
        return Err(ZkHelpersUtilsError::UnexpectedCiphertextComponents(
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
        ZkHelpersUtilsError::ConversionError(format!(
            "Failed to convert ciphertext polynomial: {e}"
        ))
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
/// Returns [`ZkHelpersUtilsError::ConversionError`] if the conversion fails.
/// Returns [`ZkHelpersUtilsError::CommitmentTooLong`] if the commitment is too long.
pub fn compute_public_key_commitment(
    params: &BfvParameters,
    public_key: &PublicKey,
) -> Result<[u8; 32], ZkHelpersUtilsError> {
    use crate::commitments::compute_pk_aggregation_commitment;

    let (pk0is, pk1is) = bfv_public_key_to_greco(params, public_key).map_err(|e| {
        ZkHelpersUtilsError::ConversionError(format!(
            "Failed to convert public key to greco: {}",
            e
        ))
    })?;

    let pk_bit = compute_modulus_bit(params);
    let commitment = compute_pk_aggregation_commitment(&pk0is, &pk1is, pk_bit);

    let bytes = commitment.to_bytes_be().1;

    if bytes.len() > 32 {
        return Err(ZkHelpersUtilsError::CommitmentTooLong(bytes.len()));
    }

    let mut padded_bytes = vec![0u8; 32];
    let start_idx = 32 - bytes.len();
    padded_bytes[start_idx..].copy_from_slice(&bytes);

    let public_key_hash: [u8; 32] = padded_bytes.try_into().map_err(|_| {
        ZkHelpersUtilsError::ConversionError("Failed to convert padded bytes to array".into())
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
/// Returns [`ZkHelpersUtilsError::UnexpectedCiphertextComponents`] if the ciphertext does not have
/// exactly two components.
/// Returns [`ZkHelpersUtilsError::ConversionError`] if the conversion fails.
/// Returns [`ZkHelpersUtilsError::CommitmentTooLong`] if the commitment is too long.
pub fn compute_ciphertext_commitment(
    params: &BfvParameters,
    ciphertext: &Ciphertext,
) -> Result<[u8; 32], ZkHelpersUtilsError> {
    use crate::commitments::compute_ciphertext_commitment;

    let (ct0is, ct1is) = bfv_ciphertext_to_greco(params, ciphertext)?;

    let pk_bit = compute_modulus_bit(params);
    let commitment = compute_ciphertext_commitment(&ct0is, &ct1is, pk_bit);

    let bytes = commitment.to_bytes_be().1;

    if bytes.len() > 32 {
        return Err(ZkHelpersUtilsError::CommitmentTooLong(bytes.len()));
    }

    let mut padded_bytes = vec![0u8; 32];
    let start_idx = 32 - bytes.len();
    padded_bytes[start_idx..].copy_from_slice(&bytes);

    let ciphertext_hash: [u8; 32] = padded_bytes.try_into().map_err(|_| {
        ZkHelpersUtilsError::ConversionError("Failed to convert padded bytes to array".into())
    })?;

    Ok(ciphertext_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::computation::Computation;
    use crate::threshold::user_data_encryption::computation::Inputs;
    use crate::threshold::user_data_encryption::UserDataEncryptionCircuitData;
    use e3_fhe_params::{build_pair_for_preset, BfvPreset};
    use fhe_traits::DeserializeParametrized;
    use num_bigint::BigInt;

    #[test]
    fn test_bfv_public_key_to_greco() {
        let (threshold_params, _) = build_pair_for_preset(BfvPreset::InsecureThreshold512).unwrap();
        let sample =
            UserDataEncryptionCircuitData::generate_sample(BfvPreset::InsecureThreshold512)
                .unwrap();

        let inputs = Inputs::compute(BfvPreset::InsecureThreshold512, &sample).unwrap();

        // Convert using our function
        let (actual_pk0is, actual_pk1is) =
            bfv_public_key_to_greco(&threshold_params, &sample.public_key).unwrap();

        // Verify the structure matches
        assert_eq!(actual_pk0is, inputs.pk0is);
        assert_eq!(actual_pk1is, inputs.pk1is);
    }

    /// Centering must hold for both components, and converting twice must give the same answer.
    ///
    /// The conversion reads the ciphertext by reference and centers a copy, so nothing it does can
    /// leave a component centered-twice or half-centered. Asserted rather than reasoned about,
    /// because the failure would be silent: a coefficient outside (-q/2, q/2] still commits to
    /// *something*, and the circuit would reject the ballot with no indication why.
    #[test]
    fn conversion_centers_both_components_and_is_repeatable() {
        let (threshold_params, _) = build_pair_for_preset(BfvPreset::InsecureThreshold512).unwrap();
        let sample =
            UserDataEncryptionCircuitData::generate_sample(BfvPreset::InsecureThreshold512)
                .unwrap();
        let inputs = Inputs::compute(BfvPreset::InsecureThreshold512, &sample).unwrap();
        let ciphertext = Ciphertext::from_bytes(&inputs.ciphertext, &threshold_params).unwrap();

        let moduli = threshold_params.moduli();
        let (ct0is, ct1is) = bfv_ciphertext_to_greco(&threshold_params, &ciphertext).unwrap();

        for crt in [&ct0is, &ct1is] {
            assert_eq!(crt.limbs.len(), moduli.len());
            for (limb, qi) in crt.limbs.iter().zip(moduli.iter()) {
                let half = BigInt::from(*qi) / BigInt::from(2u64);
                let low = -half.clone();
                for coefficient in limb.coefficients() {
                    assert!(
                        *coefficient > low && *coefficient <= half,
                        "coefficient {coefficient} outside (-q/2, q/2] for q={qi}"
                    );
                }
            }
        }

        // Idempotent in the sense that matters: the input is untouched, so a second conversion of
        // the same ciphertext produces an identical result rather than centering again.
        let (again0, again1) = bfv_ciphertext_to_greco(&threshold_params, &ciphertext).unwrap();
        assert_eq!(ct0is.limbs, again0.limbs);
        assert_eq!(ct1is.limbs, again1.limbs);
    }

    /// The commitment covers `c[0]` and `c[1]` only. Without a component-count check, a
    /// ciphertext padded with a third polynomial commits to the same value as its two-component
    /// prefix, so two different serialized ciphertexts would share one commitment. Threshold
    /// decryption then rejects the padded ciphertext and the round fails.
    #[test]
    fn ciphertext_with_more_than_two_components_is_rejected() {
        let (threshold_params, _) = build_pair_for_preset(BfvPreset::InsecureThreshold512).unwrap();
        let sample =
            UserDataEncryptionCircuitData::generate_sample(BfvPreset::InsecureThreshold512)
                .unwrap();
        let inputs = Inputs::compute(BfvPreset::InsecureThreshold512, &sample).unwrap();
        let ciphertext = Ciphertext::from_bytes(&inputs.ciphertext, &threshold_params).unwrap();

        let padded = Ciphertext::new(
            vec![
                ciphertext[0].clone(),
                ciphertext[1].clone(),
                ciphertext[1].clone(),
            ],
            &threshold_params,
        )
        .unwrap();
        assert_eq!(padded.len(), 3);

        assert!(matches!(
            bfv_ciphertext_to_greco(&threshold_params, &padded),
            Err(ZkHelpersUtilsError::UnexpectedCiphertextComponents(3))
        ));
        assert!(matches!(
            compute_ciphertext_commitment(&threshold_params, &padded),
            Err(ZkHelpersUtilsError::UnexpectedCiphertextComponents(3))
        ));

        // The two-component original still converts, so the check rejects only the padding.
        assert!(bfv_ciphertext_to_greco(&threshold_params, &ciphertext).is_ok());
    }

    #[test]
    fn test_bfv_ciphertext_to_greco() {
        let (threshold_params, _) = build_pair_for_preset(BfvPreset::InsecureThreshold512).unwrap();

        let sample =
            UserDataEncryptionCircuitData::generate_sample(BfvPreset::InsecureThreshold512)
                .unwrap();

        let inputs = Inputs::compute(BfvPreset::InsecureThreshold512, &sample).unwrap();

        let ciphertext = Ciphertext::from_bytes(&inputs.ciphertext, &threshold_params).unwrap();

        // Convert using our function
        let (actual_ct0is, actual_ct1is) =
            bfv_ciphertext_to_greco(&threshold_params, &ciphertext).unwrap();

        // Verify the structure matches
        assert_eq!(actual_ct0is, inputs.ct0is);
        assert_eq!(actual_ct1is, inputs.ct1is);
    }
}
