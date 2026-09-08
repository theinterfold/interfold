// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{anyhow, Result};
use e3_fhe_params::{try_build_bfv_params_arc, BfvParamSet, BfvPreset};
use e3_zk_helpers::circuits::threshold::user_data_encryption::circuit::UserDataEncryptionCircuitData;
use e3_zk_helpers::circuits::threshold::user_data_encryption::Inputs as UserDataEncryptionInputs;
use e3_zk_helpers::circuits::Computation;
use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe::Error as FheError;
use fhe_traits::{DeserializeParametrized, FheEncoder, FheEncrypter, Serialize};
use rand::rng;
use std::sync::Arc;

fn build_client_params(
    degree: usize,
    plaintext_modulus: u64,
    moduli: &[u64],
    error1_variance: Option<&str>,
) -> Result<std::sync::Arc<fhe::bfv::BfvParameters>> {
    try_build_bfv_params_arc(degree, plaintext_modulus, moduli, error1_variance)
        .map_err(|error| anyhow!("Invalid BFV parameters: {error}"))
}

/// Encrypt some data using BFV homomorphic encryption
///
/// # Arguments
/// * `data` - The value to encrypt (Generic type T)
/// * `public_key` - Serialized BFV public key bytes
/// # `degree` - Polynomial degree for BFV parameters
/// # `plaintext_modulus` - Plaintext modulus for BFV parameters
/// * `moduli` - Vector of moduli for BFV parameters
///
/// # Returns
/// * `Result<Vec<u8>>` - Serialized BFV ciphertext bytes
///
/// # Errors
/// Returns error string if:
/// - Public key deserialization fails
/// - Plaintext encoding fails
/// - Encryption fails
/// - Input validation vector computation fails
pub fn bfv_encrypt<T>(
    data: T,
    public_key: Vec<u8>,
    degree: usize,
    plaintext_modulus: u64,
    moduli: &[u64],
) -> Result<Vec<u8>>
where
    Plaintext: for<'a> FheEncoder<&'a T, Error = FheError>,
{
    let params = build_client_params(degree, plaintext_modulus, moduli, None)?;

    let pk = PublicKey::from_bytes(&public_key, &params)
        .map_err(|e| anyhow!("Error deserializing public key:{e}"))?;

    let pt = Plaintext::try_encode(&data, Encoding::poly(), &params)
        .map_err(|e: FheError| anyhow!("Error encoding plaintext: {e}"))?;

    let ct = pk
        .try_encrypt(&pt, &mut rng())
        .map_err(|e| anyhow!("Error encrypting data: {e}"))?;

    let encrypted_data = ct.to_bytes();
    Ok(encrypted_data)
}

#[derive(Debug, Clone)]
pub struct VerifiableEncryptionResult {
    pub encrypted_data: Vec<u8>,
    pub circuit_inputs: String,
}

/// Verifiably encrypt some data using BFV homomorphic encryption and generate circuit inputs
/// to pass into Greco to prove the validity of the ciphertext
///
/// # Arguments
/// * `data` - The value to encrypt (Generic type T)
/// * `public_key` - Serialized BFV public key bytes
/// # `degree` - Polynomial degree for BFV parameters
/// # `plaintext_modulus` - Plaintext modulus for BFV parameters
/// * `moduli` - Vector of moduli for BFV parameters
///
/// # Returns
/// * `Result<VerifiableEncryptionResult, String>` - Contains encrypted u64 and circuit inputs for ZKP
///
/// # Errors
/// Returns error string if:
/// - Public key deserialization fails
/// - Plaintext encoding fails
/// - Encryption fails
/// - Input validation vector computation fails
pub fn bfv_verifiable_encrypt<T>(
    data: T,
    public_key: Vec<u8>,
    degree: usize,
    plaintext_modulus: u64,
    moduli: Vec<u64>,
) -> Result<VerifiableEncryptionResult>
where
    Plaintext: for<'a> FheEncoder<&'a T, Error = FheError>,
{
    let preset = BfvPreset::from_threshold_parameters(degree, plaintext_modulus, &moduli)
        .ok_or_else(|| {
            anyhow!(
                "Unsupported BFV threshold parameters for verifiable encryption: degree={degree}, \
                 plaintext_modulus={plaintext_modulus}, moduli_count={}",
                moduli.len()
            )
        })?;
    let preset_parameters = BfvParamSet::from(preset);
    let params = build_client_params(
        degree,
        plaintext_modulus,
        &moduli,
        preset_parameters.error1_variance,
    )?;

    let pk = PublicKey::from_bytes(&public_key, &params)
        .map_err(|e| anyhow!("Error deserializing public key: {}", e))?;

    let plaintext = Plaintext::try_encode(&data, Encoding::poly(), &params)
        .map_err(|e: FheError| anyhow!("Error encoding plaintext: {}", e))?;

    let inputs = UserDataEncryptionInputs::compute(
        preset,
        &UserDataEncryptionCircuitData {
            public_key: pk,
            plaintext,
        },
    )?;

    let encrypted_data = inputs.ciphertext.clone();
    let circuit_inputs = inputs.to_json()?.to_string();

    Ok(VerifiableEncryptionResult {
        encrypted_data,
        circuit_inputs,
    })
}

/// Generates a new public/secret key pair and returns the public key.
///
/// # Arguments
/// * `degree` - Polynomial degree for BFV parameters
/// * `plaintext_modulus` - Plaintext modulus for BFV parameters
/// * `moduli` - Vector of moduli for BFV parameters
///
/// # Returns
/// Raw bytes of the public key
pub fn generate_public_key(
    degree: usize,
    plaintext_modulus: u64,
    moduli: Vec<u64>,
) -> Result<Vec<u8>> {
    let params = build_client_params(degree, plaintext_modulus, &moduli, None)?;

    // Generate keys.
    let mut rng = rng();
    let sk = SecretKey::random(&params, &mut rng);
    let pk = PublicKey::new(&sk, &mut rng);

    Ok(pk.to_bytes())
}

pub fn compute_pk_commitment(
    public_key: Vec<u8>,
    degree: usize,
    plaintext_modulus: u64,
    moduli: Vec<u64>,
) -> Result<[u8; 32]> {
    use e3_zk_helpers::circuits::threshold::user_data_encryption::utils::compute_public_key_commitment;

    let params = build_client_params(degree, plaintext_modulus, &moduli, None)?;

    let public_key = PublicKey::from_bytes(&public_key, &params)
        .map_err(|e| anyhow!("Error deserializing public key: {}", e))?;

    let commitment = compute_public_key_commitment(&params, &public_key)
        .map_err(|e| anyhow!("Error computing public key commitment: {}", e))?;

    Ok(commitment)
}

/// Validate client-consumed BFV public-key bytes against the on-chain
/// commitment (C5-proven by the mandatory final DKG proof).
///
/// Validation is semantic rather than byte-for-byte: `fhe.rs` normalizes an
/// internal variable-time flag while decoding threshold-aggregated keys, so a
/// decode/re-encode cycle is not a stable serialization check. The decoded key
/// is safe to consume only when its circuit commitment matches the expected
/// on-chain commitment.
pub fn validate_pk_commitment(
    public_key: &[u8],
    expected_commitment: [u8; 32],
    degree: usize,
    plaintext_modulus: u64,
    moduli: Vec<u64>,
) -> Result<()> {
    use e3_zk_helpers::circuits::threshold::user_data_encryption::utils::compute_public_key_commitment;

    let params = build_client_params(degree, plaintext_modulus, &moduli, None)?;
    let decoded = PublicKey::from_bytes(public_key, &params)
        .map_err(|e| anyhow!("Error deserializing public key: {e}"))?;

    let actual_commitment = compute_public_key_commitment(&params, &decoded)
        .map_err(|e| anyhow!("Error computing public key commitment: {e}"))?;
    if actual_commitment != expected_commitment {
        return Err(anyhow!(
            "Public key commitment mismatch: event bytes are not the key proven by C5"
        ));
    }

    Ok(())
}

pub fn compute_ct_commitment(
    ct: Vec<u8>,
    degree: usize,
    plaintext_modulus: u64,
    moduli: Vec<u64>,
) -> Result<[u8; 32]> {
    let params = build_client_params(degree, plaintext_modulus, &moduli, None)?;

    compute_ct_commitment_with_params(&ct, &params)
}

/// Computes a ciphertext commitment with BFV parameters that the caller already built.
///
/// Use this function when one operation checks multiple ciphertexts with the same parameters. It
/// avoids rebuilding the large BFV parameter tables for every ciphertext.
pub fn compute_ct_commitment_with_params(
    ct: &[u8],
    params: &Arc<BfvParameters>,
) -> Result<[u8; 32]> {
    use e3_zk_helpers::circuits::threshold::user_data_encryption::utils::compute_ciphertext_commitment;

    let ct = Ciphertext::from_bytes(ct, params)
        .map_err(|e| anyhow!("Error deserializing ciphertext: {}", e))?;

    let commitment = compute_ciphertext_commitment(params, &ct)
        .map_err(|e| anyhow!("Error computing ciphertext commitment: {}", e))?;

    Ok(commitment)
}

#[cfg(test)]
mod tests {
    use e3_fhe_params::DEFAULT_BFV_PRESET;
    use e3_fhe_params::{build_bfv_params_from_set_arc, BfvParamSet};
    use fhe_traits::FheDecoder;

    use super::*;

    #[test]
    fn verifiable_encryption_rejects_noncanonical_parameter_tuple_before_key_decode() {
        let parameters: BfvParamSet = DEFAULT_BFV_PRESET.into();
        let mut moduli = parameters.moduli.to_vec();
        moduli[0] ^= 1;

        let error = bfv_verifiable_encrypt(
            [1_u64],
            Vec::new(),
            parameters.degree,
            parameters.plaintext_modulus,
            moduli,
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("Unsupported BFV threshold parameters"));
    }

    #[test]
    fn public_key_generation_returns_error_for_invalid_parameters() {
        let error = generate_public_key(7, 17, vec![97]).unwrap_err();
        assert!(error.to_string().contains("Invalid BFV parameters"));
    }

    #[test]
    fn validates_threshold_key_matching_the_proven_commitment() {
        use fhe::mbfv::{Aggregate as _, CommonRandomPoly, PublicKeyShare};

        let param_set: BfvParamSet = DEFAULT_BFV_PRESET.into();
        let params = build_bfv_params_from_set_arc(param_set);
        let mut rng = rng();
        let crp = CommonRandomPoly::new(&params, &mut rng).unwrap();
        let shares = (0..2)
            .map(|_| {
                let secret_key = SecretKey::random(&params, &mut rng);
                PublicKeyShare::new(&secret_key, crp.clone(), &mut rng).unwrap()
            })
            .collect::<Vec<_>>();
        let expected_key = PublicKey::from_shares(shares).unwrap();
        let substituted_key = PublicKey::new(&SecretKey::random(&params, &mut rng), &mut rng);
        let expected_bytes = expected_key.to_bytes();
        let normalized_bytes = PublicKey::from_bytes(&expected_bytes, &params)
            .unwrap()
            .to_bytes();
        assert_ne!(
            normalized_bytes, expected_bytes,
            "threshold aggregation must exercise fhe.rs variable-time normalization"
        );
        let expected_commitment = compute_pk_commitment(
            expected_bytes.clone(),
            param_set.degree,
            param_set.plaintext_modulus,
            param_set.moduli.to_vec(),
        )
        .unwrap();

        validate_pk_commitment(
            &expected_bytes,
            expected_commitment,
            param_set.degree,
            param_set.plaintext_modulus,
            param_set.moduli.to_vec(),
        )
        .unwrap();

        let error = validate_pk_commitment(
            &substituted_key.to_bytes(),
            expected_commitment,
            param_set.degree,
            param_set.plaintext_modulus,
            param_set.moduli.to_vec(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("commitment mismatch"));

        let mut equivalent_encoding = expected_bytes;
        equivalent_encoding.extend_from_slice(&[0x78, 0x01]);
        validate_pk_commitment(
            &equivalent_encoding,
            expected_commitment,
            param_set.degree,
            param_set.plaintext_modulus,
            param_set.moduli.to_vec(),
        )
        .unwrap();
    }

    #[test]
    fn verifiable_parameter_builder_uses_the_canonical_error_variance() {
        for preset in BfvPreset::PAIR_PRESETS {
            let parameters = BfvParamSet::from(preset);
            let built = build_client_params(
                parameters.degree,
                parameters.plaintext_modulus,
                parameters.moduli,
                parameters.error1_variance,
            )
            .unwrap();

            assert_eq!(
                built.get_error1_variance().to_string(),
                parameters.error1_variance.unwrap()
            );
        }
    }

    #[test]
    fn test_bfv_encrypt_a64() {
        use fhe::bfv::{Ciphertext, PublicKey, SecretKey};
        use fhe_traits::{DeserializeParametrized, FheDecrypter, Serialize};

        let param_set: BfvParamSet = DEFAULT_BFV_PRESET.into();
        let params = build_bfv_params_from_set_arc(param_set);
        let degree = param_set.degree;
        let plaintext_modulus = param_set.plaintext_modulus;
        let moduli = param_set.moduli;
        let mut rng = rng();
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);

        let num = [1u64];
        let encrypted_data =
            bfv_encrypt(num, pk.to_bytes(), degree, plaintext_modulus, moduli).unwrap();

        let ct = Ciphertext::from_bytes(&encrypted_data, &params).unwrap();
        let pt = sk.try_decrypt(&ct).unwrap();

        let decoded = Vec::<u64>::try_decode(&pt, Encoding::poly()).unwrap();
        assert_eq!(decoded[0], num[0]);
    }

    #[test]
    fn test_bfv_encrypt_v64() {
        use fhe::bfv::{Ciphertext, PublicKey, SecretKey};
        use fhe_traits::{DeserializeParametrized, FheDecrypter, Serialize};

        let param_set: BfvParamSet = DEFAULT_BFV_PRESET.into();
        let params = build_bfv_params_from_set_arc(param_set);
        let degree = param_set.degree;
        let plaintext_modulus = param_set.plaintext_modulus;
        let moduli = param_set.moduli;
        let mut rng = rng();
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);

        let num = vec![1, 2];
        let encrypted_data = bfv_encrypt(
            num.clone(),
            pk.to_bytes(),
            degree,
            plaintext_modulus,
            moduli,
        )
        .unwrap();

        let ct = Ciphertext::from_bytes(&encrypted_data, &params).unwrap();
        let pt = sk.try_decrypt(&ct).unwrap();

        let decoded = Vec::<u64>::try_decode(&pt, Encoding::poly()).unwrap();
        assert_eq!(decoded[0], num[0]);
        assert_eq!(decoded[1], num[1]);
    }

    #[test]
    fn test_bfv_verifiable_encrypt_a64() {
        use fhe::bfv::{Ciphertext, PublicKey, SecretKey};
        use fhe_traits::{DeserializeParametrized, FheDecrypter, Serialize};

        let param_set: BfvParamSet = DEFAULT_BFV_PRESET.into();
        let params = build_bfv_params_from_set_arc(param_set);
        let degree = param_set.degree;
        let plaintext_modulus = param_set.plaintext_modulus;
        let moduli = param_set.moduli;
        let mut rng = rand::rng();
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);

        let num = [1u64];
        let encrypted_data = bfv_verifiable_encrypt(
            num,
            pk.to_bytes(),
            degree,
            plaintext_modulus,
            moduli.to_vec(),
        )
        .unwrap();

        let ct = Ciphertext::from_bytes(&encrypted_data.encrypted_data, &params).unwrap();
        let pt = sk.try_decrypt(&ct).unwrap();

        let decoded = Vec::<u64>::try_decode(&pt, Encoding::poly()).unwrap();
        assert_eq!(decoded[0], num[0]);
    }

    #[test]
    fn test_bfv_verifiable_encrypt_v64() {
        use fhe::bfv::{Ciphertext, PublicKey, SecretKey};
        use fhe_traits::{DeserializeParametrized, FheDecrypter, Serialize};

        let param_set: BfvParamSet = DEFAULT_BFV_PRESET.into();
        let params = build_bfv_params_from_set_arc(param_set);
        let degree = param_set.degree;
        let plaintext_modulus = param_set.plaintext_modulus;
        let moduli = param_set.moduli;
        let mut rng = rand::rng();
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);

        let num = vec![1, 2];
        let encrypted_data = bfv_verifiable_encrypt(
            num.clone(),
            pk.to_bytes(),
            degree,
            plaintext_modulus,
            moduli.to_vec(),
        )
        .unwrap();

        let ct = Ciphertext::from_bytes(&encrypted_data.encrypted_data, &params).unwrap();
        let pt = sk.try_decrypt(&ct).unwrap();

        let decoded = Vec::<u64>::try_decode(&pt, Encoding::poly()).unwrap();
        assert_eq!(decoded[0], num[0]);
        assert_eq!(decoded[1], num[1]);
    }
}
