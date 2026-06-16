// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{anyhow, Result};
use e3_fhe_params::{build_bfv_params_arc, DEFAULT_BFV_PRESET};
use e3_zk_helpers::circuits::threshold::user_data_encryption::circuit::UserDataEncryptionCircuitData;
use e3_zk_helpers::circuits::threshold::user_data_encryption::Inputs as UserDataEncryptionInputs;
use e3_zk_helpers::circuits::Computation;
use fhe::bfv::{Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe::Error as FheError;
use fhe_traits::{DeserializeParametrized, FheEncoder, FheEncrypter, Serialize};
use rand::rng;

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
    let params = build_bfv_params_arc(degree, plaintext_modulus, moduli, None);

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
    let params = build_bfv_params_arc(degree, plaintext_modulus, &moduli, None);

    let pk = PublicKey::from_bytes(&public_key, &params)
        .map_err(|e| anyhow!("Error deserializing public key: {}", e))?;

    let plaintext = Plaintext::try_encode(&data, Encoding::poly(), &params)
        .map_err(|e: FheError| anyhow!("Error encoding plaintext: {}", e))?;

    let inputs = UserDataEncryptionInputs::compute(
        DEFAULT_BFV_PRESET,
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
    let params = build_bfv_params_arc(degree, plaintext_modulus, &moduli, None);

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

    let params = build_bfv_params_arc(degree, plaintext_modulus, &moduli, None);

    let public_key = PublicKey::from_bytes(&public_key, &params)
        .map_err(|e| anyhow!("Error deserializing public key: {}", e))?;

    let commitment = compute_public_key_commitment(&params, &public_key)
        .map_err(|e| anyhow!("Error computing public key commitment: {}", e))?;

    Ok(commitment)
}

pub fn compute_ct_commitment(
    ct: Vec<u8>,
    degree: usize,
    plaintext_modulus: u64,
    moduli: Vec<u64>,
) -> Result<[u8; 32]> {
    use e3_zk_helpers::circuits::threshold::user_data_encryption::utils::compute_ciphertext_commitment;

    let params = build_bfv_params_arc(degree, plaintext_modulus, &moduli, None);

    let ct = Ciphertext::from_bytes(&ct, &params)
        .map_err(|e| anyhow!("Error deserializing ciphertext: {}", e))?;

    let commitment = compute_ciphertext_commitment(&params, &ct)
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
