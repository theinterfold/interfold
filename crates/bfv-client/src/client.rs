// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{anyhow, ensure, Result};
use e3_fhe_params::{try_build_bfv_params_arc, BfvParamSet, BfvPreset};
use e3_zk_witness::threshold::user_data_encryption::{
    encrypt_and_prepare, UserDataEncryptionCircuitData,
};
use e3_zk_witness::threshold::user_data_encryption_chunked::Inputs as ChunkedUserDataEncryptionInputs;
use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe::Error as FheError;
use fhe_traits::{DeserializeParametrized, FheEncoder, FheEncrypter, Serialize};
use rand::rng;
use serde_json::Value;
use std::sync::Arc;

/// Preserve exact witness integers when JavaScript parses the JSON returned by WASM.
fn stringify_unsafe_js_integers(value: &mut Value) {
    const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
    match value {
        Value::Array(values) => values.iter_mut().for_each(stringify_unsafe_js_integers),
        Value::Object(fields) => fields.values_mut().for_each(stringify_unsafe_js_integers),
        Value::Number(number) => {
            if number
                .as_i64()
                .is_some_and(|n| !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&n))
                || number.as_u64().is_some_and(|n| n > MAX_SAFE_INTEGER as u64)
            {
                *value = Value::String(number.to_string());
            }
        }
        _ => {}
    }
}

/// The preset of a committee key with these parameters. An l-BFV committee publishes its key as an
/// envelope, which names the l-BFV path; the parameters alone resolve to the trBFV label.
fn key_preset(
    public_key: &[u8],
    degree: usize,
    plaintext_modulus: u64,
    moduli: &[u64],
) -> Option<BfvPreset> {
    let preset = BfvPreset::from_threshold_parameters(degree, plaintext_modulus, moduli)?;
    if crate::is_lbfv_key_envelope(public_key) {
        preset.lbfv_label()
    } else {
        Some(preset)
    }
}

fn decode_public_key(
    public_key: &[u8],
    params: &Arc<BfvParameters>,
    preset: Option<BfvPreset>,
) -> Result<PublicKey> {
    let public_key = if crate::is_lbfv_key_envelope(public_key) {
        let preset = preset
            .ok_or_else(|| anyhow!("Unsupported BFV parameters for an l-BFV key envelope"))?;
        crate::inspect_lbfv_key_envelope(public_key, preset)?.1
    } else {
        public_key.to_vec()
    };
    PublicKey::from_bytes(&public_key, params)
        .map_err(|error| anyhow!("Error deserializing public key: {error}"))
}

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
    bfv_encrypt_with_encoding(
        data,
        public_key,
        degree,
        plaintext_modulus,
        moduli,
        Encoding::poly(),
    )
}

/// Encrypt some data like [`bfv_encrypt`], with the plaintext in the given encoding.
///
/// `Encoding::simd()` needs a plaintext modulus that is prime and 1 mod 2N; fhe.rs returns an
/// error otherwise.
pub fn bfv_encrypt_with_encoding<T>(
    data: T,
    public_key: Vec<u8>,
    degree: usize,
    plaintext_modulus: u64,
    moduli: &[u64],
    encoding: Encoding,
) -> Result<Vec<u8>>
where
    Plaintext: for<'a> FheEncoder<&'a T, Error = FheError>,
{
    let params = build_client_params(degree, plaintext_modulus, moduli, None)?;

    let preset = key_preset(&public_key, degree, plaintext_modulus, moduli);
    let pk = decode_public_key(&public_key, &params, preset)?;

    let pt = Plaintext::try_encode(&data, encoding, &params)
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
    bfv_verifiable_encrypt_with_encoding(
        data,
        public_key,
        degree,
        plaintext_modulus,
        moduli,
        Encoding::poly(),
    )
}

/// Verifiably encrypt some data like [`bfv_verifiable_encrypt`], with the plaintext in the given
/// encoding. The witness carries the raw polynomial of the plaintext, so `Encoding::simd()`
/// plaintexts are proven with the same circuits.
pub fn bfv_verifiable_encrypt_with_encoding<T>(
    data: T,
    public_key: Vec<u8>,
    degree: usize,
    plaintext_modulus: u64,
    moduli: Vec<u64>,
    encoding: Encoding,
) -> Result<VerifiableEncryptionResult>
where
    Plaintext: for<'a> FheEncoder<&'a T, Error = FheError>,
{
    let preset = key_preset(&public_key, degree, plaintext_modulus, &moduli).ok_or_else(|| {
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

    let pk = decode_public_key(&public_key, &params, Some(preset))?;

    let plaintext = Plaintext::try_encode(&data, encoding, &params)
        .map_err(|e: FheError| anyhow!("Error encoding plaintext: {}", e))?;

    // The trBFV path proves user encryption with `user_data_encryption`'s ct0/ct1; the l-BFV path
    // with the chunked ct0/ct1 pipeline, which takes its own witness.
    let (encrypted_data, mut witness) = if e3_fhe_params::is_lbfv_path(preset) {
        let config = e3_zk_config::threshold::user_data_encryption_chunked::Configs::new(&params)?;
        let (ciphertext, intermediates) =
            e3_zk_witness::encrypt_with_intermediates(&pk, &plaintext, &mut rng())?;
        let inputs = ChunkedUserDataEncryptionInputs::compute(
            &config,
            &UserDataEncryptionCircuitData {
                public_key: pk,
                plaintext,
            },
            &ciphertext,
            &intermediates,
        )?;
        (ciphertext.to_bytes(), inputs.to_json()?)
    } else {
        let config = e3_zk_config::threshold::user_data_encryption::Configs::new(&params)?;
        let (ciphertext, inputs) = encrypt_and_prepare(
            &config,
            &UserDataEncryptionCircuitData {
                public_key: pk,
                plaintext,
            },
        )?;
        (ciphertext.to_bytes(), inputs.to_json())
    };
    stringify_unsafe_js_integers(&mut witness);
    let circuit_inputs = witness.to_string();

    Ok(VerifiableEncryptionResult {
        encrypted_data,
        circuit_inputs,
    })
}

/// The SIMD slot values of a plaintext, given its polynomial coefficients.
///
/// A decrypted plaintext carries no encoding, so the published coefficients are the poly basis.
/// This rebuilds the fhe.rs SIMD decode from its public parts, with no key and no randomness: a
/// forward negacyclic NTT modulo `t`, then the SEAL slot order (`matrix_reps_index_map` of fhe.rs).
/// The tests compare it with `Vec::<u64>::try_decode(.., Encoding::simd())`.
///
/// # Errors
/// Returns an error if the preset has no SIMD support (the plaintext modulus is not prime and
/// 1 mod 2N), if `coefficients` does not have exactly `degree` entries, or if a coefficient is
/// not below the plaintext modulus.
pub fn simd_decode(coefficients: &[u64], preset: BfvPreset) -> Result<Vec<u64>> {
    let parameters = BfvParamSet::from(preset);
    let degree = parameters.degree;
    let t = parameters.plaintext_modulus;

    if coefficients.len() != degree {
        return Err(anyhow!(
            "Expected {degree} plaintext coefficients, got {}",
            coefficients.len()
        ));
    }
    if let Some(index) = coefficients.iter().position(|c| *c >= t) {
        return Err(anyhow!(
            "Plaintext coefficient {index} is not below the plaintext modulus {t}"
        ));
    }

    let modulus =
        fhe_math::zq::Modulus::new(t).map_err(|e| anyhow!("Invalid plaintext modulus {t}: {e}"))?;
    let ntt = fhe_math::ntt::NttOperator::new(&modulus, degree).ok_or_else(|| {
        anyhow!("The plaintext modulus {t} does not support SIMD encoding at degree {degree}")
    })?;

    let mut values = coefficients.to_vec();
    ntt.forward(&mut values);

    // `matrix_reps_index_map` of fhe.rs: slot `i` reads NTT position `map[i]`.
    let row_size = degree >> 1;
    let m = degree << 1;
    let shift = degree.leading_zeros() + 1;
    let mut slots = vec![0u64; degree];
    let mut pos = 1usize;
    for i in 0..row_size {
        let index1 = (pos - 1) >> 1;
        let index2 = (m - pos - 1) >> 1;
        slots[i] = values[index1.reverse_bits() >> shift];
        slots[row_size | i] = values[index2.reverse_bits() >> shift];
        pos = (pos * 3) & (m - 1);
    }
    Ok(slots)
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
    // On the protocol CRS, as committee keys are: user-data encryption proofs need that `a`.
    use fhe::mbfv::{Aggregate as _, PublicKeyShare};
    let crp = e3_fhe_params::create_deterministic_crp_from_default_seed(&params);
    let pk = PublicKeyShare::new(&sk, crp, &mut rng)
        .and_then(|share| PublicKey::from_shares(vec![share]))
        .map_err(|e| anyhow!("Failed to build public key: {e}"))?;

    Ok(pk.to_bytes())
}

/// Open an l-BFV committee key's on-chain commitment down to its public-key rows.
///
/// A `user_data_encryption_chunked` proof commits only to row 0, the encryption key. A circuit that
/// recomputes the committee key commitment from it needs the other row commitments and the
/// relinearization-key commitment. Fails for a key that is not an l-BFV key envelope.
pub fn open_lbfv_key_envelope(
    public_key: &[u8],
    degree: usize,
    plaintext_modulus: u64,
    moduli: &[u64],
) -> Result<crate::LbfvKeyEnvelopeOpening> {
    ensure!(
        crate::is_lbfv_key_envelope(public_key),
        "The committee key is not an l-BFV key envelope"
    );
    let preset = key_preset(public_key, degree, plaintext_modulus, moduli)
        .ok_or_else(|| anyhow!("Unsupported BFV parameters for an l-BFV key envelope"))?;
    crate::open_lbfv_key_envelope(public_key, preset)
}

pub fn compute_pk_commitment(
    public_key: Vec<u8>,
    degree: usize,
    plaintext_modulus: u64,
    moduli: Vec<u64>,
) -> Result<[u8; 32]> {
    use e3_zk_witness::threshold::user_data_encryption::compute_public_key_commitment;

    if crate::is_lbfv_key_envelope(&public_key) {
        let preset = key_preset(&public_key, degree, plaintext_modulus, &moduli)
            .ok_or_else(|| anyhow!("Unsupported BFV parameters for an l-BFV key envelope"))?;
        return Ok(crate::inspect_lbfv_key_envelope(&public_key, preset)?
            .0
            .envelope);
    }
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
    use e3_zk_witness::threshold::user_data_encryption::compute_public_key_commitment;

    if crate::is_lbfv_key_envelope(public_key) {
        let preset = key_preset(&public_key, degree, plaintext_modulus, &moduli)
            .ok_or_else(|| anyhow!("Unsupported BFV parameters for an l-BFV key envelope"))?;
        crate::validate_lbfv_key_envelope(public_key, expected_commitment, preset)?;
        return Ok(());
    }
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
    use e3_zk_witness::threshold::user_data_encryption::compute_ciphertext_commitment;

    #[cfg(crisp_fhe_optimized)]
    if let Some(components) = Ciphertext::power_basis_from_bytes_if_canonical(ct, params)? {
        use e3_fhe_params::utils::compute_modulus_bit;
        use e3_zk_witness::commitments;
        if let Some(commitment) = commitments::compute_ciphertext_commitment_from_power_basis(
            &components[0],
            &components[1],
            params.moduli(),
            compute_modulus_bit(params),
        ) {
            let bytes = commitment.to_bytes_be().1;
            anyhow::ensure!(
                bytes.len() <= 32,
                "The ciphertext commitment exceeds 32 bytes"
            );
            let mut result = [0; 32];
            result[32 - bytes.len()..].copy_from_slice(&bytes);
            return Ok(result);
        }
    }

    let ct = Ciphertext::from_bytes(ct, params)
        .map_err(|e| anyhow!("Error deserializing ciphertext: {}", e))?;

    let commitment = compute_ciphertext_commitment(params, &ct)
        .map_err(|e| anyhow!("Error computing ciphertext commitment: {}", e))?;

    Ok(commitment)
}

#[cfg(test)]
mod tests {
    use crate::decode_plaintext_to_vec_u64;
    use e3_fhe_params::DEFAULT_BFV_PRESET;
    use e3_fhe_params::{build_bfv_params_from_set_arc, BfvParamSet};
    use e3_zk_samples::threshold::user_data_encryption::public_key_on_protocol_crs;
    use fhe_traits::FheDecoder;

    use super::*;

    #[test]
    fn witness_json_preserves_large_signed_integers_for_javascript() {
        let mut witness = serde_json::json!({
            "limbs": [9_007_199_254_740_991_i64, 9_007_199_254_740_992_i64,
                -9_007_199_254_740_992_i64],
        });
        stringify_unsafe_js_integers(&mut witness);
        assert_eq!(
            witness,
            serde_json::json!({"limbs": [9_007_199_254_740_991_i64,
                "9007199254740992", "-9007199254740992"]})
        );
    }

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

    /// The committee key's parameters select the proof path: a plain insecure-64 key gets the trBFV
    /// witness, an l-BFV key envelope of the degree-128 insecure preset gets the chunked witness.
    #[test]
    fn verifiable_encryption_witness_follows_the_key_format() -> Result<()> {
        let parameters = BfvParamSet::from(BfvPreset::InsecureThreshold64);
        let lbfv_parameters = BfvParamSet::from(BfvPreset::InsecureThresholdLbfv);
        let encrypt = |public_key: Vec<u8>, parameters: &BfvParamSet| -> Result<Value> {
            let result = bfv_verifiable_encrypt(
                [1_u64],
                public_key,
                parameters.degree,
                parameters.plaintext_modulus,
                parameters.moduli.to_vec(),
            )?;
            Ok(serde_json::from_str(&result.circuit_inputs)?)
        };

        let plain_key = generate_public_key(
            parameters.degree,
            parameters.plaintext_modulus,
            parameters.moduli.to_vec(),
        )?;
        let trbfv = encrypt(plain_key, &parameters)?;
        assert!(trbfv.get("r").is_some() && trbfv.get("r1is").is_none());

        let lbfv = encrypt(
            crate::lbfv_key_envelope::tests::envelope()?,
            &lbfv_parameters,
        )?;
        assert!(lbfv.get("r1is").is_some() && lbfv.get("r").is_none());
        Ok(())
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
        assert_eq!(normalized_bytes, expected_bytes);
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
        use fhe::bfv::{Ciphertext, SecretKey};
        use fhe_traits::{DeserializeParametrized, FheDecrypter, Serialize};

        let param_set: BfvParamSet = DEFAULT_BFV_PRESET.into();
        let params = build_bfv_params_from_set_arc(param_set);
        let degree = param_set.degree;
        let plaintext_modulus = param_set.plaintext_modulus;
        let moduli = param_set.moduli;
        let mut rng = rng();
        let sk = SecretKey::random(&params, &mut rng);
        let pk = public_key_on_protocol_crs(&params, &sk, &mut rng).unwrap();

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
        use fhe::bfv::{Ciphertext, SecretKey};
        use fhe_traits::{DeserializeParametrized, FheDecrypter, Serialize};

        let param_set: BfvParamSet = DEFAULT_BFV_PRESET.into();
        let params = build_bfv_params_from_set_arc(param_set);
        let degree = param_set.degree;
        let plaintext_modulus = param_set.plaintext_modulus;
        let moduli = param_set.moduli;
        let mut rng = rng();
        let sk = SecretKey::random(&params, &mut rng);
        let pk = public_key_on_protocol_crs(&params, &sk, &mut rng).unwrap();

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
        use fhe::bfv::{Ciphertext, SecretKey};
        use fhe_traits::{DeserializeParametrized, FheDecrypter, Serialize};

        let param_set: BfvParamSet = DEFAULT_BFV_PRESET.into();
        let params = build_bfv_params_from_set_arc(param_set);
        let degree = param_set.degree;
        let plaintext_modulus = param_set.plaintext_modulus;
        let moduli = param_set.moduli;
        let mut rng = rand::rng();
        let sk = SecretKey::random(&params, &mut rng);
        let pk = public_key_on_protocol_crs(&params, &sk, &mut rng).unwrap();

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
        use fhe::bfv::{Ciphertext, SecretKey};
        use fhe_traits::{DeserializeParametrized, FheDecrypter, Serialize};

        let param_set: BfvParamSet = DEFAULT_BFV_PRESET.into();
        let params = build_bfv_params_from_set_arc(param_set);
        let degree = param_set.degree;
        let plaintext_modulus = param_set.plaintext_modulus;
        let moduli = param_set.moduli;
        let mut rng = rand::rng();
        let sk = SecretKey::random(&params, &mut rng);
        let pk = public_key_on_protocol_crs(&params, &sk, &mut rng).unwrap();

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

    /// Slots as the SIMD preset's plaintext modulus allows: a full vector, so every slot matters.
    fn simd_slots(plaintext_modulus: u64, degree: usize) -> Vec<u64> {
        (0..degree as u64)
            .map(|i| (i * 31 + 5) % plaintext_modulus)
            .collect()
    }

    #[test]
    fn simd_encrypt_round_trips_the_slots_and_simd_decode_recovers_them() {
        use fhe_traits::FheDecrypter;

        let preset = BfvPreset::InsecureThresholdSimd;
        let param_set: BfvParamSet = preset.into();
        let params = build_bfv_params_from_set_arc(param_set);
        let mut rng = rng();
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);
        let slots = simd_slots(param_set.plaintext_modulus, param_set.degree);

        let encrypted = bfv_encrypt_with_encoding(
            slots.clone(),
            pk.to_bytes(),
            param_set.degree,
            param_set.plaintext_modulus,
            param_set.moduli,
            Encoding::simd(),
        )
        .unwrap();
        let pt = sk
            .try_decrypt(&Ciphertext::from_bytes(&encrypted, &params).unwrap())
            .unwrap();

        assert_eq!(
            Vec::<u64>::try_decode(&pt, Encoding::simd()).unwrap(),
            slots
        );
        // The published plaintext is the poly basis; `simd_decode` maps it back to the slots.
        let coefficients = decode_plaintext_to_vec_u64(&pt).unwrap();
        assert_ne!(coefficients, slots);
        assert_eq!(simd_decode(&coefficients, preset).unwrap(), slots);

        // A poly encoding of the same values stays the default and decodes as the poly.
        let poly = bfv_encrypt(
            slots.clone(),
            pk.to_bytes(),
            param_set.degree,
            param_set.plaintext_modulus,
            param_set.moduli,
        )
        .unwrap();
        let pt = sk
            .try_decrypt(&Ciphertext::from_bytes(&poly, &params).unwrap())
            .unwrap();
        assert_eq!(decode_plaintext_to_vec_u64(&pt).unwrap(), slots);
    }

    #[test]
    fn simd_decode_rejects_bad_input() {
        let preset = BfvPreset::InsecureThresholdSimd;
        let parameters: BfvParamSet = preset.into();
        let zeros = vec![0u64; parameters.degree];

        // No SIMD slots at t = 100.
        let no_slots: BfvParamSet = BfvPreset::InsecureThresholdLbfv.into();
        assert!(simd_decode(
            &vec![0u64; no_slots.degree],
            BfvPreset::InsecureThresholdLbfv
        )
        .is_err());
        // The length must be the degree.
        assert!(simd_decode(&zeros[1..], preset).is_err());
        assert!(simd_decode(&[zeros.clone(), vec![0]].concat(), preset).is_err());
        // Every coefficient must be below t.
        let mut too_large = zeros.clone();
        too_large[5] = parameters.plaintext_modulus;
        assert!(simd_decode(&too_large, preset).is_err());
        assert!(simd_decode(&zeros, preset).is_ok());
    }

    #[test]
    fn verifiable_simd_encryption_produces_a_chunked_witness_for_the_slots() {
        use fhe_traits::FheDecrypter;

        let preset = BfvPreset::InsecureThresholdSimd;
        let param_set: BfvParamSet = preset.into();
        let params = build_bfv_params_from_set_arc(param_set);
        let mut rng = rng();
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);
        let slots = simd_slots(param_set.plaintext_modulus, param_set.degree);

        let result = bfv_verifiable_encrypt_with_encoding(
            slots.clone(),
            pk.to_bytes(),
            param_set.degree,
            param_set.plaintext_modulus,
            param_set.moduli.to_vec(),
            Encoding::simd(),
        )
        .unwrap();

        let witness: Value = serde_json::from_str(&result.circuit_inputs).unwrap();
        assert!(witness.get("r1is").is_some() && witness.get("r").is_none());
        let pt = sk
            .try_decrypt(&Ciphertext::from_bytes(&result.encrypted_data, &params).unwrap())
            .unwrap();
        assert_eq!(
            Vec::<u64>::try_decode(&pt, Encoding::simd()).unwrap(),
            slots
        );
    }
}
