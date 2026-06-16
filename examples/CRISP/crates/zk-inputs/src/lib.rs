// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Core CRISP ZK inputs generation library.
//!
//! This crate contains the main logic for generating CRISP inputs for zero-knowledge proofs.

use crate::ciphertext_addition::CiphertextAdditionWitness;
use e3_fhe_params::build_bfv_params_arc;
use e3_fhe_params::default_param_set;
use e3_fhe_params::BfvParamSet;
use e3_fhe_params::DEFAULT_BFV_PRESET;
use e3_zk_helpers::circuits::threshold::user_data_encryption::circuit::UserDataEncryptionCircuit;
use e3_zk_helpers::circuits::threshold::user_data_encryption::circuit::UserDataEncryptionCircuitData;
use e3_zk_helpers::CircuitComputation;
use e3_zk_helpers::Computation;
use eyre::{Context, Result};
use fhe::bfv::BfvParameters;
use fhe::bfv::Ciphertext;
use fhe::bfv::PublicKey;
use fhe::bfv::SecretKey;
use fhe::bfv::{Encoding, Plaintext};
use fhe_traits::FheDecoder;
use fhe_traits::FheDecrypter;
use fhe_traits::{DeserializeParametrized, FheEncoder, Serialize};
use num_bigint::BigInt;
use num_traits::Zero;
use rand::rng;
use std::sync::Arc;
mod ciphertext_addition;
mod utils;

pub struct ZKInputsGenerator {
    bfv_params: Arc<BfvParameters>,
}

impl ZKInputsGenerator {
    /// Creates a new generator with the specified BFV parameters.
    pub fn new(
        degree: usize,
        plaintext_modulus: u64,
        moduli: &[u64],
        error1_variance: Option<&str>,
    ) -> Self {
        let bfv_params = build_bfv_params_arc(degree, plaintext_modulus, moduli, error1_variance);
        Self { bfv_params }
    }

    /// Creates a new generator with the specified BFV parameter set.
    pub fn from_set(set: BfvParamSet) -> Self {
        let bfv_params = set.build_arc();

        Self { bfv_params }
    }

    /// Creates a generator with default BFV parameters for testing purposes.
    ///
    /// # Notes
    /// - This is for testing purposes only.
    /// - The default parameters are not suitable for production.
    /// # Returns
    /// A new ZKInputsGenerator instance with default BFV parameters
    pub fn with_defaults() -> Self {
        Self::from_set(default_param_set())
    }

    /// Generates CRISP ZK inputs for a vote encryption and addition operation.
    /// Note that this accepts the previous ciphertext in GRECO ABI encoded format.
    ///
    /// # Arguments
    /// * `prev_ciphertext` - Previous ciphertext bytes to add to (in GRECO ABI Encoded format)
    /// * `public_key` - Public key bytes for encryption
    /// * `vote` - Vote value as a vector of coefficients
    ///
    /// # Returns
    /// Tuple containing the sum ciphertext bytes and JSON string with CRISP ZK inputs
    pub fn generate_inputs_for_update(
        &self,
        prev_ciphertext: &[u8],
        public_key: &[u8],
        vote: Vec<u64>,
    ) -> Result<(Vec<u8>, String)> {
        // Deserialize the provided public key.
        let pk = PublicKey::from_bytes(public_key, &self.bfv_params)
            .with_context(|| "Failed to deserialize public key")?;

        // Encode the plaintext into a polynomial.
        let pt = Plaintext::try_encode(&vote, Encoding::poly(), &self.bfv_params)
            .with_context(|| "Failed to encode plaintext")?;

        let user_data_encryption_computation_output = UserDataEncryptionCircuit::compute(
            DEFAULT_BFV_PRESET,
            &UserDataEncryptionCircuitData {
                public_key: pk,
                plaintext: pt,
            },
        )?;

        let ct = Ciphertext::from_bytes(
            &user_data_encryption_computation_output.inputs.ciphertext,
            &self.bfv_params,
        )
        .with_context(|| "Failed to deserialize ciphertext")?;

        // Ciphertext Addition Section.
        // Deserialize the previous ciphertext.
        let prev_ct = Ciphertext::from_bytes(prev_ciphertext, &self.bfv_params)
            .with_context(|| "Failed to deserialize previous ciphertext")?;

        // Compute the ciphertext addition.
        let sum_ct = &ct + &prev_ct;

        // Compute the inputs of the ciphertext addition.
        let ciphertext_addition_inputs =
            CiphertextAdditionWitness::compute(&self.bfv_params, &prev_ct, &ct, &sum_ct)
                .with_context(|| "Failed to compute ciphertext addition inputs")?;

        let ciphertext_addition_witness_json = ciphertext_addition_inputs.to_json()?;
        let user_data_encryption_witness_json =
            user_data_encryption_computation_output.inputs.to_json()?;
        let inputs_json = utils::merge_json_objects(
            ciphertext_addition_witness_json,
            user_data_encryption_witness_json,
        )?;

        // For updates, return the sum ciphertext (ct + prev_ct)
        let ciphertext_bytes = sum_ct.to_bytes();

        Ok((ciphertext_bytes, inputs_json))
    }

    /// Generates CRISP ZK inputs for a vote encryption and addition operation.
    ///
    /// # Arguments
    /// * `prev_ciphertext` - Previous ciphertext bytes to add to
    /// * `public_key` - Public key bytes for encryption
    /// * `vote` - Vote value as a vector of coefficients
    ///
    /// # Returns
    /// Tuple containing the vote ciphertext bytes and JSON string with CRISP ZK inputs
    pub fn generate_inputs(
        &self,
        prev_ciphertext: &[u8],
        public_key: &[u8],
        vote: Vec<u64>,
    ) -> Result<(Vec<u8>, String)> {
        // Deserialize the provided public key.
        let pk = PublicKey::from_bytes(public_key, &self.bfv_params)
            .with_context(|| "Failed to deserialize public key")?;

        // Encode the plaintext into a polynomial.
        let pt = Plaintext::try_encode(&vote, Encoding::poly(), &self.bfv_params)
            .with_context(|| "Failed to encode plaintext")?;

        let user_data_encryption_computation_output = UserDataEncryptionCircuit::compute(
            DEFAULT_BFV_PRESET,
            &UserDataEncryptionCircuitData {
                public_key: pk,
                plaintext: pt,
            },
        )?;

        let ct = Ciphertext::from_bytes(
            &user_data_encryption_computation_output.inputs.ciphertext,
            &self.bfv_params,
        )
        .with_context(|| "Failed to deserialize ciphertext")?;

        // Ciphertext Addition Section.
        // Deserialize the previous ciphertext.
        let prev_ct = Ciphertext::from_bytes(prev_ciphertext, &self.bfv_params)
            .with_context(|| "Failed to deserialize previous ciphertext")?;

        // Compute the ciphertext addition.
        let sum_ct = &ct + &prev_ct;

        // Compute the inputs of the ciphertext addition.
        let mut ciphertext_addition_inputs =
            CiphertextAdditionWitness::compute(&self.bfv_params, &prev_ct, &ct, &sum_ct)
                .with_context(|| "Failed to compute ciphertext addition inputs")?;

        // IMPORTANT: First-in-slot votes have no previous ciphertext; set prev_ct_commitment to 0
        // so the on-chain verifier accepts the proof.
        ciphertext_addition_inputs.prev_ct_commitment = BigInt::zero();

        let ciphertext_addition_witness_json = ciphertext_addition_inputs.to_json()?;
        let user_data_encryption_witness_json =
            user_data_encryption_computation_output.inputs.to_json()?;
        let inputs_json = utils::merge_json_objects(
            ciphertext_addition_witness_json,
            user_data_encryption_witness_json,
        )?;

        let ciphertext_bytes = ct.to_bytes();

        Ok((ciphertext_bytes, inputs_json))
    }

    /// Encrypts a vote using the provided public key.
    ///
    /// # Arguments
    /// * `public_key` - Public key bytes for encryption
    /// * `vote` - Vote data as a vector of coefficients
    ///
    /// # Returns
    /// Ciphertext bytes
    pub fn encrypt_vote(&self, public_key: &[u8], vote: Vec<u64>) -> Result<Vec<u8>> {
        let pk = PublicKey::from_bytes(public_key, &self.bfv_params)
            .with_context(|| "Failed to deserialize public key")?;

        let pt = Plaintext::try_encode(&vote, Encoding::poly(), &self.bfv_params)
            .with_context(|| "Failed to encode plaintext")?;

        let (ct, _u_rns, _e0_rns, _e1_rns) = pk
            .try_encrypt_extended(&pt, &mut rng())
            .with_context(|| "Failed to encrypt plaintext")?;

        Ok(ct.to_bytes())
    }

    /// Decrypts a vote using the provided secret key.
    ///
    /// # Arguments
    /// * `secret_key` - Secret key bytes for decryption
    /// * `ciphertext` - Ciphertext bytes to decrypt
    ///
    /// # Returns
    /// Vote value as a vector of coefficients
    pub fn decrypt_vote(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u64>> {
        let ct = Ciphertext::from_bytes(ciphertext, &self.bfv_params)
            .with_context(|| "Failed to deserialize ciphertext")?;

        // Deserialize secret key from bytes (coefficients serialized with bincode)
        let coeffs: Vec<i64> = bincode::deserialize(secret_key)
            .with_context(|| "Failed to deserialize secret key coefficients")?;
        let sk = SecretKey::new(coeffs, &self.bfv_params);

        let pt = sk
            .try_decrypt(&ct)
            .with_context(|| "Failed to decrypt ciphertext")?;
        let vote = Vec::<u64>::try_decode(&pt, Encoding::poly())
            .with_context(|| "Failed to decode plaintext")?;

        Ok(vote)
    }

    /// Generates a new public/secret key pair and returns the secret key and public key bytes.
    ///
    /// # Returns
    /// Tuple containing the secret key bytes and public key bytes
    pub fn generate_keys(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        // Generate keys.
        let mut rng = rng();
        let sk = SecretKey::random(&self.bfv_params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);

        // Serialize secret key coefficients with bincode
        let sk_bytes =
            bincode::serialize(&sk.coeffs).with_context(|| "Failed to serialize secret key")?;

        Ok((sk_bytes, pk.to_bytes()))
    }

    /// Returns a clone of the BFV parameters used by this generator.
    pub fn get_bfv_params(&self) -> Arc<BfvParameters> {
        self.bfv_params.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_fhe_params::constants::insecure_512;
    use e3_fhe_params::{BfvParamSet, BfvPreset};

    /// Helper function to create a vote vector with alternating 0s and 1s (deterministic)
    fn create_vote_vector() -> Vec<u64> {
        (0..insecure_512::DEGREE).map(|i| (i % 2) as u64).collect()
    }

    #[test]
    fn test_inputs_generation_with_defaults() {
        let generator = ZKInputsGenerator::with_defaults();
        let (_secret_key, public_key) = generator.generate_keys().expect("failed to generate keys");
        let vote = create_vote_vector();
        let prev_ciphertext = generator
            .encrypt_vote(&public_key, vote.clone())
            .expect("failed to generate previous ciphertext");
        let result = generator.generate_inputs(&prev_ciphertext, &public_key, vote.clone());

        assert!(result.is_ok());
        let (ciphertext_bytes, json_output) = result.unwrap();
        // Verify ciphertext is not empty
        assert!(!ciphertext_bytes.is_empty());
        // Verify it's valid JSON and contains expected fields from both witnesses.
        assert!(json_output.contains("pk0is"));
        assert!(json_output.contains("prev_ct0is"));
        assert!(json_output.contains("sum_ct0is"));
    }

    #[test]
    fn test_inputs_generation_with_custom_params() {
        let generator =
            ZKInputsGenerator::from_set(BfvParamSet::from(BfvPreset::InsecureThreshold512));
        let (_secret_key, public_key) = generator.generate_keys().expect("failed to generate keys");
        let vote = create_vote_vector();
        let prev_ciphertext = generator
            .encrypt_vote(&public_key, vote.clone())
            .expect("failed to generate previous ciphertext");
        let result = generator.generate_inputs(&prev_ciphertext, &public_key, vote.clone());

        assert!(result.is_ok());
        let (ciphertext_bytes, json_output) = result.unwrap();
        // Verify ciphertext is not empty
        assert!(!ciphertext_bytes.is_empty());
        // Verify it's valid JSON and contains expected fields from both witnesses.
        assert!(json_output.contains("pk0is"));
        assert!(json_output.contains("prev_ct0is"));
        assert!(json_output.contains("sum_ct0is"));
    }

    #[test]
    fn test_inputs_generation_with_vote_0() {
        let generator = ZKInputsGenerator::with_defaults();
        let (_secret_key, public_key) = generator.generate_keys().expect("failed to generate keys");
        let vote = create_vote_vector();
        let prev_ciphertext = generator
            .encrypt_vote(&public_key, vote.clone())
            .expect("failed to generate previous ciphertext");
        let result = generator.generate_inputs(&prev_ciphertext, &public_key, vote.clone());

        assert!(result.is_ok());
        let (ciphertext_bytes, json_output) = result.unwrap();
        // Verify ciphertext is not empty
        assert!(!ciphertext_bytes.is_empty());
        // Verify it's valid JSON and contains expected fields from both witnesses.
        assert!(json_output.contains("pk0is"));
        assert!(json_output.contains("prev_ct0is"));
        assert!(json_output.contains("sum_ct0is"));
    }

    #[test]
    fn test_get_bfv_params() {
        let generator =
            ZKInputsGenerator::from_set(BfvParamSet::from(BfvPreset::InsecureThreshold512));
        let bfv_params = generator.get_bfv_params();

        assert!(bfv_params.degree() == insecure_512::DEGREE);
        assert!(bfv_params.plaintext() == insecure_512::threshold::PLAINTEXT_MODULUS);
        assert!(bfv_params.moduli() == insecure_512::threshold::MODULI);
    }

    #[test]
    fn test_secure_rng_usage() {
        let generator = ZKInputsGenerator::with_defaults();

        // Test that functions use secure randomness (no deterministic seed).
        let (secret_key, public_key) = generator.generate_keys().expect("failed to generate keys");
        assert!(!public_key.is_empty());
        assert!(!secret_key.is_empty());
        let vote = create_vote_vector();

        let ciphertext = generator
            .encrypt_vote(&public_key, vote.clone())
            .expect("failed to encrypt vote");
        assert!(!ciphertext.is_empty());

        let result = generator.generate_inputs(&ciphertext, &public_key, vote.clone());
        assert!(result.is_ok());
        let (ciphertext_bytes, json_output) = result.unwrap();
        assert!(!ciphertext_bytes.is_empty());
        assert!(json_output.contains("pk0is"));
        assert!(json_output.contains("prev_ct0is"));
        assert!(json_output.contains("sum_ct0is"));
    }

    // Error handling tests
    #[test]
    fn test_invalid_inputs() {
        let generator = ZKInputsGenerator::with_defaults();
        let vote = create_vote_vector();

        // Test invalid byte inputs.
        let result = generator.generate_inputs(&[1, 2, 3], &[4, 5, 6], vote.clone());
        assert!(result.is_err());

        // Test empty slices.
        let result = generator.generate_inputs(&[], &[], vote.clone());
        assert!(result.is_err());

        // Test invalid public key for encryption.
        let result = generator.encrypt_vote(&[1, 2, 3], vote.clone());
        assert!(result.is_err());
    }

    // Core functionality tests
    #[test]
    fn test_vote_values() {
        let generator = ZKInputsGenerator::with_defaults();
        let (_secret_key, public_key) = generator.generate_keys().expect("failed to generate keys");
        let vote = create_vote_vector();
        let prev_ciphertext = generator
            .encrypt_vote(&public_key, vote.clone())
            .expect("failed to encrypt vote");

        // Test vote = 0.
        let result_0 = generator.generate_inputs(&prev_ciphertext, &public_key, vote.clone());
        assert!(result_0.is_ok());
        let (_, _) = result_0.unwrap();

        // Test vote = 1.
        let result_1 = generator.generate_inputs(&prev_ciphertext, &public_key, vote.clone());
        assert!(result_1.is_ok());
        let (_, _) = result_1.unwrap();
    }

    #[test]
    fn test_json_output_structure() {
        let generator = ZKInputsGenerator::with_defaults();
        let (_secret_key, public_key) = generator.generate_keys().expect("failed to generate keys");
        let vote = create_vote_vector();
        let prev_ciphertext = generator
            .encrypt_vote(&public_key, vote.clone())
            .expect("failed to encrypt vote");
        let result = generator.generate_inputs(&prev_ciphertext, &public_key, vote.clone());

        assert!(result.is_ok());
        let (ciphertext_bytes, json_output) = result.unwrap();
        assert!(!ciphertext_bytes.is_empty());

        // Parse JSON to verify structure.
        let parsed: serde_json::Value =
            serde_json::from_str(&json_output).expect("Invalid JSON output");

        // Check required top-level fields (ciphertext addition + user data encryption witnesses).
        assert!(parsed.get("prev_ct0is").is_some());
        assert!(parsed.get("prev_ct1is").is_some());
        assert!(parsed.get("sum_ct0is").is_some());
        assert!(parsed.get("sum_ct1is").is_some());
        assert!(parsed.get("sum_r0is").is_some());
        assert!(parsed.get("sum_r1is").is_some());
        assert!(parsed.get("ct0is").is_some());
        assert!(parsed.get("ct1is").is_some());
        assert!(parsed.get("pk0is").is_some());
        assert!(parsed.get("pk1is").is_some());
    }

    #[test]
    fn test_cryptographic_properties() {
        let generator = ZKInputsGenerator::with_defaults();
        let (_secret_key, public_key) = generator.generate_keys().expect("Failed to generate keys");
        let vote = create_vote_vector();

        // Test that different votes produce different ciphertexts.
        let ct0 = generator
            .encrypt_vote(&public_key, vote.clone())
            .expect("Failed to encrypt vote 0");
        let ct1 = generator
            .encrypt_vote(&public_key, vote.clone())
            .expect("Failed to encrypt vote 1");

        assert_ne!(ct0, ct1);

        // Test that same vote produces different ciphertexts (due to randomness).
        let ct0_2 = generator
            .encrypt_vote(&public_key, create_vote_vector())
            .expect("Failed to encrypt vote 0 again");
        assert_ne!(ct0, ct0_2);

        // Test that all ciphertexts are non-empty.
        assert!(!ct0.is_empty());
        assert!(!ct1.is_empty());
        assert!(!ct0_2.is_empty());
    }

    #[test]
    fn test_decrypt_vote() {
        let generator = ZKInputsGenerator::with_defaults();
        let (secret_key, public_key) = generator.generate_keys().expect("failed to generate keys");
        let vote = create_vote_vector();

        // Encrypt the vote
        let ciphertext = generator
            .encrypt_vote(&public_key, vote.clone())
            .expect("failed to encrypt vote");
        assert!(!ciphertext.is_empty());

        // Decrypt the vote
        let decrypted_vote = generator
            .decrypt_vote(&secret_key, &ciphertext)
            .expect("failed to decrypt vote");

        // Verify the decrypted vote matches the original
        assert_eq!(decrypted_vote, vote);
    }

    #[test]
    fn test_decrypt_vote_roundtrip() {
        let generator = ZKInputsGenerator::with_defaults();
        let (secret_key, public_key) = generator.generate_keys().expect("failed to generate keys");

        // Test with different vote patterns
        let test_votes = vec![
            vec![0u64; insecure_512::DEGREE], // All zeros
            vec![1u64; insecure_512::DEGREE], // All ones
            create_vote_vector(),             // Alternating pattern
        ];

        for vote in test_votes {
            // Encrypt
            let ciphertext = generator
                .encrypt_vote(&public_key, vote.clone())
                .expect("failed to encrypt vote");

            // Decrypt
            let decrypted = generator
                .decrypt_vote(&secret_key, &ciphertext)
                .expect("failed to decrypt vote");

            // Verify roundtrip
            assert_eq!(decrypted, vote, "Decrypted vote should match original");
        }
    }

    #[test]
    fn test_decrypt_vote_wrong_key() {
        let generator = ZKInputsGenerator::with_defaults();
        let (_secret_key1, public_key1) =
            generator.generate_keys().expect("failed to generate keys");
        let (_secret_key2, _public_key2) =
            generator.generate_keys().expect("failed to generate keys");
        let vote = create_vote_vector();

        // Encrypt with first key pair
        let ciphertext = generator
            .encrypt_vote(&public_key1, vote.clone())
            .expect("failed to encrypt vote");

        // Try to decrypt with wrong secret key (should fail or produce garbage)
        let result = generator.decrypt_vote(&_secret_key2, &ciphertext);
        // Decryption might succeed but produce incorrect results, or it might fail
        // This test verifies the function doesn't panic
        if let Ok(decrypted) = result {
            // If decryption succeeds, the result should be different from original
            assert_ne!(
                decrypted, vote,
                "Decryption with wrong key should produce different result"
            );
        }
    }

    #[test]
    fn test_decrypt_vote_invalid_inputs() {
        let generator = ZKInputsGenerator::with_defaults();
        let (_secret_key, _public_key) =
            generator.generate_keys().expect("failed to generate keys");

        // Test invalid secret key bytes
        let result = generator.decrypt_vote(&[1, 2, 3], &[4, 5, 6]);
        assert!(result.is_err(), "Should fail with invalid secret key");

        // Test invalid ciphertext bytes
        let valid_sk_bytes = bincode::serialize(&vec![0i64; insecure_512::DEGREE]).unwrap();
        let result = generator.decrypt_vote(&valid_sk_bytes, &[1, 2, 3]);
        assert!(result.is_err(), "Should fail with invalid ciphertext");

        // Test empty inputs
        let result = generator.decrypt_vote(&[], &[]);
        assert!(result.is_err(), "Should fail with empty inputs");
    }
}
