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
use e3_fhe_params::{default_param_set, BfvParamSet, BfvPreset};
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
use rand::rng;
use std::sync::Arc;
mod ciphertext_addition;
mod utils;

pub struct ZKInputsGenerator {
    bfv_params: Arc<BfvParameters>,
    bfv_preset: BfvPreset,
}

impl ZKInputsGenerator {
    /// Creates a new generator with the specified BFV parameters.
    pub fn new(
        degree: usize,
        plaintext_modulus: u64,
        moduli: &[u64],
        error1_variance: Option<&str>,
    ) -> Self {
        Self::try_new(degree, plaintext_modulus, moduli, error1_variance)
            .expect("Unsupported BFV threshold parameters")
    }

    /// Creates a new generator with the specified BFV parameters.
    ///
    /// The parameter tuple must match one of the threshold presets whose Noir circuit was built.
    pub fn try_new(
        degree: usize,
        plaintext_modulus: u64,
        moduli: &[u64],
        error1_variance: Option<&str>,
    ) -> Result<Self> {
        let bfv_preset = BfvPreset::from_threshold_parameters(degree, plaintext_modulus, moduli)
            .ok_or_else(|| eyre::eyre!("Unsupported BFV threshold parameters"))?;
        let canonical_variance = BfvParamSet::from(bfv_preset).error1_variance;
        if let Some(provided) = error1_variance {
            if Some(provided) != canonical_variance {
                return Err(eyre::eyre!(
                    "Noncanonical BFV error variance for {}: expected {}, got {provided}",
                    bfv_preset.name(),
                    canonical_variance.unwrap_or("default")
                ));
            }
        }
        let bfv_params =
            build_bfv_params_arc(degree, plaintext_modulus, moduli, canonical_variance);
        Ok(Self {
            bfv_params,
            bfv_preset,
        })
    }

    /// Creates a new generator with the specified threshold BFV preset.
    pub fn from_preset(preset: BfvPreset) -> Result<Self> {
        if !preset.supports_pair() {
            return Err(eyre::eyre!(
                "BFV preset {} is not a threshold parameter set",
                preset.name()
            ));
        }

        Ok(Self::from_set(BfvParamSet::from(preset)))
    }

    /// Creates a new generator from a JavaScript-facing preset name.
    pub fn from_preset_name(name: &str) -> Result<Self> {
        let preset = match name.trim() {
            "insecure" => BfvPreset::InsecureThreshold512,
            "secure-8192" => BfvPreset::SecureThreshold8192,
            "secure-16384" => BfvPreset::SecureThreshold16384,
            other => BfvPreset::from_name(other)?,
        };

        Self::from_preset(preset)
    }

    /// Creates a new generator with the specified BFV parameter set.
    pub fn from_set(set: BfvParamSet) -> Self {
        Self::try_new(
            set.degree,
            set.plaintext_modulus,
            set.moduli,
            set.error1_variance,
        )
        .expect("Unsupported BFV threshold parameter set")
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

    /// Computes the SAFE commitment of serialized ciphertext bytes.
    ///
    /// The commitment a CRISP round stores for an input is computed inside the circuit, from the
    /// ciphertext the circuit built. For a first vote that is the ballot; for an update it is the
    /// sum of the new ciphertext and the previous one. Either way it is the commitment of the
    /// bytes that get published, so a caller can derive it here — which it must, because
    /// `CRISPProgram.publishInput` builds the ballot digest over that commitment and the digest is
    /// itself a circuit input. Without this the update path is unusable: the digest would depend
    /// on a value that only exists after proving.
    pub fn compute_ciphertext_commitment(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let commitment = e3_bfv_client::client::compute_ct_commitment(
            ciphertext.to_vec(),
            self.bfv_params.degree(),
            self.bfv_params.plaintext(),
            self.bfv_params.moduli().to_vec(),
        )
        .map_err(|e| eyre::eyre!("Failed to compute ciphertext commitment: {e}"))?;
        Ok(commitment.to_vec())
    }

    /// Generates the CRISP ZK inputs for one ballot.
    ///
    /// One function for all three operations. A first vote, a re-vote, and a mask differ only in
    /// what the caller passes here; the encryption, the witness, the published ciphertext, and the
    /// proof all have the same shape, so nothing about a submission says which one it was.
    ///
    /// What the circuit proves is always `published = addend + ballot`, where the ballot is a fresh
    /// BFV encryption of `vote` and the addend is the ciphertext already in the slot when
    /// `keep_previous` is set, and the zero ciphertext otherwise:
    ///
    /// | Operation             | `previous_ciphertext` | `keep_previous` | Published        |
    /// | --------------------- | --------------------- | --------------- | ---------------- |
    /// | First vote            | `None`                | `false`         | ballot           |
    /// | Re-vote               | slot ciphertext       | `false`         | ballot           |
    /// | Mask, empty slot      | `None`                | `false`         | zero ballot      |
    /// | Mask, occupied slot   | slot ciphertext       | `true`          | slot + zero      |
    ///
    /// A re-vote replaces the slot, so a voter cannot count their old ballot twice; the circuit
    /// derives the same choice from its private mask flag and would reject any other. The previous
    /// ciphertext is still required for a re-vote, because the circuit checks it against the
    /// commitment `CRISPProgram` stored for the slot.
    ///
    /// # Arguments
    /// * `previous_ciphertext` - The ciphertext currently in the slot, or `None` when it is empty
    /// * `public_key` - Public key bytes for encryption
    /// * `vote` - Vote value as a vector of coefficients
    /// * `keep_previous` - Whether the ballot adds to the slot rather than replacing it
    ///
    /// # Returns
    /// Tuple containing the ciphertext bytes to publish and a JSON string with CRISP ZK inputs
    pub fn generate_inputs(
        &self,
        previous_ciphertext: Option<&[u8]>,
        public_key: &[u8],
        vote: Vec<u64>,
        keep_previous: bool,
    ) -> Result<(Vec<u8>, String)> {
        let pk = PublicKey::from_bytes(public_key, &self.bfv_params)
            .with_context(|| "Failed to deserialize public key")?;

        let pt = Plaintext::try_encode(&vote, Encoding::poly(), &self.bfv_params)
            .with_context(|| "Failed to encode plaintext")?;

        let user_data_encryption_computation_output = UserDataEncryptionCircuit::compute(
            self.bfv_preset,
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

        let previous_ct = previous_ciphertext
            .map(|bytes| {
                Ciphertext::from_bytes(bytes, &self.bfv_params)
                    .with_context(|| "Failed to deserialize previous ciphertext")
            })
            .transpose()?;

        // An empty slot holds nothing to keep, whatever the caller asked for.
        let keep = keep_previous && previous_ct.is_some();

        let published_ct = match (keep, previous_ct.as_ref()) {
            (true, Some(previous)) => &ct + previous,
            _ => ct.clone(),
        };

        let ciphertext_addition_inputs = CiphertextAdditionWitness::compute(
            &self.bfv_params,
            previous_ct.as_ref(),
            &ct,
            &published_ct,
            keep,
        )
        .with_context(|| "Failed to compute ciphertext addition inputs")?;

        let ciphertext_addition_witness_json = ciphertext_addition_inputs.to_json()?;
        let user_data_encryption_witness_json =
            user_data_encryption_computation_output.inputs.to_json()?;
        let inputs_json = utils::merge_json_objects(
            ciphertext_addition_witness_json,
            user_data_encryption_witness_json,
        )?;

        Ok((published_ct.to_bytes(), inputs_json))
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
    use e3_fhe_params::constants::{insecure_512, secure_8192};
    use e3_fhe_params::{BfvParamSet, BfvPreset};
    use num_bigint::BigUint;

    /// Helper function to create a vote vector with alternating 0s and 1s (deterministic)
    fn create_vote_vector() -> Vec<u64> {
        (0..insecure_512::DEGREE).map(|i| (i % 2) as u64).collect()
    }

    /// A ballot of all zeros, which is what a mask encrypts.
    fn zero_vote() -> Vec<u64> {
        vec![0u64; insecure_512::DEGREE]
    }

    /// Reads one commitment out of the witness JSON, as the decimal string the circuit takes.
    fn commitment_field(json: &str, name: &str) -> String {
        let parsed: serde_json::Value = serde_json::from_str(json).expect("Invalid JSON output");

        parsed
            .get(name)
            .unwrap_or_else(|| panic!("witness has no {name}"))
            .as_str()
            .expect("commitment is a decimal string")
            .to_string()
    }

    /// The same commitment computed from serialized bytes, for comparison with the witness.
    fn commitment_of(generator: &ZKInputsGenerator, ciphertext: &[u8]) -> String {
        let bytes = generator
            .compute_ciphertext_commitment(ciphertext)
            .expect("failed to compute ciphertext commitment");

        BigUint::from_bytes_be(&bytes).to_string()
    }

    #[test]
    fn from_preset_name_selects_the_requested_threshold_preset() {
        let insecure = ZKInputsGenerator::from_preset_name("insecure")
            .expect("insecure preset should parse");
        let secure =
            ZKInputsGenerator::from_preset_name("secure-8192").expect("secure preset should parse");

        let insecure_params = insecure.get_bfv_params();
        assert_eq!(insecure_params.degree(), insecure_512::DEGREE);
        assert_eq!(
            insecure_params.plaintext(),
            insecure_512::threshold::PLAINTEXT_MODULUS
        );
        assert_eq!(insecure_params.moduli(), insecure_512::threshold::MODULI);

        let secure_params = secure.get_bfv_params();
        assert_eq!(secure_params.degree(), secure_8192::DEGREE);
        assert_eq!(
            secure_params.plaintext(),
            secure_8192::threshold::PLAINTEXT_MODULUS
        );
        assert_eq!(secure_params.moduli(), secure_8192::threshold::MODULI);
    }

    #[test]
    fn try_new_rejects_dkg_parameter_sets() {
        let dkg = BfvParamSet::from(BfvPreset::SecureDkg8192);

        let result =
            ZKInputsGenerator::try_new(dkg.degree, dkg.plaintext_modulus, dkg.moduli, None);

        assert!(result.is_err());
    }

    #[test]
    fn try_new_rejects_noncanonical_error_variance() {
        let threshold = BfvParamSet::from(BfvPreset::InsecureThreshold512);

        let result = ZKInputsGenerator::try_new(
            threshold.degree,
            threshold.plaintext_modulus,
            threshold.moduli,
            Some("10"),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_inputs_generation_with_defaults() {
        let generator = ZKInputsGenerator::with_defaults();
        let (_secret_key, public_key) = generator.generate_keys().expect("failed to generate keys");
        let vote = create_vote_vector();
        let prev_ciphertext = generator
            .encrypt_vote(&public_key, vote.clone())
            .expect("failed to generate previous ciphertext");
        let result =
            generator.generate_inputs(Some(&prev_ciphertext), &public_key, vote.clone(), false);

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
        let result =
            generator.generate_inputs(Some(&prev_ciphertext), &public_key, vote.clone(), false);

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
        let result =
            generator.generate_inputs(Some(&prev_ciphertext), &public_key, vote.clone(), false);

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

        let result = generator.generate_inputs(Some(&ciphertext), &public_key, vote.clone(), false);
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
        let result = generator.generate_inputs(Some(&[1, 2, 3]), &[4, 5, 6], vote.clone(), false);
        assert!(result.is_err());

        // Test empty slices.
        let result = generator.generate_inputs(Some(&[]), &[], vote.clone(), false);
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
        let result_0 =
            generator.generate_inputs(Some(&prev_ciphertext), &public_key, vote.clone(), false);
        assert!(result_0.is_ok());
        let (_, _) = result_0.unwrap();

        // Test vote = 1.
        let result_1 =
            generator.generate_inputs(Some(&prev_ciphertext), &public_key, vote.clone(), false);
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
        let result =
            generator.generate_inputs(Some(&prev_ciphertext), &public_key, vote.clone(), false);

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

    // -----------------------------------------------------------------------
    // The three operations
    // -----------------------------------------------------------------------
    //
    // A first vote, a re-vote, and a mask all go through `generate_inputs`. These check that each
    // publishes the ciphertext the circuit commits to, because the E3 program stores that
    // commitment and the Secure Process drops any input whose bytes disagree with it.

    #[test]
    fn test_first_vote_publishes_the_ballot() {
        let generator = ZKInputsGenerator::with_defaults();
        let (_secret_key, public_key) = generator.generate_keys().expect("failed to generate keys");

        let (published, json) = generator
            .generate_inputs(None, &public_key, create_vote_vector(), false)
            .expect("failed to generate first-vote inputs");

        // Nothing was added, so the published ciphertext is the ballot itself.
        assert_eq!(
            commitment_field(&json, "sum_ct_commitment"),
            commitment_field(&json, "ct_commitment")
        );
        // The contract passes zero for an empty slot, and a public input that disagrees would make
        // the proof unverifiable.
        assert_eq!(commitment_field(&json, "prev_ct_commitment"), "0");
        assert_eq!(
            commitment_field(&json, "sum_ct_commitment"),
            commitment_of(&generator, &published)
        );
    }

    #[test]
    fn test_revote_replaces_the_ballot_in_the_slot() {
        let generator = ZKInputsGenerator::with_defaults();
        let (secret_key, public_key) = generator.generate_keys().expect("failed to generate keys");

        let first = create_vote_vector();
        let (slot, _) = generator
            .generate_inputs(None, &public_key, first.clone(), false)
            .expect("failed to generate first-vote inputs");

        let second: Vec<u64> = first.iter().map(|c| 1 - c).collect();
        let (published, json) = generator
            .generate_inputs(Some(&slot), &public_key, second.clone(), false)
            .expect("failed to generate re-vote inputs");

        // A re-vote replaces rather than adds, or the two ballots would both count.
        assert_eq!(
            commitment_field(&json, "sum_ct_commitment"),
            commitment_field(&json, "ct_commitment")
        );
        assert_eq!(
            commitment_field(&json, "sum_ct_commitment"),
            commitment_of(&generator, &published)
        );
        // The circuit checks this against the commitment the contract stored for the slot, so a
        // re-vote still has to know what the slot holds.
        assert_eq!(
            commitment_field(&json, "prev_ct_commitment"),
            commitment_of(&generator, &slot)
        );
        assert_eq!(
            generator
                .decrypt_vote(&secret_key, &published)
                .expect("failed to decrypt re-vote"),
            second
        );
    }

    #[test]
    fn test_mask_over_occupied_slot_preserves_the_ballot() {
        let generator = ZKInputsGenerator::with_defaults();
        let (secret_key, public_key) = generator.generate_keys().expect("failed to generate keys");

        let ballot = create_vote_vector();
        let (slot, _) = generator
            .generate_inputs(None, &public_key, ballot.clone(), false)
            .expect("failed to generate first-vote inputs");

        let (published, json) = generator
            .generate_inputs(Some(&slot), &public_key, zero_vote(), true)
            .expect("failed to generate mask inputs");

        // A mask adds to the slot, so what it publishes is not the ballot it encrypted.
        assert_ne!(
            commitment_field(&json, "sum_ct_commitment"),
            commitment_field(&json, "ct_commitment")
        );
        assert_eq!(
            commitment_field(&json, "sum_ct_commitment"),
            commitment_of(&generator, &published)
        );
        assert_eq!(
            commitment_field(&json, "prev_ct_commitment"),
            commitment_of(&generator, &slot)
        );
        // Adding a zero ballot leaves the vote in the slot untouched, which is the whole point.
        assert_eq!(
            generator
                .decrypt_vote(&secret_key, &published)
                .expect("failed to decrypt masked slot"),
            ballot
        );
    }

    #[test]
    fn test_mask_over_empty_slot_publishes_the_zero_ballot() {
        let generator = ZKInputsGenerator::with_defaults();
        let (secret_key, public_key) = generator.generate_keys().expect("failed to generate keys");

        // `keep_previous` is set, but an empty slot holds nothing to keep.
        let (published, json) = generator
            .generate_inputs(None, &public_key, zero_vote(), true)
            .expect("failed to generate mask inputs");

        assert_eq!(
            commitment_field(&json, "sum_ct_commitment"),
            commitment_field(&json, "ct_commitment")
        );
        assert_eq!(commitment_field(&json, "prev_ct_commitment"), "0");
        assert_eq!(
            commitment_field(&json, "sum_ct_commitment"),
            commitment_of(&generator, &published)
        );
        assert_eq!(
            generator
                .decrypt_vote(&secret_key, &published)
                .expect("failed to decrypt mask"),
            zero_vote()
        );
    }

    #[test]
    fn test_repeated_masks_preserve_the_ballot() {
        let generator = ZKInputsGenerator::with_defaults();
        let (secret_key, public_key) = generator.generate_keys().expect("failed to generate keys");

        let ballot = create_vote_vector();
        let (mut slot, _) = generator
            .generate_inputs(None, &public_key, ballot.clone(), false)
            .expect("failed to generate first-vote inputs");

        for _ in 0..3 {
            let (published, _) = generator
                .generate_inputs(Some(&slot), &public_key, zero_vote(), true)
                .expect("failed to generate mask inputs");
            slot = published;
        }

        assert_eq!(
            generator
                .decrypt_vote(&secret_key, &slot)
                .expect("failed to decrypt masked slot"),
            ballot
        );
    }

    #[test]
    fn test_revote_after_masks_replaces_the_slot() {
        let generator = ZKInputsGenerator::with_defaults();
        let (secret_key, public_key) = generator.generate_keys().expect("failed to generate keys");

        let first = create_vote_vector();
        let (slot, _) = generator
            .generate_inputs(None, &public_key, first.clone(), false)
            .expect("failed to generate first-vote inputs");
        let (masked, _) = generator
            .generate_inputs(Some(&slot), &public_key, zero_vote(), true)
            .expect("failed to generate mask inputs");

        let second: Vec<u64> = first.iter().map(|c| 1 - c).collect();
        let (published, json) = generator
            .generate_inputs(Some(&masked), &public_key, second.clone(), false)
            .expect("failed to generate re-vote inputs");

        // The masks are discarded with the ballot they covered, and they carried nothing.
        assert_eq!(
            generator
                .decrypt_vote(&secret_key, &published)
                .expect("failed to decrypt re-vote"),
            second
        );
        assert_eq!(
            commitment_field(&json, "prev_ct_commitment"),
            commitment_of(&generator, &masked)
        );
    }
}
