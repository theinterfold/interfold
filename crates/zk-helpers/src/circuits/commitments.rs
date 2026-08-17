// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Commitment computation functions for zero-knowledge circuits.
//!
//! This module provides functions to compute commitments to various cryptographic objects
//! (polynomials, public keys, secret keys, shares, etc.) using the SAFE sponge hash function.
//! All functions match the corresponding Noir circuit implementations exactly.

use crate::packing::flatten;
use crate::utils::compute_safe;
use ark_bn254::Fr as Field;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use e3_fhe_params::{build_pair_for_preset, BfvPreset};
use e3_polynomial::{CrtPolynomial, Polynomial};
use fhe::bfv::PublicKey;
use fhe_traits::DeserializeParametrized;
use num_bigint::BigInt;
use std::slice::from_ref;

// ============================================================================
// DOMAIN SEPARATORS
// ============================================================================

/// String: "PK"
const DS_PK: [u8; 64] = [
    0x50, 0x4b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// String: "PK_GENERATION"
const DS_PK_GENERATION: [u8; 64] = [
    0x50, 0x4b, 0x5f, 0x47, 0x45, 0x4e, 0x45, 0x52, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// String: "SHARE_COMPUTATION"
const DS_SHARE_COMPUTATION: [u8; 64] = [
    0x53, 0x48, 0x41, 0x52, 0x45, 0x5f, 0x43, 0x4f, 0x4d, 0x50, 0x55, 0x54, 0x41, 0x54, 0x49, 0x4f,
    0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// String: "SHARE_COMPUTATION_CHUNK"
const DS_SHARE_COMPUTATION_CHUNK: [u8; 64] = [
    0x53, 0x48, 0x41, 0x52, 0x45, 0x5f, 0x43, 0x4f, 0x4d, 0x50, 0x55, 0x54, 0x41, 0x54, 0x49, 0x4f,
    0x4e, 0x5f, 0x43, 0x48, 0x55, 0x4e, 0x4b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// String: "SHARE_ENCRYPTION"
const DS_SHARE_ENCRYPTION: [u8; 64] = [
    0x53, 0x48, 0x41, 0x52, 0x45, 0x5f, 0x45, 0x4e, 0x43, 0x52, 0x59, 0x50, 0x54, 0x49, 0x4f, 0x4e,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// String: "PK_AGGREGATION"
const DS_PK_AGGREGATION: [u8; 64] = [
    0x50, 0x4b, 0x5f, 0x41, 0x47, 0x47, 0x52, 0x45, 0x47, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Domain separator for general-purpose ciphertext commitments.
/// String: "CIPHERTEXT"
const DS_CIPHERTEXT: [u8; 64] = [
    0x43, 0x49, 0x50, 0x48, 0x45, 0x52, 0x54, 0x45, 0x58, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// String: "AGGREGATED_SHARES"
const DS_AGGREGATED_SHARES: [u8; 64] = [
    0x41, 0x47, 0x47, 0x52, 0x45, 0x47, 0x41, 0x54, 0x45, 0x44, 0x5f, 0x53, 0x48, 0x41, 0x52, 0x45,
    0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// String: "THRESHOLD_DECRYPTION_SHARE"
const DS_THRESHOLD_DECRYPTION_SHARE: [u8; 64] = [
    0x54, 0x48, 0x52, 0x45, 0x53, 0x48, 0x4f, 0x4c, 0x44, 0x5f, 0x44, 0x45, 0x43, 0x52, 0x59, 0x50,
    0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x48, 0x41, 0x52, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// String: "VK_HASH"
const DS_VK_HASH: [u8; 64] = [
    0x56, 0x4b, 0x5f, 0x48, 0x41, 0x53, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// String: "RECURSIVE_AGGREGATION"
const DS_RECURSIVE_AGGREGATION: [u8; 64] = [
    0x52, 0x45, 0x43, 0x55, 0x52, 0x53, 0x49, 0x56, 0x45, 0x5f, 0x41, 0x47, 0x47, 0x52, 0x45, 0x47,
    0x41, 0x54, 0x49, 0x4f, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// String: "CLG_PK_GENERATION"
const DS_CLG_PK_GENERATION: [u8; 64] = [
    0x43, 0x4c, 0x47, 0x5f, 0x50, 0x4b, 0x5f, 0x47, 0x45, 0x4e, 0x45, 0x52, 0x41, 0x54, 0x49, 0x4f,
    0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// String: "CLG_SHARE_ENCRYPTION"
const DS_CLG_SHARE_ENCRYPTION: [u8; 64] = [
    0x43, 0x4c, 0x47, 0x5f, 0x53, 0x48, 0x41, 0x52, 0x45, 0x5f, 0x45, 0x4e, 0x43, 0x52, 0x59, 0x50,
    0x54, 0x49, 0x4f, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// String: "CLG_USER_DATA_ENCRYPTION"
const DS_CLG_USER_DATA_ENCRYPTION: [u8; 64] = [
    0x43, 0x4c, 0x47, 0x5f, 0x55, 0x53, 0x45, 0x52, 0x5f, 0x44, 0x41, 0x54, 0x41, 0x5f, 0x45, 0x4e,
    0x43, 0x52, 0x59, 0x50, 0x54, 0x49, 0x4f, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Domain separator for decryption share challenge.
/// String: "CLG_SHARE_DECRYPTION"
const DS_CLG_SHARE_DECRYPTION: [u8; 64] = [
    0x43, 0x4c, 0x47, 0x5f, 0x53, 0x48, 0x41, 0x52, 0x45, 0x5f, 0x44, 0x45, 0x43, 0x52, 0x59, 0x50,
    0x54, 0x49, 0x4f, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// ============================================================================
// WRAPPERS
// ============================================================================

/// Compute commitments using SAFE sponge with the given domain separator and payload.
///
/// This matches the Noir `compute_commitments` function exactly.
///
/// # Arguments
/// * `payload` - Vector of field elements to hash
/// * `domain_separator` - Domain separator for cross-protocol security
/// * `io_pattern` - IO pattern `[ABSORB(input_size), SQUEEZE(output_size)]`
///
/// # Returns
/// A vector of field elements from the sponge
pub fn compute_commitments(
    payload: Vec<Field>,
    domain_separator: [u8; 64],
    io_pattern: [u32; 2],
) -> Vec<Field> {
    compute_safe(domain_separator, payload, io_pattern)
}

/// Combine verification-key hashes with the `VK_HASH` domain separator (SAFE sponge).
///
/// Matches Noir `lib::math::commitments::compute_vk_hash`.
pub fn compute_vk_hash(vk_hashes: Vec<Field>) -> Field {
    let input_size = vk_hashes.len() as u32;
    let io_pattern = [0x80000000 | input_size, 1];
    compute_commitments(vk_hashes, DS_VK_HASH, io_pattern)[0]
}

// ============================================================================
// COMMITMENTS
// ============================================================================

/// Compute a commitment to the correct DKG public key polynomials by flattening them and hashing.
///
/// This matches the Noir `compute_pk_generation_commitment` function exactly.
///
/// # Arguments
/// * `pk0` - First component of the correct DKG public key (one vector per modulus)
/// * `pk1` - Second component of the correct DKG public key (one vector per modulus)
/// * `bit_pk` - The bit width for public key coefficient bounds
///
/// # Returns
/// A `BigInt` representing the commitment hash value
pub fn compute_dkg_pk_commitment(pk0: &CrtPolynomial, pk1: &CrtPolynomial, bit_pk: u32) -> BigInt {
    let mut payload = Vec::new();
    payload = flatten(payload, &pk0.limbs, bit_pk);
    payload = flatten(payload, &pk1.limbs, bit_pk);

    let input_size = payload.len() as u32;
    let io_pattern = [0x80000000 | input_size, 1];

    let commitment_field = compute_commitments(payload, DS_PK, io_pattern)[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute the C0 `pk_commitment` for a serialized DKG BFV public key.
///
/// The C0 proof attests to the two polynomials inside the advertised public key. Network
/// consumers must compare this value with the proof's public output before accepting the key;
/// verifying a proof without that comparison would allow the proof for one key to be attached to
/// different key bytes.
pub fn compute_dkg_pk_commitment_from_public_key_bytes(
    public_key_bytes: &[u8],
    preset: BfvPreset,
) -> Result<[u8; 32], crate::CircuitsErrors> {
    // `build_pair_for_preset` accepts the threshold member of a preset pair. Callers may already
    // have resolved the DKG counterpart, so normalize either representation here.
    let threshold_preset = preset.threshold_counterpart().unwrap_or(preset);
    let (_, dkg_params) = build_pair_for_preset(threshold_preset)
        .map_err(|e| crate::CircuitsErrors::Other(format!("BFV preset pair: {e}")))?;
    let public_key = PublicKey::from_bytes(public_key_bytes, &dkg_params)
        .map_err(|e| crate::CircuitsErrors::Other(format!("PublicKey deserialize: {e:?}")))?;

    let pk0 = public_key
        .c
        .first()
        .ok_or_else(|| crate::CircuitsErrors::Other("PublicKey is missing pk0".to_string()))?;
    let pk1 = public_key
        .c
        .get(1)
        .ok_or_else(|| crate::CircuitsErrors::Other("PublicKey is missing pk1".to_string()))?;
    let moduli = dkg_params.moduli();
    let pk0 = crate::math::fhe_poly_to_crt_centered(pk0, moduli)
        .map_err(|e| crate::CircuitsErrors::Other(format!("pk0 conversion: {e}")))?;
    let pk1 = crate::math::fhe_poly_to_crt_centered(pk1, moduli)
        .map_err(|e| crate::CircuitsErrors::Other(format!("pk1 conversion: {e}")))?;
    let commitment = compute_dkg_pk_commitment(&pk0, &pk1, crate::compute_modulus_bit(&dkg_params));

    let (_, be_bytes) = commitment.to_bytes_be();
    if be_bytes.len() > 32 {
        return Err(crate::CircuitsErrors::Other(
            "C0 pk_commitment does not fit in a field element".to_string(),
        ));
    }
    let mut padded = [0u8; 32];
    padded[32 - be_bytes.len()..].copy_from_slice(&be_bytes);
    Ok(padded)
}

/// Compute a commitment to the threshold public key by flattening pk0 and hashing.
///
/// This matches the Noir `compute_threshold_pk_commitment` function exactly,
/// which hashes only pk0 with domain separator DS_PK_GENERATION.
///
/// # Arguments
/// * `pk0` - First component of the threshold public key (CRT limbs)
/// * `bit_pk` - The bit width for public key coefficient bounds
///
/// # Returns
/// A `BigInt` representing the commitment hash value
pub fn compute_threshold_pk_commitment(pk0: &CrtPolynomial, bit_pk: u32) -> BigInt {
    let mut payload = Vec::new();
    payload = flatten(payload, &pk0.limbs, bit_pk);

    let input_size = payload.len() as u32;
    let io_pattern = [0x80000000 | input_size, 1];

    let commitment_field = compute_commitments(payload, DS_PK_GENERATION, io_pattern)[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute the pk_commitment for a serialized `PublicKeyShare`, matching what the C1 circuit outputs.
///
/// Deserializes the keyshare, extracts the pk0 polynomial, and hashes it
/// together with the CRP (pk1) to produce the commitment. Returns 32
/// big-endian bytes, ready to compare against
/// `Proof::extract_output("pk_commitment")` from a C1 proof.
///
/// The caller supplies pre-built `params` and `crp` so that batch calls
/// (multiple keyshares with the same parameters) don't rebuild them each time.
pub fn compute_pk_commitment_from_keyshare_bytes(
    keyshare_bytes: &[u8],
    params: &std::sync::Arc<fhe::bfv::BfvParameters>,
    crp: &fhe::mbfv::CommonRandomPoly,
) -> Result<[u8; 32], crate::CircuitsErrors> {
    let bit_pk = crate::compute_modulus_bit(params);
    let moduli = params.moduli();

    let pk_share = fhe::mbfv::PublicKeyShare::deserialize(keyshare_bytes, params, crp.clone())
        .map_err(|e| {
            crate::CircuitsErrors::Other(format!("PublicKeyShare deserialize: {:?}", e))
        })?;

    let mut pk0 = CrtPolynomial::from_fhe_polynomial(&pk_share.p0_share());
    pk0.reverse();
    pk0.center(moduli)
        .map_err(|e| crate::CircuitsErrors::Other(format!("pk0 center: {}", e)))?;

    let commitment = compute_threshold_pk_commitment(&pk0, bit_pk);
    let (_, be_bytes) = commitment.to_bytes_be();
    let mut padded = [0u8; 32];
    let start = 32usize.saturating_sub(be_bytes.len());
    padded[start..].copy_from_slice(&be_bytes[..be_bytes.len().min(32)]);
    Ok(padded)
}

/// Compute a commitment to the threshold secret key share by flattening it and hashing.
///
/// This matches the Noir `compute_share_computation_sk_commitment` function exactly.
///
/// # Arguments
/// * `sk` - Threshold secret key polynomial
/// * `bit_sk` - The bit width for threshold secret key share coefficient bounds
///
/// # Returns
/// A `BigInt` representing the commitment hash value
pub fn compute_share_computation_sk_commitment(sk: &Polynomial, bit_sk: u32) -> BigInt {
    let mut payload = Vec::new();
    payload = flatten(payload, from_ref(sk), bit_sk);

    let input_size = payload.len() as u32;
    let io_pattern = [0x80000000 | input_size, 1];

    let commitment_field = compute_commitments(payload, DS_SHARE_COMPUTATION, io_pattern)[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute a commitment to the threshold smudging noise share by flattening it and hashing.
///
/// This matches the Noir `compute_share_computation_e_sm_commitment` function exactly.
///
/// # Arguments
/// * `e_sm` - Threshold smudging noise polynomial (CRT limbs)
/// * `bit_e_sm` - The bit width for threshold smudging noise share coefficient bounds
///
/// # Returns
/// A `BigInt` representing the commitment hash value
pub fn compute_share_computation_e_sm_commitment(e_sm: &CrtPolynomial, bit_e_sm: u32) -> BigInt {
    let mut payload = Vec::new();
    payload = flatten(payload, &e_sm.limbs, bit_e_sm);

    let input_size = payload.len() as u32;
    let io_pattern = [0x80000000 | input_size, 1];

    let commitment_field = compute_commitments(payload, DS_SHARE_COMPUTATION, io_pattern)[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

fn field_to_bigint(field: Field) -> BigInt {
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &field.into_bigint().to_bytes_le())
}

fn compute_chunk_commitment(payload: Vec<Field>) -> BigInt {
    let input_size = payload.len() as u32;
    field_to_bigint(
        compute_commitments(
            payload,
            DS_SHARE_COMPUTATION_CHUNK,
            [0x80000000 | input_size, 1],
        )[0],
    )
}

fn chunk_polynomial(polynomial: &Polynomial, chunk_idx: usize, chunk_size: usize) -> Polynomial {
    let coefficients = polynomial.coefficients();
    let start = coefficients.len() - ((chunk_idx + 1) * chunk_size);
    Polynomial::new(coefficients[start..start + chunk_size].to_vec())
}

/// Compute the SK root for the C1 polynomial orientation.
pub fn compute_sc_sk_secret_root_commitment(
    sk: &Polynomial,
    bit_sk: u32,
    chunk_size: usize,
) -> BigInt {
    assert!(chunk_size > 0 && sk.coefficients().len().is_multiple_of(chunk_size));
    let chunk_count = sk.coefficients().len() / chunk_size;
    let mut leaves = Vec::with_capacity(chunk_count);
    for chunk_idx in 0..chunk_count {
        let chunk = chunk_polynomial(sk, chunk_idx, chunk_size);
        let mut payload = vec![
            Field::from(0u64),
            Field::from(0u64),
            Field::from(chunk_idx as u64),
            Field::from(sk.coefficients().len() as u64),
            Field::from(chunk_size as u64),
        ];
        payload = flatten(payload, std::slice::from_ref(&chunk), bit_sk);
        leaves.push(compute_chunk_commitment(payload));
    }
    let mut payload = vec![
        Field::from(1u64),
        Field::from(0u64),
        Field::from(sk.coefficients().len() as u64),
        Field::from(chunk_size as u64),
    ];
    payload.extend(leaves.into_iter().map(|leaf| field_from_bigint(&leaf)));
    compute_chunk_commitment(payload)
}

/// Compute the ESM root for the C1 polynomial orientation.
pub fn compute_sc_esm_secret_root_commitment(
    e_sm: &CrtPolynomial,
    bit_e_sm: u32,
    chunk_size: usize,
) -> BigInt {
    assert!(!e_sm.limbs.is_empty());
    assert!(
        chunk_size > 0
            && e_sm.limbs[0]
                .coefficients()
                .len()
                .is_multiple_of(chunk_size)
    );
    let degree = e_sm.limbs[0].coefficients().len();
    let chunk_count = degree / chunk_size;
    let mut leaves = Vec::with_capacity(chunk_count);
    for chunk_idx in 0..chunk_count {
        let mut payload = vec![
            Field::from(0u64),
            Field::from(1u64),
            Field::from(chunk_idx as u64),
            Field::from(degree as u64),
            Field::from(chunk_size as u64),
        ];
        let chunks = e_sm
            .limbs
            .iter()
            .map(|limb| chunk_polynomial(limb, chunk_idx, chunk_size))
            .collect::<Vec<_>>();
        payload = flatten(payload, &chunks, bit_e_sm);
        leaves.push(compute_chunk_commitment(payload));
    }
    let mut payload = vec![
        Field::from(1u64),
        Field::from(1u64),
        Field::from(degree as u64),
        Field::from(chunk_size as u64),
    ];
    payload.extend(leaves.into_iter().map(|leaf| field_from_bigint(&leaf)));
    compute_chunk_commitment(payload)
}

/// Compute a recipient share root from its C3/C4 polynomial orientation.
pub fn compute_sc_party_share_root_commitment(
    party_idx: usize,
    mod_idx: usize,
    message: &Polynomial,
    bit_share: u32,
    chunk_size: usize,
) -> BigInt {
    assert!(chunk_size > 0 && message.coefficients().len().is_multiple_of(chunk_size));
    let degree = message.coefficients().len();
    let chunk_count = degree / chunk_size;
    let mut leaves = Vec::with_capacity(chunk_count);
    for chunk_idx in 0..chunk_count {
        let chunk = chunk_polynomial(message, chunk_idx, chunk_size);
        let mut payload = vec![
            Field::from(0u64),
            Field::from(2u64),
            Field::from(party_idx as u64),
            Field::from(mod_idx as u64),
            Field::from(chunk_idx as u64),
            Field::from(degree as u64),
            Field::from(chunk_size as u64),
        ];
        payload = flatten(payload, std::slice::from_ref(&chunk), bit_share);
        leaves.push(compute_chunk_commitment(payload));
    }
    let mut payload = vec![
        Field::from(1u64),
        Field::from(2u64),
        Field::from(party_idx as u64),
        Field::from(mod_idx as u64),
        Field::from(degree as u64),
        Field::from(chunk_size as u64),
    ];
    payload.extend(leaves.into_iter().map(|leaf| field_from_bigint(&leaf)));
    compute_chunk_commitment(payload)
}

fn field_from_bigint(value: &BigInt) -> Field {
    let (_, bytes) = value.to_bytes_le();
    Field::from_le_bytes_mod_order(&bytes)
}

/// Compute share encryption commitment from message polynomial.
///
/// This matches the Noir `compute_share_encryption_commitment_from_message` function exactly.
///
/// # Arguments
/// * `message` - Message polynomial
/// * `bit_msg` - The bit width for message coefficient bounds
///
/// # Returns
/// A `BigInt` representing the commitment hash value
pub fn compute_share_encryption_commitment_from_message(
    message: &Polynomial,
    bit_msg: u32,
) -> BigInt {
    let mut payload = Vec::new();
    payload = flatten(payload, from_ref(message), bit_msg);

    let input_size = payload.len() as u32;
    let io_pattern = [0x80000000 | input_size, 1];

    let commitment_field = compute_commitments(payload, DS_SHARE_ENCRYPTION, io_pattern)[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute threshold public key aggregation commitment.
///
/// This matches the Noir `compute_pk_aggregation_commitment` function exactly.
///
/// # Arguments
/// * `pk0` - First component of the threshold public key (CRT limbs)
/// * `pk1` - Second component of the threshold public key (CRT limbs)
/// * `bit_pk` - The bit width for threshold public key coefficient bounds
///
/// # Returns
/// A `BigInt` representing the commitment hash value
pub fn compute_pk_aggregation_commitment(
    pk0: &CrtPolynomial,
    pk1: &CrtPolynomial,
    bit_pk: u32,
) -> BigInt {
    let mut payload0 = Vec::new();
    payload0 = flatten(payload0, &pk0.limbs, bit_pk);
    let io = [0x80000000 | payload0.len() as u32, 1];
    let commit_pk0 = compute_commitments(payload0, DS_PK_AGGREGATION, io)[0];

    let mut payload1 = Vec::new();
    payload1 = flatten(payload1, &pk1.limbs, bit_pk);
    let commit_pk1 = compute_commitments(payload1, DS_PK_AGGREGATION, io)[0];

    let inputs = vec![commit_pk0, commit_pk1];
    let io = [0x80000000 | inputs.len() as u32, 1];
    let commitment_field = compute_commitments(inputs, DS_PK_AGGREGATION, io)[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();

    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute aggregation commitment.
///
/// This matches the Noir `compute_recursive_aggregation_commitment` function exactly.
///
/// # Arguments
/// * `payload` - Prepared payload as a vector of field elements
///
/// # Returns
/// A `BigInt` representing the commitment hash value
pub fn compute_recursive_aggregation_commitment(payload: Vec<Field>) -> BigInt {
    let input_size = payload.len() as u32;
    let io_pattern = [0x80000000 | input_size, 1];

    let commitment_field = compute_commitments(payload, DS_RECURSIVE_AGGREGATION, io_pattern)[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute CRISP ciphertext commitment.
///
/// Matches the Noir `compute_ciphertext_commitment` exactly: commits ct0 and ct1
/// separately, then hashes the two commitments together.
///
/// # Arguments
/// * `ct0` - First component of the ciphertext (CRT limbs)
/// * `ct1` - Second component of the ciphertext (CRT limbs)
/// * `bit_ct` - The bit width for ciphertext coefficient bounds
///
/// # Returns
/// A `BigInt` representing the commitment hash value
pub fn compute_ciphertext_commitment(
    ct0: &CrtPolynomial,
    ct1: &CrtPolynomial,
    bit_ct: u32,
) -> BigInt {
    let payload0 = flatten(Vec::new(), &ct0.limbs, bit_ct);
    let io = [0x80000000 | payload0.len() as u32, 1];
    let commit_ct0 = compute_commitments(payload0, DS_CIPHERTEXT, io)[0];

    let payload1 = flatten(Vec::new(), &ct1.limbs, bit_ct);
    let commit_ct1 = compute_commitments(payload1, DS_CIPHERTEXT, io)[0];

    let inputs = vec![commit_ct0, commit_ct1];
    let io = [0x80000000 | inputs.len() as u32, 1];
    let commitment_field = compute_commitments(inputs, DS_CIPHERTEXT, io)[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();

    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute aggregated shares commitment (either sk_shares or e_sm_shares).
///
/// This matches the Noir `compute_aggregated_shares_commitment` function exactly.
///
/// # Arguments
/// * `agg_shares` - Aggregated share polynomial (CRT limbs)
/// * `bit_msg` - The bit width for message coefficient bounds
///
/// # Returns
/// A `BigInt` representing the commitment hash value
pub fn compute_aggregated_shares_commitment(agg_shares: &CrtPolynomial, bit_msg: u32) -> BigInt {
    let mut payload = Vec::new();
    payload = flatten(payload, &agg_shares.limbs, bit_msg);

    let input_size = payload.len() as u32;
    let io_pattern = [0x80000000 | input_size, 1];

    let commitment_field = compute_commitments(payload, DS_AGGREGATED_SHARES, io_pattern)[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

// ============================================================================
// THRESHOLD DECRYPTION SHARES (C6 / C7)
// ============================================================================

fn truncate_crt_polynomial_to_max_coeffs(crt: &CrtPolynomial, max_len: usize) -> CrtPolynomial {
    let limbs = crt
        .limbs
        .iter()
        .map(|limb| {
            let v: Vec<_> = limb.coefficients().iter().take(max_len).cloned().collect();
            Polynomial::new(v)
        })
        .collect();
    CrtPolynomial::new(limbs)
}

/// Commitment to a threshold decryption share: all CRT limbs, first `max_k` coefficients
/// per limb (matches Noir `compute_threshold_decryption_share_commitment`).
///
/// `native_coeff_bit` must be the max bit width of coefficients in \([0, q_l)\) per CRT limb.
pub fn compute_threshold_decryption_share_commitment(
    d_share: &CrtPolynomial,
    native_coeff_bit: u32,
    max_k: usize,
) -> BigInt {
    let truncated = truncate_crt_polynomial_to_max_coeffs(d_share, max_k);
    let mut payload = Vec::new();
    payload = flatten(payload, &truncated.limbs, native_coeff_bit);

    let input_size = payload.len() as u32;
    let io_pattern = [0x80000000 | input_size, 1];

    let commitment_field =
        compute_commitments(payload, DS_THRESHOLD_DECRYPTION_SHARE, io_pattern)[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

// ============================================================================
// COMMITMENTS FOR CHALLENGES
// ============================================================================

/// Compute public key generation challenge.
///
/// This matches the Noir `compute_threshold_pk_challenge` function exactly.
///
/// # Arguments
/// * `payload` - Prepared payload as a vector of field elements
///
/// # Returns
/// A `BigInt` representing the commitment hash value
pub fn compute_threshold_pk_challenge(payload: Vec<Field>) -> BigInt {
    let input_size = payload.len() as u32;
    let io_pattern = [0x80000000 | input_size, 1];

    let challenge_field = compute_commitments(payload, DS_CLG_PK_GENERATION, io_pattern)[0];
    let challenge_bytes = challenge_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &challenge_bytes)
}

/// Compute share encryption challenge.
///
/// This matches the Noir `compute_share_encryption_challenge` function exactly.
///
/// # Arguments
/// * `payload` - Prepared payload as a vector of field elements
/// * `l` - Number of moduli
///
/// # Returns
/// A vector of `BigInt` challenges (2*L elements)
pub fn compute_share_encryption_challenge(payload: Vec<Field>, l: usize) -> Vec<BigInt> {
    let input_size = payload.len() as u32;
    let io_pattern = [0x80000000 | input_size, (2 * l as u32)];

    compute_commitments(payload, DS_CLG_SHARE_ENCRYPTION, io_pattern)
        .into_iter()
        .map(|challenge_field| {
            let challenge_bytes = challenge_field.into_bigint().to_bytes_le();
            BigInt::from_bytes_le(num_bigint::Sign::Plus, &challenge_bytes)
        })
        .collect()
}

/// Compute User Data Encryption challenge commitment.
///
/// This matches the Noir `compute_user_data_encryption_challenge_commitment` function exactly.
/// Verifies pk_commitment using pk0is and pk1is, then generates challenges from gammas_payload.
///
/// # Arguments
/// * `pk0is` - First component of public keys (CRT limbs)
/// * `pk1is` - Second component of public keys (CRT limbs)
/// * `gammas_payload` - Payload for generating challenges
/// * `pk_commitment` - Expected public key commitment value
/// * `bit_pk` - The bit width for public key coefficient bounds
/// * `l` - Number of moduli
///
/// # Returns
/// A vector of `BigInt` challenges (2*L elements)
///
/// # Panics
/// Panics if the computed public key commitment doesn't match `pk_commitment`
pub fn compute_user_data_encryption_challenge_commitment(
    pk0is: &CrtPolynomial,
    pk1is: &CrtPolynomial,
    gammas_payload: Vec<Field>,
    pk_commitment: &BigInt,
    bit_pk: u32,
    l: usize,
) -> Vec<BigInt> {
    let computed_pk_commitment = compute_pk_aggregation_commitment(pk0is, pk1is, bit_pk);
    if computed_pk_commitment != *pk_commitment {
        panic!(
            "PK commitment mismatch in User Data Encryption circuit: expected {}, got {}",
            pk_commitment, computed_pk_commitment
        );
    }

    let input_size = gammas_payload.len() as u32;
    let io_pattern = [0x80000000 | input_size, (2 * l as u32)];

    compute_commitments(gammas_payload, DS_CLG_USER_DATA_ENCRYPTION, io_pattern)
        .into_iter()
        .map(|challenge_field| {
            let challenge_bytes = challenge_field.into_bigint().to_bytes_le();
            BigInt::from_bytes_le(num_bigint::Sign::Plus, &challenge_bytes)
        })
        .collect()
}

/// Compute threshold share decryption challenge.
///
/// This matches the Noir `compute_threshold_share_decryption_challenge` function exactly.
///
/// # Arguments
/// * `payload` - Prepared payload as a vector of field elements
///
/// # Returns
/// A `BigInt` representing the commitment hash value
pub fn compute_threshold_share_decryption_challenge(payload: Vec<Field>) -> BigInt {
    let input_size = payload.len() as u32;
    let io_pattern = [0x80000000 | input_size, 1];

    let commitment_field = compute_commitments(payload, DS_CLG_SHARE_DECRYPTION, io_pattern)[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_polynomial::CrtPolynomial;

    fn field_to_bigint(value: Field) -> BigInt {
        let bytes = value.into_bigint().to_bytes_le();
        BigInt::from_bytes_le(num_bigint::Sign::Plus, &bytes)
    }

    #[test]
    fn compute_ciphertext_commitment_matches_manual_payload() {
        let bit_ct = 4;
        let ct0 = CrtPolynomial::from_bigint_vectors(vec![vec![BigInt::from(1), BigInt::from(2)]]);
        let ct1 = CrtPolynomial::from_bigint_vectors(vec![vec![BigInt::from(3), BigInt::from(4)]]);

        let mut payload0 = Vec::new();
        payload0 = flatten(payload0, &ct0.limbs, bit_ct);
        let io = [0x80000000 | payload0.len() as u32, 1];
        let commit_ct0 = compute_commitments(payload0, DS_CIPHERTEXT, io)[0];

        let mut payload1 = Vec::new();
        payload1 = flatten(payload1, &ct1.limbs, bit_ct);
        let io = [0x80000000 | payload1.len() as u32, 1];
        let commit_ct1 = compute_commitments(payload1, DS_CIPHERTEXT, io)[0];

        let inputs = vec![commit_ct0, commit_ct1];
        let io = [0x80000000 | inputs.len() as u32, 1];
        let expected = field_to_bigint(compute_commitments(inputs, DS_CIPHERTEXT, io)[0]);

        let actual = compute_ciphertext_commitment(&ct0, &ct1, bit_ct);
        assert_eq!(actual, expected);
    }

    #[test]
    fn compute_threshold_pk_challenge_returns_single_bigint() {
        let payload = vec![Field::from(1u64), Field::from(2u64)];
        let input_size = payload.len() as u32;
        let io_pattern = [0x80000000 | input_size, 1];
        let expected_challenge = field_to_bigint(
            compute_commitments(payload.clone(), DS_CLG_PK_GENERATION, io_pattern)[0],
        );

        let challenge = compute_threshold_pk_challenge(payload);
        assert_eq!(challenge, expected_challenge);
    }

    #[test]
    fn compute_share_encryption_challenge_returns_2l_elements() {
        let payload = vec![Field::from(1u64), Field::from(2u64)];
        let l = 3;

        let challenges = compute_share_encryption_challenge(payload, l);
        assert_eq!(challenges.len(), 2 * l);
    }

    #[test]
    fn compute_recursive_aggregation_commitment_matches_manual_payload() {
        let payload = vec![Field::from(1u64), Field::from(2u64)];

        let input_size = payload.len() as u32;
        let io_pattern = [0x80000000 | input_size, 1];
        let expected = field_to_bigint(
            compute_commitments(payload.clone(), DS_RECURSIVE_AGGREGATION, io_pattern)[0],
        );

        let actual = compute_recursive_aggregation_commitment(payload);
        assert_eq!(actual, expected);
    }

    #[test]
    fn compute_threshold_share_decryption_challenge_returns_single_bigint() {
        let payload = vec![Field::from(1u64), Field::from(2u64)];

        let input_size = payload.len() as u32;
        let io_pattern = [0x80000000 | input_size, 1];
        let expected = field_to_bigint(
            compute_commitments(payload.clone(), DS_CLG_SHARE_DECRYPTION, io_pattern)[0],
        );

        let actual = compute_threshold_share_decryption_challenge(payload);
        assert_eq!(actual, expected);
    }

    #[test]
    fn compute_vk_hash_matches_manual_commitment() {
        let vk_hashes = vec![
            Field::from(7u64),
            Field::from(8u64),
            Field::from(9u64),
            Field::from(10u64),
        ];
        let input_size = vk_hashes.len() as u32;
        let io_pattern = [0x80000000 | input_size, 1];
        let expected = compute_commitments(vk_hashes.clone(), super::DS_VK_HASH, io_pattern)[0];
        assert_eq!(compute_vk_hash(vk_hashes), expected);
    }

    #[test]
    fn compute_pk_commitment_from_keyshare_roundtrip() {
        use e3_fhe_params::{
            build_pair_for_preset, create_deterministic_crp_from_default_seed, BfvPreset,
        };
        use fhe::bfv::SecretKey;
        use fhe::mbfv::PublicKeyShare;
        use fhe_traits::Serialize;
        let preset = BfvPreset::InsecureThreshold512;
        let (params, _) = build_pair_for_preset(preset).unwrap();
        let crp = create_deterministic_crp_from_default_seed(&params);

        let mut rng = rand::rng();
        // Generate a real keyshare
        let sk = SecretKey::random(&params, &mut rng);
        let pk_share = PublicKeyShare::new(&sk, crp.clone(), &mut rng).unwrap();
        let ks_bytes = pk_share.to_bytes();

        // Compute commitment via the helper
        let commitment =
            compute_pk_commitment_from_keyshare_bytes(&ks_bytes, &params, &crp).unwrap();

        // Compute commitment manually (same steps as PkAggInputs::compute)
        let bit_pk = crate::compute_modulus_bit(&params);
        let mut pk0 = CrtPolynomial::from_fhe_polynomial(&pk_share.p0_share());
        pk0.reverse();
        pk0.center(params.moduli()).unwrap();
        let expected = compute_threshold_pk_commitment(&pk0, bit_pk);
        let (_, be_bytes) = expected.to_bytes_be();
        let mut expected_padded = [0u8; 32];
        let start = 32usize.saturating_sub(be_bytes.len());
        expected_padded[start..].copy_from_slice(&be_bytes[..be_bytes.len().min(32)]);

        assert_eq!(commitment, expected_padded);
    }

    #[test]
    fn compute_dkg_pk_commitment_from_public_key_bytes_matches_circuit_inputs() {
        use crate::circuits::dkg::pk::{Bits, Inputs, PkCircuitData};
        use crate::Computation;
        use e3_fhe_params::{build_pair_for_preset, BfvPreset};
        use fhe::bfv::{PublicKey, SecretKey};
        use fhe_traits::Serialize;

        let preset = BfvPreset::InsecureThreshold512;
        let (_, dkg_params) = build_pair_for_preset(preset).unwrap();
        let mut rng = rand::rng();
        let secret_key = SecretKey::random(&dkg_params, &mut rng);
        let public_key = PublicKey::new(&secret_key, &mut rng);
        let public_key_bytes = public_key.to_bytes();

        let actual =
            compute_dkg_pk_commitment_from_public_key_bytes(&public_key_bytes, preset).unwrap();

        let inputs = Inputs::compute(preset, &PkCircuitData { public_key }).unwrap();
        let bits = Bits::compute(preset, &()).unwrap();
        let expected = compute_dkg_pk_commitment(&inputs.pk0is, &inputs.pk1is, bits.pk_bit);
        let (_, expected_bytes) = expected.to_bytes_be();
        let mut expected_padded = [0u8; 32];
        expected_padded[32 - expected_bytes.len()..].copy_from_slice(&expected_bytes);

        assert_eq!(actual, expected_padded);
    }

    #[test]
    fn compute_dkg_pk_commitment_rejects_malformed_public_key() {
        assert!(compute_dkg_pk_commitment_from_public_key_bytes(
            b"not a BFV public key",
            e3_fhe_params::BfvPreset::InsecureThreshold512,
        )
        .is_err());
    }
}
