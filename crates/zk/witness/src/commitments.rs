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

use ark_bn254::Fr as Field;
use ark_ff::{BigInt as FieldInteger, BigInteger, PrimeField};
use e3_fhe_params::{build_pair_for_preset, BfvPreset};
use e3_polynomial::{CrtPolynomial, Polynomial};
use e3_polynomial_fhe::FromFhePolynomial as _;
use e3_safe::SafeSponge;
use fhe::bfv::PublicKey;
use fhe_math::rq::{Poly, PowerBasis};
use fhe_traits::DeserializeParametrized;
use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero};
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
    let mut sponge = SafeSponge::start(io_pattern, domain_separator);
    sponge.absorb(payload);
    let digests = sponge.squeeze();
    sponge.finish();
    digests
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
) -> Result<[u8; 32], crate::WitnessError> {
    // `build_pair_for_preset` accepts the threshold member of a preset pair. Callers may already
    // have resolved the DKG counterpart, so normalize either representation here.
    let threshold_preset = preset.threshold_counterpart().unwrap_or(preset);
    let (_, dkg_params) = build_pair_for_preset(threshold_preset)
        .map_err(|e| crate::WitnessError::Other(format!("BFV preset pair: {e}")))?;
    let public_key = PublicKey::from_bytes(public_key_bytes, &dkg_params)
        .map_err(|e| crate::WitnessError::Other(format!("PublicKey deserialize: {e:?}")))?;

    let pk0 = public_key
        .c
        .first()
        .ok_or_else(|| crate::WitnessError::Other("PublicKey is missing pk0".to_string()))?;
    let pk1 = public_key
        .c
        .get(1)
        .ok_or_else(|| crate::WitnessError::Other("PublicKey is missing pk1".to_string()))?;
    let moduli = dkg_params.moduli();
    let pk0 = crate::encoding::fhe_poly_to_crt_centered(pk0, moduli)
        .map_err(|e| crate::WitnessError::Other(format!("pk0 conversion: {e}")))?;
    let pk1 = crate::encoding::fhe_poly_to_crt_centered(pk1, moduli)
        .map_err(|e| crate::WitnessError::Other(format!("pk1 conversion: {e}")))?;
    let commitment = compute_dkg_pk_commitment(
        &pk0,
        &pk1,
        e3_fhe_params::utils::compute_modulus_bit(&dkg_params),
    );

    let (_, be_bytes) = commitment.to_bytes_be();
    if be_bytes.len() > 32 {
        return Err(crate::WitnessError::Other(
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
) -> Result<[u8; 32], crate::WitnessError> {
    let bit_pk = e3_fhe_params::utils::compute_modulus_bit(params);
    let moduli = params.moduli();

    let pk_share = fhe::mbfv::PublicKeyShare::deserialize(keyshare_bytes, params, crp.clone())
        .map_err(|e| crate::WitnessError::Other(format!("PublicKeyShare deserialize: {:?}", e)))?;

    let mut pk0 = CrtPolynomial::from_fhe_polynomial(&pk_share.p0_share());
    pk0.reverse();
    pk0.center(moduli)
        .map_err(|e| crate::WitnessError::Other(format!("pk0 center: {}", e)))?;

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
    let payload1 = flatten(Vec::new(), &ct1.limbs, bit_ct);
    ciphertext_commitment_from_packed(payload0, payload1)
}

/// Computes the same SAFE commitment directly from canonical power-basis rows.
/// Returns `None` when the caller must use the general polynomial path.
pub fn compute_ciphertext_commitment_from_power_basis(
    ct0: &Poly<PowerBasis>,
    ct1: &Poly<PowerBasis>,
    moduli: &[u64],
    bit_ct: u32,
) -> Option<BigInt> {
    let pack = |component: &Poly<PowerBasis>| {
        if component.coefficients().nrows() != moduli.len() {
            return None;
        }
        let mut payload = Vec::new();
        for (row, modulus) in component.coefficients().outer_iter().zip(moduli.iter()) {
            payload.extend(pack_centered_rns_row(row.as_slice()?, *modulus, bit_ct)?);
        }
        Some(payload)
    };
    Some(ciphertext_commitment_from_packed(pack(ct0)?, pack(ct1)?))
}

fn ciphertext_commitment_from_packed(payload0: Vec<Field>, payload1: Vec<Field>) -> BigInt {
    let io = [0x80000000 | payload0.len() as u32, 1];
    let commit_ct0 = compute_commitments(payload0, DS_CIPHERTEXT, io)[0];

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

/// Compute hex-aligned packing parameters for a given `BIT`.
/// Matches the Noir `packing_layout` function exactly.
///
/// # Arguments
/// * `bit` - The bit width for coefficient bounds
///
/// # Returns
/// A tuple of (nibble_bits, group) where:
/// - `nibble_bits`: The bit width rounded up to the next multiple of 4
/// - `group`: Maximum number of limbs that fit in one BN254 field element
fn packing_layout(bit: u32) -> (u32, u32) {
    // Ceil BIT up to the next multiple of 4 (nibble alignment).
    let nibble_bits = bit.div_ceil(4) * 4;

    // Each stored limb uses an extra nibble because negative coefficients
    // will be shifted to positive, so radix = 2^(nibble_bits+4).
    assert!(nibble_bits + 4 <= 254);

    // Maximum limbs that fit in one BN254 element without wrap.
    let group = 254 / (nibble_bits + 4);
    assert!(group >= 1);
    (nibble_bits, group)
}

/// Pack a polynomial's coefficients into a Vec<Field> of carriers using the shared hex-aligned layout.
///
/// Matches the Noir `packer` function exactly.
/// Packs multiple coefficients into each field element using nibble-aligned layout.
///
/// # Arguments
/// * `poly` - Polynomial whose coefficients to pack
/// * `bit` - The bit width for coefficient bounds
///
/// # Returns
/// A vector of field elements containing the packed coefficients.
/// The number of field elements is `ceil(poly.coefficients().len() / group)` where `group` is
/// determined by the packing layout.
fn packer(polynomial: &Polynomial, bit: u32) -> Vec<Field> {
    packer_fixed_width(polynomial, bit).unwrap_or_else(|| packer_bigint(polynomial, bit))
}

/// Uses four machine words when each shifted coefficient fits its allocated digit.
/// Other values use the original arbitrary-precision path.
fn packer_fixed_width(polynomial: &Polynomial, bit: u32) -> Option<Vec<Field>> {
    let (nibble_bits, group) = packing_layout(bit);
    if nibble_bits > 120 {
        return None;
    }
    let digit_bits = nibble_bits + 4;
    let base = 1i128 << nibble_bits;
    let radix = 1u128 << digit_bits;
    let values = polynomial.coefficients();
    let mut output = Vec::with_capacity(values.len().div_ceil(group as usize));
    for chunk in values.chunks(group as usize) {
        let mut accumulator = FieldInteger::<4>::from(0u64);
        for index in 0..group as usize {
            let value = match chunk.get(index) {
                Some(value) => value.to_i128()?,
                None => 0,
            };
            let digit = u128::try_from(value.checked_add(base)?).ok()?;
            if digit >= radix {
                return None;
            }
            accumulator <<= digit_bits;
            let carry = accumulator.add_with_carry(&FieldInteger([
                digit as u64,
                (digit >> 64) as u64,
                0,
                0,
            ]));
            debug_assert!(!carry);
        }
        // The nibble-aligned layout uses at most 252 bits, below the field modulus.
        output.push(Field::from_bigint(accumulator)?);
    }
    Some(output)
}

fn packer_bigint(polynomial: &Polynomial, bit: u32) -> Vec<Field> {
    let values = polynomial.coefficients();
    let (nibble_bits, group) = packing_layout(bit);

    let base = BigInt::from(2).pow(nibble_bits);
    let radix = BigInt::from(2).pow(nibble_bits + 4);

    let a = values.len() as u32;
    let num_chunks = a.div_ceil(group);
    let mut out = Vec::new();

    // Process in fixed-size chunks of `group` limbs.
    for chunk in 0..num_chunks {
        // How many real values go into this chunk.
        let remain = a - (chunk * group);
        let take = if remain < group { remain } else { group };

        // Build field element accumulator (big-endian concatenation in `radix`).
        let mut acc = BigInt::zero();
        for i in 0..take {
            let v = &values[(chunk * group + i) as usize];
            acc = acc * &radix + (v + &base);
        }

        // Pad remaining limb slots with the canonical zero-limb `digit = base`.
        for _ in 0..(group - take) {
            acc = acc * &radix + &base;
        }

        // Convert BigInt to Field element
        let acc_biguint = if acc < BigInt::zero() {
            // Should not happen with our packing scheme, but handle it
            panic!("Negative accumulator in packer");
        } else {
            acc.to_biguint().unwrap()
        };

        // Convert to Field via bytes
        let bytes = acc_biguint.to_bytes_le();
        let field_elem = Field::from_le_bytes_mod_order(&bytes);
        out.push(field_elem);
    }
    out
}

/// Flatten a slice of polynomials into a single linear stream of packed `Field` carriers.
///
/// Matches the Noir `flatten` function exactly.
/// Packs each polynomial's coefficients using the same bit width and appends them sequentially.
///
/// # Arguments
/// * `inputs` - Initial vector of field elements to append to
/// * `polys` - Slice of polynomials to pack
/// * `bit` - The bit width for coefficient bounds
///
/// # Returns
/// Extended vector with packed polynomial coefficients appended in order.
/// The polynomials are packed sequentially, maintaining a stable transcript layout.
fn flatten(mut inputs: Vec<Field>, polynomials: &[Polynomial], bit: u32) -> Vec<Field> {
    for polynomial in polynomials {
        let packed = packer(polynomial, bit);
        inputs.extend(packed);
    }
    inputs
}

/// Reverses, centers, and packs one canonical RNS row without per-coefficient allocations.
/// Returns `None` if the row cannot use the fixed-width path.
fn pack_centered_rns_row(coefficients: &[u64], modulus: u64, bit: u32) -> Option<Vec<Field>> {
    let (nibble_bits, group) = packing_layout(bit);
    if modulus == 0 || nibble_bits > 120 || coefficients.iter().any(|value| *value >= modulus) {
        return None;
    }
    let base = 1i128 << nibble_bits;
    let digit_bits = nibble_bits + 4;
    let radix = 1u128 << digit_bits;
    let group = group as usize;
    let mut values = coefficients.iter().rev();
    let mut output = Vec::with_capacity(coefficients.len().div_ceil(group));
    for _ in 0..coefficients.len().div_ceil(group) {
        let mut accumulator = FieldInteger::<4>::from(0u64);
        for _ in 0..group {
            let value = values.next().copied().unwrap_or(0);
            let negative = if modulus.is_multiple_of(2) {
                value >= modulus / 2
            } else {
                value > modulus / 2
            };
            let centered = i128::from(value) - if negative { i128::from(modulus) } else { 0 };
            let digit = u128::try_from(centered.checked_add(base)?).ok()?;
            if digit >= radix {
                return None;
            }
            accumulator <<= digit_bits;
            if accumulator.add_with_carry(&FieldInteger([digit as u64, (digit >> 64) as u64, 0, 0]))
            {
                return None;
            }
        }
        output.push(Field::from_bigint(accumulator)?);
    }
    Some(output)
}

#[cfg(test)]
mod packing_tests {
    use super::*;

    #[test]
    fn direct_rns_packing_matches_reverse_center_and_bigint_packing() {
        for modulus in [
            2u64,
            3,
            16,
            17,
            65537,
            (1 << 51) - 1,
            (1 << 62) - 57,
            u64::MAX,
        ] {
            let bit = 64 - (modulus / 2).leading_zeros();
            for length in [0, 1, 3, 4, 7, 16, 31, 512] {
                let edges = [0, 1, modulus / 2, modulus - 1];
                let coefficients: Vec<_> = edges.into_iter().cycle().take(length).collect();
                let mut reference = Polynomial::from_u64_vector(coefficients.clone());
                reference.reverse();
                reference.center(&BigInt::from(modulus));
                assert_eq!(
                    pack_centered_rns_row(&coefficients, modulus, bit).unwrap(),
                    packer_bigint(&reference, bit)
                );
            }
        }
        assert!(pack_centered_rns_row(&[17], 17, 5).is_none());
        assert!(pack_centered_rns_row(&[0], 0, 5).is_none());
    }

    #[test]
    fn fixed_width_packing_matches_bigint_at_boundaries() {
        for bit in [0, 1, 4, 5, 8, 31, 32, 51, 53, 60, 64, 100, 120] {
            let (nibble_bits, group) = packing_layout(bit);
            let base = BigInt::from(1) << nibble_bits;
            let edge = [
                -&base,
                -&base + 1,
                BigInt::from(-1),
                BigInt::zero(),
                &base - 1,
                base,
            ];
            for length in [
                0,
                1,
                group as usize - 1,
                group as usize,
                group as usize + 1,
                100,
            ] {
                let polynomial =
                    Polynomial::new(edge.iter().cycle().take(length).cloned().collect());
                assert_eq!(
                    packer_fixed_width(&polynomial, bit).unwrap(),
                    packer_bigint(&polynomial, bit)
                );
            }
        }
    }

    #[test]
    fn fixed_width_packing_matches_bigint_for_deterministic_samples() {
        let mut state = 7u64;
        for bit in 1..=64 {
            let values = (0..131)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    let magnitude = u128::from(state) & ((1u128 << bit) - 1);
                    let value = BigInt::from(magnitude);
                    if state & 1 == 0 {
                        value
                    } else {
                        -value
                    }
                })
                .collect();
            let polynomial = Polynomial::new(values);
            assert_eq!(
                packer_fixed_width(&polynomial, bit).unwrap(),
                packer_bigint(&polynomial, bit)
            );
        }
    }

    #[test]
    fn packing_retains_bigint_fallback() {
        for (bit, value) in [(8, BigInt::from(1) << 40), (200, BigInt::from(1) << 199)] {
            let polynomial = Polynomial::new(vec![value]);
            assert!(packer_fixed_width(&polynomial, bit).is_none());
            assert_eq!(packer(&polynomial, bit), packer_bigint(&polynomial, bit));
        }
    }

    #[test]
    fn test_packing_layout() {
        // Test nibble alignment
        // For bit=1 or 4: nibble_bits=4, radix uses 4+4=8 bits, so group=254/8=31
        assert_eq!(packing_layout(1), (4, 31));
        assert_eq!(packing_layout(4), (4, 31));
        // For bit=5 or 8: nibble_bits=8, radix uses 8+4=12 bits, so group=254/12=21
        assert_eq!(packing_layout(5), (8, 21));
        assert_eq!(packing_layout(8), (8, 21));
        // For bit=51: nibble_bits=52, radix uses 52+4=56 bits, so group=254/56=4
        assert_eq!(packing_layout(51), (52, 4));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_polynomial::CrtPolynomial;

    #[test]
    fn compute_pk_commitment_from_keyshare_roundtrip() {
        use e3_fhe_params::{
            build_pair_for_preset, create_deterministic_crp_from_default_seed, BfvPreset,
        };
        use fhe::bfv::SecretKey;
        use fhe::mbfv::PublicKeyShare;
        use fhe_traits::Serialize;
        let preset = BfvPreset::InsecureThreshold64;
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
        let bit_pk = e3_fhe_params::utils::compute_modulus_bit(&params);
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
        use crate::dkg::pk::Inputs;
        use e3_fhe_params::{build_pair_for_preset, BfvPreset};
        use e3_zk_config::dkg::pk::Configs;
        use fhe::bfv::{PublicKey, SecretKey};
        use fhe_traits::Serialize;

        let preset = BfvPreset::InsecureThreshold64;
        let (_, dkg_params) = build_pair_for_preset(preset).unwrap();
        let mut rng = rand::rng();
        let secret_key = SecretKey::random(&dkg_params, &mut rng);
        let public_key = PublicKey::new(&secret_key, &mut rng);
        let public_key_bytes = public_key.to_bytes();

        let actual =
            compute_dkg_pk_commitment_from_public_key_bytes(&public_key_bytes, preset).unwrap();

        let config = Configs::new(&dkg_params).unwrap();
        let inputs = Inputs::compute(&config, &public_key).unwrap();
        let expected = compute_dkg_pk_commitment(&inputs.pk0is, &inputs.pk1is, config.pk_bit);
        let (_, expected_bytes) = expected.to_bytes_be();
        let mut expected_padded = [0u8; 32];
        expected_padded[32 - expected_bytes.len()..].copy_from_slice(&expected_bytes);

        assert_eq!(actual, expected_padded);
    }

    #[test]
    fn compute_dkg_pk_commitment_rejects_malformed_public_key() {
        assert!(compute_dkg_pk_commitment_from_public_key_bytes(
            b"not a BFV public key",
            e3_fhe_params::BfvPreset::InsecureThreshold64,
        )
        .is_err());
    }
}
