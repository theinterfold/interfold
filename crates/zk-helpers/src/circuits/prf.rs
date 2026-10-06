// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Rust twin of `circuits/lib/src/math/prf.nr`.
//!
//! Party ids are 1-based. Ciphertext coefficients are absorbed low degree first.
//! Returned mask rows are low degree first.

use super::commitments::compute_prf_key_commitment;
use crate::utils::compute_safe;
use ark_bn254::Fr as Field;
use ark_ff::{BigInteger, PrimeField};
use e3_fhe_params::BfvPreset;
use e3_polynomial::Polynomial;
use num_bigint::{BigInt, BigUint, Sign};

const ABSORB_FLAG: u32 = 0x8000_0000;

/// Domain separator `fhe.rs/trbfv/prf/poseidon2/ctx`.
const DS_PRF_CTX: [u8; 64] = [
    0x66, 0x68, 0x65, 0x2e, 0x72, 0x73, 0x2f, 0x74, 0x72, 0x62, 0x66, 0x76, 0x2f, 0x70, 0x72, 0x66,
    0x2f, 0x70, 0x6f, 0x73, 0x65, 0x69, 0x64, 0x6f, 0x6e, 0x32, 0x2f, 0x63, 0x74, 0x78, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Domain separator `fhe.rs/trbfv/prf/poseidon2/eval`.
const DS_PRF_EVAL: [u8; 64] = [
    0x66, 0x68, 0x65, 0x2e, 0x72, 0x73, 0x2f, 0x74, 0x72, 0x62, 0x66, 0x76, 0x2f, 0x70, 0x72, 0x66,
    0x2f, 0x70, 0x6f, 0x73, 0x65, 0x69, 0x64, 0x6f, 0x6e, 0x32, 0x2f, 0x65, 0x76, 0x61, 0x6c, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

fn field_mod_u64(value: Field, modulus: u64) -> u64 {
    let bytes = value.into_bigint().to_bytes_le();
    let reduced = BigUint::from_bytes_le(&bytes) % BigUint::from(modulus);
    reduced.to_u64_digits().first().copied().unwrap_or(0)
}

fn key_field(key: &[u8]) -> Field {
    Field::from_le_bytes_mod_order(key)
}

fn push_ciphertext(input: &mut Vec<Field>, limbs: &[Polynomial]) {
    let degree = limbs.first().map(|poly| poly.coefficients().len()).unwrap_or(0);
    input.push(Field::from(limbs.len() as u64));
    input.push(Field::from(degree as u64));
    for limb in limbs {
        let coeffs = limb.coefficients();
        for col in 0..degree {
            let coefficient = &coeffs[degree - 1 - col];
            let bytes = coefficient.to_bytes_le().1;
            let mut le = [0u8; 32];
            let copy = bytes.len().min(32);
            le[..copy].copy_from_slice(&bytes[..copy]);
            input.push(Field::from_le_bytes_mod_order(&le));
        }
    }
}

fn evaluate(key: &[u8], digest: &[Field], moduli: &[u64], degree: usize) -> Vec<Vec<u64>> {
    let squeeze_len = moduli.len() * degree;
    let squeezed = compute_safe(
        DS_PRF_EVAL,
        vec![key_field(key), digest[0], digest[1]],
        [ABSORB_FLAG | 3, squeeze_len as u32],
    );
    moduli
        .iter()
        .enumerate()
        .map(|(row, modulus)| {
            (0..degree)
                .map(|col| field_mod_u64(squeezed[row * degree + col], *modulus))
                .collect()
        })
        .collect()
}

fn add_rows(acc: &mut [Vec<u64>], positive: &[Vec<u64>], negative: &[Vec<u64>], moduli: &[u64]) {
    for (row, modulus) in moduli.iter().enumerate() {
        let q = u128::from(*modulus);
        for col in 0..acc[row].len() {
            let combined = u128::from(acc[row][col]) + u128::from(positive[row][col]) + q
                - u128::from(negative[row][col]);
            acc[row][col] = (combined % q) as u64;
        }
    }
}

/// Mask coefficients in low-degree-first order, one row per CRT limb.
///
/// `ct0` and `ct1` are circuit-order polynomials (highest degree first).
/// `decryptors` holds 1-based party ids. Keys are indexed by the 0-based party.
pub fn decryption_mask_low_degree(
    party_idx: usize,
    decryptors: &[u32],
    outgoing_keys: &[Vec<u8>],
    incoming_keys: &[Vec<u8>],
    ct0: &[Polynomial],
    ct1: &[Polynomial],
    moduli: &[u64],
) -> Result<Vec<Vec<u64>>, String> {
    if ct0.len() != moduli.len() || ct1.len() != moduli.len() {
        return Err("PRF ciphertext limb count does not match the moduli".into());
    }
    if outgoing_keys.len() != incoming_keys.len() {
        return Err("PRF outgoing and incoming key counts differ".into());
    }
    if party_idx >= outgoing_keys.len() {
        return Err("PRF party index is outside the key list".into());
    }
    if outgoing_keys.iter().chain(incoming_keys).any(Vec::is_empty) {
        return Err("PRF key is empty".into());
    }
    if outgoing_keys
        .iter()
        .chain(incoming_keys)
        .any(|key| key.iter().all(|byte| *byte == 0))
    {
        return Err("PRF key is all zeros".into());
    }
    let degree = ct0.first().map(|poly| poly.coefficients().len()).unwrap_or(0);
    let h = decryptors.len();
    let mut input = Vec::new();
    input.push(Field::from(h as u64));
    for id in decryptors {
        input.push(Field::from(u64::from(*id)));
    }
    input.push(Field::from(0u64));
    input.push(Field::from(2u64));
    push_ciphertext(&mut input, ct0);
    push_ciphertext(&mut input, ct1);
    let absorb_len = input.len() as u32;
    let digest = compute_safe(DS_PRF_CTX, input, [ABSORB_FLAG | absorb_len, 2]);

    let mut mask = vec![vec![0u64; degree]; moduli.len()];
    for (other, (outgoing, incoming)) in outgoing_keys.iter().zip(incoming_keys).enumerate() {
        let other_id = (other + 1) as u32;
        if other != party_idx && decryptors.contains(&other_id) {
            let positive = evaluate(outgoing, &digest, moduli, degree);
            let negative = evaluate(incoming, &digest, moduli, degree);
            add_rows(&mut mask, &positive, &negative, moduli);
        }
    }
    Ok(mask)
}

/// Require one non-empty key per party. An empty list or an empty key is rejected.
pub fn resolve_keys(keys: &[Vec<u8>], count: usize) -> Result<Vec<Vec<u8>>, String> {
    if keys.is_empty() {
        return Err("PRF key list is empty".into());
    }
    if keys.len() != count {
        return Err(format!(
            "PRF key count {} does not match the required count {count}",
            keys.len()
        ));
    }
    if keys.iter().any(Vec::is_empty) {
        return Err("PRF key is empty".into());
    }
    Ok(keys.to_vec())
}

/// Require one non-empty key.
pub fn resolve_key(key: &[u8]) -> Result<Vec<u8>, String> {
    if key.is_empty() {
        return Err("PRF key is empty".into());
    }
    Ok(key.to_vec())
}

/// Decimal commitment of one key under the 0-based recipient.
pub fn prf_key_commitment_bigint(recipient_party_idx: u32, key: &[u8]) -> BigInt {
    let field = compute_prf_key_commitment(recipient_party_idx, key);
    BigInt::from_bytes_le(Sign::Plus, &field.into_bigint().to_bytes_le())
}

/// Key bits as JSON numbers. Bit 0 is the least significant bit of the first byte.
pub fn prf_key_bits_json(key: &[u8]) -> Vec<serde_json::Value> {
    e3_fhe_params::prf_key_bits(key)
        .into_iter()
        .map(|bit| serde_json::Value::from(u64::from(bit)))
        .collect()
}

/// Turn low-degree mask rows into circuit-order polynomials.
pub fn circuit_order_mask(low_degree: &[Vec<u64>]) -> Vec<Polynomial> {
    low_degree
        .iter()
        .map(|row| {
            let mut poly = Polynomial::from_u64_vector(row.clone());
            poly.reverse();
            poly
        })
        .collect()
}

/// One all-zero key per party.
pub fn zero_keys(preset: BfvPreset, count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|_| e3_fhe_params::zero_prf_key(preset))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_key_list_is_rejected() {
        let error = resolve_keys(&[], 3).unwrap_err();
        assert!(error.contains("empty"));
    }

    #[test]
    fn empty_key_is_rejected() {
        let error = resolve_key(&[]).unwrap_err();
        assert!(error.contains("empty"));
        let error = resolve_keys(&[vec![1, 2, 3, 4], Vec::new()], 2).unwrap_err();
        assert!(error.contains("empty"));
    }

    #[test]
    fn empty_prf_key_does_not_return_a_zero_mask() {
        let limb = Polynomial::from_u64_vector(vec![1, 2, 3, 4]);
        let error = decryption_mask_low_degree(
            0,
            &[1, 2],
            &[Vec::new(), Vec::new()],
            &[vec![0, 0, 0, 0], vec![0, 0, 0, 0]],
            &[limb.clone()],
            &[limb],
            &[97],
        )
        .unwrap_err();
        assert!(error.contains("empty"));
    }

    #[test]
    fn all_zero_prf_key_is_rejected() {
        let limb = Polynomial::from_u64_vector(vec![1, 2, 3, 4]);
        let zeros = vec![0u8; 4];
        let error = decryption_mask_low_degree(
            0,
            &[1, 2],
            &[zeros.clone(), vec![1, 0, 0, 0]],
            &[zeros, vec![2, 0, 0, 0]],
            &[limb.clone()],
            &[limb],
            &[97],
        )
        .unwrap_err();
        assert!(error.contains("all zeros"));
    }
}
