// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::shares::ShamirShare;
use anyhow::Result;
use e3_crypto::{Cipher, SensitiveBytes};
use fhe::mbfv::PublicKeyShare;
use fhe::{
    bfv::{self, BfvParameters, SecretKey},
    trbfv::{Lambda, SmudgingBoundCalculator, SmudgingBoundCalculatorConfig},
};
use fhe_math::rq::{Ntt, Poly, PowerBasis, RepresentationTag};
use fhe_traits::DeserializeWithContext;
use fhe_traits::Serialize as FheSerialize;
use num_bigint::BigUint;
use petname::Petnames;
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use std::{
    hash::{DefaultHasher, Hash, Hasher},
    sync::Arc,
};

/// Simple serialization wrapper for SecretKey coefficients.
#[derive(SerdeSerialize, SerdeDeserialize)]
struct SecretKeyData {
    coeffs: Box<[i64]>,
}

/// Serialize a BFV SecretKey to bytes.
pub fn serialize_secret_key(sk: &SecretKey) -> Result<Vec<u8>> {
    let data = SecretKeyData {
        coeffs: sk.coeffs.clone(),
    };
    Ok(bincode::serialize(&data)?)
}

/// Deserialize a BFV SecretKey from bytes.
pub fn deserialize_secret_key(bytes: &[u8], params: &Arc<BfvParameters>) -> Result<SecretKey> {
    let data: SecretKeyData = bincode::deserialize(bytes)?;
    Ok(SecretKey::new(data.coeffs.to_vec(), params))
}

pub fn try_poly_pb_from_bytes(bytes: &[u8], params: &BfvParameters) -> Result<Poly<PowerBasis>> {
    Ok(Poly::<PowerBasis>::from_bytes(
        bytes,
        params.context_at_level(0)?,
    )?)
}

pub fn try_poly_ntt_from_bytes(bytes: &[u8], params: &BfvParameters) -> Result<Poly<Ntt>> {
    Ok(Poly::<Ntt>::from_bytes(bytes, params.context_at_level(0)?)?)
}

pub fn try_poly_from_sensitive_bytes(
    bytes: SensitiveBytes,
    params: Arc<BfvParameters>,
    cipher: &Cipher,
) -> Result<Poly<PowerBasis>> {
    try_poly_pb_from_bytes(&bytes.access(cipher)?, &params)
}

pub fn try_polys_from_sensitive_bytes_vec(
    bytes_vec: Vec<SensitiveBytes>,
    params: Arc<BfvParameters>,
    cipher: &Cipher,
) -> Result<Vec<Poly<PowerBasis>>> {
    bytes_vec
        .into_iter()
        .map(|s| try_poly_from_sensitive_bytes(s, params.clone(), cipher))
        .collect::<Result<Vec<_>>>()
}

pub fn calculate_error_size(
    params: Arc<bfv::BfvParameters>,
    n: usize,
    num_ciphertexts: usize,
    lambda: Lambda,
) -> Result<BigUint> {
    let config = SmudgingBoundCalculatorConfig::new(params, n, num_ciphertexts, lambda);
    let calculator = SmudgingBoundCalculator::new(config);
    Ok(calculator.calculate_sm_bound()?)
}

pub fn stringify_poly<R: RepresentationTag>(name: &str, poly: &Poly<R>) -> String {
    format!("{}=Poly({})", name, hash_to_petname(hash_poly(poly)))
}

pub fn print_public_key_share(name: &str, pubkey: &PublicKeyShare) {
    println!("{}", stringify_public_key_share(name, pubkey));
}

pub fn print_shamir_share(name: &str, share: &ShamirShare) {
    println!("ShamirShare({})", stringify_shamir_share(name, share));
}

pub fn print_shamir_share_vec(name: &str, share: Vec<ShamirShare>) {
    println!("Vec<ShamirShare>({})", name);
    share.iter().for_each(|sh| print_shamir_share(" ", sh));
}

pub fn print_shamir_share_vec_vec(name: &str, share: Vec<Vec<ShamirShare>>) {
    println!("Vec<Vec<ShamirShare>>({})", name);
    share
        .iter()
        .for_each(|vsh| print_shamir_share_vec(" ", vsh.clone()))
}

fn hash_to_petname(hash: u64) -> String {
    let petnames = Petnames::default();

    // Access as fields, not methods:
    let adjectives = &petnames.adjectives;
    let nouns = &petnames.nouns;

    let adj_idx = (hash % adjectives.len() as u64) as usize;
    let noun_idx = ((hash / adjectives.len() as u64) % nouns.len() as u64) as usize;

    format!("{}-{}", adjectives[adj_idx], nouns[noun_idx])
}

pub fn hash_to_colored_petname(hash: u64) -> String {
    let petname = hash_to_petname(hash);
    format!("{}  {}  {}", hash_to_bg_color(hash), petname, reset_color())
}

fn hash_poly<R: RepresentationTag>(poly: &Poly<R>) -> u64 {
    hash_bytes(&poly.to_bytes())
}

pub fn hash_bytes(data: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    hasher.finish()
}

fn stringify_shamir_share(name: &str, share: &ShamirShare) -> String {
    format!(
        "{}{}",
        name,
        hash_to_colored_petname(hash_share(share).unwrap())
    )
}

fn stringify_public_key_share(name: &str, share: &PublicKeyShare) -> String {
    format!(
        "{}{}",
        name,
        hash_to_colored_petname(hash_pubkey_share(share).unwrap())
    )
}

fn hash_share(share: &ShamirShare) -> Result<u64> {
    let bytes = bincode::serialize(share)?;
    Ok(hash_bytes(&bytes))
}

fn hash_pubkey_share(share: &PublicKeyShare) -> Result<u64> {
    let bytes = share.to_bytes();
    Ok(hash_bytes(&bytes))
}

fn hash_to_bg_color(hash: u64) -> String {
    // Extract RGB from the hash
    let r = (hash & 0xFF) as u8;
    let g = ((hash >> 8) & 0xFF) as u8;
    let b = ((hash >> 16) & 0xFF) as u8;

    // Calculate relative luminance
    let luminance = (0.299 * r as f64 + 0.587 * g as f64 + 0.114 * b as f64) / 255.0;

    // Choose black or white text based on luminance
    let fg_color = if luminance > 0.5 {
        "\x1b[30m"
    } else {
        "\x1b[97m"
    };

    // Return ANSI escape code for background + foreground
    format!("\x1b[48;2;{};{};{}m{}", r, g, b, fg_color)
}

fn reset_color() -> &'static str {
    "\x1b[0m"
}
