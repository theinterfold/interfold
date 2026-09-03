// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Native core: CKKS client-side encryption with witnessed randomness and
//! the Greco witness inputs for the `user_data_encryption_ckks_ct0` /
//! `_ct1` Noir circuits.
//!
//! This mirrors `e3_zk_helpers::threshold::user_data_encryption_ckks::Inputs::compute`
//! with ONE difference: the encryption RNG is injectable (a 32-byte seed
//! selects a deterministic ChaCha20 stream) so tests can pin a witness and
//! so a wasm caller may supply browser entropy explicitly. The witness
//! derivation is split out as [`witness_from_encryption`] so it can be
//! checked for byte-identical parity against the native builder (see the
//! crate tests).
//!
//! FOLLOW-UP MERGE NOTE (crates/zk-helpers is owned by another agent):
//! * `Inputs::compute` takes no RNG. If it gains an
//!   `Inputs::compute_with_rng`, [`witness_from_encryption`] collapses to
//!   a thin wrapper.
//! * `DS_USER_DATA_ENCRYPTION_COMMITMENT` and `crt_reconstruct` are private
//!   / nested there; local copies live here.

use ark_ff::{BigInteger, PrimeField};
use e3_polynomial::{CrtPolynomial, Polynomial};
use e3_zk_helpers::circuits::commitments::compute_commitments;
use e3_zk_helpers::threshold::user_data_encryption_ckks::{
    ckks_preset_for_param_set, generate_toml, Bits, Bounds, CkksPreset, Inputs,
};
use e3_zk_helpers::{
    compute_q_product, cyclotomic_polynomial, decompose_residue, flatten, Computation,
};
use fhe::ckks::{CkksCiphertext, CkksEncoder, CkksPlaintext, CkksPublicKey, CkksSecretKey};
use fhe_math::rq::{Ntt, Poly};
use fhe_traits::{DeserializeParametrized, Serialize as FheSerialize};
use num_bigint::{BigInt, BigUint};
use num_traits::ToPrimitive;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

/// Error type of the CKKS witness builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CkksZkError(pub String);

impl std::fmt::Display for CkksZkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CkksZkError {}

impl From<String> for CkksZkError {
    fn from(s: String) -> Self {
        CkksZkError(s)
    }
}

impl From<&str> for CkksZkError {
    fn from(s: &str) -> Self {
        CkksZkError(s.to_string())
    }
}

pub type Result<T> = std::result::Result<T, CkksZkError>;

fn err<E: std::fmt::Display>(context: &str) -> impl FnOnce(E) -> CkksZkError + '_ {
    move |e| CkksZkError(format!("{context}: {e}"))
}

/// Domain separator `"USER_DATA_ENCRYPTION_COMMITMENT"` zero-padded to 64
/// bytes — MUST match `lib::math::commitments::DS_USER_DATA_ENCRYPTION_COMMITMENT`
/// in the Noir lib (the `u` / `m` commitments of both Greco legs).
pub const DS_USER_DATA_ENCRYPTION_COMMITMENT: [u8; 64] = {
    let name = b"USER_DATA_ENCRYPTION_COMMITMENT";
    let mut ds = [0u8; 64];
    let mut i = 0;
    while i < name.len() {
        ds[i] = name[i];
        i += 1;
    }
    ds
};

/// Keys the `user_data_encryption_ckks_ct0*` circuits declare.
pub const CT0_KEYS: &[&str] = &["pk0is", "ct0is", "u", "e0", "m", "r1is", "r2is"];
/// Keys the `user_data_encryption_ckks_ct1*` circuits declare.
pub const CT1_KEYS: &[&str] = &["pk1is", "ct1is", "u", "e1", "p1is", "p2is"];

/// Public description of a param set, for JS callers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamSetInfo {
    pub param_set: u8,
    pub degree: usize,
    pub slots: usize,
    /// Moduli as decimal strings (u64 does not survive JSON in JS).
    pub moduli: Vec<String>,
    pub scale_bits: u32,
    pub input_bound: f64,
    pub num_limbs: usize,
}

/// Everything one client encryption produces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessBundle {
    pub param_set: u8,
    /// Serialized `CkksCiphertext` (fhe.rs wire encoding), hex without 0x.
    pub ciphertext_hex: String,
    /// Prover.toml for the ct0 leg (native `generate_toml` output; carries
    /// both legs' keys — nargo ignores undeclared keys).
    pub prover_toml_ct0: String,
    /// Prover.toml for the ct1 leg (identical bytes to `prover_toml_ct0`;
    /// a separate field so callers never have to know that).
    pub prover_toml_ct1: String,
    /// Full circuit-input JSON (native `Inputs::to_json` shape).
    pub circuit_inputs: serde_json::Value,
    /// noir_js `InputMap` for the ct0 circuit: only the keys `main`
    /// declares, every coefficient as a canonical-field DECIMAL STRING.
    pub ct0_inputs: serde_json::Value,
    /// noir_js `InputMap` for the ct1 circuit (same convention).
    pub ct1_inputs: serde_json::Value,
    /// `u_commitment` public output shared by both legs (0x + 32-byte hex).
    pub u_commitment_hex: String,
    /// `m_commitment` public output of the ct0 leg (0x + 32-byte hex).
    pub m_commitment_hex: String,
    /// The scaled message polynomial `m` as fed to the circuit (reversed,
    /// centered mod Q), signed decimal strings.
    pub message_poly: Vec<String>,
    /// `m` per CRT limb (reversed, centered mod `q_i`), signed decimal
    /// strings — the shape an app-validity circuit consumes limb-wise.
    pub message_poly_limbs: Vec<Vec<String>>,
    /// The normalized value(s) that were encoded (`value / cap`).
    pub encoded_values: Vec<f64>,
}

/// Build the canonical CKKS preset (params + input bound) for an on-chain
/// `ParamSet` value (0, 2, 3).
pub fn preset_for_param_set(param_set: u8) -> Result<CkksPreset> {
    ckks_preset_for_param_set(param_set).map_err(err("preset"))
}

/// Serialized `CkksParameters` for the param set (fhe.rs wire encoding).
pub fn params_bytes_for_param_set(param_set: u8) -> Result<Vec<u8>> {
    Ok(preset_for_param_set(param_set)?.params.to_bytes())
}

/// JSON-friendly description of the param set.
pub fn param_set_info(param_set: u8) -> Result<ParamSetInfo> {
    let preset = preset_for_param_set(param_set)?;
    let params = &preset.params;
    Ok(ParamSetInfo {
        param_set,
        degree: params.degree(),
        slots: params.degree() / 2,
        moduli: params.moduli().iter().map(|q| q.to_string()).collect(),
        scale_bits: params.scale().log2().round() as u32,
        input_bound: preset.input_bound,
        num_limbs: params.moduli().len(),
    })
}

/// Deterministic RNG from a 32-byte seed, or OS/browser entropy.
pub fn rng_from_seed(seed: Option<&[u8]>) -> Result<ChaCha20Rng> {
    match seed {
        Some(s) => {
            let arr: [u8; 32] = s
                .try_into()
                .map_err(|_| CkksZkError(format!("seed must be 32 bytes, got {}", s.len())))?;
            Ok(ChaCha20Rng::from_seed(arr))
        }
        None => Ok(ChaCha20Rng::from_rng(&mut rand::rng())),
    }
}

/// Encrypt `value / cap` under `pk` (optionally slot-replicated) and build
/// the Greco witness bundle. ONE encryption feeds the ciphertext AND both
/// witness tomls.
pub fn encrypt_and_witness(
    param_set: u8,
    pk_bytes: &[u8],
    value: f64,
    cap: f64,
    replicate_slots: bool,
    seed: Option<&[u8]>,
) -> Result<WitnessBundle> {
    let mut rng = rng_from_seed(seed)?;
    encrypt_and_witness_with_rng(param_set, pk_bytes, value, cap, replicate_slots, &mut rng)
}

/// [`encrypt_and_witness`] with a caller-supplied RNG.
pub fn encrypt_and_witness_with_rng<R: RngCore + CryptoRng>(
    param_set: u8,
    pk_bytes: &[u8],
    value: f64,
    cap: f64,
    replicate_slots: bool,
    rng: &mut R,
) -> Result<WitnessBundle> {
    if !(cap.is_finite() && cap > 0.0) {
        return Err("cap must be a positive finite number".into());
    }
    if !value.is_finite() {
        return Err("value must be finite".into());
    }
    let preset = preset_for_param_set(param_set)?;
    let normalized = value / cap;
    if normalized.abs() > preset.input_bound {
        return Err(format!(
            "normalized value {normalized} exceeds the param-set input bound {} \
             (value {value} over cap {cap})",
            preset.input_bound
        )
        .into());
    }
    let pk = CkksPublicKey::from_bytes(pk_bytes, &preset.params)
        .map_err(err("CKKS public key decode"))?;

    let slots = preset.params.degree() / 2;
    let values = if replicate_slots {
        vec![normalized; slots]
    } else {
        vec![normalized]
    };

    let encoder = CkksEncoder::new(&preset.params);
    let pt = encoder.encode(&values, 0).map_err(err("CKKS encode"))?;
    let (ct, u, e0, e1) = pk
        .try_encrypt_extended(&pt, rng)
        .map_err(err("CKKS encrypt"))?;

    let inputs = witness_from_encryption(&preset, &pk, &pt, &ct, &u, &e0, &e1)?;
    bundle_from_inputs(param_set, &preset, inputs, values)
}

/// Greco witness derivation from an extended encryption — the exact math
/// of the native `Inputs::compute` (witness polys reversed + centered,
/// `e0`/`m` lifted centered mod Q, per-limb `r1/r2` and `p1/p2` quotients
/// from `decompose_residue`).
#[allow(clippy::too_many_arguments)]
pub fn witness_from_encryption(
    preset: &CkksPreset,
    pk: &CkksPublicKey,
    pt: &CkksPlaintext,
    ct: &CkksCiphertext,
    u: &Poly<Ntt>,
    e0: &Poly<Ntt>,
    e1: &Poly<Ntt>,
) -> Result<Inputs> {
    let params = &preset.params;
    let moduli = params.moduli();
    let n = params.degree() as u64;
    let cyclo = cyclotomic_polynomial(n);

    // Randomness u and error e1: first limb, centered (small polynomials).
    let mut u_poly = CrtPolynomial::from_fhe_polynomial(u).limb(0).clone();
    let mut e1_poly = CrtPolynomial::from_fhe_polynomial(e1).limb(0).clone();
    u_poly.center(&BigInt::from(moduli[0]));
    u_poly.reverse();
    e1_poly.center(&BigInt::from(moduli[0]));
    e1_poly.reverse();

    // e0 and m: unique centered lift mod Q, then reversed.
    let e0_poly = lift_mod_q_centered(&CrtPolynomial::from_fhe_polynomial(e0), moduli)?;
    let m_poly = lift_mod_q_centered(&CrtPolynomial::from_fhe_polynomial(pt.poly()), moduli)?;

    let mut ct0 = CrtPolynomial::from_fhe_polynomial(&ct[0]);
    let mut ct1 = CrtPolynomial::from_fhe_polynomial(&ct[1]);
    let mut pk0 = CrtPolynomial::from_fhe_polynomial(&pk.c[0]);
    let mut pk1 = CrtPolynomial::from_fhe_polynomial(&pk.c[1]);
    for p in [&mut ct0, &mut ct1, &mut pk0, &mut pk1] {
        p.reverse();
        p.center(moduli).map_err(err("center"))?;
    }

    let l = moduli.len();
    let mut pk0is = Vec::with_capacity(l);
    let mut pk1is = Vec::with_capacity(l);
    let mut ct0is = Vec::with_capacity(l);
    let mut ct1is = Vec::with_capacity(l);
    let mut r1is = Vec::with_capacity(l);
    let mut r2is = Vec::with_capacity(l);
    let mut p1is = Vec::with_capacity(l);
    let mut p2is = Vec::with_capacity(l);

    let e0_plus_m = e0_poly.add(&m_poly);
    for (i, qi) in moduli.iter().enumerate() {
        let qi_bigint = BigInt::from(*qi);
        let ct0i = ct0.limbs[i].clone();
        let ct1i = ct1.limbs[i].clone();
        let pk0i = pk0.limbs[i].clone();
        let pk1i = pk1.limbs[i].clone();

        // ct0i_hat = pk0i*u + e0 + m over the integers.
        let ct0i_hat = pk0i.mul(&u_poly).add(&e0_plus_m);
        let (r1i, r2i) = decompose_residue(&ct0i, &ct0i_hat, &qi_bigint, &cyclo, n);

        // ct1i_hat = pk1i*u + e1.
        let ct1i_hat = pk1i.mul(&u_poly).add(&e1_poly);
        let (p1i, p2i) = decompose_residue(&ct1i, &ct1i_hat, &qi_bigint, &cyclo, n);

        pk0is.push(pk0i);
        pk1is.push(pk1i);
        ct0is.push(ct0i);
        ct1is.push(ct1i);
        r1is.push(r1i);
        r2is.push(r2i);
        p1is.push(p1i);
        p2is.push(p2i);
    }

    Ok(Inputs {
        pk0is: CrtPolynomial::new(pk0is),
        pk1is: CrtPolynomial::new(pk1is),
        ct0is: CrtPolynomial::new(ct0is),
        ct1is: CrtPolynomial::new(ct1is),
        r1is: CrtPolynomial::new(r1is),
        r2is: CrtPolynomial::new(r2is),
        p1is: CrtPolynomial::new(p1is),
        p2is: CrtPolynomial::new(p2is),
        e0: e0_poly,
        e1: e1_poly,
        u: u_poly,
        m: m_poly,
        ciphertext: ct.to_bytes(),
    })
}

fn lift_mod_q_centered(crt: &CrtPolynomial, moduli: &[u64]) -> Result<Polynomial> {
    let q_product = BigInt::from(compute_q_product(moduli));
    let half_q = (&q_product - BigInt::from(1)) / BigInt::from(2);
    let degree = crt
        .limbs
        .first()
        .map(|l| l.coefficients().len())
        .ok_or("empty CRT polynomial")?;
    let mut coeffs = Vec::with_capacity(degree);
    for j in 0..degree {
        let residues: Vec<u64> = crt
            .limbs
            .iter()
            .map(|limb| {
                limb.coefficients()[j]
                    .to_u64()
                    .ok_or_else(|| CkksZkError("RNS residue does not fit u64".into()))
            })
            .collect::<Result<_>>()?;
        let v = BigInt::from(crt_reconstruct(&residues, moduli)?);
        coeffs.push(if v > half_q { v - &q_product } else { v });
    }
    let mut poly = Polynomial::new(coeffs);
    poly.reverse();
    Ok(poly)
}

/// CRT reconstruction: residues `x_i in [0, q_i)` -> unique `x in [0, Q)`.
fn crt_reconstruct(residues: &[u64], moduli: &[u64]) -> Result<BigUint> {
    if residues.len() != moduli.len() {
        return Err("crt_reconstruct: residues/moduli length mismatch".into());
    }
    let q = BigInt::from(compute_q_product(moduli));
    let mut acc = BigInt::from(0);
    for (r, m) in residues.iter().zip(moduli) {
        let mi = BigInt::from(*m);
        let qi = &q / &mi;
        let inv = mod_inverse(&qi, &mi).ok_or("crt_reconstruct: non-coprime moduli")?;
        acc += BigInt::from(*r) * qi * inv;
    }
    let acc = ((acc % &q) + &q) % &q;
    acc.to_biguint()
        .ok_or_else(|| "crt_reconstruct: negative".into())
}

fn mod_inverse(a: &BigInt, m: &BigInt) -> Option<BigInt> {
    let (mut old_r, mut r) = (((a % m) + m) % m, m.clone());
    let (mut old_s, mut s) = (BigInt::from(1), BigInt::from(0));
    while r != BigInt::from(0) {
        let q = &old_r / &r;
        let tmp = &old_r - &q * &r;
        old_r = std::mem::replace(&mut r, tmp);
        let tmp = &old_s - &q * &s;
        old_s = std::mem::replace(&mut s, tmp);
    }
    if old_r != BigInt::from(1) {
        return None;
    }
    Some(((old_s % m) + m) % m)
}

/// Pack an [`Inputs`] struct into the JS-facing bundle.
pub fn bundle_from_inputs(
    param_set: u8,
    preset: &CkksPreset,
    inputs: Inputs,
    encoded_values: Vec<f64>,
) -> Result<WitnessBundle> {
    let bounds = Bounds::compute(preset.clone(), &()).map_err(err("bounds"))?;
    let bits = Bits::compute(preset.clone(), &bounds).map_err(err("bits"))?;

    let u_commitment_hex = single_poly_commitment_hex(&inputs.u, bits.u_bit);
    let m_commitment_hex = single_poly_commitment_hex(&inputs.m, bits.m_bit);

    let message_poly: Vec<String> = inputs
        .m
        .coefficients()
        .iter()
        .map(|c| c.to_string())
        .collect();
    let message_poly_limbs = m_limbs(&inputs.m, preset.params.moduli());

    let circuit_inputs = inputs.to_json().map_err(err("inputs to_json"))?;
    let ct0_inputs = pick_stringified(&circuit_inputs, CT0_KEYS);
    let ct1_inputs = pick_stringified(&circuit_inputs, CT1_KEYS);

    let ciphertext_hex = hex::encode(&inputs.ciphertext);
    let toml = generate_toml(inputs).map_err(err("generate_toml"))?;

    Ok(WitnessBundle {
        param_set,
        ciphertext_hex,
        prover_toml_ct0: toml.clone(),
        prover_toml_ct1: toml,
        circuit_inputs,
        ct0_inputs,
        ct1_inputs,
        u_commitment_hex,
        m_commitment_hex,
        message_poly,
        message_poly_limbs,
        encoded_values,
    })
}

/// Sub-select `keys` and turn every JSON number into its decimal string
/// (noir_js takes strings; JS numbers lose precision above 2^53).
fn pick_stringified(all: &serde_json::Value, keys: &[&str]) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    for k in keys {
        if let Some(v) = all.get(*k) {
            out.insert((*k).to_string(), stringify_numbers(v));
        }
    }
    serde_json::Value::Object(out)
}

fn stringify_numbers(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Number(n) => serde_json::Value::String(n.to_string()),
        serde_json::Value::Array(a) => {
            serde_json::Value::Array(a.iter().map(stringify_numbers).collect())
        }
        serde_json::Value::Object(o) => serde_json::Value::Object(
            o.iter()
                .map(|(k, v)| (k.clone(), stringify_numbers(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// `m` reduced + centered per CRT limb (keeps the circuit's reversed order).
fn m_limbs(m: &Polynomial, moduli: &[u64]) -> Vec<Vec<String>> {
    moduli
        .iter()
        .map(|q| {
            let mut limb = m.clone();
            let qb = BigInt::from(*q);
            limb.reduce(&qb);
            limb.center(&qb);
            limb.coefficients().iter().map(|c| c.to_string()).collect()
        })
        .collect()
}

/// `compute_single_polynomial_commitment::<N, BIT>(poly, DS_USER_DATA_ENCRYPTION_COMMITMENT)`
/// as the Noir lib computes it: flatten with the BIT layout, SAFE sponge
/// with io pattern `[ABSORB(len), SQUEEZE(1)]`.
pub fn single_poly_commitment(poly: &Polynomial, bit: u32) -> BigUint {
    let payload = flatten(Vec::new(), std::slice::from_ref(poly), bit);
    let io = [0x8000_0000 | payload.len() as u32, 1];
    let field = compute_commitments(payload, DS_USER_DATA_ENCRYPTION_COMMITMENT, io)[0];
    BigUint::from_bytes_le(&field.into_bigint().to_bytes_le())
}

fn single_poly_commitment_hex(poly: &Polynomial, bit: u32) -> String {
    let bytes = single_poly_commitment(poly, bit).to_bytes_be();
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(&bytes);
    format!("0x{}", hex::encode(padded))
}

/// Recompute the `(u_commitment, m_commitment)` pair from a circuit-input
/// JSON (either the full `circuit_inputs` or a `ct0_inputs` map).
pub fn commitments_from_inputs_json(
    param_set: u8,
    inputs: &serde_json::Value,
) -> Result<(String, String)> {
    let preset = preset_for_param_set(param_set)?;
    let bounds = Bounds::compute(preset.clone(), &()).map_err(err("bounds"))?;
    let bits = Bits::compute(preset, &bounds).map_err(err("bits"))?;
    let u = poly_from_json(inputs.get("u").ok_or("missing `u`")?)?;
    let m = poly_from_json(inputs.get("m").ok_or("missing `m`")?)?;
    Ok((
        single_poly_commitment_hex(&u, bits.u_bit),
        single_poly_commitment_hex(&m, bits.m_bit),
    ))
}

/// Parse `{"coefficients": [...]}` back to a signed polynomial (canonical
/// field values above p/2 are read as negatives).
fn poly_from_json(v: &serde_json::Value) -> Result<Polynomial> {
    let p = e3_zk_helpers::get_zkp_modulus();
    let half = &p / BigInt::from(2);
    let coeffs = v
        .get("coefficients")
        .and_then(|c| c.as_array())
        .ok_or("polynomial JSON must have a `coefficients` array")?;
    let mut out = Vec::with_capacity(coeffs.len());
    for c in coeffs {
        let s = match c {
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::String(s) => s.clone(),
            _ => return Err("coefficient must be a number or decimal string".into()),
        };
        let mut x: BigInt = s
            .parse()
            .map_err(|_| CkksZkError(format!("bad coefficient {s}")))?;
        if x > half {
            x -= &p;
        }
        out.push(x);
    }
    Ok(Polynomial::new(out))
}

/// Public wrapper of [`poly_from_json`] for the wasm layer.
pub fn poly_from_json_pub(v: &serde_json::Value) -> Result<Polynomial> {
    poly_from_json(v)
}

/// Public wrapper of [`m_limbs`] for the wasm layer.
pub fn m_limbs_pub(m: &Polynomial, moduli: &[u64]) -> Vec<Vec<String>> {
    m_limbs(m, moduli)
}

/// Key generation helper (fixtures / tests): returns `(sk_bytes, pk_bytes)`.
pub fn generate_keypair<R: RngCore + CryptoRng>(
    param_set: u8,
    rng: &mut R,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let preset = preset_for_param_set(param_set)?;
    let sk = CkksSecretKey::random(&preset.params, rng);
    let pk = CkksPublicKey::new(&sk, rng).map_err(err("pk"))?;
    Ok((sk.to_bytes(), pk.to_bytes()))
}

/// Decrypt + decode a ciphertext (tests / fixtures only).
pub fn decrypt(param_set: u8, sk_bytes: &[u8], ct_bytes: &[u8]) -> Result<Vec<f64>> {
    let preset = preset_for_param_set(param_set)?;
    let sk = CkksSecretKey::from_bytes(sk_bytes, &preset.params).map_err(err("sk decode"))?;
    let ct = CkksCiphertext::from_bytes(ct_bytes, &preset.params).map_err(err("ct decode"))?;
    let pt = sk.try_decrypt(&ct).map_err(err("decrypt"))?;
    CkksEncoder::new(&preset.params)
        .decode(&pt)
        .map_err(err("decode"))
}
