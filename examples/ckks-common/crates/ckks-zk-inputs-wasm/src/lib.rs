// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS client-side encryption + Greco witness inputs, with WASM/JavaScript
//! bindings (mirrors CRISP's `zk-inputs-wasm`).
//!
//! JS surface (all JSON in / out, numbers that may exceed 2^53 are decimal
//! strings):
//! * `ckksParamsForParamSet(set) -> Uint8Array` — serialized `CkksParameters`.
//! * `ckksParamSetInfo(set) -> object` — degree/slots/moduli/scale/bound.
//! * `encryptAndWitness(set, pk, value, cap, replicateSlots, seed?) -> object`
//!   — one encryption; ciphertext + both Prover.tomls + noir_js input maps
//!   + `u`/`m` commitments + the message polynomial (whole and limb-wise).
//! * `encryptCreditAndWitness(pk, featureProof, cap, model, index, mask, seed?) -> object`
//!   — ParamSet-4 credit-v2 submission (two slot encryptions):
//!   `{logit, mask, credit_inputs}` (see `core::encrypt_credit_and_witness`).
//! * `creditModelFromF64(weights[8], bias) -> {weights, bias}` — the
//!   fixed-point model the circuit takes (×2^16, rounded).
//! * `creditLogit(featureProof.features, cap, model) -> number` and
//!   `sigmoidCubic(z)` — the values the applicant checks its opening against.
//! * `commitmentsFromInputs(set, inputsJson) -> {u_commitment_hex, m_commitment_hex}`.
//! * `messagePolyJson(set, inputsJson) -> {message_poly, message_poly_limbs}`.
//! * `generateKeypair(set) -> {secretKey, publicKey}` / `decrypt(...)` —
//!   test fixtures only.

pub mod core;

pub use crate::core::{
    bundle_from_inputs, commitments_from_inputs_json, encrypt_and_witness_with_rng,
    encrypt_credit_and_witness, generate_keypair, param_set_info, params_bytes_for_param_set,
    preset_for_param_set, rng_from_seed, single_poly_commitment, witness_from_encryption,
    CkksZkError, CreditFeatureProof, CreditModel, ParamSetInfo, WitnessBundle, CREDIT_FEATURES,
    CT0_KEYS, CT1_KEYS, DS_USER_DATA_ENCRYPTION_COMMITMENT,
};

use wasm_bindgen::prelude::*;

type JsResult<T> = std::result::Result<T, JsValue>;

fn js_err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

fn to_js<T: serde::Serialize>(v: &T) -> JsResult<JsValue> {
    let s = serde_json::to_string(v).map_err(js_err)?;
    js_sys::JSON::parse(&s).map_err(|_| JsValue::from_str("failed to parse JSON into JS"))
}

fn from_js(v: JsValue) -> JsResult<serde_json::Value> {
    let s = js_sys::JSON::stringify(&v)
        .map_err(|_| JsValue::from_str("failed to stringify JS value"))?;
    let s: String = s.into();
    serde_json::from_str(&s).map_err(js_err)
}

/// Serialized CKKS parameters for an on-chain `ParamSet` (0, 2, 3).
#[wasm_bindgen(js_name = "ckksParamsForParamSet")]
pub fn ckks_params_for_param_set(param_set: u8) -> JsResult<Vec<u8>> {
    core::params_bytes_for_param_set(param_set).map_err(js_err)
}

/// Human/JS-readable description of a param set.
#[wasm_bindgen(js_name = "ckksParamSetInfo")]
pub fn ckks_param_set_info(param_set: u8) -> JsResult<JsValue> {
    to_js(&core::param_set_info(param_set).map_err(js_err)?)
}

/// Encrypt `value / cap` under `public_key` and produce the Greco witness
/// bundle. `seed` (32 bytes) makes the encryption deterministic — pass
/// `undefined` in production so fresh browser entropy is used.
#[wasm_bindgen(js_name = "encryptAndWitness")]
pub fn encrypt_and_witness(
    param_set: u8,
    public_key: &[u8],
    value: f64,
    cap: f64,
    replicate_slots: bool,
    seed: Option<Vec<u8>>,
) -> JsResult<JsValue> {
    let bundle = core::encrypt_and_witness(
        param_set,
        public_key,
        value,
        cap,
        replicate_slots,
        seed.as_deref(),
    )
    .map_err(js_err)?;
    to_js(&bundle)
}

/// COEFFICIENT-encoded encryption for the ParamSet-5 apps (matching /
/// treasury / federated averaging): `coefficients` is the FULL length-N
/// vector already laid out by the app SDK (`forward` / `reversed` /
/// `mask` / `gradient_block` / `constant`); every entry `|c| <= 1024`.
/// Same bundle shape as `encryptAndWitness`. `seed` (32 bytes) makes the
/// encryption deterministic — pass `undefined` in production.
#[wasm_bindgen(js_name = "encryptCoefficientsAndWitness")]
pub fn encrypt_coefficients_and_witness_js(
    param_set: u8,
    public_key: &[u8],
    coefficients: Vec<f64>,
    seed: Option<Vec<u8>>,
) -> JsResult<JsValue> {
    let mut rng = core::rng_from_seed(seed.as_deref()).map_err(js_err)?;
    let bundle =
        core::encrypt_coefficients_and_witness(param_set, public_key, &coefficients, &mut rng)
            .map_err(js_err)?;
    to_js(&bundle)
}

/// Credit-scoring v2 (ParamSet 4) submission: encrypt the model's logit
/// and the output mask at slot `index` (two encryptions), return
/// `{logit: bundle, mask: bundle, credit_inputs}`.
///
/// `feature_proof` is the server-served Merkle opening as JSON
/// (`{address, features[8], merkle_root, depth, indices[], siblings[]}`,
/// big integers as decimal strings); `model` is `{weights[8], bias}` in
/// the ×2^16 fixed point (`creditModelFromF64`); `mask < 2^20` (value
/// `mask / 2^10`).
#[wasm_bindgen(js_name = "encryptCreditAndWitness")]
pub fn encrypt_credit_and_witness_js(
    public_key: &[u8],
    feature_proof: JsValue,
    cap: u32,
    model: JsValue,
    index: u32,
    mask: u32,
    seed: Option<Vec<u8>>,
) -> JsResult<JsValue> {
    let feature_proof: CreditFeatureProof =
        serde_json::from_value(from_js(feature_proof)?).map_err(js_err)?;
    let model: CreditModel = serde_json::from_value(from_js(model)?).map_err(js_err)?;
    let mut rng = core::rng_from_seed(seed.as_deref()).map_err(js_err)?;
    let (logit, mask_bundle, credit_inputs) = core::encrypt_credit_and_witness(
        public_key,
        feature_proof,
        cap,
        model,
        index,
        mask,
        &mut rng,
    )
    .map_err(js_err)?;
    to_js(&serde_json::json!({
        "logit": logit,
        "mask": mask_bundle,
        "credit_inputs": credit_inputs,
    }))
}

/// The fixed-point model (`×2^16`, rounded) the credit circuit takes.
#[wasm_bindgen(js_name = "creditModelFromF64")]
pub fn credit_model_from_f64_js(weights: Vec<f64>, bias: f64) -> JsResult<JsValue> {
    let weights: [f64; CREDIT_FEATURES] = weights
        .try_into()
        .map_err(|_| JsValue::from_str("weights must have exactly 8 entries"))?;
    to_js(&CreditModel::from_f64(&weights, bias))
}

/// The f64 logit `<w, x/cap> + b` the applicant encrypts for `features`
/// under the fixed-point `model`.
#[wasm_bindgen(js_name = "creditLogit")]
pub fn credit_logit_js(features: Vec<u32>, cap: u32, model: JsValue) -> JsResult<f64> {
    let features: [u32; CREDIT_FEATURES] = features
        .try_into()
        .map_err(|_| JsValue::from_str("features must have exactly 8 entries"))?;
    let model: CreditModel = serde_json::from_value(from_js(model)?).map_err(js_err)?;
    if cap == 0 {
        return Err(JsValue::from_str("cap must be nonzero"));
    }
    Ok(model.logit(&features, cap))
}

/// The cubic sigmoid the network evaluates on the encrypted logit:
/// `0.5 + 0.197 z - 0.004 z^3` (`e3_trckks::policy::sigmoid_cubic`).
#[wasm_bindgen(js_name = "sigmoidCubic")]
pub fn sigmoid_cubic_js(z: f64) -> f64 {
    core::sigmoid_cubic(z)
}

/// Test-fixture decrypt for coefficient-encoded ciphertexts: returns the
/// first `count` decoded COEFFICIENTS (what the credit output carries).
#[wasm_bindgen(js_name = "decryptCoefficients")]
pub fn decrypt_coefficients_js(
    param_set: u8,
    secret_key: &[u8],
    ciphertext: &[u8],
    count: usize,
) -> JsResult<Vec<f64>> {
    core::decrypt_coefficients(param_set, secret_key, ciphertext, count).map_err(js_err)
}

/// Recompute `{u_commitment_hex, m_commitment_hex}` from a circuit-input
/// object (the `circuit_inputs` or `ct0_inputs` of a bundle).
#[wasm_bindgen(js_name = "commitmentsFromInputs")]
pub fn commitments_from_inputs(param_set: u8, inputs: JsValue) -> JsResult<JsValue> {
    let inputs = from_js(inputs)?;
    let (u, m) = core::commitments_from_inputs_json(param_set, &inputs).map_err(js_err)?;
    to_js(&serde_json::json!({ "u_commitment_hex": u, "m_commitment_hex": m }))
}

/// The message polynomial `m` (whole, centered mod Q) and its per-limb
/// centered residues, from a circuit-input object.
#[wasm_bindgen(js_name = "messagePolyJson")]
pub fn message_poly_json(param_set: u8, inputs: JsValue) -> JsResult<JsValue> {
    let inputs = from_js(inputs)?;
    let preset = core::preset_for_param_set(param_set).map_err(js_err)?;
    let m = core::poly_from_json_pub(
        inputs
            .get("m")
            .ok_or_else(|| JsValue::from_str("missing `m`"))?,
    )
    .map_err(js_err)?;
    let whole: Vec<String> = m.coefficients().iter().map(|c| c.to_string()).collect();
    let limbs = core::m_limbs_pub(&m, preset.params.moduli());
    to_js(&serde_json::json!({ "message_poly": whole, "message_poly_limbs": limbs }))
}

/// Test-fixture keypair: `{secretKey: Uint8Array, publicKey: Uint8Array}`.
#[wasm_bindgen(js_name = "generateKeypair")]
pub fn generate_keypair_js(param_set: u8) -> JsResult<JsValue> {
    let mut rng = core::rng_from_seed(None).map_err(js_err)?;
    let (sk, pk) = core::generate_keypair(param_set, &mut rng).map_err(js_err)?;
    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &"secretKey".into(),
        &js_sys::Uint8Array::from(&sk[..]).into(),
    )?;
    js_sys::Reflect::set(
        &result,
        &"publicKey".into(),
        &js_sys::Uint8Array::from(&pk[..]).into(),
    )?;
    Ok(result.into())
}

/// Test-fixture decrypt: returns the decoded slot values.
#[wasm_bindgen(js_name = "decrypt")]
pub fn decrypt_js(param_set: u8, secret_key: &[u8], ciphertext: &[u8]) -> JsResult<Vec<f64>> {
    core::decrypt(param_set, secret_key, ciphertext).map_err(js_err)
}

/// Library version.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
