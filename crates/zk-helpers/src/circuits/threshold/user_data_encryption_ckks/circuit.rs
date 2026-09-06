// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::computation::DkgInputType;
use crate::registry::Circuit;
use e3_fhe_params::ParameterType;
use fhe::ckks::{CkksParameters, CkksPublicKey};
use std::sync::Arc;

#[derive(Debug)]
pub struct UserDataEncryptionCkksCircuit;

impl Circuit for UserDataEncryptionCkksCircuit {
    const NAME: &'static str = "user-data-encryption-ckks";
    const PREFIX: &'static str = "USER_DATA_ENCRYPTION_CKKS";
    const SUPPORTED_PARAMETER: ParameterType = ParameterType::THRESHOLD;
    const DKG_INPUT_TYPE: Option<DkgInputType> = None;
}

/// Parameter set for the CKKS user-data-encryption computation.
///
/// CKKS has no `BfvPreset` yet; the parameters and the application-level
/// input bound travel together. `input_bound` is the bound `B` on the
/// magnitude of every encoded value; the circuit's message bound is
/// `m_bound = delta * B` (coefficient-domain input-validity check).
#[derive(Clone)]
pub struct CkksPreset {
    /// The CKKS parameters.
    pub params: Arc<CkksParameters>,
    /// Bound `B` on the magnitude of each input value.
    pub input_bound: f64,
}

pub struct UserDataEncryptionCkksCircuitData {
    /// The CKKS public key to encrypt under.
    pub public_key: CkksPublicKey,
    /// The real-valued inputs (at most `N/2` slots).
    pub values: Vec<f64>,
}

/// The canonical dev CKKS preset: mirrors the shape of the BFV
/// `insecure-512` preset (N=512, two moduli) with scale `2^26` and an
/// application input bound of 100.0.
///
/// Prime generation in `CkksParametersBuilder` is deterministic for fixed
/// degree and sizes, so this preset is reproducible across builds — which the
/// regenerate-and-diff codegen guard relies on.
pub fn insecure_512_ckks() -> Result<CkksPreset, crate::CircuitsErrors> {
    // Canonical insecure-512 CKKS params from e3-fhe-params: EXACT moduli
    // (not size-derived) so circuit constants match the runtime and the
    // DKG transport bound (q_i <= t_dkg). Size-derived moduli drifted from
    // the runtime's and violated the transport bound.
    let params = e3_fhe_params::ckks_presets::ckks_params_for_on_chain_param_set(0)
        .map_err(|e| crate::CircuitsErrors::Other(e.to_string()))?;
    Ok(CkksPreset {
        params,
        input_bound: 100.0,
    })
}

/// The Greco preset for an on-chain `ParamSet` value, pairing the
/// canonical CKKS parameters with the application-level input bound `B`
/// the circuit's message bound derives from (`m_bound = ceil(delta*B)+1`).
///
/// * `0` — dev insecure-512 preset (`B = 100`, matches [`insecure_512_ckks`]).
/// * `2` — auction sign-extraction ladder. The demo encrypts RAW bids up
///   to the public bid cap (1000), so `B = 1000`.
/// * `3` — statistics preset. The survey encrypts CAP-NORMALIZED salaries
///   (`salary / cap <= 1`), so `B = 1`.
/// * `4` — credit-scoring preset (4 limbs, COEFFICIENT encoding). Every
///   coefficient is a masked feature `x_j + μ_j ∈ [0, 1 + 2^10)`, so
///   `B = 1025` (`ckks_credit_validity::CREDIT_INPUT_BOUND`); the resulting
///   `m_bound ≈ 2^50` exceeds one limb's `(q_i − 1)/2 ≈ 2^35` and is
///   carried by the mod-Q lift (same path as ParamSet 3).
///
/// Every participant and every verifier must derive the SAME bound from
/// the param set — it is baked into the circuit configs (codegen) and the
/// on-chain verifier VKs.
pub fn ckks_preset_for_param_set(param_set: u8) -> Result<CkksPreset, crate::CircuitsErrors> {
    if param_set == crate::threshold::ckks_credit_validity::CREDIT_PARAM_SET {
        return crate::threshold::ckks_credit_validity::credit_preset();
    }
    let input_bound = match param_set {
        0 => 100.0,
        2 => 1000.0,
        3 => 1.0,
        // ParamSet 5 (coefficient inner products): the per-coefficient
        // message bound. Cap-normalised vector entries are ≤ 1, but the
        // cross-term MASK coefficients are uniform in [0, 1024) and the
        // federated sample count sits on coefficient 0 as an integer
        // < 1024 — Greco's `m_bound` must admit the LARGEST coefficient
        // any ParamSet-5 ciphertext carries. Coefficient-encoded, so the
        // slot→coefficient factor in `m_bound`'s derivation is moot (the
        // bound is per coefficient directly).
        5 => 1024.0,
        other => {
            return Err(crate::CircuitsErrors::Other(format!(
                "no Greco CKKS preset for on-chain ParamSet {other}"
            )))
        }
    };
    let params = e3_fhe_params::ckks_presets::ckks_params_for_on_chain_param_set(param_set)
        .map_err(|e| crate::CircuitsErrors::Other(e.to_string()))?;
    Ok(CkksPreset {
        params,
        input_bound,
    })
}
