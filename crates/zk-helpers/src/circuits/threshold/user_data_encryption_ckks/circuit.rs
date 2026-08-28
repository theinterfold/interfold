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
    let params = fhe::ckks::CkksParametersBuilder::new()
        .set_degree(512)
        .set_moduli_sizes(&[36, 36])
        .set_scale(2f64.powi(26))
        .build_arc()
        .map_err(|e| crate::CircuitsErrors::Other(e.to_string()))?;
    Ok(CkksPreset {
        params,
        input_bound: 100.0,
    })
}
