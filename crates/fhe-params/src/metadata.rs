// SPDX-License-Identifier: LGPL-3.0-only

//! BFV metadata for code generation. Decimal strings preserve integer precision in other languages.

use crate::{
    bfv_encryption_scheme_id, bfv_parameter_hash, current_bfv_crypto_config_id, encode_bfv_params,
    search::bfv::BfvSearchConfig, BfvPreset, PresetError, BFV_ENCRYPTION_SCHEME,
    INTERFOLD_BFV_VERSION,
};
use fhe::bfv::BfvParameters;
use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BfvMetadata {
    pub encryption_scheme: &'static str,
    pub encryption_scheme_id: String,
    pub circuit_version: &'static str,
    pub presets: Vec<BfvPresetMetadata>,
}

impl BfvMetadata {
    pub fn current() -> Result<Self, PresetError> {
        let mut presets = Vec::new();
        for (param_set, preset) in BfvPreset::ON_CHAIN_PARAMETER_SETS {
            let (threshold, dkg) = preset.build_pair()?;
            let dkg_preset = preset
                .dkg_counterpart()
                .ok_or(PresetError::MissingPair(preset.name()))?;
            let encoded_params = encode_bfv_params(&threshold);
            presets.push(BfvPresetMetadata {
                preset: preset.artifacts_dir(),
                param_set,
                threshold: ParameterMetadata::new(preset, &threshold),
                dkg: ParameterMetadata::new(dkg_preset, &dkg),
                parameter_hash: bfv_parameter_hash(&encoded_params).to_string(),
                crypto_config_id: current_bfv_crypto_config_id(&encoded_params).to_string(),
                search: preset
                    .search_config()
                    .ok_or(PresetError::MissingPair(preset.name()))?
                    .into(),
            });
        }
        Ok(Self {
            encryption_scheme: BFV_ENCRYPTION_SCHEME,
            encryption_scheme_id: bfv_encryption_scheme_id().to_string(),
            circuit_version: INTERFOLD_BFV_VERSION,
            presets,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BfvPresetMetadata {
    pub preset: String,
    pub param_set: u8,
    pub threshold: ParameterMetadata,
    pub dkg: ParameterMetadata,
    pub parameter_hash: String,
    pub crypto_config_id: String,
    pub search: SearchMetadata,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParameterMetadata {
    pub name: &'static str,
    pub degree: String,
    pub plaintext_modulus: String,
    pub moduli: Vec<String>,
    pub error1_variance: String,
}

impl ParameterMetadata {
    fn new(preset: BfvPreset, params: &BfvParameters) -> Self {
        Self {
            name: preset.name(),
            degree: params.degree().to_string(),
            plaintext_modulus: params.plaintext().to_string(),
            moduli: params.moduli().iter().map(u64::to_string).collect(),
            error1_variance: params.get_error1_variance().to_string(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchMetadata {
    pub n: String,
    pub z: String,
    pub k: String,
    pub lambda: u32,
    pub b: String,
    pub b_chi: String,
    pub min_margin: f64,
    pub d: Option<String>,
    pub insecure: bool,
    pub mult_depth: u32,
    pub min_prime_bits: u8,
}

impl From<BfvSearchConfig> for SearchMetadata {
    fn from(config: BfvSearchConfig) -> Self {
        Self {
            n: config.n.to_string(),
            z: config.z.to_string(),
            k: config.k.to_string(),
            lambda: config.lambda,
            b: config.b.to_string(),
            b_chi: config.b_chi.to_string(),
            min_margin: config.min_margin,
            d: config.d.map(|degree| degree.to_string()),
            insecure: config.insecure,
            mult_depth: config.mult_depth,
            min_prime_bits: config.min_prime_bits,
        }
    }
}
