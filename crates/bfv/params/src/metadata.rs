// SPDX-License-Identifier: LGPL-3.0-only

//! BFV metadata for code generation. Decimal strings preserve integer precision in other languages.

use crate::{
    bfv_encryption_scheme_id, bfv_parameter_hash, bfv_profile_crypto_config_id,
    current_bfv_crypto_config_id, encode_bfv_params, search::bfv::BfvSearchConfig, BfvPreset,
    BfvProfile, BfvProfileError, PresetError, BFV_ENCRYPTION_SCHEME, BFV_PROFILE_CONFIG_DOMAIN,
    INTERFOLD_BFV_VERSION,
};
use e3_committee::CiphernodesCommitteeSize;
use fhe::bfv::BfvParameters;
use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BfvMetadata {
    pub encryption_scheme: &'static str,
    pub encryption_scheme_id: String,
    pub circuit_version: &'static str,
    pub presets: Vec<BfvPresetMetadata>,
    pub profile_config_domain: &'static str,
    pub profiles: Vec<BfvProfileMetadata>,
}

impl BfvMetadata {
    pub fn current() -> Result<Self, BfvProfileError> {
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
                threshold: ParameterMetadata::new(preset.name(), &threshold),
                dkg: ParameterMetadata::new(dkg_preset.name(), &dkg),
                parameter_hash: bfv_parameter_hash(&encoded_params).to_string(),
                crypto_config_id: current_bfv_crypto_config_id(&encoded_params).to_string(),
                search: preset
                    .search_config()
                    .ok_or(PresetError::MissingSearchConfig(preset.name()))?
                    .into(),
            });
        }
        Ok(Self {
            encryption_scheme: BFV_ENCRYPTION_SCHEME,
            encryption_scheme_id: bfv_encryption_scheme_id().to_string(),
            circuit_version: INTERFOLD_BFV_VERSION,
            presets,
            profile_config_domain: BFV_PROFILE_CONFIG_DOMAIN,
            profiles: BfvProfile::ALL
                .into_iter()
                .map(BfvProfileMetadata::new)
                .collect::<Result<_, _>>()?,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BfvProfileMetadata {
    pub profile: &'static str,
    pub protocol: &'static str,
    pub statement_version: &'static str,
    pub param_set: u8,
    pub threshold: ParameterMetadata,
    pub dkg: ParameterMetadata,
    pub threshold_parameter_hash: String,
    pub dkg_parameter_hash: String,
    pub configurations: Vec<BfvProfileConfigurationMetadata>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BfvProfileConfigurationMetadata {
    pub committee: &'static str,
    pub crypto_config_id: String,
    pub artifacts_dir: String,
    pub admission_enabled: bool,
}

impl BfvProfileMetadata {
    fn new(profile: BfvProfile) -> Result<Self, BfvProfileError> {
        let (threshold, dkg) = profile.build_pair()?;
        let threshold_bytes = encode_bfv_params(&threshold);
        let dkg_bytes = encode_bfv_params(&dkg);
        let mut configurations = Vec::new();
        for committee in CiphernodesCommitteeSize::ALL {
            if !profile.supports_committee(committee) {
                continue;
            }
            configurations.push(BfvProfileConfigurationMetadata {
                committee: committee.as_str(),
                crypto_config_id: bfv_profile_crypto_config_id(
                    profile.protocol(),
                    &threshold_bytes,
                    &dkg_bytes,
                    committee,
                    profile.statement_version(),
                )
                .to_string(),
                artifacts_dir: profile.artifacts_dir_for_committee(committee)?,
                admission_enabled: profile.admission_enabled(),
            });
        }
        Ok(Self {
            profile: profile.name(),
            protocol: profile.protocol().name(),
            statement_version: profile.statement_version(),
            param_set: profile.param_set(),
            threshold: ParameterMetadata::new(profile.threshold_preset().name(), &threshold),
            dkg: ParameterMetadata::new(profile.dkg_name(), &dkg),
            threshold_parameter_hash: bfv_parameter_hash(&threshold_bytes).to_string(),
            dkg_parameter_hash: bfv_parameter_hash(&dkg_bytes).to_string(),
            configurations,
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
    fn new(name: &'static str, params: &BfvParameters) -> Self {
        Self {
            name,
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
        let BfvSearchConfig {
            n,
            z,
            k,
            lambda,
            b,
            b_chi,
            min_margin,
            d,
            insecure,
            mult_depth,
            min_prime_bits,
            verbose: _, // Search logging is not part of the parameter recipe.
        } = config;
        Self {
            n: n.to_string(),
            z: z.to_string(),
            k: k.to_string(),
            lambda,
            b: b.to_string(),
            b_chi: b_chi.to_string(),
            min_margin,
            d: d.map(|degree| degree.to_string()),
            insecure,
            mult_depth,
            min_prime_bits,
        }
    }
}
