// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Preset definitions, builders, and arithmetic utilities for BFV FHE parameters.

pub mod builder;
pub mod constants;
pub mod crp;
#[cfg(feature = "abi-encoding")]
pub mod encoding;
#[cfg(feature = "abi-encoding")]
pub mod metadata;
pub mod presets;
pub mod search;
pub mod utils;

pub use builder::{
    build_bfv_params, build_bfv_params_arc, build_bfv_params_from_set,
    build_bfv_params_from_set_arc, build_pair_for_preset, try_build_bfv_params_arc,
};
pub use constants::{BFV_ENCRYPTION_SCHEME, INTERFOLD_BFV_VERSION};
pub use crp::{create_deterministic_crp_from_default_seed, create_deterministic_crp_from_seed};
#[cfg(feature = "abi-encoding")]
pub use encoding::{
    bfv_crypto_config_id, bfv_encryption_scheme_id, bfv_parameter_hash,
    current_bfv_crypto_config_id, decode_bfv_params, decode_bfv_params_arc, encode_bfv_params,
    EncodingError,
};
pub use presets::{
    default_param_set, BfvParamSet, BfvPreset, LambdaConfig, ParameterType, PresetError,
    PresetMetadata, PresetSearchDefaults, SecurityTier, DEFAULT_BFV_PRESET,
};
