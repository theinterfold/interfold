// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! What the threshold-BFV library needs, derived from a request's crypto parameters as the current
//! node derives it: the request's threshold preset, and its DKG counterpart for share encryption.

use crate::JobError;
use alloy_primitives::{Address, B256};
use e3_fhe_params::{
    create_deterministic_crp_from_default_seed, current_bfv_crypto_config_id, encode_bfv_params,
    BfvParamSet, BfvPreset, LambdaConfig,
};
use e3_protocol::node::CryptoParams;
use e3_trbfv::TrBFVConfig;
use e3_utils::utility_types::ArcBytes;
use fhe::{bfv::BfvParameters, mbfv::CommonRandomPoly};
use fhe_traits::Serialize as _;
use std::collections::BTreeMap;
use std::sync::Arc;

/// The crypto configuration of each on-chain parameter set this build runs, as the Interfold
/// contract records it for a request.
pub fn crypto_configs() -> BTreeMap<u8, B256> {
    BfvPreset::ON_CHAIN_PARAMETER_SETS
        .iter()
        .map(|&(param_set, preset)| {
            let params = BfvParamSet::from(preset).build_arc();
            let config = current_bfv_crypto_config_id(&encode_bfv_params(&params));
            (param_set, config)
        })
        .collect()
}

pub(crate) fn threshold_preset(params: &CryptoParams) -> Result<BfvPreset, JobError> {
    BfvPreset::from_on_chain_param_set(params.param_set)
        .ok_or(JobError::UnsupportedParams(params.param_set))
}

pub(crate) fn threshold_params(params: &CryptoParams) -> Result<Arc<BfvParameters>, JobError> {
    Ok(BfvParamSet::from(threshold_preset(params)?).build_arc())
}

pub(crate) fn dkg_params(params: &CryptoParams) -> Result<Arc<BfvParameters>, JobError> {
    let preset = threshold_preset(params)?
        .dkg_counterpart()
        .ok_or(JobError::UnsupportedParams(params.param_set))?;
    Ok(BfvParamSet::from(preset).build_arc())
}

pub(crate) fn config(params: &CryptoParams) -> Result<TrBFVConfig, JobError> {
    let committee = params.committee_size.values();
    let threshold = threshold_params(params)?;
    let encoded = encode_bfv_params(&threshold);
    Ok(TrBFVConfig::new(
        ArcBytes::from_bytes(&encoded),
        committee.n as u64,
        committee.threshold as u64,
    ))
}

/// Every party derives the same common random polynomial from a fixed seed, not the E3's.
pub(crate) fn crp_poly(params: &CryptoParams) -> Result<CommonRandomPoly, JobError> {
    Ok(create_deterministic_crp_from_default_seed(
        &threshold_params(params)?,
    ))
}

pub(crate) fn crp(params: &CryptoParams) -> Result<ArcBytes, JobError> {
    Ok(ArcBytes::from_bytes(&crp_poly(params)?.to_bytes()))
}

pub(crate) fn lambda(params: &CryptoParams) -> Result<LambdaConfig, JobError> {
    Ok(threshold_preset(params)?.lambda_config())
}

pub(crate) fn ciphertexts(params: &CryptoParams) -> Result<usize, JobError> {
    let defaults = threshold_preset(params)?
        .search_defaults()
        .ok_or(JobError::UnsupportedParams(params.param_set))?;
    usize::try_from(defaults.z).map_err(JobError::crypto)
}

/// A member's party ID: its index in the committee, which is ascending by address.
pub(crate) fn party(committee: &[Address], member: Address) -> Result<usize, JobError> {
    committee
        .iter()
        .position(|candidate| *candidate == member)
        .ok_or(JobError::crypto("the member is not in the committee"))
}
