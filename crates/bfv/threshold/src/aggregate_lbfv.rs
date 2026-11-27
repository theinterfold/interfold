// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Derive operational l-BFV keys from accepted share bytes.

use anyhow::{anyhow, ensure, Result};
use e3_fhe_params::{build_pair_for_preset, lbfv_crs_seed, lbfv_urs_seed, BfvPreset};
use e3_utils::ArcBytes;
use fhe::aggregate::AggregateIter;
use fhe::bfv::BfvParameters;
use fhe::trlbfv::{aggregate_relinearization_key, LBFVPublicKey, PublicKeyShare, RelinKeyShare};
use fhe_traits::{DeserializeParametrized, Serialize as FheSerialize};
use std::sync::{Arc, OnceLock};

/// Operational key material from one accepted contribution set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LbfvOperationalKeys {
    /// Canonical fhe.rs serialization of the complete l-component public key.
    pub public_key: ArcBytes,
    /// Canonical fhe.rs serialization of the matching relinearization key.
    pub relinearization_key: ArcBytes,
}

/// Validate one public-key contribution against a supported l-BFV preset.
pub fn validate_lbfv_public_key_share_bytes(bytes: &[u8]) -> Result<()> {
    validate_share_bytes(bytes, true)
}

/// Validate one relinearization-key contribution against a supported l-BFV preset.
pub fn validate_lbfv_relinearization_key_share_bytes(bytes: &[u8]) -> Result<()> {
    validate_share_bytes(bytes, false)
}

/// Threshold parameters of both l-BFV presets, built once because network ingress validates every
/// document.
fn lbfv_share_params() -> Result<&'static [Arc<BfvParameters>; 2]> {
    static PARAMS: OnceLock<std::result::Result<[Arc<BfvParameters>; 2], String>> = OnceLock::new();
    PARAMS
        .get_or_init(|| {
            let build = |preset| {
                build_pair_for_preset(preset)
                    .map(|(params, _)| params)
                    .map_err(|error| error.to_string())
            };
            Ok([
                build(BfvPreset::InsecureThresholdLbfv)?,
                build(BfvPreset::SecureThreshold16384)?,
            ])
        })
        .as_ref()
        .map_err(|error| anyhow!("{error}"))
}

fn validate_share_bytes(bytes: &[u8], public_key: bool) -> Result<()> {
    let mut errors = Vec::new();
    for params in lbfv_share_params()? {
        let result = if public_key {
            PublicKeyShare::from_bytes(bytes, params).map(|_| ())
        } else {
            RelinKeyShare::from_bytes(bytes, params).map(|_| ())
        };
        match result {
            Ok(()) => return Ok(()),
            Err(error) => errors.push(error.to_string()),
        }
    }
    let kind = if public_key {
        "public-key"
    } else {
        "relinearization-key"
    };
    Err(anyhow::anyhow!(
        "l-BFV {kind} contribution does not use a supported fhe.rs wire format: {}",
        errors.join("; ")
    ))
}

/// Aggregate accepted public-key and RLK contributions in one canonical order.
///
/// The caller must perform signer, party-set, session, and commitment validation before calling
/// this adapter. Both serializations derive from the same ordered contribution set.
pub fn aggregate_lbfv_keys(
    preset: BfvPreset,
    public_key_share_bytes: &[ArcBytes],
    rlk_share_bytes: &[ArcBytes],
) -> Result<LbfvOperationalKeys> {
    ensure!(
        lbfv_crs_seed(preset).is_some() && lbfv_urs_seed(preset).is_some(),
        "operational l-BFV RLK requires a preset with l-BFV constants"
    );
    ensure!(
        !public_key_share_bytes.is_empty() && public_key_share_bytes.len() == rlk_share_bytes.len(),
        "public-key and RLK share counts must be equal and nonzero"
    );

    let (params, _) = build_pair_for_preset(preset)?;
    let public_key_shares = public_key_share_bytes
        .iter()
        .map(|bytes| PublicKeyShare::from_bytes(bytes, &params))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let rlk_shares = rlk_share_bytes
        .iter()
        .map(|bytes| RelinKeyShare::from_bytes(bytes, &params))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let public_key: LBFVPublicKey = public_key_shares.into_iter().aggregate()?;
    let operational = aggregate_relinearization_key(&rlk_shares, &public_key)?;
    Ok(LbfvOperationalKeys {
        public_key: ArcBytes::from_bytes(&public_key.to_bytes()),
        relinearization_key: ArcBytes::from_bytes(&operational.to_bytes()),
    })
}
