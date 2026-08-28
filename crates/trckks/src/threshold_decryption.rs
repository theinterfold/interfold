// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Decryption-share computation and threshold decryption jobs for CKKS.

use crate::TrCkksConfig;
use anyhow::{Context as _, Result};
use e3_utils::utility_types::ArcBytes;
use fhe::ckks::CkksCiphertext;
use fhe::trckks::TRCKKS;
use fhe_math::rq::{Poly, PowerBasis};
use fhe_traits::{DeserializeParametrized, DeserializeWithContext, Serialize as FheSerialize};
use serde::{Deserialize, Serialize};
use tracing::info;

/// Request: compute this party's decryption share for one ciphertext.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CalculateDecryptionShareRequest {
    /// Job name for tracing.
    pub name: String,
    /// Threshold CKKS configuration.
    pub trckks_config: TrCkksConfig,
    /// The ciphertext to decrypt (serialized `CkksCiphertext`).
    pub ciphertext: ArcBytes,
    /// This party's aggregated secret-key share polynomial (level 0).
    pub sk_poly_sum: ArcBytes,
    /// This party's aggregated smudging share polynomial (level 0).
    pub es_poly_sum: ArcBytes,
}

/// Response: the serialized decryption-share polynomial.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalculateDecryptionShareResponse {
    pub decryption_share: ArcBytes,
}

/// Compute a decryption share. Shares are projected to the ciphertext's
/// level automatically (RNS-row dropping, matching the Shamir structure).
pub fn calculate_decryption_share(
    req: CalculateDecryptionShareRequest,
) -> Result<CalculateDecryptionShareResponse> {
    info!("trckks::calculate_decryption_share: {}", req.name);
    let params = req.trckks_config.params()?;
    let trckks = TRCKKS::new(
        req.trckks_config.num_parties() as usize,
        req.trckks_config.threshold() as usize,
        params.clone(),
    )?;

    let ct = CkksCiphertext::from_bytes(&req.ciphertext, &params)
        .context("failed to decode ciphertext")?;

    let level0_ctx = params.context_at_level(0)?;
    let sk_poly = Poly::<PowerBasis>::from_bytes(&req.sk_poly_sum, level0_ctx)
        .context("failed to decode sk share poly")?;
    let es_poly = Poly::<PowerBasis>::from_bytes(&req.es_poly_sum, level0_ctx)
        .context("failed to decode es share poly")?;

    let sk_at_level = trckks.project_share_to_level(&sk_poly, ct.level)?;
    let es_at_level = trckks.project_share_to_level(&es_poly, ct.level)?;

    let d_share = trckks.decryption_share(&ct, sk_at_level.into_ntt(), es_at_level)?;

    Ok(CalculateDecryptionShareResponse {
        decryption_share: ArcBytes::from_bytes(&d_share.to_bytes()),
    })
}

/// Request: combine `threshold + 1` decryption shares into the plaintext.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CalculateThresholdDecryptionRequest {
    /// Threshold CKKS configuration.
    pub trckks_config: TrCkksConfig,
    /// The ciphertext being decrypted.
    pub ciphertext: ArcBytes,
    /// Exactly `threshold + 1` serialized decryption shares.
    pub decryption_shares: Vec<ArcBytes>,
    /// 1-based party indices matching `decryption_shares` order.
    pub party_ids: Vec<u64>,
}

/// Response: the decoded real values (one per used slot).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CalculateThresholdDecryptionResponse {
    /// Decoded slot values.
    pub values: Vec<f64>,
}

/// Combine decryption shares and decode the CKKS plaintext to real values.
pub fn calculate_threshold_decryption(
    req: CalculateThresholdDecryptionRequest,
) -> Result<CalculateThresholdDecryptionResponse> {
    info!("trckks::calculate_threshold_decryption");
    let params = req.trckks_config.params()?;
    let trckks = TRCKKS::new(
        req.trckks_config.num_parties() as usize,
        req.trckks_config.threshold() as usize,
        params.clone(),
    )?;

    let ct = CkksCiphertext::from_bytes(&req.ciphertext, &params)
        .context("failed to decode ciphertext")?;
    let ct_ctx = params.context_at_level(ct.level)?;

    let shares = req
        .decryption_shares
        .iter()
        .map(|bytes| {
            Poly::<PowerBasis>::from_bytes(bytes, ct_ctx)
                .context("failed to decode decryption share")
        })
        .collect::<Result<Vec<_>>>()?;
    let party_ids: Vec<usize> = req.party_ids.iter().map(|&x| x as usize).collect();

    let pt = trckks.decrypt(shares, party_ids, &ct)?;
    let encoder = fhe::ckks::CkksEncoder::new(&params);
    let values = encoder.decode(&pt)?;

    Ok(CalculateThresholdDecryptionResponse { values })
}
