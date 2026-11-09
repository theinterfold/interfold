// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::hash::Hash;

use crate::helpers::try_poly_from_sensitive_bytes;
/// This module defines event payloads that will generate a decryption share for the given ciphertext for this node
use crate::TrBFVConfig;
use anyhow::*;
use e3_crypto::{Cipher, SensitiveBytes};
use e3_utils::utility_types::ArcBytes;
use fhe::{
    bfv::Ciphertext,
    trbfv::{AggregatedSmudgingShare, SsSmudgingDecryptionConfig, SsSmudgingDecryptor},
};
use fhe_math::rq::{Poly, PowerBasis};
use fhe_traits::DeserializeParametrized;
use fhe_traits::Serialize;
use tracing::info;
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CalculateDecryptionShareRequest {
    /// Name to identify the job.
    pub name: String,
    /// TrBFV configuration
    pub trbfv_config: TrBFVConfig,
    /// One ciphertext to decrypt; SS noise must not be reused across outputs.
    pub ciphertexts: Vec<ArcBytes>,
    /// A single summed polynomial for this nodes secret key.
    pub sk_poly_sum: SensitiveBytes,
    /// A vector of summed polynomials for this parties smudging noise
    pub es_poly_sum: Vec<SensitiveBytes>,
}

struct InnerRequest {
    /// TrBFV configuration
    pub trbfv_config: TrBFVConfig,
    pub ciphertext: Ciphertext,
    /// A single summed polynomial for this nodes secret key.
    pub sk_poly_sum: Poly<PowerBasis>,
    pub es_poly_sum: Poly<PowerBasis>,
}

impl TryFrom<(&Cipher, CalculateDecryptionShareRequest)> for InnerRequest {
    type Error = anyhow::Error;
    fn try_from(
        value: (&Cipher, CalculateDecryptionShareRequest),
    ) -> std::result::Result<InnerRequest, Self::Error> {
        let (cipher, req) = value;
        ensure!(
            req.ciphertexts.len() == 1,
            "SS decryption requires exactly one ciphertext"
        );
        ensure!(
            req.es_poly_sum.len() == 1,
            "SS decryption requires exactly one smudging share"
        );
        let trbfv_config = req.trbfv_config;
        let ciphertext = Ciphertext::from_bytes(&req.ciphertexts[0], &trbfv_config.params())
            .context("Could not parse ciphertext")?;
        let sk_poly_sum =
            try_poly_from_sensitive_bytes(req.sk_poly_sum, trbfv_config.params(), cipher)?;
        let noise = req
            .es_poly_sum
            .into_iter()
            .next()
            .context("Missing smudging share")?;
        let es_poly_sum = try_poly_from_sensitive_bytes(noise, trbfv_config.params(), cipher)?;

        Ok(InnerRequest {
            sk_poly_sum,
            es_poly_sum,
            ciphertext,
            trbfv_config,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CalculateDecryptionShareResponse {
    /// The decryption share for the given ciphertext
    pub d_share_poly: Vec<ArcBytes>,
}

struct InnerResponse {
    pub d_share_poly: Vec<Poly<PowerBasis>>,
}

impl From<InnerResponse> for CalculateDecryptionShareResponse {
    fn from(value: InnerResponse) -> Self {
        CalculateDecryptionShareResponse {
            d_share_poly: value
                .d_share_poly
                .into_iter()
                .map(|p| ArcBytes::from_bytes(&p.to_bytes()))
                .collect(),
        }
    }
}

pub fn calculate_decryption_share(
    cipher: &Cipher,
    req: CalculateDecryptionShareRequest,
) -> Result<CalculateDecryptionShareResponse> {
    info!("Calculating decryption share: `{}`...", req.name);
    let req: InnerRequest = (cipher, req).try_into()?;

    let num_ciphernodes = req.trbfv_config.num_parties() as usize;
    let threshold = req.trbfv_config.threshold() as usize;
    let params = req.trbfv_config.params();
    let sk_poly_sum = Zeroizing::new(req.sk_poly_sum.into_ntt());
    let es_poly_sum = req.es_poly_sum;
    let decryptor = SsSmudgingDecryptor::new(SsSmudgingDecryptionConfig::new(
        num_ciphernodes,
        threshold,
        params,
    )?);

    info!("Calculating d_share_poly...");
    // Import the saved aggregate at the storage boundary; consume it once for this output.
    // Runtime recovery reuses the same successful response, not noise for a new ciphertext.
    let noise = AggregatedSmudgingShare::from_transport(Zeroizing::new(es_poly_sum));
    let d_share_poly = vec![decryptor
        .decryption_share(&req.ciphertext, &sk_poly_sum, noise)
        .context("Could not decrypt ciphertext 0")?
        .into_parts()];
    info!("Returning successful result...");

    Ok(InnerResponse { d_share_poly }.into())
}
