// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::sync::Arc;

/// This module defines event payloads that will dcrypt a ciphertext with a threshold quorum of decryption shares
use crate::{helpers::try_poly_pb_from_bytes, PartyId, TrBFVConfig};
use anyhow::*;
use e3_bfv_client::{decode_plaintext_to_vec_u64, encode_vec_u64_to_bytes};
use e3_utils::utility_types::ArcBytes;
use fhe::bfv::Plaintext;
use fhe::{bfv::Ciphertext, trbfv::ShareManager};
use fhe_math::rq::{Poly, PowerBasis};
use fhe_traits::DeserializeParametrized;
use tracing::info;

/// Shamir shares for a single party to decrypt a batch of ciphertexts.
/// shares[i] is the decryption share that corresponds to ciphertext[i] at the same index.
type SinglePartysDecryptionShares = Vec<ArcBytes>;

/// Decoded shamir shares for decrypting a single ciphertext from all parties
/// shares[i] is a single parties share for a single ciphertext
type AllPartysDecodedShares = Vec<Poly<PowerBasis>>;

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CalculateThresholdDecryptionRequest {
    /// TrBFV configuration
    pub trbfv_config: TrBFVConfig,
    /// Each party's ID (0 based) unordered and their Shamir shares for decrypting the ciphertext batch.
    pub d_share_polys: Vec<(PartyId, SinglePartysDecryptionShares)>,
    /// A vector of Ciphertexts to decrypt
    pub ciphertexts: Vec<ArcBytes>,
}

struct InnerRequest {
    /// TrBFV configuration
    trbfv_config: TrBFVConfig,
    /// Transposed decryption shares organized by ciphertext index.
    /// Eg. `d_share_polys[i]` contains all parties' shares for decrypting ciphertext `i`.
    d_share_polys: Vec<AllPartysDecodedShares>,
    /// A vector of Ciphertexts to decrypt
    ciphertexts: Vec<Ciphertext>,
    /// A list of party_ids that corresponds to the index order in the d_share_polys matrix. Note
    /// this is still 0 based at this stage.
    reconstructing_parties: Vec<usize>,
}

impl TryFrom<CalculateThresholdDecryptionRequest> for InnerRequest {
    type Error = anyhow::Error;
    fn try_from(
        value: CalculateThresholdDecryptionRequest,
    ) -> std::result::Result<Self, Self::Error> {
        let trbfv_config = value.trbfv_config.clone();

        let params = value.trbfv_config.params();
        let ciphertexts = value
            .ciphertexts
            .into_iter()
            .map(|ciphertext| {
                Ciphertext::from_bytes(&ciphertext, &trbfv_config.params())
                    .context("cannot deserialize ciphertext")
            })
            .collect::<Result<Vec<_>>>()?;

        // NOTE: Ensure the polys are ordered by party_id
        let mut ordered_polys = value.d_share_polys;
        ordered_polys.sort_by_key(|&(key, _)| key);

        let capacity = ordered_polys.len();
        let mut d_share_polys = Vec::with_capacity(capacity);
        let mut reconstructing_parties = Vec::with_capacity(capacity);

        for (party_id, vec_of_bytes) in ordered_polys {
            let polys: Vec<Poly<PowerBasis>> = vec_of_bytes
                .iter()
                .map(|bytes| try_poly_pb_from_bytes(bytes, &params))
                .collect::<Result<Vec<_>>>()?;

            d_share_polys.push(polys);
            reconstructing_parties.push(party_id as usize);
        }

        // Now this is indexed by ciphertext -> ciphernode
        let d_share_polys = transpose(d_share_polys);

        // For each d_share_poly in d_share_polys assemble
        Ok(InnerRequest {
            d_share_polys,
            ciphertexts,
            trbfv_config,
            reconstructing_parties,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CalculateThresholdDecryptionResponse {
    /// The resultant plaintext vector corresponding to the ciphertext vector
    pub plaintext: Vec<ArcBytes>,
}

struct InnerResponse {
    plaintext: Vec<Plaintext>,
}

impl TryFrom<InnerResponse> for CalculateThresholdDecryptionResponse {
    type Error = anyhow::Error;
    fn try_from(value: InnerResponse) -> std::result::Result<Self, Self::Error> {
        Ok(CalculateThresholdDecryptionResponse {
            plaintext: value
                .plaintext
                .into_iter()
                .map(|open_result| -> Result<_> {
                    let decoded = decode_plaintext_to_vec_u64(&open_result)?;
                    let bytes = encode_vec_u64_to_bytes(&decoded);
                    Ok(ArcBytes::from_bytes(&bytes))
                })
                .collect::<Result<_>>()?,
        })
    }
}

pub fn calculate_threshold_decryption(
    req: CalculateThresholdDecryptionRequest,
) -> Result<CalculateThresholdDecryptionResponse> {
    info!("Calculating threshold decryption...");
    let req: InnerRequest = req.try_into()?;

    let params = req.trbfv_config.params();
    let threshold = req.trbfv_config.threshold() as usize;
    let num_ciphernodes = req.trbfv_config.num_parties() as usize;
    let d_share_polys = req.d_share_polys;

    // NOTE: party_ids must be 1 based not 0 based
    let reconstructing_parties: Vec<usize> =
        req.reconstructing_parties.iter().map(|n| n + 1).collect();

    let plaintext = req
        .ciphertexts
        .into_iter()
        .enumerate()
        .map(|(index, ciphertext)| {
            info!(
                "Calculating threshold decryption for ciphertext {}...",
                index
            );

            let share_manager = ShareManager::new(num_ciphernodes, threshold, params.clone())?;
            let Some(threshold_shares) = d_share_polys.get(index) else {
                bail!("Poly not found for index {}", index)
            };
            share_manager
                .decrypt_from_shares(
                    threshold_shares.clone(),
                    reconstructing_parties.clone(),
                    Arc::new(ciphertext),
                )
                .context("Could not decrypt ciphertext")
        })
        .collect::<Result<Vec<_>>>()?;
    info!("Successfully calculated threshold decryption! Returning...");
    InnerResponse { plaintext }.try_into()
}

fn transpose<T: Clone>(matrix: Vec<Vec<T>>) -> Vec<Vec<T>> {
    if matrix.is_empty() || matrix[0].is_empty() {
        return vec![];
    }

    let rows = matrix.len();
    let cols = matrix[0].len();

    let mut result: Vec<Vec<T>> = (0..cols).map(|_| Vec::with_capacity(rows)).collect();

    for row in matrix {
        for (col_idx, item) in row.into_iter().enumerate() {
            result[col_idx].push(item);
        }
    }

    result
}
