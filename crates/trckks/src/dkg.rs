// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Distributed key generation jobs for threshold CKKS.
//!
//! Each committee member runs [`gen_pk_share_and_sk_sss`] to produce its
//! public-key share and the Shamir share matrices of its secret + smudging
//! contributions; the shares are exchanged and every member runs
//! [`aggregate_collected_shares`]; anyone aggregates the public-key shares
//! with [`aggregate_pk_shares`].

use crate::TrCkksConfig;
use anyhow::{bail, Context as _, Result};
use e3_utils::utility_types::ArcBytes;
use fhe::ckks::CkksSecretKey;
use fhe::trckks::{CkksCrp, CkksPublicKeyShare, TRCKKS};
use fhe_math::rq::{Poly, PowerBasis};
use fhe_traits::DeserializeWithContext;
use fhe_traits::Serialize as FheSerialize;
use ndarray::Array2;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tracing::info;

/// Serializable Shamir share matrices: one `[n, degree]` matrix per RNS
/// modulus, flattened row-major.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareMatrices {
    /// Per-modulus flattened matrices.
    pub data: Vec<Vec<u64>>,
    /// Rows (parties) per matrix.
    pub rows: usize,
    /// Columns (degree) per matrix.
    pub cols: usize,
}

impl ShareMatrices {
    pub fn from_arrays(arrays: &[Array2<u64>]) -> Self {
        let rows = arrays.first().map_or(0, |a| a.nrows());
        let cols = arrays.first().map_or(0, |a| a.ncols());
        Self {
            data: arrays.iter().map(|a| a.iter().copied().collect()).collect(),
            rows,
            cols,
        }
    }

    pub fn to_arrays(&self) -> Result<Vec<Array2<u64>>> {
        self.data
            .iter()
            .map(|flat| {
                Array2::from_shape_vec((self.rows, self.cols), flat.clone())
                    .context("malformed share matrix")
            })
            .collect()
    }

    /// Extract party `j`'s row from every modulus matrix, stacked as one
    /// `[moduli, degree]` matrix (the shape `aggregate_collected_shares`
    /// consumes).
    pub fn rows_for_party(&self, j: usize) -> Result<Array2<u64>> {
        if j >= self.rows {
            bail!(
                "party index {j} out of range: share matrices have {} rows",
                self.rows
            );
        }
        let arrays = self.to_arrays()?;
        let mut arr = Array2::<u64>::zeros((arrays.len(), self.cols));
        for (r, m) in arrays.iter().enumerate() {
            arr.row_mut(r).assign(&m.row(j));
        }
        Ok(arr)
    }
}

/// Request: generate this member's pk share and dealt secret/smudging shares.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GenPkShareAndSkSssRequest {
    /// Threshold CKKS configuration.
    pub trckks_config: TrCkksConfig,
    /// The public CRP seed all members agreed on.
    pub crp_seed: [u8; 32],
    /// Smudging noise bits (see `TRCKKS::generate_smudging_error`).
    pub smudging_bits: usize,
}

/// Response: this member's public-key share and dealt share matrices.
///
/// NOTE: in production the share matrices travel encrypted per recipient
/// (like `e3_trbfv::shares::Encrypted`); plaintext here keeps the first
/// integration lean.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GenPkShareAndSkSssResponse {
    /// Serialized `CkksPublicKeyShare` p0 polynomial.
    pub pk_share: ArcBytes,
    /// Shamir share matrices of this member's secret contribution.
    pub sk_sss: ShareMatrices,
    /// Shamir share matrices of this member's smudging contribution.
    pub es_sss: ShareMatrices,
}

/// Run the DKG dealing step for one committee member.
pub fn gen_pk_share_and_sk_sss<R: RngCore + CryptoRng>(
    rng: &mut R,
    req: GenPkShareAndSkSssRequest,
) -> Result<GenPkShareAndSkSssResponse> {
    info!("trckks::gen_pk_share_and_sk_sss");
    let params = req.trckks_config.params()?;
    let n = req.trckks_config.num_parties() as usize;
    let threshold = req.trckks_config.threshold() as usize;

    let trckks = TRCKKS::new(n, threshold, params.clone())?;
    let crp = CkksCrp::from_seed(&params, req.crp_seed)?;

    let sk_i = CkksSecretKey::random(&params, rng);
    let pk_share = CkksPublicKeyShare::new(&sk_i, crp, rng)?;

    let sk_poly = trckks.coeffs_to_poly(sk_i.coeffs.as_ref())?;
    let sk_shares = trckks.generate_secret_shares_from_poly(sk_poly, rng)?;

    let es = trckks.generate_smudging_error(req.smudging_bits, rng)?;
    let es_poly = trckks.smudging_to_poly(&es)?;
    let es_shares = trckks.generate_secret_shares_from_poly(es_poly, rng)?;

    Ok(GenPkShareAndSkSssResponse {
        pk_share: ArcBytes::from_bytes(&pk_share.p0_to_bytes()),
        sk_sss: ShareMatrices::from_arrays(&sk_shares),
        es_sss: ShareMatrices::from_arrays(&es_shares),
    })
}

/// Aggregate all members' public-key shares into the joint public key.
pub fn aggregate_pk_shares(
    config: &TrCkksConfig,
    crp_seed: [u8; 32],
    pk_share_bytes: &[ArcBytes],
) -> Result<fhe::ckks::CkksPublicKey> {
    let params = config.params()?;
    let crp = CkksCrp::from_seed(&params, crp_seed)?;
    let ctx = params.context_at_level(0)?;

    let shares = pk_share_bytes
        .iter()
        .map(|bytes| {
            let p0 = Poly::<fhe_math::rq::Ntt>::from_bytes(bytes, ctx)
                .context("failed to decode pk share poly")?;
            Ok(CkksPublicKeyShare::from_parts(
                params.clone(),
                p0,
                crp.clone(),
            ))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(CkksPublicKeyShare::aggregate(&shares)?)
}

/// Aggregate the share rows this member received from every dealer into its
/// share of the joint secret (or joint smudging noise).
pub fn aggregate_collected_shares(
    config: &TrCkksConfig,
    dealt: &[ShareMatrices],
    party_index_zero_based: usize,
) -> Result<Poly<PowerBasis>> {
    let params = config.params()?;
    let trckks = TRCKKS::new(
        config.num_parties() as usize,
        config.threshold() as usize,
        params,
    )?;
    let collected = dealt
        .iter()
        .map(|m| m.rows_for_party(party_index_zero_based))
        .collect::<Result<Vec<_>>>()?;
    Ok(trckks.aggregate_collected_shares(&collected)?)
}

/// Serialize an aggregated share polynomial.
pub fn share_poly_to_bytes(poly: &Poly<PowerBasis>) -> ArcBytes {
    ArcBytes::from_bytes(&poly.to_bytes())
}
