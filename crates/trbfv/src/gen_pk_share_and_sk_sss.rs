// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/// This module defines event payloads that will generate the public key share as well as the sk shamir secret shares to be distributed to other members of the committee.
/// This has been separated from the esi setup in order to be able to take advantage of parallelism
use crate::{
    shares::{Encrypted, SharedSecret},
    TrBFVConfig,
};
use anyhow::Result;
use e3_crypto::{Cipher, SensitiveBytes};
use e3_fhe_params::LambdaConfig;
use e3_utils::utility_types::ArcBytes;
use fhe::{
    bfv::SecretKey,
    mbfv::{CommonRandomPoly, PublicKeyShare},
    trbfv::{ShareManager, TRBFV},
};
use fhe_traits::Serialize as FheSerialize;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use tracing::info;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GenPkShareAndSkSssRequest {
    /// TrBFV configuration
    pub trbfv_config: TrBFVConfig,
    /// Crp
    pub crp: ArcBytes,
    /// Statistical security level λ for smudging noise generation. Carries the
    /// secure/insecure tier chosen from the preset so it survives serialization.
    pub lambda: LambdaConfig,
    /// Number of ciphertexts (z) for smudging noise generation.
    pub num_ciphertexts: usize,
}

struct InnerRequest {
    pub trbfv_config: TrBFVConfig,
    pub crp: CommonRandomPoly,
    pub lambda: LambdaConfig,
    pub num_ciphertexts: usize,
}

impl TryFrom<GenPkShareAndSkSssRequest> for InnerRequest {
    type Error = anyhow::Error;

    fn try_from(value: GenPkShareAndSkSssRequest) -> std::result::Result<Self, Self::Error> {
        let crp = CommonRandomPoly::deserialize(&value.crp, &value.trbfv_config.params())?;
        Ok(InnerRequest {
            trbfv_config: value.trbfv_config,
            crp,
            lambda: value.lambda,
            num_ciphertexts: value.num_ciphertexts,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GenPkShareAndSkSssResponse {
    /// PublicKey share for this node
    pub pk_share: ArcBytes,
    /// SecretKey Shamir Shares for other parties
    pub sk_sss: Encrypted<SharedSecret>,
    /// Raw pk0 share polynomial (RNS form) for ZK proof generation (C1).
    pub pk0_share_raw: ArcBytes,
    /// Raw secret key polynomial (RNS form) for ZK proof generation (C1) — encrypted at rest.
    pub sk_raw: SensitiveBytes,
    /// Raw error polynomial from key generation (RNS form) for ZK proof generation (C1) — encrypted at rest.
    pub eek_raw: SensitiveBytes,
    /// Raw smudging noise polynomial (RNS form) for ZK proof generation (C1) — encrypted at rest.
    pub e_sm_raw: SensitiveBytes,
}

impl TryFrom<(InnerResponse, &Cipher)> for GenPkShareAndSkSssResponse {
    type Error = anyhow::Error;
    fn try_from(
        (value, cipher): (InnerResponse, &Cipher),
    ) -> std::result::Result<Self, Self::Error> {
        let pk_share = ArcBytes::from_bytes(&value.pk_share.to_bytes());
        let sk_sss = Encrypted::new(value.sk_sss, cipher)?;
        Ok(GenPkShareAndSkSssResponse {
            pk_share,
            sk_sss,
            pk0_share_raw: value.pk0_share_raw,
            sk_raw: SensitiveBytes::new(value.sk_raw.to_vec(), cipher)?,
            eek_raw: SensitiveBytes::new(value.eek_raw.to_vec(), cipher)?,
            e_sm_raw: SensitiveBytes::new(value.e_sm_raw.to_vec(), cipher)?,
        })
    }
}

struct InnerResponse {
    /// Aggregation-compatible PublicKeyShare for this node.
    pub pk_share: PublicKeyShare,
    /// Secret key Shamir shares for other parties.
    pub sk_sss: SharedSecret,
    /// Raw pk0 share polynomial bytes for ZK proof.
    pub pk0_share_raw: ArcBytes,
    /// Raw secret key polynomial bytes for ZK proof.
    pub sk_raw: ArcBytes,
    /// Raw error polynomial bytes for ZK proof.
    pub eek_raw: ArcBytes,
    /// Raw smudging noise polynomial bytes for ZK proof.
    pub e_sm_raw: ArcBytes,
}

pub fn gen_pk_share_and_sk_sss<R: RngCore + CryptoRng>(
    rng: &mut R,
    cipher: &Cipher,
    req: GenPkShareAndSkSssRequest,
) -> Result<GenPkShareAndSkSssResponse> {
    info!("gen_pk_share_and_sk_sss");
    let req: InnerRequest = req.try_into()?;

    let params = req.trbfv_config.params();
    let crp = req.crp;
    let threshold = req.trbfv_config.threshold();
    let num_ciphernodes = req.trbfv_config.num_parties();

    info!(
        "gen_pk_share_and_sk_sss: n={}, t={}",
        num_ciphernodes, threshold
    );
    let sk_share = SecretKey::random(&params, rng);
    let (pk0_share, _, _, eek) = PublicKeyShare::new_extended(&sk_share, crp.clone(), rng)?;

    let pk_share = PublicKeyShare::deserialize(&pk0_share.to_bytes(), &params, crp.clone())?;

    // Generate smudging noise
    let trbfv = TRBFV::new(num_ciphernodes as usize, threshold as usize, params.clone())?;
    let share_manager_for_esm =
        ShareManager::new(num_ciphernodes as usize, threshold as usize, params.clone())?;
    let lambda = req.lambda.into_lambda()?;
    let esi_coeffs = trbfv.generate_smudging_error(req.num_ciphertexts, lambda, rng)?;
    let e_sm_rns = share_manager_for_esm.bigints_to_poly(&esi_coeffs)?;
    let e_sm_raw = ArcBytes::from_bytes(&e_sm_rns.deref().to_bytes());

    let pk0_share_raw = ArcBytes::from_bytes(&pk0_share.to_bytes());
    let eek_raw = ArcBytes::from_bytes(&eek.to_bytes());

    let mut share_manager =
        ShareManager::new(num_ciphernodes as usize, threshold as usize, params.clone())?;

    let sk_poly = share_manager.coeffs_to_poly_level0(sk_share.coeffs.clone().as_ref())?;
    let sk_raw = ArcBytes::from_bytes(&sk_poly.to_bytes());

    info!("gen_pk_share_and_sk_sss:generate_secret_shares_from_poly...");
    let sk_sss = SharedSecret::from(share_manager.generate_secret_shares_from_poly(sk_poly, rng)?);

    (
        InnerResponse {
            pk_share,
            sk_sss,
            pk0_share_raw,
            sk_raw,
            eek_raw,
            e_sm_raw,
        },
        cipher,
    )
        .try_into()
}
