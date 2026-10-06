// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::hash::Hash;
use std::ops::Deref;

use crate::helpers::try_poly_from_sensitive_bytes;
/// This module defines event payloads that will generate a decryption share for the given ciphertext for this node
use crate::TrBFVConfig;
use anyhow::*;
use e3_crypto::{Cipher, SensitiveBytes};
use e3_fhe_params::{fresh_smudging_inputs, sample_fresh_smudging_error, BfvPreset};
use e3_polynomial::{CrtPolynomial, Polynomial};
use e3_utils::utility_types::ArcBytes;
use e3_zk_helpers::circuits::prf::decryption_mask_low_degree;
use e3_zk_helpers::circuits::threshold::decrypted_shares_aggregation::utils::lagrange_coeff_at_zero;
use fhe::bfv::Ciphertext;
use fhe_math::rq::{Poly, PowerBasis};
use fhe_traits::DeserializeParametrized;
use fhe_traits::Serialize;
use num_traits::ToPrimitive;
use tracing::info;

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CalculateDecryptionShareRequest {
    /// Name to identify the job.
    pub name: String,
    /// TrBFV configuration
    pub trbfv_config: TrBFVConfig,
    /// One or more Ciphertexts to decrypt
    pub ciphertexts: Vec<ArcBytes>,
    /// A single summed polynomial for this nodes secret key.
    pub sk_poly_sum: SensitiveBytes,
    /// Zero-based party index.
    pub party_idx: u32,
    /// Strictly increasing 1-based decryptor ids.
    pub decryptors: Vec<u32>,
    /// Outgoing PRF keys indexed by recipient.
    pub outgoing_prf_keys: Vec<Vec<u8>>,
    /// Incoming PRF keys indexed by sender.
    pub incoming_prf_keys: Vec<Vec<u8>>,
}

struct InnerRequest {
    /// TrBFV configuration
    pub trbfv_config: TrBFVConfig,
    /// One or more Ciphertexts to decrypt
    pub ciphertexts: Vec<Ciphertext>,
    /// A single summed polynomial for this nodes secret key.
    pub sk_poly_sum: Poly<PowerBasis>,
}

impl TryFrom<(&Cipher, CalculateDecryptionShareRequest)> for InnerRequest {
    type Error = anyhow::Error;
    fn try_from(
        value: (&Cipher, CalculateDecryptionShareRequest),
    ) -> std::result::Result<InnerRequest, Self::Error> {
        let trbfv_config = value.1.trbfv_config.clone();
        let ciphertexts = value
            .1
            .ciphertexts
            .into_iter()
            .map(|ciphertext| {
                Ciphertext::from_bytes(&ciphertext, &trbfv_config.params())
                    .context("Could not parse ciphertext")
            })
            .collect::<Result<Vec<Ciphertext>>>()?;

        let sk_poly_sum =
            try_poly_from_sensitive_bytes(value.1.sk_poly_sum, trbfv_config.params(), value.0)?;

        Ok(InnerRequest {
            sk_poly_sum,
            ciphertexts,
            trbfv_config,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CalculateDecryptionShareResponse {
    /// The decryption share for the given ciphertext
    pub d_share_poly: Vec<ArcBytes>,
    /// Fresh noise used in each share. The C6 witness must reuse these bytes.
    pub e_fresh: Vec<SensitiveBytes>,
    /// Digest of the sorted decryptor ids and the ciphertext bytes this share opens.
    pub context_digest: [u8; 32],
}

struct InnerResponse {
    pub d_share_poly: Vec<Poly<PowerBasis>>,
    pub e_fresh: Vec<Poly<PowerBasis>>,
    pub context_digest: [u8; 32],
}

impl InnerResponse {
    fn encrypt(self, cipher: &Cipher) -> Result<CalculateDecryptionShareResponse> {
        Ok(CalculateDecryptionShareResponse {
            d_share_poly: self
                .d_share_poly
                .into_iter()
                .map(|p| ArcBytes::from_bytes(&p.to_bytes()))
                .collect(),
            e_fresh: self
                .e_fresh
                .into_iter()
                .map(|p| SensitiveBytes::new(p.to_bytes(), cipher))
                .collect::<Result<Vec<_>>>()?,
            context_digest: self.context_digest,
        })
    }
}

pub fn calculate_decryption_share(
    cipher: &Cipher,
    req: CalculateDecryptionShareRequest,
) -> Result<CalculateDecryptionShareResponse> {
    info!("Calculating decryption share: `{}`...", req.name);
    let reconstruction = req.trbfv_config.threshold() as usize + 1;
    if req.decryptors.len() != reconstruction {
        bail!(
            "decryptor count {} must equal threshold + 1 ({reconstruction})",
            req.decryptors.len()
        );
    }
    let party_idx = req.party_idx as usize;
    let decryptors = req.decryptors.clone();
    let outgoing_prf_keys = req.outgoing_prf_keys.clone();
    let incoming_prf_keys = req.incoming_prf_keys.clone();
    let mut digest_ids = decryptors.clone();
    digest_ids.sort_unstable();
    let context_digest = crate::calculate_threshold_decryption::decryption_context_digest(
        &digest_ids,
        &req.ciphertexts,
    );
    let req: InnerRequest = (cipher, req).try_into()?;

    let params = req.trbfv_config.params();
    let preset = BfvPreset::from_threshold_parameters(
        params.degree(),
        params.plaintext(),
        params.moduli(),
    )
    .context("threshold parameters do not match a supported preset")?;
    let noise = fresh_smudging_inputs(preset, req.trbfv_config.num_parties() as usize)
        .map_err(|error| anyhow!(error))?;
    let sk = CrtPolynomial::from_fhe_polynomial(&req.sk_poly_sum);
    let mut e_fresh = Vec::with_capacity(req.ciphertexts.len());
    for _ in 0..req.ciphertexts.len() {
        let coeffs = sample_fresh_smudging_error(
            params.clone(),
            noise.num_parties,
            noise.num_ciphertexts,
            noise.mult_depth,
            noise.lambda,
        )?;
        let polynomial = Poly::<PowerBasis>::from_bigints(&coeffs, params.context_at_level(0)?)?;
        e_fresh.push(polynomial.deref().clone());
    }

    info!("Calculating d_share_poly...");
    let d_share_poly = req
        .ciphertexts
        .iter()
        .zip(e_fresh.iter())
        .enumerate()
        .map(|(index, (ciphertext, noise))| {
            info!("Create decryption share for ct index {}...", index);
            partial_decryption_share(
                ciphertext,
                &sk,
                noise,
                party_idx,
                &decryptors,
                &outgoing_prf_keys,
                &incoming_prf_keys,
                params.moduli(),
            )
        })
        .collect::<Result<Vec<Poly<PowerBasis>>>>()?;
    info!("Returning successful result...");

    InnerResponse {
        d_share_poly,
        e_fresh,
        context_digest,
    }
    .encrypt(cipher)
}

fn partial_decryption_share(
    ciphertext: &Ciphertext,
    sk: &CrtPolynomial,
    noise: &Poly<PowerBasis>,
    party_idx: usize,
    decryptors: &[u32],
    outgoing_keys: &[Vec<u8>],
    incoming_keys: &[Vec<u8>],
    moduli: &[u64],
) -> Result<Poly<PowerBasis>> {
    let ct0 = CrtPolynomial::from_fhe_polynomial(&ciphertext[0]);
    let ct1 = CrtPolynomial::from_fhe_polynomial(&ciphertext[1]);
    let reverse_limbs = |poly: &CrtPolynomial| -> Vec<Polynomial> {
        poly.limbs
            .iter()
            .map(|limb| {
                let mut reversed = limb.clone();
                reversed.reverse();
                reversed
            })
            .collect()
    };
    let low_mask = decryption_mask_low_degree(
        party_idx,
        decryptors,
        outgoing_keys,
        incoming_keys,
        &reverse_limbs(&ct0),
        &reverse_limbs(&ct1),
        moduli,
    )
    .map_err(|error| anyhow!(error))?;
    let c1 = ciphertext[1].clone().into_power_basis();
    let ctx = c1.ctx().clone();
    let sk_poly = sk
        .to_fhe_polynomial(&ctx, moduli)
        .context("cannot encode the secret share for NTT multiplication")?;
    // One negacyclic product for every CRT limb. Scaling by λ stays outside the NTT.
    let product = (&c1.into_ntt() * &sk_poly.into_ntt()).into_power_basis();
    let product_coeffs = product.coefficients();
    let noise_coeffs = noise.coefficients();
    let mut coeffs = noise_coeffs.to_owned();
    for (limb, modulus) in moduli.iter().enumerate() {
        let q = u128::from(*modulus);
        let lambda = lagrange_coeff_at_zero(decryptors, (party_idx as u32) + 1, *modulus)
            .map_err(|error| anyhow!(error.to_string()))?;
        let lambda = u128::from(
            lambda
                .to_u64()
                .context("Lagrange coefficient does not fit u64")?,
        );
        for column in 0..product_coeffs.ncols() {
            let scaled = (u128::from(product_coeffs[[limb, column]]) * lambda) % q;
            let fresh = u128::from(noise_coeffs[[limb, column]]);
            let mask = u128::from(low_mask[limb][column]);
            coeffs[[limb, column]] = ((scaled + fresh + mask) % q) as u64;
        }
    }
    let mut share = noise.clone();
    share.set_coefficients(coeffs);
    Ok(share)
}
