// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
use std::{collections::HashMap, sync::Arc};

use anyhow::{Context, Result};
use e3_crypto::{Cipher, SensitiveBytes};
use e3_events::ThresholdShare;
use e3_fhe_params::{BfvParamSet, BfvPreset, LambdaConfig};
use e3_trbfv::{
    calculate_decryption_key::{
        calculate_decryption_key, CalculateDecryptionKeyRequest, CalculateDecryptionKeyResponse,
    },
    gen_esi_sss::{gen_esi_sss, GenEsiSssRequest, GenEsiSssResponse},
    gen_pk_share_and_sk_sss::{
        gen_pk_share_and_sk_sss, GenPkShareAndSkSssRequest, GenPkShareAndSkSssResponse,
    },
    shares::{BfvEncryptedShares, EncryptableVec, ShamirShare, SharedSecret},
    TrBFVConfig,
};
use e3_utils::{ArcBytes, SharedRng};
use fhe::{
    bfv::{BfvParameters, PublicKey, SecretKey},
    mbfv::{AggregateIter, CommonRandomPoly, PublicKeyShare},
};
use fhe_traits::Serialize;

// The following functions are designed to aid testing our usecases

/// Result of generating shares - includes the shares plus BFV keys for decryption
pub struct GeneratedShares {
    pub shares: HashMap<u64, ThresholdShare>,
    /// BFV secret keys for each party (for decryption in tests)
    pub bfv_secret_keys: Vec<SecretKey>,
    /// The Arc<BfvParameters> used to create the secret keys and encrypt shares.
    /// Must be reused when decrypting (try_decrypt uses Arc::ptr_eq).
    pub bfv_params: Arc<BfvParameters>,
}

pub fn generate_shares_hash_map(
    trbfv_config: &TrBFVConfig,
    crp: &CommonRandomPoly,
    rng: &SharedRng,
    cipher: &Cipher,
) -> Result<GeneratedShares> {
    let threshold_n = trbfv_config.num_parties() as usize;

    // First, generate BFV encryption keys for all parties
    let bfv_params = BfvParamSet::from(BfvPreset::InsecureDkg512).build_arc();
    let mut bfv_rng = rand::rng();
    let mut bfv_secret_keys = Vec::with_capacity(threshold_n);
    let mut bfv_public_keys = Vec::with_capacity(threshold_n);

    for _ in 0..threshold_n {
        let sk = SecretKey::random(&bfv_params, &mut bfv_rng);
        let pk = fhe::bfv::PublicKey::new(&sk, &mut bfv_rng);
        bfv_secret_keys.push(sk);
        bfv_public_keys.push(pk);
    }

    let mut shares_hash_map = HashMap::new();
    for party_id in 0u64..threshold_n as u64 {
        let GenPkShareAndSkSssResponse {
            sk_sss,
            pk_share,
            e_sm_raw,
            ..
        } = {
            let mut rng_guard = rng.lock().unwrap();
            gen_pk_share_and_sk_sss(
                &mut *rng_guard,
                cipher,
                GenPkShareAndSkSssRequest {
                    trbfv_config: trbfv_config.clone(),
                    crp: ArcBytes::from_bytes(&crp.to_bytes()),
                    lambda: LambdaConfig::Insecure(40),
                    num_ciphertexts: 1,
                },
            )
        }?;

        let GenEsiSssResponse { esi_sss } = {
            let mut rng_guard = rng.lock().unwrap();
            gen_esi_sss(
                &mut *rng_guard,
                cipher,
                GenEsiSssRequest {
                    trbfv_config: trbfv_config.clone(),
                    e_sm_raw: e_sm_raw.clone(),
                },
            )?
        };

        // Decrypt locally stored secrets
        let decrypted_sk_sss: SharedSecret = sk_sss.decrypt(cipher)?;
        let decrypted_esi_sss: Vec<SharedSecret> = esi_sss
            .into_iter()
            .map(|s| s.decrypt(cipher))
            .collect::<Result<_>>()?;

        // Encrypt shares for all recipients using BFV
        let encrypted_sk_sss = BfvEncryptedShares::encrypt_all(
            &decrypted_sk_sss,
            &bfv_public_keys,
            &bfv_params,
            &mut bfv_rng,
        )?;

        let encrypted_esi_sss: Vec<BfvEncryptedShares> = decrypted_esi_sss
            .iter()
            .map(|esi| {
                BfvEncryptedShares::encrypt_all(esi, &bfv_public_keys, &bfv_params, &mut bfv_rng)
            })
            .collect::<Result<_>>()?;

        shares_hash_map.insert(
            party_id,
            ThresholdShare {
                party_id,
                esi_sss: encrypted_esi_sss,
                sk_sss: encrypted_sk_sss,
                pk_share,
            },
        );
    }
    Ok(GeneratedShares {
        shares: shares_hash_map,
        bfv_secret_keys,
        bfv_params,
    })
}

pub fn get_public_key(
    shares_hash_map: &HashMap<u64, ThresholdShare>,
    params: Arc<BfvParameters>,
    crp: &CommonRandomPoly,
) -> Result<PublicKey> {
    Ok(shares_hash_map
        .clone()
        .into_values()
        .map(|v| v.pk_share)
        .map(|k| {
            PublicKeyShare::deserialize(&k, &params, crp.clone())
                .context("Could not deserialize public key")
        })
        .collect::<Result<Vec<PublicKeyShare>>>()?
        .into_iter()
        .aggregate()?)
}

pub fn get_decryption_keys(
    shares: Vec<ThresholdShare>,
    bfv_secret_keys: &[SecretKey],
    cipher: &Cipher,
    trbfv_config: &TrBFVConfig,
    bfv_params: &Arc<BfvParameters>,
) -> Result<HashMap<usize, (Vec<SensitiveBytes>, SensitiveBytes)>> {
    let threshold_n = trbfv_config.num_parties() as usize;
    let degree = bfv_params.degree();

    // Individualize based on node - each party decrypts their share from each sender
    let mut decryption_keys = HashMap::new();
    for (party_id, sk_bfv) in bfv_secret_keys.iter().enumerate().take(threshold_n) {
        // Decrypt sk_sss share from each sender using our BFV secret key
        let sk_sss_collected: Vec<ShamirShare> = shares
            .iter()
            .map(|ts| {
                let encrypted = ts
                    .sk_sss
                    .clone_share(party_id)
                    .ok_or_else(|| anyhow::anyhow!("No sk_sss share for party {}", party_id))?;
                encrypted.decrypt(sk_bfv, bfv_params, degree)
            })
            .collect::<Result<_>>()?;

        // Similarly decrypt esi_sss — shape [sender][esi_idx]
        let per_sender_esi: Vec<Vec<ShamirShare>> = shares
            .iter()
            .map(|ts| {
                ts.esi_sss
                    .iter()
                    .map(|esi_shares| {
                        let encrypted = esi_shares.clone_share(party_id).ok_or_else(|| {
                            anyhow::anyhow!("No esi_sss share for party {}", party_id)
                        })?;
                        encrypted.decrypt(sk_bfv, bfv_params, degree)
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .collect::<Result<_>>()?;

        // Transpose to [esi_idx][sender] — CalculateDecryptionKey aggregates per smudging noise
        let num_esi = per_sender_esi.first().map_or(0, |v| v.len());
        let esi_sss_collected: Vec<Vec<ShamirShare>> = (0..num_esi)
            .map(|esi_idx| {
                per_sender_esi
                    .iter()
                    .map(|sender_esi| sender_esi[esi_idx].clone())
                    .collect()
            })
            .collect();

        let CalculateDecryptionKeyResponse {
            es_poly_sum,
            sk_poly_sum,
        } = calculate_decryption_key(
            cipher,
            CalculateDecryptionKeyRequest {
                trbfv_config: trbfv_config.clone(),
                esi_sss_collected: esi_sss_collected
                    .into_iter()
                    .map(|s| s.encrypt(cipher))
                    .collect::<Result<_>>()?,
                sk_sss_collected: sk_sss_collected.encrypt(cipher)?,
            },
        )?;
        decryption_keys.insert(party_id, (es_poly_sum, sk_poly_sum));
    }
    Ok(decryption_keys)
}
