// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure DKG share-generation crypto.
//!
//! Given the locally generated/decrypted share material and the collected BFV
//! encryption keys, [`build_shares_generated_plan`] performs the BFV
//! share-encryption fan-out and assembles every C1/C2/C3 proof request plus the
//! [`ThresholdShare`] broadcast payload. No actix/persistence/bus access — the
//! actor decrypts the at-rest share material, calls this, then publishes the
//! resulting [`ThresholdSharePending`] and stashes the own-share material.
//!
//! [`ThresholdSharePending`]: e3_events::ThresholdSharePending

use anyhow::{anyhow, bail, Result};
use e3_crypto::{Cipher, SensitiveBytes};
use e3_events::{
    EncryptionKey, PkGenerationProofRequest, ShareComputationProofRequest,
    ShareEncryptionProofRequest, ThresholdShare,
};
use e3_fhe_params::{build_pair_for_preset, BfvPreset};
use e3_trbfv::shares::{BfvEncryptedShares, SharedSecret};
use e3_utils::utility_types::ArcBytes;
use e3_zk_helpers::computation::DkgInputType;
use e3_zk_helpers::CiphernodesCommitteeSize;
use fhe::bfv::{BfvParameters, PublicKey};
use fhe_traits::{DeserializeParametrized, Serialize as _};
use rand::rngs::OsRng;
use rand_core::UnwrapErr;
use std::sync::Arc;
use tracing::info;

use crate::domain::ProofRequestData;

/// Fully assembled output of the share-generation phase.
pub(crate) struct SharesGeneratedPlan {
    /// The BFV-encrypted shares broadcast to every other party.
    pub full_share: ThresholdShare,
    /// C1 (PkGeneration) proof request.
    pub proof_request: PkGenerationProofRequest,
    /// C2a (SkShareComputation) proof request.
    pub sk_share_computation_request: ShareComputationProofRequest,
    /// C2b (ESmShareComputation) proof request.
    pub e_sm_share_computation_request: ShareComputationProofRequest,
    /// C3a (SK share encryption) proof requests.
    pub sk_share_encryption_requests: Vec<ShareEncryptionProofRequest>,
    /// C3b (E_SM share encryption) proof requests.
    pub e_sm_share_encryption_requests: Vec<ShareEncryptionProofRequest>,
    /// Party IDs with a collected C0 key. Only these parties receive a share.
    pub recipient_party_ids: Vec<u64>,
    /// Own plaintext sk share rows (bincode `Vec<Vec<u64>>`, encrypted at rest) for C4a.
    pub own_sk_share_raw: SensitiveBytes,
    /// Own plaintext esi share rows (one per smudging noise, encrypted at rest) for C4b.
    pub own_esi_shares_raw: Vec<SensitiveBytes>,
}

/// Perform the BFV share-encryption fan-out and build all C1/C2/C3 proof
/// requests for this party's freshly generated DKG share material.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_shares_generated_plan(
    cipher: &Cipher,
    share_enc_preset: BfvPreset,
    party_id: u64,
    threshold_m: u64,
    threshold_n: u64,
    pk_share: ArcBytes,
    decrypted_sk_sss: SharedSecret,
    decrypted_esi_sss: Vec<SharedSecret>,
    e_sm_raw: SensitiveBytes,
    proof_request_data: ProofRequestData,
    collected_encryption_keys: &[Arc<EncryptionKey>],
) -> Result<SharesGeneratedPlan> {
    let derived_committee_size =
        CiphernodesCommitteeSize::from_threshold(threshold_m as usize, threshold_n as usize)?;

    // Get collected BFV public keys from all parties (from persisted state)
    let encryption_keys = collected_encryption_keys;

    // Convert to BFV public keys using DKG params
    let threshold_preset = share_enc_preset
        .threshold_counterpart()
        .ok_or_else(|| anyhow!("No threshold counterpart for {:?}", share_enc_preset))?;
    let (_, params) = build_pair_for_preset(threshold_preset)?;
    let (recipient_pks, recipient_party_ids) = recipient_keys_for_c3(
        encryption_keys,
        party_id,
        derived_committee_size.values().n,
        derived_committee_size.values().h,
        &params,
    )?;
    let recipient_share_indices: Vec<usize> = (0..recipient_pks.len()).collect();
    let own_idx = party_id as usize;

    // Serialize for C2a/C2b proof requests (encrypted at rest)
    let sk_sss_raw = SensitiveBytes::new(
        bincode::serialize(&decrypted_sk_sss)
            .map_err(|e| anyhow!("Failed to serialize sk_sss: {}", e))?,
        cipher,
    )?;
    let esi_sss_raw: Vec<SensitiveBytes> = decrypted_esi_sss
        .iter()
        .map(|s| {
            let bytes =
                bincode::serialize(s).map_err(|e| anyhow!("Failed to serialize esi_sss: {}", e))?;
            SensitiveBytes::new(bytes, cipher)
        })
        .collect::<Result<_>>()?;

    // Cache own plaintext share rows for C4 (no self-encryption); stored encrypted at rest.
    let own_sk_shamir = decrypted_sk_sss.extract_party_share(party_id as usize)?;
    let own_sk_rows: Vec<Vec<u64>> = own_sk_shamir
        .rows()
        .into_iter()
        .map(|row| row.iter().copied().collect())
        .collect();
    let own_sk_share_raw = SensitiveBytes::new(
        bincode::serialize(&own_sk_rows)
            .map_err(|e| anyhow!("Failed to serialize own sk share: {}", e))?,
        cipher,
    )?;

    let own_esi_shares_raw: Vec<SensitiveBytes> = decrypted_esi_sss
        .iter()
        .map(|esi| {
            let shamir = esi.extract_party_share(party_id as usize)?;
            let rows: Vec<Vec<u64>> = shamir
                .rows()
                .into_iter()
                .map(|row| row.iter().copied().collect())
                .collect();
            let bytes = bincode::serialize(&rows)
                .map_err(|e| anyhow!("Failed to serialize own esi share: {}", e))?;
            SensitiveBytes::new(bytes, cipher)
        })
        .collect::<Result<_>>()?;

    // BFV-encrypt shares to all recipients except own slot (own share is bound via C2,
    // consumed locally by C4). Returns per-row randomness for C3 proofs.
    let mut rng = UnwrapErr(OsRng);
    let (encrypted_sk_sss, sk_witnesses) =
        BfvEncryptedShares::encrypt_all_extended_for_share_indices(
            &decrypted_sk_sss,
            &recipient_pks,
            &recipient_share_indices,
            &params,
            &mut rng,
            Some(own_idx),
        )?;

    let (encrypted_esi_sss, esi_witnesses): (Vec<_>, Vec<_>) = decrypted_esi_sss
        .iter()
        .map(|esi| {
            BfvEncryptedShares::encrypt_all_extended_for_share_indices(
                esi,
                &recipient_pks,
                &recipient_share_indices,
                &params,
                &mut rng,
                Some(own_idx),
            )
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .unzip();

    // Create the full share with all parties' encrypted data
    let full_share = ThresholdShare {
        party_id,
        pk_share,
        sk_sss: encrypted_sk_sss,
        esi_sss: encrypted_esi_sss,
    };

    // Build C1 request (PkGenerationProof)
    let proof_request = PkGenerationProofRequest::new(
        proof_request_data.pk0_share_raw.clone(),
        proof_request_data.sk_raw.clone(),
        proof_request_data.eek_raw.clone(),
        e_sm_raw.clone(),
        threshold_preset,
        derived_committee_size,
    );

    // Build C2a request (SkShareComputation)
    let sk_share_computation_request = ShareComputationProofRequest {
        secret_raw: proof_request_data.sk_raw.clone(),
        secret_sss_raw: sk_sss_raw,
        dkg_input_type: DkgInputType::SecretKey,
        params_preset: threshold_preset,
        committee_size: derived_committee_size,
    };

    // Build C2b request (ESmShareComputation)
    let e_sm_share_computation_request = ShareComputationProofRequest {
        secret_raw: e_sm_raw.clone(),
        secret_sss_raw: esi_sss_raw
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("esi_sss_raw is empty — expected at least one entry"))?,
        dkg_input_type: DkgInputType::SmudgingNoise,
        params_preset: threshold_preset,
        committee_size: derived_committee_size,
    };

    // Build C3a proof requests (SK share encryption) from witnesses.
    // The own slot was skipped during BFV encryption (witness vec empty), so it
    // contributes no C3a request.
    let mut sk_share_encryption_requests = Vec::new();
    for (recipient_idx, recipient_witnesses) in sk_witnesses.iter().enumerate() {
        if recipient_idx == own_idx {
            continue;
        }
        let recipient_party_id = recipient_share_indices[recipient_idx];
        for (row_idx, witness) in recipient_witnesses.iter().enumerate() {
            sk_share_encryption_requests.push(ShareEncryptionProofRequest {
                share_row_raw: SensitiveBytes::new(
                    bincode::serialize(&witness.share_row)
                        .map_err(|e| anyhow!("Failed to serialize share_row: {}", e))?,
                    cipher,
                )?,
                ciphertext_raw: ArcBytes::from_bytes(&witness.ciphertext.to_bytes()),
                recipient_pk_raw: ArcBytes::from_bytes(&recipient_pks[recipient_idx].to_bytes()),
                u_rns_raw: SensitiveBytes::new(witness.u_rns.to_bytes(), cipher)?,
                e0_rns_raw: SensitiveBytes::new(witness.e0_rns.to_bytes(), cipher)?,
                e1_rns_raw: SensitiveBytes::new(witness.e1_rns.to_bytes(), cipher)?,
                dkg_input_type: DkgInputType::SecretKey,
                params_preset: threshold_preset,
                committee_size: derived_committee_size,
                recipient_party_id,
                row_index: row_idx,
                esi_index: 0,
            });
        }
    }

    // Build C3b proof requests (E_SM share encryption) from witnesses; skip own slot.
    let mut e_sm_share_encryption_requests = Vec::new();
    for (esi_idx, esi_recipient_witnesses) in esi_witnesses.iter().enumerate() {
        for (recipient_idx, recipient_witnesses) in esi_recipient_witnesses.iter().enumerate() {
            if recipient_idx == own_idx {
                continue;
            }
            let recipient_party_id = recipient_share_indices[recipient_idx];
            for (row_idx, witness) in recipient_witnesses.iter().enumerate() {
                e_sm_share_encryption_requests.push(ShareEncryptionProofRequest {
                    share_row_raw: SensitiveBytes::new(
                        bincode::serialize(&witness.share_row)
                            .map_err(|e| anyhow!("Failed to serialize share_row: {}", e))?,
                        cipher,
                    )?,
                    ciphertext_raw: ArcBytes::from_bytes(&witness.ciphertext.to_bytes()),
                    recipient_pk_raw: ArcBytes::from_bytes(
                        &recipient_pks[recipient_idx].to_bytes(),
                    ),
                    u_rns_raw: SensitiveBytes::new(witness.u_rns.to_bytes(), cipher)?,
                    e0_rns_raw: SensitiveBytes::new(witness.e0_rns.to_bytes(), cipher)?,
                    e1_rns_raw: SensitiveBytes::new(witness.e1_rns.to_bytes(), cipher)?,
                    dkg_input_type: DkgInputType::SmudgingNoise,
                    params_preset: threshold_preset,
                    committee_size: derived_committee_size,
                    recipient_party_id,
                    row_index: row_idx,
                    esi_index: esi_idx,
                });
            }
        }
    }

    let total_proofs =
        3 + sk_share_encryption_requests.len() + e_sm_share_encryption_requests.len();
    info!(
        "Built share-generation plan ({} proofs: C1, C2a, C2b + {} C3a + {} C3b)",
        total_proofs,
        sk_share_encryption_requests.len(),
        e_sm_share_encryption_requests.len()
    );

    Ok(SharesGeneratedPlan {
        full_share,
        proof_request,
        sk_share_computation_request,
        e_sm_share_computation_request,
        sk_share_encryption_requests,
        e_sm_share_encryption_requests,
        recipient_party_ids,
        own_sk_share_raw,
        own_esi_shares_raw,
    })
}

/// Keep C3's N recipient slots while withholding shares from parties without a C0 key.
fn recipient_keys_for_c3(
    encryption_keys: &[Arc<EncryptionKey>],
    own_party_id: u64,
    n: usize,
    h: usize,
    params: &Arc<BfvParameters>,
) -> Result<(Vec<PublicKey>, Vec<u64>)> {
    let own_idx = usize::try_from(own_party_id)?;
    if own_idx >= n {
        bail!("own party {} is outside committee N ({})", own_party_id, n);
    }

    let mut keys_by_party = vec![None; n];
    for key in encryption_keys {
        let idx = usize::try_from(key.party_id)?;
        if idx >= n {
            bail!(
                "recipient party {} is outside committee N ({})",
                key.party_id,
                n
            );
        }
        if keys_by_party[idx].is_some() {
            bail!("duplicate encryption key for party {}", key.party_id);
        }
        keys_by_party[idx] = Some(
            PublicKey::from_bytes(&key.pk_bfv, params)
                .map_err(|e| anyhow!("Failed to deserialize BFV public key: {:?}", e))?,
        );
    }

    let own_pk = keys_by_party[own_idx]
        .as_ref()
        .ok_or_else(|| {
            anyhow!(
                "own party {} missing from collected encryption keys",
                own_party_id
            )
        })?
        .clone();
    let recipient_party_ids: Vec<u64> = keys_by_party
        .iter()
        .enumerate()
        .filter_map(|(idx, pk)| pk.as_ref().map(|_| idx as u64))
        .collect();
    if recipient_party_ids.len() < h {
        bail!(
            "collected {} encryption keys, fewer than committee H ({})",
            recipient_party_ids.len(),
            h
        );
    }

    // C3 must prove an encryption of every N-wide C2 share except the sender's own.
    // For an absent recipient, use the sender's C0 key for that proof slot. The
    // sender already knows the plaintext share; the placeholder is never delivered.
    let recipient_pks = keys_by_party
        .into_iter()
        .map(|key| key.unwrap_or_else(|| own_pk.clone()))
        .collect();
    Ok((recipient_pks, recipient_party_ids))
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_fhe_params::BfvParamSet;
    use fhe::bfv::SecretKey;
    use ndarray::Array2;

    #[actix::test]
    async fn missing_c0_keeps_n_c3_slots_and_skips_share_delivery() -> Result<()> {
        let cipher = Cipher::from_password("test-password").await?;
        let threshold_preset = BfvPreset::InsecureThreshold512;
        let (_, params) = build_pair_for_preset(threshold_preset)?;
        let degree = params.degree();
        let l = BfvParamSet::from(threshold_preset).moduli.len();
        let mut rng = rand::rng();
        let sk_0 = SecretKey::random(&params, &mut rng);
        let pk_0 = PublicKey::new(&sk_0, &mut rng);
        let sk_2 = SecretKey::random(&params, &mut rng);
        let pk_2 = PublicKey::new(&sk_2, &mut rng);
        let keys = vec![
            Arc::new(EncryptionKey::new(
                2,
                ArcBytes::from_bytes(&pk_2.to_bytes()),
            )),
            Arc::new(EncryptionKey::new(
                0,
                ArcBytes::from_bytes(&pk_0.to_bytes()),
            )),
        ];
        let secret = SharedSecret::new(
            (0..l)
                .map(|row| {
                    Array2::from_shape_fn((3, degree), |(party, _)| (party + row + 1) as u64)
                })
                .collect(),
        );
        let sensitive = SensitiveBytes::new(vec![1], &cipher)?;
        let plan = build_shares_generated_plan(
            &cipher,
            BfvPreset::InsecureDkg512,
            2,
            1,
            3,
            ArcBytes::from_bytes(&[7]),
            secret.clone(),
            vec![secret.clone()],
            sensitive.clone(),
            ProofRequestData {
                pk0_share_raw: ArcBytes::from_bytes(&[7]),
                sk_raw: sensitive.clone(),
                eek_raw: sensitive,
            },
            &keys,
        )?;

        assert_eq!(plan.recipient_party_ids, vec![0, 2]);
        assert_eq!(plan.full_share.num_parties(), 3);
        assert_eq!(plan.sk_share_encryption_requests.len(), 2 * l);
        assert_eq!(plan.e_sm_share_encryption_requests.len(), 2 * l);
        assert_eq!(
            plan.sk_share_encryption_requests
                .iter()
                .filter(|request| request.recipient_party_id == 1)
                .count(),
            l
        );
        assert!(plan
            .sk_share_encryption_requests
            .iter()
            .filter(|request| request.recipient_party_id == 1)
            .all(|request| request.recipient_pk_raw.as_ref() == pk_2.to_bytes()));

        let decrypted_live = plan
            .full_share
            .sk_sss
            .clone_share(0)
            .expect("party 0 ciphertext")
            .decrypt(&sk_0, &params, degree)?;
        assert_eq!(decrypted_live, secret.extract_party_share(0)?);
        let decrypted_placeholder = plan
            .full_share
            .sk_sss
            .clone_share(1)
            .expect("party 1 proof placeholder")
            .decrypt(&sk_2, &params, degree)?;
        assert_eq!(decrypted_placeholder, secret.extract_party_share(1)?);
        Ok(())
    }

    #[test]
    fn c3_recipient_roster_rejects_duplicate_and_out_of_range_keys() -> Result<()> {
        let (_, params) = build_pair_for_preset(BfvPreset::InsecureThreshold512)?;
        let mut rng = rand::rng();
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);
        let key = |party_id| {
            Arc::new(EncryptionKey::new(
                party_id,
                ArcBytes::from_bytes(&pk.to_bytes()),
            ))
        };

        assert!(recipient_keys_for_c3(&[key(0), key(0)], 0, 3, 2, &params).is_err());
        assert!(recipient_keys_for_c3(&[key(0), key(3)], 0, 3, 2, &params).is_err());
        assert!(recipient_keys_for_c3(&[key(0), key(1)], 2, 3, 2, &params).is_err());
        assert!(recipient_keys_for_c3(&[key(0)], 0, 3, 2, &params).is_err());
        Ok(())
    }
}
