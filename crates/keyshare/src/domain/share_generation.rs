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
use fhe::bfv::PublicKey;
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
    /// Positional index -> real party_id for every recipient.
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
    let recipient_pks: Vec<PublicKey> = encryption_keys
        .iter()
        .map(|k| {
            PublicKey::from_bytes(&k.pk_bfv, &params)
                .map_err(|e| anyhow!("Failed to deserialize BFV public key: {:?}", e))
        })
        .collect::<Result<_>>()?;
    // Share-encryption fan-out targets every registered party (`N`); `own_idx` is then
    // skipped in `encrypt_all_extended_for_share_indices`, producing N-1 ciphertexts.
    // The C3a/C3b NodeFold slots are sized for `N`, so any drift between the collected
    // encryption-key roster and the configured committee would corrupt the fold witness.
    if recipient_pks.len() != derived_committee_size.values().n {
        bail!(
            "share-encryption recipients ({}) do not match committee N ({}); C3 fan-out would mis-size the NodeFold slots",
            recipient_pks.len(),
            derived_committee_size.values().n
        );
    }
    let recipient_party_ids: Vec<u64> = encryption_keys.iter().map(|k| k.party_id).collect();
    let recipient_share_indices: Vec<usize> = recipient_party_ids
        .iter()
        .map(|&recipient_party_id| recipient_party_id as usize)
        .collect();
    let own_idx = recipient_party_ids
        .iter()
        .position(|&recipient_party_id| recipient_party_id == party_id)
        .ok_or_else(|| {
            anyhow!(
                "own party {} missing from collected encryption keys",
                party_id
            )
        })?;

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
