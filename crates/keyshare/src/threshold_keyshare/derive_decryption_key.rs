// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure decryption-key aggregation crypto.
//!
//! After C2/C3 verification, [`build_decryption_key_plan`] decrypts this party's
//! row from every honest sender, splices in the locally cached own share, builds
//! the [`CalculateDecryptionKeyRequest`] and the C4 (share-decryption) proof
//! requests, and selects the canonical honest roster. No actix/persistence/bus
//! access — the actor publishes the compute request, persists the honest set and
//! stashes the C4 requests from the returned plan.

use anyhow::{anyhow, bail, Context, Result};
use e3_crypto::Cipher;
use e3_events::{DkgShareDecryptionProofRequest, E3id, ThresholdShare};
use e3_fhe_params::{BfvParamSet, BfvPreset};
use e3_trbfv::{
    calculate_decryption_key::CalculateDecryptionKeyRequest,
    helpers::deserialize_secret_key,
    shares::{EncryptableVec, ShamirShare},
    TrBFVConfig,
};
use e3_utils::utility_types::ArcBytes;
use e3_zk_helpers::computation::DkgInputType;
use e3_zk_helpers::CiphernodesCommitteeSize;
use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;
use tracing::{info, warn};

use crate::domain::{vec_of_rows_to_shamir_share, AggregatingDecryptionKey};

/// Outcome of decryption-key aggregation planning.
pub(crate) enum DecryptionKeyPlan {
    /// Too few honest parties remain after dimension filtering — the caller
    /// should publish `E3Failed(InsufficientCommitteeMembers)`.
    Insufficient,
    /// Proceed: dispatch `CalculateDecryptionKey`, persist `honest_party_ids` and
    /// stash the C4 proof requests.
    Proceed {
        calc_request: CalculateDecryptionKeyRequest,
        sk_request: DkgShareDecryptionProofRequest,
        esm_requests: Vec<DkgShareDecryptionProofRequest>,
        honest_party_ids: BTreeSet<u64>,
    },
}

/// Decrypt honest shares, splice the own share, and assemble the decryption-key
/// compute request plus C4 proof requests.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_decryption_key_plan(
    cipher: &Cipher,
    share_enc_preset: BfvPreset,
    own_party_id: u64,
    committee_size: CiphernodesCommitteeSize,
    trbfv_config: TrBFVConfig,
    current: &AggregatingDecryptionKey,
    shares: Vec<Arc<ThresholdShare>>,
    dishonest_parties: Option<HashSet<u64>>,
    selected_party_ids: &BTreeSet<u64>,
    e3_id: &E3id,
) -> Result<DecryptionKeyPlan> {
    let party_id = own_party_id as usize;
    let committee = committee_size.values();

    if shares.is_empty() {
        bail!("No pending verification shares");
    }
    let sk_bytes = current.sk_bfv.access(cipher)?;
    let params = BfvParamSet::from(share_enc_preset).build_arc();
    let sk_bfv = deserialize_secret_key(&sk_bytes, &params)?;
    let degree = params.degree();

    // Own plaintext shares (bincode `Vec<Vec<u64>>` shape [L][N]) cached at generation time.
    let own_sk_rows: Vec<Vec<u64>> =
        bincode::deserialize(&current.own_sk_share_raw.access_raw(cipher)?)
            .context("Failed to deserialize own_sk_share_raw")?;
    let own_esi_rows_per_esi: Vec<Vec<Vec<u64>>> = current
        .own_esi_shares_raw
        .iter()
        .map(|sb| {
            let bytes = sb.access_raw(cipher)?;
            bincode::deserialize::<Vec<Vec<u64>>>(&bytes)
                .context("Failed to deserialize own esi share")
        })
        .collect::<Result<_>>()?;

    // Expected dimensions derived from own (trusted) shares.
    let expected_num_esi = own_esi_rows_per_esi.len();
    let expected_num_moduli_sk = own_sk_rows.len();
    let expected_num_moduli_esi = own_esi_rows_per_esi
        .first()
        .map(|rows| rows.len())
        .unwrap_or(0);

    // Filter to honest external parties (collector already excludes self).
    let honest_shares: Vec<_> = shares
        .iter()
        .filter(|ts| {
            dishonest_parties
                .as_ref()
                .is_none_or(|dp| !dp.contains(&ts.party_id))
        })
        .collect();

    // Validate per-party dimensions and exclude mismatched parties.
    let mut dimension_excluded: Vec<u64> = Vec::new();
    let mut honest_shares: Vec<_> = honest_shares
        .into_iter()
        .filter(|ts| {
            if ts.esi_sss.len() != expected_num_esi {
                warn!(
                    "Party {} has wrong esi_sss count ({} vs expected {}) — excluding from honest set",
                    ts.party_id, ts.esi_sss.len(), expected_num_esi
                );
                dimension_excluded.push(ts.party_id);
                return false;
            }
            let idx = if ts.sk_sss.len() == 1 { 0 } else { party_id };
            match ts.sk_sss.clone_share(idx) {
                Some(share) if share.num_moduli() != expected_num_moduli_sk => {
                    warn!(
                        "Party {} has wrong sk num_moduli ({} vs expected {}) — excluding from honest set",
                        ts.party_id, share.num_moduli(), expected_num_moduli_sk
                    );
                    dimension_excluded.push(ts.party_id);
                    return false;
                }
                None => {
                    warn!(
                        "Party {} has no sk_sss share at index {} — excluding from honest set",
                        ts.party_id, idx
                    );
                    dimension_excluded.push(ts.party_id);
                    return false;
                }
                _ => {}
            }
            for (esi_idx, esi_shares) in ts.esi_sss.iter().enumerate() {
                let idx = if esi_shares.len() == 1 { 0 } else { party_id };
                match esi_shares.clone_share(idx) {
                    Some(share) if share.num_moduli() != expected_num_moduli_esi => {
                        warn!(
                            "Party {} has wrong esi num_moduli at index {} ({} vs expected {}) — excluding from honest set",
                            ts.party_id, esi_idx, share.num_moduli(), expected_num_moduli_esi
                        );
                        dimension_excluded.push(ts.party_id);
                        return false;
                    }
                    None => {
                        warn!(
                            "Party {} has no esi_sss share at index {} (esi {}) — excluding from honest set",
                            ts.party_id, idx, esi_idx
                        );
                        dimension_excluded.push(ts.party_id);
                        return false;
                    }
                    _ => {}
                }
            }
            true
        })
        .collect();
    honest_shares.sort_unstable_by_key(|share| share.party_id);

    if !dimension_excluded.is_empty() {
        warn!(
            "Excluded {} parties with dimension mismatches: {:?}",
            dimension_excluded.len(),
            dimension_excluded
        );
        // Re-check threshold after exclusion: own share + external shares must exceed T.
        if honest_shares.len() < committee.threshold {
            return Ok(DecryptionKeyPlan::Insufficient);
        }
    }

    // Noir C4 is parameterized by the H dealers named in the accepted roster.
    let committee_h = committee.h;
    if selected_party_ids.len() != committee_h
        || selected_party_ids
            .iter()
            .any(|&party_id| party_id >= committee.n as u64)
    {
        bail!("selected DKG roster does not match committee H and N");
    }
    let honest_party_ids = selected_party_ids.clone();
    honest_shares.retain(|s| honest_party_ids.contains(&s.party_id));
    let expected_external = committee_h - usize::from(honest_party_ids.contains(&own_party_id));
    if honest_shares.len() != expected_external {
        return Ok(DecryptionKeyPlan::Insufficient);
    }

    debug_assert!(
        honest_shares
            .windows(2)
            .all(|w| w[0].party_id < w[1].party_id),
        "honest_shares must be strictly ascending by party_id"
    );

    let canonical_sorted: Vec<u64> = honest_party_ids.iter().copied().collect();
    let own_plaintext_idx = canonical_sorted.iter().position(|&pid| pid == own_party_id);
    if own_plaintext_idx.is_none() {
        warn!(
            "Party {own_party_id} is outside the canonical honest roster (H={committee_h}, roster={honest_party_ids:?}) for E3 {e3_id}; \
             NodeFold/C5 on the aggregator will not include this party"
        );
    }
    let num_honest = honest_party_ids.len();
    let external_for_c4: &[&Arc<ThresholdShare>] = &honest_shares;

    info!(
        "Decrypting shares from {} honest parties (canonical roster size H={}) for E3 {}",
        num_honest, committee_h, e3_id
    );

    // The own slot has no ciphertext. A party outside the roster decrypts all H slots.
    let num_moduli_sk = expected_num_moduli_sk;
    let mut sk_ciphertexts_raw = Vec::new();
    for ts in external_for_c4 {
        let idx = if ts.sk_sss.len() == 1 { 0 } else { party_id };
        let share = ts
            .sk_sss
            .clone_share(idx)
            .ok_or(anyhow!("No sk_sss share at index {}", idx))?;
        for ct_bytes in share.ciphertext_bytes() {
            sk_ciphertexts_raw.push(ct_bytes.clone());
        }
    }

    // C4b: esi_sss external ciphertexts — one set per smudging noise
    let num_esi = expected_num_esi;
    let num_moduli_esi = expected_num_moduli_esi;
    let mut esi_ciphertexts_raw: Vec<Vec<ArcBytes>> = vec![Vec::new(); num_esi];
    for ts in external_for_c4 {
        for (esi_idx, esi_shares) in ts.esi_sss.iter().enumerate() {
            let idx = if esi_shares.len() == 1 { 0 } else { party_id };
            let share = esi_shares
                .clone_share(idx)
                .ok_or(anyhow!("No esi_sss share at index {}", idx))?;
            for ct_bytes in share.ciphertext_bytes() {
                esi_ciphertexts_raw[esi_idx].push(ct_bytes.clone());
            }
        }
    }

    // Decrypt our share row from each external honest sender using BFV.
    let mut sk_sss_collected: Vec<ShamirShare> = external_for_c4
        .iter()
        .map(|ts| {
            let idx = if ts.sk_sss.len() == 1 { 0 } else { party_id };
            let encrypted = ts
                .sk_sss
                .clone_share(idx)
                .ok_or(anyhow!("No sk_sss share at index {}", idx))?;
            encrypted.decrypt(&sk_bfv, &params, degree)
        })
        .collect::<Result<_>>()?;

    if let Some(idx) = own_plaintext_idx {
        let own_sk_shamir = vec_of_rows_to_shamir_share(&own_sk_rows, degree)?;
        sk_sss_collected.insert(idx, own_sk_shamir);
    }

    // Decrypt per-party ESI shares: shape [external_party][esm_idx]
    let mut per_party_esi: Vec<Vec<ShamirShare>> = external_for_c4
        .iter()
        .map(|ts| {
            ts.esi_sss
                .iter()
                .map(|esi_shares| {
                    let idx = if esi_shares.len() == 1 { 0 } else { party_id };
                    let encrypted = esi_shares
                        .clone_share(idx)
                        .ok_or(anyhow!("No esi_sss share at index {}", idx))?;
                    encrypted.decrypt(&sk_bfv, &params, degree)
                })
                .collect::<Result<Vec<_>>>()
        })
        .collect::<Result<_>>()?;

    if let Some(idx) = own_plaintext_idx {
        let own_esi_shamirs: Vec<ShamirShare> = own_esi_rows_per_esi
            .iter()
            .map(|rows| vec_of_rows_to_shamir_share(rows, degree))
            .collect::<Result<_>>()?;
        per_party_esi.insert(idx, own_esi_shamirs);
    }

    // Transpose to [esm_idx][party] — CalculateDecryptionKey aggregates per smudging noise
    let esi_sss_collected: Vec<Vec<ShamirShare>> = (0..num_esi)
        .map(|esm_idx| {
            per_party_esi
                .iter()
                .map(|party_esi| party_esi[esm_idx].clone())
                .collect()
        })
        .collect();

    // Build CalculateDecryptionKey request
    let calc_request = CalculateDecryptionKeyRequest {
        trbfv_config,
        esi_sss_collected: esi_sss_collected
            .into_iter()
            .map(|s| s.encrypt(cipher))
            .collect::<Result<_>>()?,
        sk_sss_collected: sk_sss_collected.encrypt(cipher)?,
    };

    // Build C4 proof requests — stored for sending after CalculateDecryptionKey completes
    let threshold_preset = share_enc_preset
        .threshold_counterpart()
        .ok_or_else(|| anyhow!("No threshold counterpart for {:?}", share_enc_preset))?;

    let sk_request = DkgShareDecryptionProofRequest {
        sk_bfv: current.sk_bfv.clone(),
        honest_ciphertexts_raw: sk_ciphertexts_raw,
        num_honest_parties: num_honest,
        num_moduli: num_moduli_sk,
        own_plaintext_idx,
        recipient_party_id: party_id as u64,
        own_share_raw: own_plaintext_idx.map(|_| current.own_sk_share_raw.clone()),
        dkg_input_type: DkgInputType::SecretKey,
        params_preset: threshold_preset,
        committee_size,
    };

    let esm_requests: Vec<DkgShareDecryptionProofRequest> = esi_ciphertexts_raw
        .into_iter()
        .enumerate()
        .map(|(esi_idx, esi_cts)| DkgShareDecryptionProofRequest {
            sk_bfv: current.sk_bfv.clone(),
            honest_ciphertexts_raw: esi_cts,
            num_honest_parties: num_honest,
            num_moduli: num_moduli_esi,
            own_plaintext_idx,
            recipient_party_id: party_id as u64,
            own_share_raw: own_plaintext_idx.map(|_| current.own_esi_shares_raw[esi_idx].clone()),
            dkg_input_type: DkgInputType::SmudgingNoise,
            params_preset: threshold_preset,
            committee_size,
        })
        .collect();

    Ok(DecryptionKeyPlan::Proceed {
        calc_request,
        sk_request,
        esm_requests,
        honest_party_ids,
    })
}
