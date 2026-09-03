// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Encrypted-transport CKKS DKG: dealt rows travel BFV-encrypted per
//! recipient inside the EXISTING [`e3_events::ThresholdShare`] event — no
//! event-schema change.
//!
//! Reuse argument: `ThresholdShare` carries `pk_share: ArcBytes` plus
//! [`BfvEncryptedShares`] whose plaintext payload is a party's Shamir row
//! per RNS modulus (`[L][degree]` u64 matrix). The CKKS dealt matrices have
//! exactly that shape ([`e3_fhe::CkksKeyshareMaterial`]), so the transport
//! layer (per-recipient BFV encryption under each member's ephemeral DKG
//! key, C3-provable witnesses) applies unchanged; only the pk-share bytes
//! and the post-decryption aggregation differ per scheme. `esi_sss` (a Vec
//! in the event because BFV deals one esi per decryption) has length 1 for
//! CKKS: one smudging secret per committee member.
//!
//! PARAMETER CONSTRAINT (checked by `build_encrypted_threshold_share`):
//! dealt share coefficients travel as BFV plaintexts, so every CKKS
//! ciphertext modulus `q_i` must satisfy `q_i <= t_dkg` (the transport
//! preset's plaintext modulus). The insecure pairing that works is CKKS
//! moduli `[0xffffee001, 0xffffc4001]` (the BFV threshold moduli) under
//! `InsecureDkg512` (`t_dkg = 0xffffee001`); a CKKS deployment picking its
//! own moduli must keep them within its DKG counterpart's `t`.

use anyhow::{bail, Context, Result};
use e3_events::ThresholdShare;
use e3_fhe::{CkksFhe, CkksKeyshareMaterial};
use e3_trbfv::shares::{BfvEncryptedShares, SharedSecret};
use e3_utils::utility_types::ArcBytes;
use fhe::bfv::{BfvParameters, PublicKey, SecretKey};
use ndarray::Array2;
use rand::{CryptoRng, RngCore};
use std::sync::Arc;

/// Reassemble a dealt matrix set (`[L]` flat vecs) into `Vec<Array2<u64>>`
/// (the `SharedSecret` layout: rows = parties, cols = degree).
fn to_shared_secret(flat: &[Vec<u64>], rows: usize, cols: usize) -> Result<SharedSecret> {
    let mats = flat
        .iter()
        .enumerate()
        .map(|(m, v)| {
            Array2::from_shape_vec((rows, cols), v.clone())
                .with_context(|| format!("dealt matrix {m} has wrong shape"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(SharedSecret::new(mats))
}

/// Build the broadcast `ThresholdShare` for this party: every recipient's
/// dealt rows BFV-encrypted under their ephemeral DKG public key.
///
/// `recipient_pks[j]` is party `j+1`'s ephemeral BFV key (from the existing
/// `EncryptionKey` collection round). `own_slot` (0-based) is skipped —
/// a party never encrypts its own rows (they stay local, like BFV).
/// `ckks_moduli` are the committee's CKKS ciphertext moduli, validated
/// against the transport plaintext modulus (see module docs).
pub fn build_encrypted_threshold_share<R: RngCore + CryptoRng>(
    material: &CkksKeyshareMaterial,
    own_party_id: u64,
    recipient_pks: &[PublicKey],
    share_enc_params: &Arc<BfvParameters>,
    ckks_moduli: &[u64],
    rng: &mut R,
) -> Result<ThresholdShare> {
    let own_slot = (own_party_id as usize)
        .checked_sub(1)
        .context("party ids are 1-based")?;
    if recipient_pks.len() != material.rows {
        bail!(
            "recipient pk count {} != committee size {}",
            recipient_pks.len(),
            material.rows
        );
    }
    // Share coefficients travel as BFV plaintexts mod t_dkg: any CKKS
    // modulus above t_dkg would wrap and corrupt the dealt rows.
    let t_dkg = share_enc_params.plaintext();
    for (m, q) in ckks_moduli.iter().enumerate() {
        if *q > t_dkg {
            bail!(
                "CKKS modulus q_{m} = {q:#x} exceeds DKG transport plaintext \
                 modulus {t_dkg:#x}; dealt shares would wrap in transit"
            );
        }
    }
    let sk_secret = to_shared_secret(&material.sk_sss, material.rows, material.cols)?;
    let es_secret = to_shared_secret(&material.es_sss, material.rows, material.cols)?;

    let (sk_sss, _sk_witnesses) = BfvEncryptedShares::encrypt_all_extended(
        &sk_secret,
        recipient_pks,
        share_enc_params,
        rng,
        Some(own_slot),
    )?;
    let (es_enc, _es_witnesses) = BfvEncryptedShares::encrypt_all_extended(
        &es_secret,
        recipient_pks,
        share_enc_params,
        rng,
        Some(own_slot),
    )?;

    Ok(ThresholdShare {
        party_id: own_party_id,
        pk_share: ArcBytes::from_bytes(&material.pk_share),
        sk_sss,
        esi_sss: vec![es_enc],
    })
}

/// Decrypt the rows a broadcast `ThresholdShare` carries for this party.
///
/// Returns `(sk_row, es_row)` as `[L][degree]` matrices, or the sender's own
/// locally-kept rows when `share.party_id == own_party_id`.
#[allow(clippy::type_complexity)]
pub fn decrypt_dealt_rows(
    share: &ThresholdShare,
    own_party_id: u64,
    own_material: Option<&CkksKeyshareMaterial>,
    sk_bfv: &SecretKey,
    share_enc_params: &Arc<BfvParameters>,
    degree: usize,
) -> Result<(Vec<Vec<u64>>, Vec<Vec<u64>>)> {
    let slot = (own_party_id as usize)
        .checked_sub(1)
        .context("party ids are 1-based")?;

    if share.party_id == own_party_id {
        // Own rows never travel encrypted: read them from local material.
        let material =
            own_material.context("own ThresholdShare requires local keyshare material")?;
        let extract = |mats: &[Vec<u64>]| -> Vec<Vec<u64>> {
            mats.iter()
                .map(|flat| flat[slot * material.cols..(slot + 1) * material.cols].to_vec())
                .collect()
        };
        return Ok((extract(&material.sk_sss), extract(&material.es_sss)));
    }

    let decrypt_one = |enc: &BfvEncryptedShares| -> Result<Vec<Vec<u64>>> {
        let encrypted = enc
            .clone_share(slot)
            .with_context(|| format!("no encrypted share for recipient slot {slot}"))?;
        let shamir = encrypted.decrypt(sk_bfv, share_enc_params, degree)?;
        Ok(shamir.outer_iter().map(|r| r.to_vec()).collect())
    };
    let sk_row = decrypt_one(&share.sk_sss)?;
    let es = share
        .esi_sss
        .first()
        .context("CKKS ThresholdShare must carry exactly one esi entry")?;
    Ok((sk_row, decrypt_one(es)?))
}

/// Aggregate decrypted dealt rows from all members into this party's share
/// polynomials, plus the joint public key — the encrypted-transport version
/// of `build_ready_for_decryption`.
pub fn finalize_from_threshold_shares(
    fhe: &CkksFhe,
    own_party_id: u64,
    own_material: &CkksKeyshareMaterial,
    shares: &[Arc<ThresholdShare>],
    sk_bfv: &SecretKey,
    share_enc_params: &Arc<BfvParameters>,
) -> Result<super::workflow::ReadyForDecryption> {
    let n_parties = own_material.rows;
    if shares.len() != n_parties {
        bail!(
            "cannot finalize DKG: {}/{} threshold shares collected",
            shares.len(),
            n_parties
        );
    }
    let mut sorted: Vec<_> = shares.to_vec();
    sorted.sort_by_key(|s| s.party_id);
    for w in sorted.windows(2) {
        if w[0].party_id == w[1].party_id {
            bail!("duplicate threshold share from party {}", w[0].party_id);
        }
    }

    let degree = own_material.cols;
    let mut sk_rows = Vec::with_capacity(n_parties);
    let mut es_rows = Vec::with_capacity(n_parties);
    for share in &sorted {
        let (sk_row, es_row) = decrypt_dealt_rows(
            share,
            own_party_id,
            Some(own_material),
            sk_bfv,
            share_enc_params,
            degree,
        )?;
        sk_rows.push(sk_row);
        es_rows.push(es_row);
    }

    let public_key = fhe.get_aggregate_public_key(e3_fhe::GetCkksAggregatePublicKey {
        keyshares: e3_events::OrderedSet::from(
            sorted
                .iter()
                .map(|s| s.pk_share.clone())
                .collect::<Vec<_>>(),
        ),
    })?;
    let sk_poly_sum = fhe.aggregate_rows(sk_rows.iter().map(|r| r.as_slice()))?;
    let es_poly_sum = fhe.aggregate_rows(es_rows.iter().map(|r| r.as_slice()))?;

    Ok(super::workflow::ReadyForDecryption {
        party_id: own_party_id,
        public_key: ArcBytes::from_bytes(&public_key),
        sk_poly_sum: ArcBytes::from_bytes(&sk_poly_sum),
        es_poly_sum: ArcBytes::from_bytes(&es_poly_sum),
    })
}
