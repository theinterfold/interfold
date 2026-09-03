// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure threshold-CKKS keyshare workflow (scheme twin of the BFV
//! `threshold_keyshare` capability).
//!
//! Same phase discipline as the BFV flow — CollectingKeyshares ->
//! ReadyForDecryption -> Decrypting -> Completed — expressed as pure
//! plan-building functions over [`e3_fhe::CkksFhe`], with NO actix, bus,
//! persistence, or timer dependencies. The actor shell dispatches here for
//! E3s whose program binds the CKKS scheme (`E3Scheme::Ckks`).
//!
//! DKG share transport (per-recipient BFV encryption of dealt rows) lives
//! in `encrypted_dkg`; the phase machine in `machine`. C1/C3 proof
//! emission for CKKS is not wired (witness generators exist in
//! e3-zk-helpers); the explicit posture per proof type is
//! `e3_fhe_params::ckks_presets::CkksProofPosture`.

use anyhow::{anyhow, bail, Result};
use e3_events::OrderedSet;
use e3_fhe::{
    CkksDecryptionShareRequest, CkksFhe, CkksKeyshareMaterial, GetCkksAggregatePlaintext,
    GetCkksAggregatePublicKey,
};
use e3_utils::utility_types::ArcBytes;
use serde::{Deserialize, Serialize};

/// Phase state for one party's CKKS DKG, persisted by the actor shell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CkksKeyshareState {
    /// Waiting for every member's broadcast (pk share + dealt rows for us).
    CollectingKeyshares(CollectingKeyshares),
    /// DKG complete: joint pk known, aggregated share polys held.
    ReadyForDecryption(ReadyForDecryption),
    /// Decryption share published for the ciphertext output.
    Decrypting(ReadyForDecryption),
    /// Plaintext aggregated.
    Completed,
}

/// One member's DKG broadcast as this party receives it: the pk share and
/// the share-matrix ROW dealt to us (already extracted by the sender).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CkksDealtShare {
    /// 1-based party id of the dealer.
    pub dealer_party_id: u64,
    /// Dealer's serialized pk share (`p0`).
    pub pk_share: ArcBytes,
    /// Row of the dealer's sk share matrices for THIS party: `[L][degree]`.
    pub sk_row: Vec<Vec<u64>>,
    /// Row of the dealer's smudging share matrices for this party.
    pub es_row: Vec<Vec<u64>>,
}

/// Collection phase data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectingKeyshares {
    /// Own 1-based party id.
    pub party_id: u64,
    /// Committee size.
    pub n_parties: usize,
    /// Own generated material (secret coeffs SENSITIVE — actor encrypts at
    /// rest with `e3_crypto::Cipher`, same as the BFV sk share).
    pub own: CkksKeyshareMaterial,
    /// Received dealt shares, dealer id -> share.
    pub received: Vec<CkksDealtShare>,
}

/// Post-DKG state: everything needed to serve decryption requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadyForDecryption {
    pub party_id: u64,
    /// Joint public key bytes (broadcast to users for encryption).
    pub public_key: ArcBytes,
    /// Aggregated sk share polynomial (level 0, serialized).
    pub sk_poly_sum: ArcBytes,
    /// Aggregated smudging share polynomial (level 0, serialized).
    pub es_poly_sum: ArcBytes,
}

/// Extract the dealt row for `recipient` (1-based) from own material — the
/// payload a member broadcasts to that recipient.
pub fn dealt_row_for(
    own: &CkksKeyshareMaterial,
    own_party_id: u64,
    recipient_party_id: u64,
) -> Result<CkksDealtShare> {
    let j = (recipient_party_id as usize)
        .checked_sub(1)
        .ok_or_else(|| anyhow!("party ids are 1-based"))?;
    if j >= own.rows {
        bail!(
            "recipient {recipient_party_id} out of range ({} rows)",
            own.rows
        );
    }
    let extract = |mats: &[Vec<u64>]| -> Vec<Vec<u64>> {
        mats.iter()
            .map(|flat| flat[j * own.cols..(j + 1) * own.cols].to_vec())
            .collect()
    };
    Ok(CkksDealtShare {
        dealer_party_id: own_party_id,
        pk_share: ArcBytes::from_bytes(&own.pk_share),
        sk_row: extract(&own.sk_sss),
        es_row: extract(&own.es_sss),
    })
}

/// Transition: all `n_parties` dealt shares collected (including own) ->
/// aggregate rows + pk shares into `ReadyForDecryption`.
pub fn build_ready_for_decryption(
    fhe: &CkksFhe,
    state: &CollectingKeyshares,
) -> Result<ReadyForDecryption> {
    if state.received.len() != state.n_parties {
        bail!(
            "cannot finalize DKG: {}/{} dealt shares collected",
            state.received.len(),
            state.n_parties
        );
    }
    // Deterministic dealer order (dealer id), duplicate detection.
    let mut shares = state.received.clone();
    shares.sort_by_key(|s| s.dealer_party_id);
    for w in shares.windows(2) {
        if w[0].dealer_party_id == w[1].dealer_party_id {
            bail!("duplicate dealt share from party {}", w[0].dealer_party_id);
        }
    }

    // Joint pk from all pk shares.
    let public_key = fhe.get_aggregate_public_key(GetCkksAggregatePublicKey {
        keyshares: OrderedSet::from(
            shares
                .iter()
                .map(|s| s.pk_share.clone())
                .collect::<Vec<_>>(),
        ),
    })?;

    // Aggregate the received rows into this party's share polynomials.
    let sk_poly_sum = fhe.aggregate_rows(shares.iter().map(|s| s.sk_row.as_slice()))?;
    let es_poly_sum = fhe.aggregate_rows(shares.iter().map(|s| s.es_row.as_slice()))?;

    Ok(ReadyForDecryption {
        party_id: state.party_id,
        public_key: ArcBytes::from_bytes(&public_key),
        sk_poly_sum: ArcBytes::from_bytes(&sk_poly_sum),
        es_poly_sum: ArcBytes::from_bytes(&es_poly_sum),
    })
}

/// Decryption-share step (CiphertextOutputPublished handler body).
pub fn build_decryption_share(
    fhe: &CkksFhe,
    state: &ReadyForDecryption,
    ciphertext_output: &[u8],
) -> Result<Vec<u8>> {
    fhe.decryption_share(CkksDecryptionShareRequest {
        sk_poly_sum: state.sk_poly_sum.to_vec(),
        es_poly_sum: state.es_poly_sum.to_vec(),
        ciphertext: ciphertext_output.to_vec(),
    })
}

/// Plaintext aggregation step (aggregator side): combine `t+1` shares.
pub fn aggregate_plaintext(
    fhe: &CkksFhe,
    decryption_shares: Vec<(u64, ArcBytes)>,
    ciphertext_output: &[u8],
) -> Result<Vec<f64>> {
    let (party_ids, shares): (Vec<u64>, Vec<ArcBytes>) = decryption_shares.into_iter().unzip();
    let bytes = fhe.get_aggregate_plaintext(GetCkksAggregatePlaintext {
        decryption_shares: shares,
        party_ids,
        ciphertext_output: ciphertext_output.to_vec(),
    })?;
    CkksFhe::decode_plaintext_output(&bytes)
}
