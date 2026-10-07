// SPDX-License-Identifier: LGPL-3.0-only

//! Deterministic plaintext formatting and C7 aggregation job planning.

use super::*;
use e3_zk_helpers::circuits::threshold::decrypted_shares_aggregation::MAX_MSG_NON_ZERO_COEFFS;
use tracing::warn;

/// Match C7's ordered commitments, one-based party IDs, and message to the selected C6 batch.
/// Each proof must come from the C7 circuit of `preset`'s protocol path.
pub(crate) fn c7_proofs_match_batch(
    proofs: &[Proof],
    c6: &[(u64, Vec<Proof>)],
    plaintext: &[ArcBytes],
    slots: usize,
    preset: e3_fhe_params::BfvPreset,
) -> bool {
    use alloy::primitives::U256;
    if proofs.len() != plaintext.len() || c6.len() < slots || slots == 0 {
        return false;
    }
    let layout = CircuitName::ThresholdShareDecryption.output_layout();
    proofs
        .iter()
        .zip(plaintext)
        .enumerate()
        .all(|(index, (proof, message))| {
            if !e3_events::ProofType::C7DecryptedSharesAggregation
                .circuit_names_for(preset)
                .contains(&proof.circuit)
                || proof.public_signals.len() != (2 * slots + MAX_MSG_NON_ZERO_COEFFS) * 32
            {
                return false;
            }
            let fields: Vec<_> = proof.public_signals.chunks_exact(32).collect();
            for (slot, (party, shares)) in c6.iter().take(slots).enumerate() {
                let Some(commitment) = shares
                    .get(index)
                    .and_then(|share| layout.extract_field(&share.public_signals, "d_commitment"))
                else {
                    return false;
                };
                if fields[slot] != commitment
                    || fields[slots + slot]
                        != (U256::from(*party) + U256::from(1)).to_be_bytes::<32>()
                {
                    return false;
                }
            }
            let Ok(mut message) = e3_bfv_client::decode_bytes_to_vec_u64(message) else {
                return false;
            };
            message.resize(MAX_MSG_NON_ZERO_COEFFS, 0);
            fields[2 * slots..]
                .iter()
                .zip(message)
                .all(|(field, value)| *field == U256::from(value).to_be_bytes::<32>())
        })
}

/// Pad/truncate each decrypted plaintext limb to the fixed `MAX_MSG_NON_ZERO_COEFFS * 8`.
pub(crate) fn format_decrypted_plaintext(plaintext: &[ArcBytes]) -> Vec<ArcBytes> {
    let len = MAX_MSG_NON_ZERO_COEFFS * 8;
    plaintext
        .iter()
        .map(|pt| {
            let mut bytes = pt.extract_bytes();
            if bytes.len() >= len {
                bytes.truncate(len);
            } else {
                bytes.resize(len, 0);
            }
            ArcBytes::from_bytes(&bytes)
        })
        .collect()
}

/// Bind each C7 (per-ciphertext) proof to the first `c6_total_slots` honest C6 inner
/// proofs for that ciphertext, producing the per-ciphertext decryption-aggregation jobs.
/// Returns `None` when an expected C6 inner proof is missing for some ciphertext index
/// (the actor then fails the decryption round).
pub(crate) fn build_decryption_aggregation_jobs(
    c7_proofs: &[Proof],
    honest_c6: &[(u64, Vec<Proof>)],
    c6_total_slots: usize,
) -> Option<Vec<DecryptionAggregationJobRequest>> {
    let mut jobs = Vec::with_capacity(c7_proofs.len());
    for (ct_idx, c7_proof) in c7_proofs.iter().enumerate() {
        let mut c6_inner_proofs = Vec::with_capacity(c6_total_slots);
        let c6_slot_indices: Vec<u32> = (0..c6_total_slots as u32).collect();
        for (_, wps) in honest_c6.iter().take(c6_total_slots) {
            let Some(p) = wps.get(ct_idx) else {
                warn!("C6 inner proof missing for party at ct index {}", ct_idx);
                return None;
            };
            c6_inner_proofs.push(p.clone());
        }
        jobs.push(DecryptionAggregationJobRequest {
            c6_inner_proofs,
            c6_slot_indices,
            c7_proof: c7_proof.clone(),
        });
    }
    Some(jobs)
}
