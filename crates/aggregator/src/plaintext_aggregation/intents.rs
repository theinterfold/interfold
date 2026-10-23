// SPDX-License-Identifier: LGPL-3.0-only

//! Deterministic plaintext formatting and C7 aggregation job planning.

use super::*;
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
                || proof.public_signals.len() != (2 * slots + preset.max_msg_non_zero_coeffs()) * 32
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
            message.resize(preset.max_msg_non_zero_coeffs(), 0);
            fields[2 * slots..]
                .iter()
                .zip(message)
                .all(|(field, value)| *field == U256::from(value).to_be_bytes::<32>())
        })
}

/// Pad/truncate each decrypted plaintext limb to `preset.max_msg_non_zero_coeffs() * 8` bytes.
pub(crate) fn format_decrypted_plaintext(
    plaintext: &[ArcBytes],
    preset: e3_fhe_params::BfvPreset,
) -> Vec<ArcBytes> {
    let len = preset.max_msg_non_zero_coeffs() * 8;
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

#[cfg(test)]
mod tests {
    use super::*;
    use e3_fhe_params::BfvPreset;

    #[test]
    fn the_published_length_follows_the_preset_cap() {
        let plaintext = vec![ArcBytes::from_bytes(&[7u8; 128 * 8])];
        let simd = format_decrypted_plaintext(&plaintext, BfvPreset::InsecureThresholdSimd);
        assert_eq!(simd[0].extract_bytes(), vec![7u8; 128 * 8]);

        // A 50-cap preset truncates the same plaintext; the SIMD preset pads a short one.
        let capped = format_decrypted_plaintext(&plaintext, BfvPreset::InsecureThreshold64);
        assert_eq!(capped[0].extract_bytes(), vec![7u8; 50 * 8]);
        let short = format_decrypted_plaintext(
            &[ArcBytes::from_bytes(&[1u8; 8])],
            BfvPreset::InsecureThresholdSimd,
        );
        assert_eq!(short[0].extract_bytes().len(), 128 * 8);
    }
}
