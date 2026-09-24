// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use e3_events::{CircuitName, ProofType};

impl ThresholdPlaintextAggregator {
    /// Check the signed sender, share bytes, and ciphertext order before reserving a party slot.
    /// ZK verification still runs after collection. An unauthenticated bundle cannot exclude a party.
    pub(super) fn share_is_authenticated(
        &mut self,
        party_id: u64,
        shares: &[ArcBytes],
        proofs: &[SignedProofPayload],
        ciphertexts: &[ArcBytes],
    ) -> Result<bool> {
        let Some(address) = usize::try_from(party_id)
            .ok()
            .and_then(|party| self.committee_addresses.get(party))
        else {
            return Ok(false);
        };
        if !self.honest_committee_addresses.contains(address)
            || shares.is_empty()
            || shares.len() != ciphertexts.len()
            || proofs.len() != ciphertexts.len()
            || proofs.iter().any(|proof| {
                proof.payload.e3_id != self.e3_id
                    || proof.payload.proof_type != ProofType::C6ThresholdShareDecryption
                    || proof.payload.proof.circuit != CircuitName::ThresholdShareDecryption
                    || !proof.verify_address(address).unwrap_or(false)
            })
        {
            return Ok(false);
        }
        if self.pending.ciphertext_commitments.is_none() {
            let (params, _) = e3_fhe_params::build_pair_for_preset(self.params_preset)?;
            self.pending.ciphertext_commitments = Some(
                ciphertexts
                    .iter()
                    .map(|ciphertext| {
                        e3_bfv_client::compute_ct_commitment_with_params(ciphertext, &params)
                    })
                    .collect::<Result<_>>()?,
            );
        }
        let commitments = self.pending.ciphertext_commitments.as_ref().unwrap();
        let layout = CircuitName::ThresholdShareDecryption.input_layout();
        if commitments.len() != proofs.len()
            || proofs.iter().zip(commitments).any(|(proof, expected)| {
                layout.extract_field(&proof.payload.proof.public_signals, "ct_commitment")
                    != Some(expected.as_slice())
            })
        {
            return Ok(false);
        }
        Ok(
            ThresholdPlaintextAggregation::verify_shares_match_c6_commitments(
                self.params_preset,
                &[(party_id, shares.to_vec())],
                &BTreeMap::from([(party_id, proofs.to_vec())]),
            )
            .is_empty(),
        )
    }
}
