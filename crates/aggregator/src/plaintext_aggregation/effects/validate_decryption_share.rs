// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use e3_events::{CircuitName, ProofType};

impl ThresholdPlaintextAggregator {
    pub(super) fn c6_has_canonical_domain(&self, proof: &Proof, ciphertext: &ArcBytes) -> bool {
        let Ok(e3_id) = self.e3_id.clone().try_into() else {
            return false;
        };
        let domain = e3_committee_hash::decryption_domain_limbs(
            self.e3_id.chain_id(),
            e3_id,
            self.decryption_domain,
            alloy::primitives::keccak256(&ciphertext[..]),
        );
        let layout = CircuitName::ThresholdShareDecryption.input_layout();
        proof.circuit == CircuitName::ThresholdShareDecryption
            && [("domain_hi", domain.hi), ("domain_lo", domain.lo)]
                .into_iter()
                .all(|(name, limb)| {
                    let expected = alloy::primitives::U256::from(limb).to_be_bytes::<32>();
                    layout.extract_field(&proof.public_signals, name) == Some(expected.as_slice())
                })
    }

    /// Check the signed sender, shares, ciphertext order, and domain before reserving a party slot.
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
        let valid_shape = !shares.is_empty()
            && shares.len() == ciphertexts.len()
            && proofs.len() == ciphertexts.len();
        if !valid_shape {
            return Ok(false);
        }
        let valid_sender = self.honest_committee_addresses.contains(address)
            && proofs.iter().all(|proof| {
                proof.payload.e3_id == self.e3_id
                    && proof.payload.proof_type == ProofType::C6ThresholdShareDecryption
                    && proof.payload.proof.circuit == CircuitName::ThresholdShareDecryption
                    && proof.verify_address(address).unwrap_or(false)
            });
        if !valid_sender {
            return Ok(false);
        }

        if !proofs.iter().zip(ciphertexts).all(|(proof, ciphertext)| {
            self.c6_has_canonical_domain(&proof.payload.proof, ciphertext)
        }) {
            return Ok(false);
        }

        let commitments = self.ciphertext_commitments(ciphertexts)?;
        let layout = CircuitName::ThresholdShareDecryption.input_layout();
        let valid_ciphertexts = commitments.len() == proofs.len()
            && proofs.iter().zip(commitments).all(|(proof, expected)| {
                layout.extract_field(&proof.payload.proof.public_signals, "ct_commitment")
                    == Some(expected.as_slice())
            });
        if !valid_ciphertexts {
            return Ok(false);
        }

        let Ok(verifier) = C6ShareVerifier::new(self.params_preset) else {
            warn!("Could not prepare the share commitment check");
            return Ok(false);
        };
        Ok(verifier.matches(shares, proofs))
    }

    fn ciphertext_commitments(&mut self, ciphertexts: &[ArcBytes]) -> Result<&[[u8; 32]]> {
        match &mut self.pending.ciphertext_commitments {
            Some(commitments) => Ok(commitments),
            cache @ None => {
                let (params, _) = e3_fhe_params::build_pair_for_preset(self.params_preset)?;
                let commitments = ciphertexts
                    .iter()
                    .map(|ciphertext| {
                        e3_bfv_client::compute_ct_commitment_with_params(ciphertext, &params)
                    })
                    .collect::<Result<_>>()?;
                Ok(cache.insert(commitments))
            }
        }
    }
}
