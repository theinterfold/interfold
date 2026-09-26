// SPDX-License-Identifier: LGPL-3.0-only

//! Bind raw decryption shares to their C6 proof commitments.

use super::*;
use e3_zk_helpers::{
    circuits::commitments::compute_threshold_decryption_share_commitment,
    circuits::threshold::decrypted_shares_aggregation::MAX_MSG_NON_ZERO_COEFFS,
    threshold::share_decryption::{Bits, Bounds},
    Computation,
};
use fhe::bfv::BfvParameters;
use std::sync::Arc;
use tracing::warn;

pub(crate) struct C6ShareVerifier {
    params: Arc<BfvParameters>,
    d_native_bit: u32,
}

impl C6ShareVerifier {
    pub(crate) fn new(preset: BfvPreset) -> Result<Self> {
        let (params, _) = e3_fhe_params::build_pair_for_preset(preset)?;
        // Use the same bit-width calculation as C6 code generation.
        let bits = Bits::compute(preset, &Bounds::compute(preset, &())?)?;
        Ok(Self {
            params,
            d_native_bit: bits.d_native_bit,
        })
    }

    pub(crate) fn matches(&self, shares: &[ArcBytes], proofs: &[SignedProofPayload]) -> bool {
        !shares.is_empty()
            && shares.len() == proofs.len()
            && shares
                .iter()
                .zip(proofs)
                .all(|(share, proof)| self.share_matches(share, &proof.payload.proof))
    }

    fn share_matches(&self, share: &ArcBytes, proof: &Proof) -> bool {
        let layout = CircuitName::ThresholdShareDecryption.output_layout();
        let Some(expected) = layout.extract_field(&proof.public_signals, "d_commitment") else {
            return false;
        };
        let Ok(poly) = e3_trbfv::helpers::try_poly_pb_from_bytes(share, &self.params) else {
            return false;
        };
        let crt = e3_polynomial::CrtPolynomial::from_fhe_polynomial(&poly);
        let commitment = compute_threshold_decryption_share_commitment(
            &crt,
            self.d_native_bit,
            MAX_MSG_NON_ZERO_COEFFS,
        );
        let (_, bytes) = commitment.to_bytes_be();
        let mut padded = [0u8; 32];
        if bytes.len() > padded.len() {
            return false;
        }
        padded[32 - bytes.len()..].copy_from_slice(&bytes);
        padded == expected
    }
}

impl ThresholdPlaintextAggregation {
    /// Return parties whose raw shares differ from their verified C6 commitments.
    pub(crate) fn verify_shares_match_c6_commitments(
        params_preset: BfvPreset,
        honest_shares: &[(u64, Vec<ArcBytes>)],
        c6_proofs: &BTreeMap<u64, Vec<SignedProofPayload>>,
    ) -> BTreeSet<u64> {
        let Ok(verifier) = C6ShareVerifier::new(params_preset) else {
            warn!("Could not prepare the share commitment check");
            return honest_shares.iter().map(|(party, _)| *party).collect();
        };
        honest_shares
            .iter()
            .filter_map(|(party_id, shares)| {
                if c6_proofs
                    .get(party_id)
                    .is_some_and(|proofs| verifier.matches(shares, proofs))
                {
                    return None;
                }
                warn!(
                    party_id,
                    "Decryption share does not match its verified C6 commitment"
                );
                Some(*party_id)
            })
            .collect()
    }
}
