// SPDX-License-Identifier: LGPL-3.0-only

//! Pure share collection, expulsion, and C6 verification transitions.

use super::*;

/// Plain, synchronous domain service for threshold-plaintext aggregation decisions.
pub(crate) struct ThresholdPlaintextAggregation;

impl ThresholdPlaintextAggregation {
    /// Add a decryption share to a `Collecting` state, returning the next state. Once all
    /// `required_shares` honest-committee shares have arrived this transitions to `VerifyingC6`.
    /// `required_shares` is the canonical honest-committee size `H` (computed by the actor).
    pub(crate) fn add_share(
        state: ThresholdPlaintextAggregatorState,
        party_id: u64,
        share: Vec<ArcBytes>,
        signed_decryption_proofs: Vec<SignedProofPayload>,
        required_shares: u64,
    ) -> Result<ThresholdPlaintextAggregatorState> {
        info!("Adding share for party_id={}", party_id);
        let current: Collecting = state.try_into()?;
        let expected_outputs = current.ciphertext_output.len();
        ensure!(
            share.len() == expected_outputs,
            "party {party_id} supplied {} decryption shares for {expected_outputs} ciphertext outputs",
            share.len()
        );
        ensure!(
            signed_decryption_proofs.len() == expected_outputs,
            "party {party_id} supplied {} C6 proofs for {expected_outputs} ciphertext outputs",
            signed_decryption_proofs.len()
        );
        let ciphertext_output = current.ciphertext_output;
        let threshold_m = current.threshold_m;
        let threshold_n = current.threshold_n;
        let params = current.params.clone();
        let mut shares = current.shares;
        let mut c6_proofs = current.c6_proofs;

        info!("pushing to share collection {} {:?}", party_id, share);
        shares.insert(party_id, share);
        c6_proofs.insert(party_id, signed_decryption_proofs);

        if (shares.len() as u64) < required_shares {
            return Ok(ThresholdPlaintextAggregatorState::Collecting(Collecting {
                params,
                threshold_n,
                threshold_m,
                ciphertext_output,
                shares,
                c6_proofs,
                seed: current.seed,
                deadline_unix_ms: current.deadline_unix_ms,
                timeout_context: current.timeout_context,
            }));
        }

        info!(
            "Changing state to VerifyingC6 because received all {required_shares} honest-committee shares..."
        );

        Ok(ThresholdPlaintextAggregatorState::VerifyingC6(
            VerifyingC6 {
                shares,
                c6_proofs,
                ciphertext_output,
                threshold_m,
                threshold_n,
                params,
            },
        ))
    }

    /// Apply a committee-member expulsion to a `Collecting` state, removing the party's share
    /// and C6 proofs, and transitioning to `VerifyingC6` when enough shares remain.
    pub(crate) fn handle_member_expelled(
        state: ThresholdPlaintextAggregatorState,
        party_id: u64,
        required_shares: u64,
    ) -> Result<ThresholdPlaintextAggregatorState> {
        let ThresholdPlaintextAggregatorState::Collecting(current) = state else {
            return Ok(state);
        };

        let mut shares = current.shares;
        let mut c6_proofs = current.c6_proofs;
        let threshold_n = current.threshold_n;

        shares.remove(&party_id);
        c6_proofs.remove(&party_id);

        if required_shares < current.threshold_m {
            warn!(
                "ThresholdPlaintextAggregator: honest committee size H ({required_shares}) < threshold_m ({}) after expulsion",
                current.threshold_m
            );
            return Ok(ThresholdPlaintextAggregatorState::Collecting(Collecting {
                threshold_m: current.threshold_m,
                threshold_n,
                shares,
                c6_proofs,
                seed: current.seed,
                ciphertext_output: current.ciphertext_output,
                params: current.params,
                deadline_unix_ms: current.deadline_unix_ms,
                timeout_context: current.timeout_context,
            }));
        }

        if (shares.len() as u64) < required_shares {
            return Ok(ThresholdPlaintextAggregatorState::Collecting(Collecting {
                threshold_m: current.threshold_m,
                threshold_n,
                shares,
                c6_proofs,
                seed: current.seed,
                ciphertext_output: current.ciphertext_output,
                params: current.params,
                deadline_unix_ms: current.deadline_unix_ms,
                timeout_context: current.timeout_context,
            }));
        }

        Ok(ThresholdPlaintextAggregatorState::VerifyingC6(
            VerifyingC6 {
                threshold_m: current.threshold_m,
                threshold_n,
                shares,
                c6_proofs,
                ciphertext_output: current.ciphertext_output,
                params: current.params,
            },
        ))
    }

    /// Build the per-party C6 proof bundles dispatched to ShareVerification.
    pub(crate) fn plan_c6_dispatch(
        c6_proofs: BTreeMap<u64, Vec<SignedProofPayload>>,
    ) -> Vec<PartyProofsToVerify> {
        c6_proofs
            .into_iter()
            .map(|(party_id, signed_proofs)| PartyProofsToVerify {
                sender_party_id: party_id,
                signed_proofs,
            })
            .collect()
    }

    /// Verify that each honest party's raw decryption share bytes match the
    /// `d_commitment` output in their verified C6 proof. Returns party IDs
    /// that failed the check.
    ///
    /// Catches the attack where a node sends a valid C6 proof for share `d_A` but
    /// broadcasts different bytes `d_B`.
    pub(crate) fn verify_shares_match_c6_commitments(
        params_preset: BfvPreset,
        honest_shares: &[(u64, Vec<ArcBytes>)],
        c6_proofs: &BTreeMap<u64, Vec<SignedProofPayload>>,
    ) -> BTreeSet<u64> {
        let mut mismatched = BTreeSet::new();

        let Ok((threshold_params, _)) = e3_fhe_params::build_pair_for_preset(params_preset) else {
            warn!("Could not build BFV params for d_commitment check — skipping");
            return mismatched;
        };

        // Reuse the same Bounds/Bits computation that C6 codegen uses,
        // so d_native_bit stays in sync if the formula ever changes.
        let Ok(bounds) = C6Bounds::compute(params_preset, &()) else {
            warn!("Could not compute bounds for d_commitment check — skipping");
            return mismatched;
        };
        let Ok(bits) = C6Bits::compute(params_preset, &bounds) else {
            warn!("Could not compute bits for d_commitment check — skipping");
            return mismatched;
        };
        let d_native_bit = bits.d_native_bit;

        let max_k = MAX_MSG_NON_ZERO_COEFFS;
        let c6_output_layout = CircuitName::ThresholdShareDecryption.output_layout();

        for (party_id, shares) in honest_shares {
            let Some(proofs) = c6_proofs.get(party_id) else {
                warn!(
                    "No C6 proofs for party {} — marking as mismatched",
                    party_id
                );
                mismatched.insert(*party_id);
                continue;
            };
            let Some(first_proof) = proofs.first() else {
                warn!(
                    "Empty C6 proof list for party {} — marking as mismatched",
                    party_id
                );
                mismatched.insert(*party_id);
                continue;
            };
            let Some(c6_d_bytes) = c6_output_layout
                .extract_field(&first_proof.payload.proof.public_signals, "d_commitment")
            else {
                warn!(
                    "Could not extract d_commitment from C6 proof for party {} — marking as mismatched",
                    party_id
                );
                mismatched.insert(*party_id);
                continue;
            };

            let Some(share_bytes) = shares.first() else {
                warn!(
                    "No share bytes for party {} — marking as mismatched",
                    party_id
                );
                mismatched.insert(*party_id);
                continue;
            };
            let Ok(poly) =
                e3_trbfv::helpers::try_poly_pb_from_bytes(share_bytes, &threshold_params)
            else {
                warn!(
                    "Could not deserialize share for party {} — marking as mismatched",
                    party_id
                );
                mismatched.insert(*party_id);
                continue;
            };
            let crt = e3_polynomial::CrtPolynomial::from_fhe_polynomial(&poly);

            // C6 public `d_commitment` hashes native truncated limbs (same layout as C7), not
            // reversed+centered witness `d`.
            let computed = compute_threshold_decryption_share_commitment(&crt, d_native_bit, max_k);

            // Convert to big-endian 32-byte padded format matching
            // Barretenberg's public_signals encoding.
            let (_, be_bytes) = computed.to_bytes_be();
            let mut computed_padded = [0u8; 32];
            let start = 32usize.saturating_sub(be_bytes.len());
            computed_padded[start..].copy_from_slice(&be_bytes[..be_bytes.len().min(32)]);

            if computed_padded != c6_d_bytes {
                warn!(
                    "d_commitment mismatch for party {}: raw share commitment differs from C6 proof output",
                    party_id
                );
                mismatched.insert(*party_id);
            }
        }

        mismatched
    }
}
