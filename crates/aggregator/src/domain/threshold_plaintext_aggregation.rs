// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Plain, synchronous domain logic for threshold-plaintext (decryption) aggregation.
//!
//! This module holds the [`ThresholdPlaintextAggregatorState`] state machine plus the pure
//! transition/decision functions used by the `ThresholdPlaintextAggregator` actor. Nothing
//! here touches actix, `Persistable`, or the event bus: the actor feeds inputs in, gets a
//! next-state or a decision back, and performs the persistence/publish/dispatch side effects
//! itself.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Result};
use e3_events::CircuitName;
use e3_events::{
    DecryptionAggregationJobRequest, PartyProofsToVerify, Proof, Seed, SignedProofPayload,
};
use e3_fhe_params::BfvPreset;
use e3_utils::utility_types::ArcBytes;
use e3_zk_helpers::circuits::commitments::compute_threshold_decryption_share_commitment;
use e3_zk_helpers::circuits::threshold::decrypted_shares_aggregation::MAX_MSG_NON_ZERO_COEFFS;
use e3_zk_helpers::threshold::share_decryption::{Bits as C6Bits, Bounds as C6Bounds};
use e3_zk_helpers::Computation;
use tracing::{info, warn};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Collecting {
    pub(crate) threshold_m: u64,
    pub(crate) threshold_n: u64,
    pub(crate) shares: BTreeMap<u64, Vec<ArcBytes>>,
    /// Signed raw C6 proofs for ShareVerification.
    pub(crate) c6_proofs: BTreeMap<u64, Vec<SignedProofPayload>>,
    pub(crate) seed: Seed,
    pub(crate) ciphertext_output: Vec<ArcBytes>,
    pub(crate) params: ArcBytes,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifyingC6 {
    pub(crate) threshold_m: u64,
    pub(crate) threshold_n: u64,
    pub(crate) shares: BTreeMap<u64, Vec<ArcBytes>>,
    pub(crate) c6_proofs: BTreeMap<u64, Vec<SignedProofPayload>>,
    pub(crate) ciphertext_output: Vec<ArcBytes>,
    pub(crate) params: ArcBytes,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Computing {
    pub(crate) threshold_m: u64,
    pub(crate) threshold_n: u64,
    pub(crate) shares: Vec<(u64, Vec<ArcBytes>)>,
    pub(crate) ciphertext_output: Vec<ArcBytes>,
    pub(crate) params: ArcBytes,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GeneratingC7Proof {
    pub(crate) threshold_m: u64,
    pub(crate) threshold_n: u64,
    pub(crate) shares: Vec<(u64, Vec<ArcBytes>)>,
    pub(crate) plaintext: Vec<ArcBytes>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Complete {
    pub(crate) decrypted: Vec<ArcBytes>,
    pub(crate) shares: Vec<(u64, Vec<ArcBytes>)>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ThresholdPlaintextAggregatorState {
    Collecting(Collecting),
    VerifyingC6(VerifyingC6),
    Computing(Computing),
    GeneratingC7Proof(GeneratingC7Proof),
    Complete(Complete),
}

impl TryFrom<ThresholdPlaintextAggregatorState> for Collecting {
    type Error = anyhow::Error;
    fn try_from(
        value: ThresholdPlaintextAggregatorState,
    ) -> std::result::Result<Self, Self::Error> {
        match value {
            ThresholdPlaintextAggregatorState::Collecting(s) => Ok(s),
            _ => bail!("PlaintextState was expected to be Collecting but it was not."),
        }
    }
}

impl TryFrom<ThresholdPlaintextAggregatorState> for VerifyingC6 {
    type Error = anyhow::Error;
    fn try_from(
        value: ThresholdPlaintextAggregatorState,
    ) -> std::result::Result<Self, Self::Error> {
        match value {
            ThresholdPlaintextAggregatorState::VerifyingC6(s) => Ok(s),
            _ => bail!("Inconsistent state: expected VerifyingC6"),
        }
    }
}

impl TryFrom<ThresholdPlaintextAggregatorState> for Computing {
    type Error = anyhow::Error;
    fn try_from(
        value: ThresholdPlaintextAggregatorState,
    ) -> std::result::Result<Self, Self::Error> {
        match value {
            ThresholdPlaintextAggregatorState::Computing(s) => Ok(s),
            _ => bail!("Inconsistent state: expected Computing"),
        }
    }
}

impl TryFrom<ThresholdPlaintextAggregatorState> for GeneratingC7Proof {
    type Error = anyhow::Error;
    fn try_from(
        value: ThresholdPlaintextAggregatorState,
    ) -> std::result::Result<Self, Self::Error> {
        match value {
            ThresholdPlaintextAggregatorState::GeneratingC7Proof(s) => Ok(s),
            _ => bail!("Inconsistent state: expected GeneratingC7Proof"),
        }
    }
}

impl TryFrom<ThresholdPlaintextAggregatorState> for Complete {
    type Error = anyhow::Error;
    fn try_from(
        value: ThresholdPlaintextAggregatorState,
    ) -> std::result::Result<Self, Self::Error> {
        match value {
            ThresholdPlaintextAggregatorState::Complete(s) => Ok(s),
            _ => bail!("Inconsistent state: expected Complete"),
        }
    }
}

impl ThresholdPlaintextAggregatorState {
    pub fn init(
        threshold_m: u64,
        threshold_n: u64,
        seed: Seed,
        ciphertext_output: Vec<ArcBytes>,
        params: ArcBytes,
    ) -> Self {
        ThresholdPlaintextAggregatorState::Collecting(Collecting {
            threshold_m,
            threshold_n,
            shares: BTreeMap::new(),
            c6_proofs: BTreeMap::new(),
            seed,
            ciphertext_output,
            params,
        })
    }
}

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

/// Pad/truncate each decrypted plaintext limb to the fixed `MAX_MSG_NON_ZERO_COEFFS * 8`
/// byte width expected by consumers of `PlaintextAggregated`.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ab(b: u8) -> ArcBytes {
        ArcBytes::from_bytes(&[b])
    }

    fn collecting(threshold_m: u64, threshold_n: u64) -> ThresholdPlaintextAggregatorState {
        ThresholdPlaintextAggregatorState::init(
            threshold_m,
            threshold_n,
            Seed([0u8; 32]),
            vec![ab(1)],
            ab(2),
        )
    }

    #[test]
    fn add_share_below_required_stays_collecting() {
        let state = collecting(1, 3);
        let next =
            ThresholdPlaintextAggregation::add_share(state, 0, vec![ab(10)], vec![], 3).unwrap();
        match next {
            ThresholdPlaintextAggregatorState::Collecting(c) => {
                assert_eq!(c.shares.len(), 1);
                assert!(c.shares.contains_key(&0));
            }
            _ => panic!("expected Collecting"),
        }
    }

    #[test]
    fn add_share_reaching_required_transitions_to_verifying_c6() {
        let mut state = collecting(1, 3);
        for pid in 0..3u64 {
            state = ThresholdPlaintextAggregation::add_share(
                state,
                pid,
                vec![ab(pid as u8)],
                vec![],
                3,
            )
            .unwrap();
        }
        match state {
            ThresholdPlaintextAggregatorState::VerifyingC6(v) => {
                assert_eq!(v.shares.len(), 3);
            }
            _ => panic!("expected VerifyingC6"),
        }
    }

    #[test]
    fn add_share_wrong_state_errors() {
        let state = ThresholdPlaintextAggregatorState::VerifyingC6(VerifyingC6 {
            threshold_m: 1,
            threshold_n: 3,
            shares: BTreeMap::new(),
            c6_proofs: BTreeMap::new(),
            ciphertext_output: vec![ab(1)],
            params: ab(2),
        });
        let res = ThresholdPlaintextAggregation::add_share(state, 0, vec![ab(0)], vec![], 3);
        assert!(res.is_err());
    }

    #[test]
    fn handle_member_expelled_removes_share_and_stays_collecting() {
        let mut state = collecting(1, 3);
        for pid in 0..2u64 {
            state = ThresholdPlaintextAggregation::add_share(
                state,
                pid,
                vec![ab(pid as u8)],
                vec![],
                3,
            )
            .unwrap();
        }
        // required_shares stays 3; remove party 0 -> 1 share left -> Collecting
        let next = ThresholdPlaintextAggregation::handle_member_expelled(state, 0, 3).unwrap();
        match next {
            ThresholdPlaintextAggregatorState::Collecting(c) => {
                assert_eq!(c.shares.len(), 1);
                assert!(!c.shares.contains_key(&0));
            }
            _ => panic!("expected Collecting"),
        }
    }

    #[test]
    fn handle_member_expelled_transitions_when_enough_remain() {
        let mut state = collecting(1, 3);
        for pid in 0..3u64 {
            state = ThresholdPlaintextAggregation::add_share(
                state,
                pid,
                vec![ab(pid as u8)],
                vec![],
                3,
            )
            .unwrap();
        }
        // After 3 shares it's already VerifyingC6; rebuild a Collecting with 3 shares to
        // exercise the expulsion->VerifyingC6 path with required_shares lowered to 2.
        let state = ThresholdPlaintextAggregatorState::Collecting(Collecting {
            threshold_m: 1,
            threshold_n: 3,
            shares: BTreeMap::from([(0, vec![ab(0)]), (1, vec![ab(1)]), (2, vec![ab(2)])]),
            c6_proofs: BTreeMap::new(),
            seed: Seed([0u8; 32]),
            ciphertext_output: vec![ab(1)],
            params: ab(2),
        });
        let _ = state;
        let state = ThresholdPlaintextAggregatorState::Collecting(Collecting {
            threshold_m: 1,
            threshold_n: 3,
            shares: BTreeMap::from([(0, vec![ab(0)]), (1, vec![ab(1)]), (2, vec![ab(2)])]),
            c6_proofs: BTreeMap::new(),
            seed: Seed([0u8; 32]),
            ciphertext_output: vec![ab(1)],
            params: ab(2),
        });
        // remove party 0 -> 2 shares remain, required_shares=2 -> VerifyingC6
        let next = ThresholdPlaintextAggregation::handle_member_expelled(state, 0, 2).unwrap();
        match next {
            ThresholdPlaintextAggregatorState::VerifyingC6(v) => {
                assert_eq!(v.shares.len(), 2);
            }
            _ => panic!("expected VerifyingC6"),
        }
    }

    #[test]
    fn handle_member_expelled_wrong_state_is_noop() {
        let state = ThresholdPlaintextAggregatorState::Complete(Complete {
            decrypted: vec![ab(1)],
            shares: vec![],
        });
        let next = ThresholdPlaintextAggregation::handle_member_expelled(state, 0, 3).unwrap();
        assert!(matches!(
            next,
            ThresholdPlaintextAggregatorState::Complete(_)
        ));
    }

    #[test]
    fn plan_c6_dispatch_emits_party_proofs_in_party_order() {
        let mut c6: BTreeMap<u64, Vec<SignedProofPayload>> = BTreeMap::new();
        c6.insert(2, vec![]);
        c6.insert(0, vec![]);
        c6.insert(1, vec![]);
        let plan = ThresholdPlaintextAggregation::plan_c6_dispatch(c6);
        let ids: Vec<u64> = plan.iter().map(|p| p.sender_party_id).collect();
        assert_eq!(ids, vec![0, 1, 2]);
    }
}
