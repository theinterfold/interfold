// SPDX-License-Identifier: LGPL-3.0-only

//! Pure share collection, expulsion, and C6 verification transitions.

use super::*;

/// Plain, synchronous domain service for threshold-plaintext aggregation decisions.
pub(crate) struct ThresholdPlaintextAggregation;

impl ThresholdPlaintextAggregation {
    /// Start verification at T+1 shares. Keep later shares outside the current batch.
    pub(crate) fn add_share(
        state: ThresholdPlaintextAggregatorState,
        party_id: u64,
        share: Vec<ArcBytes>,
        signed_decryption_proofs: Vec<SignedProofPayload>,
    ) -> Result<ThresholdPlaintextAggregatorState> {
        let expected_outputs = match &state {
            ThresholdPlaintextAggregatorState::Collecting(current) => {
                current.ciphertext_output.len()
            }
            ThresholdPlaintextAggregatorState::VerifyingC6(current) => {
                current.ciphertext_output.len()
            }
            _ => return Ok(state),
        };
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
        match state {
            ThresholdPlaintextAggregatorState::Collecting(mut current) => {
                if !current.rejected_parties.contains(&party_id)
                    && !current.shares.contains_key(&party_id)
                {
                    current.shares.insert(party_id, share);
                    current.c6_proofs.insert(party_id, signed_decryption_proofs);
                }
                Ok(Self::start_verification_if_ready(current))
            }
            ThresholdPlaintextAggregatorState::VerifyingC6(mut current) => {
                if !current.rejected_parties.contains(&party_id)
                    && !current.shares.contains_key(&party_id)
                {
                    current
                        .queued_shares
                        .entry(party_id)
                        .or_insert(QueuedDecryptionShare {
                            share,
                            proofs: signed_decryption_proofs,
                        });
                }
                Ok(ThresholdPlaintextAggregatorState::VerifyingC6(current))
            }
            _ => unreachable!(),
        }
    }

    fn start_verification_if_ready(current: Collecting) -> ThresholdPlaintextAggregatorState {
        if current.shares.len() as u64 <= current.threshold_m {
            return ThresholdPlaintextAggregatorState::Collecting(current);
        }
        ThresholdPlaintextAggregatorState::VerifyingC6(VerifyingC6 {
            shares: current.shares,
            c6_proofs: current.c6_proofs,
            ciphertext_output: current.ciphertext_output,
            threshold_m: current.threshold_m,
            threshold_n: current.threshold_n,
            params: current.params,
            seed: current.seed,
            rejected_parties: current.rejected_parties,
            queued_shares: BTreeMap::new(),
        })
    }

    pub(crate) fn retry_collection(
        mut current: VerifyingC6,
        rejected: BTreeSet<u64>,
    ) -> ThresholdPlaintextAggregatorState {
        current.rejected_parties.extend(rejected);
        for (party_id, queued) in current.queued_shares {
            current.shares.entry(party_id).or_insert(queued.share);
            current.c6_proofs.entry(party_id).or_insert(queued.proofs);
        }
        current
            .shares
            .retain(|party, _| !current.rejected_parties.contains(party));
        current
            .c6_proofs
            .retain(|party, _| !current.rejected_parties.contains(party));
        Self::start_verification_if_ready(Collecting {
            shares: current.shares,
            c6_proofs: current.c6_proofs,
            ciphertext_output: current.ciphertext_output,
            threshold_m: current.threshold_m,
            threshold_n: current.threshold_n,
            params: current.params,
            seed: current.seed,
            rejected_parties: current.rejected_parties,
        })
    }

    /// Apply a committee-member expulsion to a `Collecting` state, removing the party's share
    /// and C6 proofs, and transitioning to `VerifyingC6` when enough shares remain.
    pub(crate) fn handle_member_expelled(
        state: ThresholdPlaintextAggregatorState,
        party_id: u64,
    ) -> Result<ThresholdPlaintextAggregatorState> {
        match state {
            ThresholdPlaintextAggregatorState::Collecting(mut current) => {
                current.rejected_parties.insert(party_id);
                current.shares.remove(&party_id);
                current.c6_proofs.remove(&party_id);
                Ok(Self::start_verification_if_ready(current))
            }
            ThresholdPlaintextAggregatorState::VerifyingC6(mut current) => {
                current.rejected_parties.insert(party_id);
                current.queued_shares.remove(&party_id);
                Ok(ThresholdPlaintextAggregatorState::VerifyingC6(current))
            }
            _ => Ok(state),
        }
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
}
