// SPDX-License-Identifier: LGPL-3.0-only

//! Bound the wait for honest-party NodeDkgFold proofs.

use super::super::*;
use std::time::Duration;

impl PublicKeyAggregator {
    /// Honest parties whose NodeDkgFold proof has not arrived yet.
    ///
    /// Returns an empty vector when the aggregator is not collecting node proofs, so callers
    /// can treat "nothing missing" and "not applicable" identically.
    pub(in crate::actors::publickey_aggregator) fn missing_node_proof_parties(&self) -> Vec<u64> {
        let Some(PublicKeyAggregatorState::GeneratingC5Proof {
            dkg_node_proofs,
            honest_party_ids,
            dkg_aggregated_proof,
            ..
        }) = self.state.get()
        else {
            return Vec::new();
        };
        if dkg_aggregated_proof.is_some() {
            return Vec::new();
        }
        honest_party_ids
            .iter()
            .filter(|id| !dkg_node_proofs.contains_key(id))
            .copied()
            .collect()
    }

    /// Fail the E3 when the node-proof budget expires with proofs still missing.
    ///
    /// The late parties cannot simply be dropped: C5 is already signed over exactly these H
    /// keyshares, so re-selecting the honest set would invalidate a published proof. Failing
    /// explicitly — naming the parties that did not deliver — converts an unbounded stall into
    /// an attributable, bounded outcome that the slashing layer can act on.
    pub(in crate::actors::publickey_aggregator) fn fail_on_missing_node_proofs(
        &mut self,
        ec: &EventContext<Sequenced>,
        budget: Duration,
    ) {
        let missing = self.missing_node_proof_parties();
        if missing.is_empty() {
            return;
        }

        error!(
            e3_id = %self.e3_id,
            missing_party_ids = ?missing,
            budget_secs = budget.as_secs(),
            "DKG node-proof collection budget expired; failing E3 (a member could not complete \
             its NodeDkgFold — C5 is already signed over this honest set, so it cannot be \
             re-selected)"
        );

        if let Err(err) = self.bus.publish(
            E3Failed {
                e3_id: self.e3_id.clone(),
                failed_at_stage: E3Stage::CommitteeFinalized,
                reason: FailureReason::DKGTimeout,
            },
            ec.clone(),
        ) {
            error!(
                e3_id = %self.e3_id,
                "Failed to publish E3Failed after node-proof timeout: {err}"
            );
        }
    }
}
