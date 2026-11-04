// SPDX-License-Identifier: LGPL-3.0-only

//! Stream the canonical honest-party NodeFold accumulator.

use super::super::*;

impl PublicKeyAggregator {
    /// Dispatch the next [`ZkRequest::NodesFoldStep`] if the next slot's proof is buffered
    /// and no step is currently in flight. When all H slots are done, calls
    /// [`try_dispatch_dkg_aggregation`].
    pub(in crate::actors::publickey_aggregator) fn try_dispatch_nodes_fold_step(
        &mut self,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.get();
        let Some(PublicKeyAggregatorState::GeneratingC5Proof {
            dkg_node_proofs,
            honest_party_ids,
            nodes_fold_accumulator,
            nodes_fold_completed_slots,
            nodes_fold_step_correlation,
            dkg_aggregation_correlation,
            dkg_aggregated_proof,
            ..
        }) = state.as_ref()
        else {
            return Ok(());
        };

        if nodes_fold_step_correlation.is_some()
            || dkg_aggregation_correlation.is_some()
            || dkg_aggregated_proof.is_some()
        {
            return Ok(());
        }

        let next_slot = *nodes_fold_completed_slots;
        let total_slots = honest_party_ids.len();

        if next_slot as usize >= total_slots {
            return self.try_dispatch_dkg_aggregation(ec);
        }

        let Some(&party_id) = honest_party_ids.iter().nth(next_slot as usize) else {
            return Ok(());
        };

        let Some(Some(inner_proof)) = dkg_node_proofs.get(&party_id) else {
            return Ok(());
        };

        let inner_proof = inner_proof.clone();
        let prior_accumulator = nodes_fold_accumulator.clone();

        let corr = CorrelationId::new();
        self.bus.publish(
            ComputeRequest::zk(
                ZkRequest::NodesFoldStep(NodesFoldStepRequest {
                    inner_proof,
                    prior_accumulator,
                    slot_index: next_slot,
                    total_slots,
                    e3_id: self.e3_id.to_string(),
                    params_preset: self.params_preset,
                    committee_size: self.committee_size,
                }),
                corr,
                self.e3_id.clone(),
            ),
            ec.clone(),
        )?;

        info!(
            "PublicKeyAggregator: dispatched NodesFoldStep slot={}/{} for E3 {}",
            next_slot, total_slots, self.e3_id
        );

        self.state.try_mutate(ec, |state| {
            let PublicKeyAggregatorState::GeneratingC5Proof {
                public_key,
                keyshare_bytes,
                nodes,
                party_nodes,
                dkg_node_proofs,
                dkg_fold_attestations,
                honest_party_ids,
                dishonest_parties,
                circuit_committee_n,
                circuit_committee_h,
                dkg_aggregation_correlation,
                dkg_aggregated_proof,
                c5_proof_pending,
                last_ec,
                nodes_fold_accumulator,
                nodes_fold_completed_slots,
                nodes_fold_step_correlation: _,
            } = state
            else {
                return Ok(state);
            };
            Ok(PublicKeyAggregatorState::GeneratingC5Proof {
                public_key,
                keyshare_bytes,
                nodes,
                party_nodes,
                dkg_node_proofs,
                dkg_fold_attestations,
                honest_party_ids,
                dishonest_parties,
                circuit_committee_n,
                circuit_committee_h,
                dkg_aggregation_correlation,
                dkg_aggregated_proof,
                c5_proof_pending,
                last_ec,
                nodes_fold_accumulator,
                nodes_fold_completed_slots,
                nodes_fold_step_correlation: Some(corr),
            })
        })?;
        Ok(())
    }

    /// Handle a completed [`ZkResponse::NodesFoldStep`]: advance the accumulator and dispatch
    /// the next fold step (or the final DkgAggregation when all H slots are done).
    pub(in crate::actors::publickey_aggregator) fn handle_nodes_fold_step_response(
        &mut self,
        correlation_id: CorrelationId,
        accumulator_proof: Proof,
    ) -> Result<()> {
        let state = self.state.get();
        let Some(PublicKeyAggregatorState::GeneratingC5Proof {
            nodes_fold_step_correlation,
            nodes_fold_completed_slots,
            last_ec,
            ..
        }) = state.as_ref()
        else {
            return Ok(());
        };

        if nodes_fold_step_correlation.as_ref() != Some(&correlation_id) {
            return Ok(());
        }

        let completed = nodes_fold_completed_slots + 1;
        let Some(ec) = last_ec.clone() else {
            return Err(anyhow::anyhow!(
                "No EventContext for NodesFoldStep response"
            ));
        };

        info!(
            "PublicKeyAggregator: NodesFoldStep complete (slot {} done) for E3 {}",
            completed - 1,
            self.e3_id
        );

        self.state.try_mutate_without_context(|state| {
            let PublicKeyAggregatorState::GeneratingC5Proof {
                public_key,
                keyshare_bytes,
                nodes,
                party_nodes,
                dkg_node_proofs,
                dkg_fold_attestations,
                honest_party_ids,
                dishonest_parties,
                circuit_committee_n,
                circuit_committee_h,
                dkg_aggregation_correlation,
                dkg_aggregated_proof,
                c5_proof_pending,
                last_ec,
                nodes_fold_step_correlation: _,
                ..
            } = state
            else {
                return Ok(state);
            };
            Ok(PublicKeyAggregatorState::GeneratingC5Proof {
                public_key,
                keyshare_bytes,
                nodes,
                party_nodes,
                dkg_node_proofs,
                dkg_fold_attestations,
                honest_party_ids,
                dishonest_parties,
                circuit_committee_n,
                circuit_committee_h,
                dkg_aggregation_correlation,
                dkg_aggregated_proof,
                c5_proof_pending,
                last_ec,
                nodes_fold_accumulator: Some(accumulator_proof),
                nodes_fold_completed_slots: completed,
                nodes_fold_step_correlation: None,
            })
        })?;

        self.try_dispatch_nodes_fold_step(&ec)
    }
}
