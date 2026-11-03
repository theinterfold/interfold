// SPDX-License-Identifier: LGPL-3.0-only

//! Stream the canonical honest-party NodeFold accumulator.

use super::super::*;

impl PublicKeyAggregator {
    /// Dispatch the next [`ZkRequest::NodesFoldStep`] when the proofs of every slot it takes
    /// ([`nodes_fold_step_len`]) are buffered and no step is in flight. When all H slots are done,
    /// calls [`try_dispatch_dkg_aggregation`].
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

        // A step takes the next slots in canonical order, so it waits for each of their proofs;
        // folding one slot at a time waited the same way, one slot at a time.
        let len = nodes_fold_step_len(next_slot as usize, total_slots);
        let mut inner_proofs = Vec::with_capacity(len);
        for party_id in honest_party_ids.iter().skip(next_slot as usize).take(len) {
            let Some(Some(inner_proof)) = dkg_node_proofs.get(party_id) else {
                return Ok(());
            };
            inner_proofs.push(inner_proof.clone());
        }
        let slot_indices: Vec<u32> = (next_slot..next_slot + len as u32).collect();
        let prior_accumulator = nodes_fold_accumulator.clone();

        let corr = CorrelationId::new();
        self.bus.publish(
            ComputeRequest::zk(
                ZkRequest::NodesFoldStep(NodesFoldStepRequest {
                    inner_proofs,
                    prior_accumulator,
                    slot_indices,
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
            "PublicKeyAggregator: dispatched NodesFoldStep slots={}..{}/{} for E3 {}",
            next_slot,
            next_slot as usize + len,
            total_slots,
            self.e3_id
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
            honest_party_ids,
            last_ec,
            ..
        }) = state.as_ref()
        else {
            return Ok(());
        };

        if nodes_fold_step_correlation.as_ref() != Some(&correlation_id) {
            return Ok(());
        }

        // The step in flight took exactly the slots `nodes_fold_step_len` gives for this point.
        let completed = nodes_fold_completed_slots
            + nodes_fold_step_len(*nodes_fold_completed_slots as usize, honest_party_ids.len())
                as u32;
        let Some(ec) = last_ec.clone() else {
            return Err(anyhow::anyhow!(
                "No EventContext for NodesFoldStep response"
            ));
        };

        info!(
            "PublicKeyAggregator: NodesFoldStep complete ({} slots done) for E3 {}",
            completed, self.e3_id
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
