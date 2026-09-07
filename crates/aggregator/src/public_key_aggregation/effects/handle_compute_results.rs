// SPDX-License-Identifier: LGPL-3.0-only

//! Correlate compute results and map terminal worker failures.

use super::super::*;

impl PublicKeyAggregator {
    pub(in crate::actors::publickey_aggregator) fn handle_compute_response(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
    ) -> Result<()> {
        let (msg, _ec) = msg.into_components();
        if msg.e3_id != self.e3_id {
            return Ok(());
        }
        match msg.response {
            ComputeResponseKind::Zk(ZkResponse::NodesFoldStep(resp)) => {
                self.handle_nodes_fold_step_response(msg.correlation_id, resp.accumulator_proof)?;
            }
            ComputeResponseKind::Zk(ZkResponse::DkgAggregation(resp)) => {
                let state = self.state.get();
                let Some(PublicKeyAggregatorState::GeneratingC5Proof { last_ec, .. }) =
                    state.as_ref()
                else {
                    return Ok(());
                };
                let Some(_ec) = last_ec.clone() else {
                    return Err(anyhow::anyhow!(
                        "No EventContext for DkgAggregation response"
                    ));
                };
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
                        nodes_fold_accumulator,
                        nodes_fold_completed_slots,
                        nodes_fold_step_correlation,
                        node_proof_deadline_at,
                    } = state
                    else {
                        return Ok(state);
                    };
                    if dkg_aggregation_correlation.as_ref() != Some(&msg.correlation_id) {
                        return Ok(PublicKeyAggregatorState::GeneratingC5Proof {
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
                            nodes_fold_step_correlation,
                            node_proof_deadline_at,
                        });
                    }
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
                        dkg_aggregation_correlation: None,
                        dkg_aggregated_proof: Some(resp.proof.clone()),
                        c5_proof_pending,
                        last_ec,
                        nodes_fold_accumulator,
                        nodes_fold_completed_slots,
                        nodes_fold_step_correlation,
                        node_proof_deadline_at,
                    })
                })?;
                self.try_publish_complete()?;
            }
            _ => {}
        }
        Ok(())
    }

    pub(in crate::actors::publickey_aggregator) fn handle_compute_request_error(
        &mut self,
        msg: TypedEvent<ComputeRequestError>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();
        if msg.request().e3_id != self.e3_id {
            return Ok(());
        }

        let matched_nodes_fold_step = matches!(
            self.state.get(),
            Some(PublicKeyAggregatorState::GeneratingC5Proof {
                nodes_fold_step_correlation,
                ..
            }) if nodes_fold_step_correlation.as_ref() == Some(msg.correlation_id())
        );

        if matched_nodes_fold_step {
            error!(
                "PublicKeyAggregator: NodesFoldStep failed for E3 {}: {:?}",
                self.e3_id,
                msg.get_err()
            );
            self.bus.publish(
                E3Failed {
                    e3_id: self.e3_id.clone(),
                    failed_at_stage: E3Stage::CommitteeFinalized,
                    reason: FailureReason::DKGInvalidShares,
                },
                ec.clone(),
            )?;
            self.state.try_mutate(&ec, |state| {
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
                    c5_proof_pending: _,
                    last_ec,
                    nodes_fold_accumulator,
                    nodes_fold_completed_slots,
                    nodes_fold_step_correlation: _,
                    node_proof_deadline_at,
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
                    c5_proof_pending: None,
                    last_ec,
                    nodes_fold_accumulator,
                    nodes_fold_completed_slots,
                    nodes_fold_step_correlation: None,
                    node_proof_deadline_at,
                })
            })?;
            return Ok(());
        }

        let matched_dkg_aggregation = matches!(
            self.state.get(),
            Some(PublicKeyAggregatorState::GeneratingC5Proof {
                dkg_aggregation_correlation,
                ..
            }) if dkg_aggregation_correlation.as_ref() == Some(msg.correlation_id())
        );

        if !matched_dkg_aggregation {
            return Ok(());
        }

        error!(
            "PublicKeyAggregator: DkgAggregation failed for E3 {}: {:?}",
            self.e3_id,
            msg.get_err()
        );

        self.bus.publish(
            E3Failed {
                e3_id: self.e3_id.clone(),
                failed_at_stage: E3Stage::CommitteeFinalized,
                reason: FailureReason::DKGInvalidShares,
            },
            ec.clone(),
        )?;

        self.state.try_mutate(&ec, |state| {
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
                dkg_aggregation_correlation: _,
                dkg_aggregated_proof,
                c5_proof_pending: _,
                last_ec,
                nodes_fold_accumulator,
                nodes_fold_completed_slots,
                nodes_fold_step_correlation,
                node_proof_deadline_at,
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
                dkg_aggregation_correlation: None,
                dkg_aggregated_proof,
                c5_proof_pending: None,
                last_ec,
                nodes_fold_accumulator,
                nodes_fold_completed_slots,
                nodes_fold_step_correlation,
                node_proof_deadline_at,
            })
        })?;

        Ok(())
    }
}
