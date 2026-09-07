// SPDX-License-Identifier: LGPL-3.0-only

//! Dispatch the final DKG aggregation proof once all prerequisites exist.

use super::super::*;

impl PublicKeyAggregator {
    /// Dispatch [`ZkRequest::DkgAggregation`] once C5, all honest NodeFold proofs, and the
    /// streaming nodes_fold are all ready.
    pub(in crate::actors::publickey_aggregator) fn try_dispatch_dkg_aggregation(
        &mut self,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.get();
        let Some(PublicKeyAggregatorState::GeneratingC5Proof {
            party_nodes,
            dkg_node_proofs,
            honest_party_ids,
            c5_proof_pending,
            dkg_aggregation_correlation,
            dkg_aggregated_proof,
            circuit_committee_n,
            circuit_committee_h,
            nodes_fold_accumulator,
            nodes_fold_completed_slots,
            ..
        }) = state.as_ref()
        else {
            return Ok(());
        };

        let Some(c5_proof) = c5_proof_pending.as_ref() else {
            return Ok(());
        };

        if dkg_aggregation_correlation.is_some() || dkg_aggregated_proof.is_some() {
            return Ok(());
        }

        let all_honest_proofs_present = honest_party_ids
            .iter()
            .all(|id| dkg_node_proofs.contains_key(id));
        if !all_honest_proofs_present {
            return Ok(());
        }

        // Proof aggregation is a node-level test/CI setting and must be configured consistently
        // across a test swarm. Honest-party proofs should therefore be uniformly Some
        // (aggregation on) or uniformly None (aggregation skipped). A mixed bag would silently
        // truncate the dispatched request below; reject it explicitly.
        let some_count = honest_party_ids
            .iter()
            .filter(|id| {
                dkg_node_proofs
                    .get(id)
                    .map(Option::is_some)
                    .unwrap_or(false)
            })
            .count();
        if some_count != 0 && some_count != honest_party_ids.len() {
            error!(
                "PublicKeyAggregator: mixed Some/None DKG node proofs across honest parties \
                 ({some_count} of {} present); failing E3 {}",
                honest_party_ids.len(),
                self.e3_id
            );
            self.bus.publish(
                E3Failed {
                    e3_id: self.e3_id.clone(),
                    failed_at_stage: E3Stage::CommitteeFinalized,
                    reason: FailureReason::DKGInvalidShares,
                },
                ec.clone(),
            )?;
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
                    dkg_aggregation_correlation: _,
                    dkg_aggregated_proof,
                    c5_proof_pending: _,
                    last_ec,
                    nodes_fold_accumulator,
                    nodes_fold_completed_slots,
                    nodes_fold_step_correlation,
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
                })
            })?;
            return Ok(());
        }

        let mut pairs: Vec<_> = dkg_node_proofs
            .iter()
            .filter(|(pid, _)| honest_party_ids.contains(pid))
            .filter_map(|(pid, p)| p.as_ref().map(|proof| (*pid, proof.clone())))
            .collect();
        pairs.sort_by_key(|(pid, _)| *pid);
        let party_ids: Vec<u64> = pairs.iter().map(|(pid, _)| *pid).collect();
        let node_fold_proofs: Vec<Proof> = pairs.into_iter().map(|(_, p)| p).collect();
        // Party-id ordering across three representations has been a real source of circuit
        // mismatches, so keep the correspondence loggable — but at debug, not on every dispatch.
        debug!(
            "DkgAggregation dispatch ordering: honest_party_ids(submission-idx)={:?} \
             dkg_node_proofs_keys(real party_id from DKGRecursiveAggregationComplete)={:?} \
             party_ids_passed_to_circuit={:?}",
            honest_party_ids.iter().collect::<Vec<_>>(),
            {
                let mut k: Vec<u64> = dkg_node_proofs.keys().copied().collect();
                k.sort();
                k
            },
            party_ids
        );

        if node_fold_proofs.is_empty() {
            // Proof aggregation was skipped by the node's test/CI setting. Do NOT call
            // `try_publish_complete` here — it
            // is the most common entry into this method, so re-entering it would create
            // unbounded mutual recursion (stack overflow in deployed nodes).
            info!("PublicKeyAggregator: test/CI skip flag active — skipping DkgAggregation");
            return Ok(());
        }

        // Streaming fold must be complete before dispatching the final aggregation.
        let fold_complete = *nodes_fold_completed_slots == honest_party_ids.len() as u32;
        if !fold_complete {
            return Ok(());
        }
        let precomputed_fold = nodes_fold_accumulator.clone();

        // Build the FULL committee address vector (length N) in ascending party_id order.
        // The DKG aggregator circuit's `committee_members: [Field; N_PARTIES]` is the
        // committee-hash preimage; passing only the H honest subset would silently
        // hash a shorter array and diverge from on-chain `keccak(topNodes)`.
        let mut full_committee_party_ids: Vec<u64> = party_nodes.keys().copied().collect();
        full_committee_party_ids.sort();
        let committee_addresses =
            committee_addresses_in_party_order(&full_committee_party_ids, party_nodes)?;
        #[cfg(debug_assertions)]
        {
            debug_assert_eq!(
                committee_addresses.len(),
                *circuit_committee_n,
                "DkgAggregator committee_addresses must have N entries (full topNodes)"
            );
            debug_assert_eq!(
                party_ids.len(),
                *circuit_committee_h,
                "DkgAggregator party_ids must have H entries (honest set)"
            );
        }

        let corr = CorrelationId::new();
        self.bus.publish(
            ComputeRequest::zk(
                ZkRequest::DkgAggregation(DkgAggregationRequest {
                    node_fold_proofs,
                    nodes_fold_proof: precomputed_fold,
                    c5_proof: c5_proof.clone(),
                    party_ids,
                    committee_addresses,
                    params_preset: self.params_preset,
                    committee_size: self.committee_size,
                }),
                corr,
                self.e3_id.clone(),
            ),
            ec.clone(),
        )?;

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
                dkg_aggregation_correlation: _,
                dkg_aggregated_proof,
                c5_proof_pending,
                last_ec,
                nodes_fold_accumulator,
                nodes_fold_completed_slots,
                nodes_fold_step_correlation,
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
                dkg_aggregation_correlation: Some(corr),
                dkg_aggregated_proof,
                c5_proof_pending,
                last_ec,
                nodes_fold_accumulator,
                nodes_fold_completed_slots,
                nodes_fold_step_correlation,
            })
        })?;
        Ok(())
    }
}
