// SPDX-License-Identifier: LGPL-3.0-only

//! Correlate C5 and per-node DKG fold artifacts.

use super::super::*;

impl PublicKeyAggregator {
    pub(in crate::actors::publickey_aggregator) fn handle_pk_aggregation_proof_signed(
        &mut self,
        msg: TypedEvent<PkAggregationProofSigned>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();

        if msg.e3_id != self.e3_id {
            return Ok(());
        }

        let state = self.state.get();
        if matches!(
            state.as_ref(),
            Some(PublicKeyAggregatorState::Complete { .. })
        ) {
            info!("Ignoring late C5 proof after public-key aggregation completed");
            return Ok(());
        }
        if !matches!(
            state.as_ref(),
            Some(PublicKeyAggregatorState::GeneratingC5Proof { .. })
        ) {
            return Err(anyhow::anyhow!(
                "handle_pk_aggregation_proof_signed called outside GeneratingC5Proof state"
            ));
        }

        info!("C5 proof signed — waiting for cross-node DKG fold to complete...");

        let c5_proof = msg.signed_proof.payload.proof.clone();
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
                nodes_fold_accumulator,
                nodes_fold_completed_slots,
                nodes_fold_step_correlation,
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
                c5_proof_pending: Some(c5_proof),
                last_ec: Some(ec.clone()),
                nodes_fold_accumulator,
                nodes_fold_completed_slots,
                nodes_fold_step_correlation,
            })
        })?;
        self.try_publish_complete()
    }

    // -- Cross-node DKG proof aggregation --------------------------------------------------

    pub(in crate::actors::publickey_aggregator) fn handle_dkg_recursive_aggregation_complete(
        &mut self,
        msg: TypedEvent<DKGRecursiveAggregationComplete>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();

        if msg.e3_id != self.e3_id {
            return Ok(());
        }

        let state = self.state.get();
        let Some(PublicKeyAggregatorState::GeneratingC5Proof {
            party_nodes,
            dkg_node_proofs,
            honest_party_ids,
            circuit_committee_n,
            circuit_committee_h,
            ..
        }) = state.as_ref()
        else {
            info!(
                "PublicKeyAggregator: early DKG proof from party {} — buffering until GeneratingC5Proof",
                msg.party_id
            );
            self.early_dkg_proofs.push(TypedEvent::new(msg, ec));
            return Ok(());
        };
        if dkg_node_proofs.contains_key(&msg.party_id) {
            warn!(
                "Duplicate DKGRecursiveAggregationComplete for party {} — ignoring",
                msg.party_id
            );
            return Ok(());
        }

        // A fold built over a different DKG roster cannot join this aggregation: the
        // aggregator circuit checks every C4 row against every C2 row of the roster.
        let expected_roster_hash = {
            let mut ids: Vec<u64> = honest_party_ids.iter().copied().collect();
            ids.sort_unstable();
            e3_events::DkgRosterProposed::roster_hash(&ids)
        };
        if msg.roster_hash != [0; 32] && msg.roster_hash != expected_roster_hash {
            warn!(
                party_id = msg.party_id,
                "DKG fold built over a different DKG roster — rejecting"
            );
            return Ok(());
        }

        if honest_party_ids.contains(&msg.party_id) {
            let Some(expected_node) = party_nodes.get(&msg.party_id) else {
                warn!(
                    party_id = msg.party_id,
                    "DKG fold from party without registered node address — rejecting"
                );
                return Ok(());
            };
            // Proof aggregation OFF: nodes emit `DKGRecursiveAggregationComplete`
            // with `proof=None` and `attestation=None`. Accept it so
            // `try_publish_complete` can detect `all_proofs_are_none` and publish.
            // Proof aggregation ON: both must be present and verified together.
            match (&msg.aggregated_proof, &msg.fold_attestation) {
                (None, None) => {
                    // no-aggregation mode — skip attestation verification
                }
                (Some(proof), Some(attestation)) => {
                    let Some(expected_context) = self.dkg_fold_attestation_context else {
                        warn!(
                            party_id = msg.party_id,
                            "DKG fold attestation context missing — rejecting"
                        );
                        return Ok(());
                    };
                    let meta = self.params_preset.metadata();
                    let committee_n = *circuit_committee_n;
                    let committee_h = *circuit_committee_h;
                    let n_moduli = meta.num_moduli;
                    if committee_n == 0 || committee_h == 0 {
                        warn!(
                            party_id = msg.party_id,
                            "DKG fold attestation verify skipped — circuit committee dims unset"
                        );
                        return Ok(());
                    }
                    if let Err(e) = verify_dkg_fold_attestation(
                        &self.e3_id,
                        msg.party_id,
                        proof,
                        attestation,
                        expected_context,
                        expected_node,
                        committee_n,
                        committee_h,
                        n_moduli,
                    ) {
                        warn!(
                            party_id = msg.party_id,
                            error = %e,
                            "DKG fold attestation verification failed — rejecting"
                        );
                        return Ok(());
                    }
                }
                (Some(_), None) => {
                    warn!(
                        party_id = msg.party_id,
                        "DKG fold has proof but missing attestation — rejecting (attribution)"
                    );
                    return Ok(());
                }
                (None, Some(_)) => {
                    warn!(
                        party_id = msg.party_id,
                        "DKG fold has attestation but missing proof — rejecting"
                    );
                    return Ok(());
                }
            }
        }

        info!(
            "PublicKeyAggregator: buffered DKG proof from party {} (buffered={})",
            msg.party_id,
            dkg_node_proofs.len() + 1
        );

        self.state.try_mutate(&ec, |state| {
            let PublicKeyAggregatorState::GeneratingC5Proof {
                public_key,
                keyshare_bytes,
                nodes,
                party_nodes,
                mut dkg_node_proofs,
                mut dkg_fold_attestations,
                honest_party_ids,
                dishonest_parties,
                circuit_committee_n,
                circuit_committee_h,
                dkg_aggregation_correlation,
                dkg_aggregated_proof,
                c5_proof_pending,
                nodes_fold_accumulator,
                nodes_fold_completed_slots,
                nodes_fold_step_correlation,
                last_ec: _,
            } = state
            else {
                return Ok(state);
            };
            dkg_node_proofs.insert(msg.party_id, msg.aggregated_proof);
            if let Some(attestation) = msg.fold_attestation.clone() {
                dkg_fold_attestations.insert(msg.party_id, attestation);
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
                dkg_aggregation_correlation,
                dkg_aggregated_proof,
                c5_proof_pending,
                last_ec: Some(ec.clone()),
                nodes_fold_accumulator,
                nodes_fold_completed_slots,
                nodes_fold_step_correlation,
            })
        })?;

        self.try_dispatch_nodes_fold_step(&ec)
    }
}
