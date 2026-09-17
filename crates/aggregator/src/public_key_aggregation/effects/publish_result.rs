// SPDX-License-Identifier: LGPL-3.0-only

//! Publish the completed public-key artifact and persist terminal state.

use super::super::*;

impl PublicKeyAggregator {
    /// Publish the completed public-key intent for the active protocol path.
    /// Publish `PublicKeyAggregated` when C5 and the final DkgAggregator proof are ready, or when
    /// a test-only node deliberately skips recursive aggregation.
    pub(in crate::actors::publickey_aggregator) fn try_publish_complete(&mut self) -> Result<()> {
        if self.is_lbfv() {
            return self.try_publish_lbfv_complete();
        }

        if let Some(ec) = self.state.get().and_then(|s| {
            if let PublicKeyAggregatorState::GeneratingC5Proof { last_ec, .. } = &s {
                last_ec.clone()
            } else {
                None
            }
        }) {
            self.try_dispatch_dkg_aggregation(&ec)?;
        }

        let PublicKeyAggregatorState::GeneratingC5Proof {
            public_key,
            nodes,
            party_nodes,
            dkg_fold_attestations,
            honest_party_ids,
            c5_proof_pending,
            dkg_aggregated_proof,
            dkg_aggregation_correlation: _,
            last_ec,
            ..
        } = self
            .state
            .get()
            .ok_or_else(|| anyhow::anyhow!("Expected GeneratingC5Proof state"))?
        else {
            return Ok(());
        };

        let Some(c5_proof) = c5_proof_pending.as_ref() else {
            return Ok(());
        };

        let all_proofs_are_none = self
            .state
            .get()
            .and_then(|s| {
                if let PublicKeyAggregatorState::GeneratingC5Proof {
                    dkg_node_proofs,
                    honest_party_ids,
                    ..
                } = &s
                {
                    let all_present = honest_party_ids
                        .iter()
                        .all(|id| dkg_node_proofs.contains_key(id));
                    Some(all_present && dkg_node_proofs.values().all(|p| p.is_none()))
                } else {
                    None
                }
            })
            .unwrap_or(false);

        if !all_proofs_are_none && dkg_aggregated_proof.is_none() {
            return Ok(());
        }

        let ec = last_ec
            .clone()
            .ok_or_else(|| anyhow::anyhow!("No EventContext for publish"))?;

        let pk_commitment = extract_pk_commitment(c5_proof)?;
        // Test-only nodes reuse the already-generated C5 proof as a non-empty placeholder. Mock
        // verifiers accept it; production DKG verifiers reject it because it is not a
        // DkgAggregator proof. This keeps the testing escape hatch entirely in the ciphernode.
        let published_dkg_proof = dkg_aggregated_proof
            .clone()
            .or_else(|| all_proofs_are_none.then(|| c5_proof.clone()));

        info!(
            "Publishing PublicKeyAggregated (dkg_evm_proof={})",
            if dkg_aggregated_proof.is_some() {
                "aggregated"
            } else {
                "disabled-for-test"
            }
        );

        // Full committee (N entries) — used by on-chain `committee_hash` binding.
        let mut full_committee_party_ids: Vec<u64> = party_nodes.keys().copied().collect();
        full_committee_party_ids.sort();
        let committee_addresses =
            committee_addresses_in_party_order(&full_committee_party_ids, &party_nodes)?;

        // Honest subset (H entries) — used by downstream actors for share-collection gating.
        let honest_party_ids_vec: Vec<u64> = honest_party_ids.iter().copied().collect();
        let honest_committee_addresses =
            committee_addresses_in_party_order(&honest_party_ids_vec, &party_nodes)?;

        let dkg_attestation_bundle = match dkg_aggregated_proof.as_ref() {
            Some(_) => {
                let bundle = e3_zk_prover::encode_dkg_attestation_bundle(
                    &honest_party_ids,
                    &party_nodes,
                    &dkg_fold_attestations,
                )?;
                Some(ArcBytes::from_bytes(&bundle))
            }
            // The mock fold-attestation verifier used by test deployments only requires a
            // non-empty payload. Production deployments never take this path.
            None => Some(ArcBytes::from_bytes(&[1])),
        };

        let event = PublicKeyAggregated {
            pubkey: public_key.clone(),
            e3_id: self.e3_id.clone(),
            nodes: nodes.clone(),
            committee_addresses: committee_addresses.clone(),
            honest_committee_addresses: honest_committee_addresses.clone(),
            pk_commitment,
            dkg_aggregator_proof: published_dkg_proof,
            dkg_attestation_bundle,
        };
        self.recovery.try_mutate(&ec, |mut recovery| {
            recovery.pending_publication = Some(event.clone());
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })?;
        self.bus.publish(event, ec.clone())?;

        self.state.try_mutate(&ec, |_| {
            Ok(PublicKeyAggregatorState::Complete {
                public_key,
                keyshares: OrderedSet::new(),
                nodes,
                committee_addresses,
                honest_committee_addresses,
            })
        })?;

        Ok(())
    }

    fn try_publish_lbfv_complete(&mut self) -> Result<()> {
        let state = self
            .state
            .get()
            .ok_or_else(|| anyhow::anyhow!("Expected public-key aggregation state"))?;

        if self
            .lbfv_aggregation_state()?
            .is_some_and(|aggregation| aggregation.is_failed())
        {
            return Ok(());
        }

        if matches!(&state, PublicKeyAggregatorState::Complete { .. }) {
            let Some(publication) = self
                .lbfv_publication_state()?
                .and_then(|state| state.pending)
            else {
                return Ok(());
            };
            if let Some(ec) = self.recovery.get().and_then(|state| state.last_ec) {
                self.bus.publish(publication, ec)?;
            } else {
                self.bus.publish_without_context(publication)?;
            }
            return Ok(());
        }

        let PublicKeyAggregatorState::GeneratingC5Proof {
            public_key,
            nodes,
            party_nodes,
            honest_party_ids,
            dkg_fold_attestations,
            c5_proof_pending,
            last_ec,
            ..
        } = state
        else {
            return Ok(());
        };
        let Some(ec) = last_ec else {
            return Ok(());
        };

        self.try_dispatch_dkg_aggregation(&ec)?;

        if let Some(publication) = self
            .lbfv_publication_state()?
            .and_then(|state| state.pending)
        {
            let committee_addresses = publication.committee_addresses.clone();
            let honest_committee_addresses = publication.honest_committee_addresses.clone();
            self.bus.publish(publication, ec.clone())?;
            return self.mark_lbfv_complete(committee_addresses, honest_committee_addresses, ec);
        }

        let Some(c5_proof) = c5_proof_pending else {
            return Ok(());
        };
        let Some(aggregation) = self.lbfv_aggregation_state()? else {
            return Ok(());
        };
        aggregation.validate_loaded()?;
        if aggregation.operational_rlk.is_none() {
            return Ok(());
        }
        let Some(dkg_aggregator_v2_proof) = aggregation.dkg_aggregated_proof else {
            return Ok(());
        };
        anyhow::ensure!(
            dkg_aggregator_v2_proof.circuit == e3_events::CircuitName::DkgAggregatorV2,
            "l-BFV publication requires a DkgAggregatorV2 proof"
        );
        let dkg_attestation_bundle = e3_zk_prover::encode_dkg_attestation_bundle(
            &honest_party_ids,
            &party_nodes,
            &dkg_fold_attestations,
        )?;

        let mut full_committee_party_ids: Vec<u64> = party_nodes.keys().copied().collect();
        full_committee_party_ids.sort_unstable();
        let committee_addresses =
            committee_addresses_in_party_order(&full_committee_party_ids, &party_nodes)?;
        let honest_party_ids_vec: Vec<u64> = honest_party_ids.iter().copied().collect();
        let honest_committee_addresses =
            committee_addresses_in_party_order(&honest_party_ids_vec, &party_nodes)?;
        let publication = LbfvPublicKeyAggregated {
            pubkey: public_key,
            e3_id: self.e3_id.clone(),
            nodes,
            committee_addresses,
            honest_committee_addresses,
            pk_commitment: extract_pk_commitment(&c5_proof)?,
            dkg_aggregator_v2_proof,
            dkg_attestation_bundle: Some(ArcBytes::from_bytes(&dkg_attestation_bundle)),
        };

        self.recovery.try_mutate(&ec, |mut recovery| {
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })?;
        self.set_lbfv_publication(publication.clone(), &ec)?;
        let committee_addresses = publication.committee_addresses.clone();
        let honest_committee_addresses = publication.honest_committee_addresses.clone();
        self.bus.publish(publication, ec.clone())?;
        self.mark_lbfv_complete(committee_addresses, honest_committee_addresses, ec)
    }

    fn mark_lbfv_complete(
        &mut self,
        committee_addresses: Vec<alloy::primitives::Address>,
        honest_committee_addresses: Vec<alloy::primitives::Address>,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        self.state.try_mutate(&ec, |state| {
            let PublicKeyAggregatorState::GeneratingC5Proof {
                public_key, nodes, ..
            } = state
            else {
                return Ok(state);
            };
            Ok(PublicKeyAggregatorState::Complete {
                public_key,
                keyshares: OrderedSet::new(),
                nodes,
                committee_addresses,
                honest_committee_addresses,
            })
        })
    }
}
