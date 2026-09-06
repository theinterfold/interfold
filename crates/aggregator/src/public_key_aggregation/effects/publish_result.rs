// SPDX-License-Identifier: LGPL-3.0-only

//! Publish the completed public-key artifact and persist terminal state.

use super::super::*;

impl PublicKeyAggregator {
    /// Publish `PublicKeyAggregated` when C5 and the final DkgAggregator proof are ready, or when
    /// a test/CI node deliberately skips recursive aggregation.
    pub(in crate::actors::publickey_aggregator) fn try_publish_complete(&mut self) -> Result<()> {
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
        // Test/CI nodes reuse the already-generated C5 proof as a non-empty placeholder. Mock
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
                "test-placeholder"
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
            // BFV publishes the recursively folded `dkg_aggregator_proof`; the
            // per-party CKKS blob is never used on this path.
            ckks_pk_proof_blob: None,
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
}
