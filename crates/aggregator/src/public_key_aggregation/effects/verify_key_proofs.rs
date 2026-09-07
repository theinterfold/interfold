// SPDX-License-Identifier: LGPL-3.0-only

//! C1 verification and honest-keyshare selection.

use super::*;
use std::collections::HashMap;

impl PublicKeyAggregator {
    pub fn add_keyshare(
        &mut self,
        keyshare: ArcBytes,
        node: String,
        party_id: u64,
        c1_proof: Option<SignedProofPayload>,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        if matches!(
            self.state.get().as_ref(),
            Some(PublicKeyAggregatorState::Complete { .. })
        ) {
            info!("Ignoring replayed keyshare after public-key aggregation completed");
            return Ok(());
        }
        self.state.try_mutate(ec, |state| {
            PublicKeyAggregation::add_keyshare(
                state,
                keyshare.clone(),
                node.clone(),
                party_id,
                c1_proof.clone(),
            )
        })
    }

    pub(in crate::actors::publickey_aggregator) fn dispatch_c1_verification(
        &mut self,
        submission_order: &[(u64, String, ArcBytes)],
        c1_proofs: &[Option<SignedProofPayload>],
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let C1Dispatch {
            party_proofs,
            no_proof_parties,
        } = PublicKeyAggregation::plan_c1_dispatch(submission_order, c1_proofs);

        // Store no-proof parties in state for the response handler
        if !no_proof_parties.is_empty() {
            self.state.try_mutate(&ec, |mut state| {
                if let PublicKeyAggregatorState::VerifyingC1 {
                    no_proof_parties: ref mut stored,
                    ..
                } = state
                {
                    *stored = no_proof_parties.clone();
                }
                Ok(state)
            })?;
        }

        if party_proofs.is_empty() {
            return Err(anyhow::anyhow!(
                "No C1 proofs to verify — all keyshares must include a signed C1 proof"
            ));
        }

        info!(
            "Dispatching C1 proof verification for {} parties ({} missing proofs)",
            party_proofs.len(),
            no_proof_parties.len()
        );

        self.bus.publish(
            ShareVerificationDispatched {
                e3_id: self.e3_id.clone(),
                kind: VerificationKind::PkGenerationProofs,
                share_proofs: party_proofs,
                decryption_proofs: vec![],
                pre_dishonest: no_proof_parties.into_iter().collect(),
                params_preset: self.params_preset,
                committee_size: self.committee_size,
            },
            ec,
        )?;
        Ok(())
    }

    pub(in crate::actors::publickey_aggregator) fn handle_c1_verification_complete(
        &mut self,
        msg: TypedEvent<ShareVerificationComplete>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();

        if msg.kind != VerificationKind::PkGenerationProofs {
            return Ok(());
        }

        if msg.e3_id != self.e3_id {
            return Ok(());
        }

        if matches!(
            self.state.get().as_ref(),
            Some(PublicKeyAggregatorState::Complete { .. })
        ) {
            info!("Ignoring late C1 verification after public-key aggregation completed");
            return Ok(());
        }

        let PublicKeyAggregatorState::VerifyingC1 {
            submission_order,
            threshold_m,
            circuit_committee_n,
            circuit_committee_h,
            c1_proofs,
            canonical_party_nodes,
            ..
        } = self
            .state
            .get()
            .ok_or_else(|| anyhow::anyhow!("Expected VerifyingC1 state"))?
        else {
            return Err(anyhow::anyhow!(
                "handle_c1_verification_complete called outside VerifyingC1 state"
            ));
        };

        let mut dishonest_parties = msg.dishonest_parties.clone();
        let collected = submission_order.len();
        let circuit_h = circuit_committee_h;

        // Filter out parties that failed C1 ZK verification. Keyed by the real
        // sortition party_id carried in `submission_order`, not arrival index.
        let mut honest_entries: Vec<(u64, String, ArcBytes, Option<SignedProofPayload>)> =
            submission_order
                .into_iter()
                .zip(c1_proofs)
                .filter(|((pid, _, _), _)| !dishonest_parties.contains(pid))
                .map(|((pid, node, ks), c1)| (pid, node, ks, c1))
                .collect();

        // Cross-check: verify each party's keyshare matches their C1 pk_commitment.
        // Parties that fail are marked dishonest and reported via SignedProofFailed.
        let audit = check_c1_keyshare_commitments(&honest_entries, &self.fhe);
        for party_id in &audit.missing_proof {
            dishonest_parties.insert(*party_id);
        }

        // Emit SignedProofFailed for each commitment-mismatched party
        for (party_id, signed_proof) in &audit.mismatched {
            dishonest_parties.insert(*party_id);
            match signed_proof.recover_address() {
                Ok(faulting_node) => {
                    if let Err(e) = self.bus.publish(
                        SignedProofFailed {
                            e3_id: self.e3_id.clone(),
                            faulting_node,
                            proof_type: ProofType::C1PkGeneration,
                            signed_payload: signed_proof.clone(),
                        },
                        ec.clone(),
                    ) {
                        error!(
                            e3_id = %self.e3_id,
                            party_id,
                            "Failed to publish SignedProofFailed: {e}"
                        );
                    }
                }
                Err(e) => warn!(
                    e3_id = %self.e3_id,
                    "Could not recover address from C1 proof for party {}: {e}",
                    party_id
                ),
            }
        }

        if !audit.mismatched.is_empty() {
            warn!(
                e3_id = %self.e3_id,
                "C1 commitment mismatch for {} parties — filtering before aggregation",
                audit.mismatched.len()
            );
            // Re-filter honest_entries after commitment check
            honest_entries.retain(|(pid, _, _, _)| !dishonest_parties.contains(pid));
        }

        // Sort, fail-closed below H, cap to the H lowest party_ids, and fail when
        // <= threshold_m remain. All pure decision logic lives in the service; the
        // actor only publishes E3Failed on the Fail outcome.
        let (honest_entries, honest_party_ids) = match PublicKeyAggregation::select_honest_set(
            &self.e3_id,
            honest_entries,
            &dishonest_parties,
            circuit_h,
            threshold_m,
            collected,
        ) {
            HonestSelection::Fail => {
                self.bus.publish(
                    E3Failed {
                        e3_id: self.e3_id.clone(),
                        failed_at_stage: E3Stage::CommitteeFinalized,
                        reason: FailureReason::DKGInvalidShares,
                    },
                    ec,
                )?;
                return Ok(());
            }
            HonestSelection::Proceed {
                honest_entries,
                honest_party_ids,
            } => (honest_entries, honest_party_ids),
        };

        let (honest_keyshares, honest_nodes): (Vec<ArcBytes>, Vec<String>) = honest_entries
            .iter()
            .map(|(_, node, ks, _)| (ks.clone(), node.clone()))
            .unzip();

        debug_assert_eq!(
            honest_party_ids.len(),
            honest_keyshares.len(),
            "honest roster and keyshare payload lengths must match"
        );

        // Synchronous aggregation
        info!(
            "Aggregating public key from {} honest shares...",
            honest_keyshares.len()
        );
        let honest_keyshares_set = OrderedSet::from(honest_keyshares.clone());
        let pubkey = self.fhe.get_aggregate_public_key(GetAggregatePublicKey {
            keyshares: honest_keyshares_set.clone(),
        })?;

        let committee_h = honest_keyshares.len();
        let honest_nodes_set = OrderedSet::from(honest_nodes.clone());
        // Feed keyshares to C5 in ascending party_id order so that
        // `c5_public[i]` (pk_commitment of the i-th input keyshare) matches
        // party_ids[i] and the row-i node_fold pk bound by dkg_aggregator.nr.
        // `honest_keyshares` preserves the submission-index (== party_id) order
        // from `honest_entries`; do NOT sort by byte content.
        let keyshare_bytes: Vec<ArcBytes> = honest_keyshares.clone();

        let pubkey = ArcBytes::from_bytes(&pubkey);
        info!("Publishing PkAggregationProofPending for C5 proof generation...");
        self.bus.publish(
            PkAggregationProofPending {
                e3_id: self.e3_id.clone(),
                proof_request: PkAggregationProofRequest {
                    keyshare_bytes: keyshare_bytes.clone(),
                    aggregated_pk_bytes: pubkey.clone(),
                    params_preset: self.params_preset,
                    // C5 witness uses `committee_h` keyshares; artifact lookup needs canonical (N, H, T).
                    committee_n: circuit_committee_n,
                    committee_h,
                    committee_threshold: threshold_m,
                },
                public_key: pubkey.clone(),
                nodes: honest_nodes_set.clone(),
            },
            ec.clone(),
        )?;

        // Proof binding uses the full immutable committee, including a member excluded before it
        // produced a keyshare. Deriving this map from keyshare submitters would shorten the roster
        // and make the final N-sized DKG proof impossible.
        anyhow::ensure!(
            canonical_party_nodes.len() == circuit_committee_n,
            "finalized committee has {} entries; expected circuit N={circuit_committee_n}",
            canonical_party_nodes.len()
        );
        let party_nodes = canonical_party_nodes;

        let circuit_committee_h = circuit_h;
        self.state.try_mutate(&ec, |_| {
            Ok(PublicKeyAggregatorState::GeneratingC5Proof {
                public_key: pubkey.clone(),
                keyshare_bytes,
                nodes: honest_nodes_set,
                party_nodes,
                dkg_node_proofs: HashMap::new(),
                dkg_fold_attestations: HashMap::new(),
                honest_party_ids: honest_party_ids.clone(),
                dishonest_parties: dishonest_parties.clone(),
                circuit_committee_n,
                circuit_committee_h,
                dkg_aggregation_correlation: None,
                dkg_aggregated_proof: None,
                c5_proof_pending: None,
                last_ec: Some(ec.clone()),
                nodes_fold_accumulator: None,
                nodes_fold_completed_slots: 0,
                nodes_fold_step_correlation: None,
            })
        })?;

        // Replay any DKG proofs that arrived before we entered GeneratingC5Proof.
        let early = std::mem::take(&mut self.early_dkg_proofs);
        for event in early {
            self.handle_dkg_recursive_aggregation_complete(event)?;
        }

        self.try_dispatch_dkg_aggregation(&ec)?;

        Ok(())
    }
}
