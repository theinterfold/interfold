// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::domain::committee::committee_addresses_in_party_order;
use crate::domain::publickey_aggregation::{
    check_c1_keyshare_commitments, extract_pk_commitment, verify_dkg_fold_attestation, C1Dispatch,
    HonestSelection, PublicKeyAggregation,
};
use actix::prelude::*;
use anyhow::Result;
use e3_data::Persistable;
use e3_events::{
    prelude::*, BusHandle, ComputeRequest, ComputeRequestError, ComputeResponse,
    ComputeResponseKind, CorrelationId, DKGRecursiveAggregationComplete, Die,
    DkgAggregationRequest, E3Failed, E3Stage, E3id, EventContext, FailureReason, InterfoldEvent,
    InterfoldEventData, KeyshareCreated, NodesFoldStepRequest, OrderedSet,
    PkAggregationProofPending, PkAggregationProofRequest, PkAggregationProofSigned, Proof,
    ProofType, PublicKeyAggregated, Sequenced, ShareVerificationComplete,
    ShareVerificationDispatched, SignedProofFailed, SignedProofPayload, TypedEvent,
    VerificationKind, ZkRequest, ZkResponse,
};
use e3_events::{trap, EType};
use e3_fhe::{Fhe, GetAggregatePublicKey};
use e3_fhe_params::BfvPreset;
use e3_utils::NotifySync;
use e3_utils::{ArcBytes, MAILBOX_LIMIT};
use e3_zk_helpers::CiphernodesCommitteeSize;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info, warn};

// Public-key aggregation state machine + pure transition logic now live in
// `crate::domain::publickey_aggregation`; re-exported here to preserve the public path
// `e3_aggregator::publickey_aggregator::PublicKeyAggregatorState`.
pub use crate::domain::publickey_aggregation::PublicKeyAggregatorState;

pub struct PublicKeyAggregator {
    fhe: Arc<Fhe>,
    bus: BusHandle,
    e3_id: E3id,
    state: Persistable<PublicKeyAggregatorState>,
    params_preset: BfvPreset,
    committee_size: CiphernodesCommitteeSize,
    /// DKG recursive aggregation events received before entering GeneratingC5Proof.
    early_dkg_proofs: Vec<TypedEvent<DKGRecursiveAggregationComplete>>,
}

pub struct PublicKeyAggregatorParams {
    pub fhe: Arc<Fhe>,
    pub bus: BusHandle,
    pub e3_id: E3id,
    pub params_preset: BfvPreset,
    pub committee_size: CiphernodesCommitteeSize,
}

/// Aggregate PublicKey for a committee of nodes. This actor listens for KeyshareCreated events
/// around a particular e3_id, verifies C1 proofs, aggregates the public key, generates a C5
/// proof of correct aggregation, and broadcasts a PublicKeyAggregated event on the event bus.
impl PublicKeyAggregator {
    pub fn new(
        params: PublicKeyAggregatorParams,
        state: Persistable<PublicKeyAggregatorState>,
    ) -> Self {
        PublicKeyAggregator {
            fhe: params.fhe,
            bus: params.bus,
            e3_id: params.e3_id,
            state,
            params_preset: params.params_preset,
            committee_size: params.committee_size,
            early_dkg_proofs: Vec::new(),
        }
    }

    pub fn add_keyshare(
        &mut self,
        keyshare: ArcBytes,
        node: String,
        party_id: u64,
        c1_proof: Option<SignedProofPayload>,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
<<<<<<< HEAD:crates/aggregator/src/publickey_aggregator.rs
        self.state.try_mutate(&ec, |mut state| {
            let PublicKeyAggregatorState::Collecting {
                threshold_n,
                threshold_m,
                keyshares,
                c1_proofs,
                nodes,
                submission_order,
                ..
            } = &mut state
            else {
                return Err(anyhow::anyhow!("Can only add keyshare in Collecting state"));
            };

            keyshares.insert(keyshare.clone());
            c1_proofs.push(c1_proof);
            nodes.insert(node.clone());
            submission_order.push((party_id, node.clone(), keyshare));
            let n = *threshold_n;
            let m = *threshold_m;
            let collected = keyshares.len();
            info!(
                party_id,
                node = %node,
                arrival_slot = submission_order.len() - 1,
                collected,
                expected = n,
                remaining = n.saturating_sub(collected),
                "PublicKeyAggregator: keyshare received from party {party_id} ({collected}/{n}), {} still needed",
                n.saturating_sub(collected)
            );
            if keyshares.len() == n {
                info!("All keyshares collected, transitioning to VerifyingC1...");
                return Ok(PublicKeyAggregatorState::VerifyingC1 {
                    submission_order: std::mem::take(submission_order),
                    threshold_m: m,
                    c1_proofs: std::mem::take(c1_proofs),
                    no_proof_parties: Vec::new(),
                });
            }

            Ok(state)
=======
        self.state.try_mutate(ec, |state| {
            PublicKeyAggregation::add_keyshare(
                state,
                keyshare.clone(),
                node.clone(),
                party_id,
                c1_proof.clone(),
            )
>>>>>>> main:crates/aggregator/src/actors/publickey_aggregator.rs
        })
    }

    fn dispatch_c1_verification(
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

    fn handle_c1_verification_complete(
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

        let PublicKeyAggregatorState::VerifyingC1 {
            submission_order,
            threshold_m,
            circuit_committee_n,
            circuit_committee_h,
            c1_proofs,
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

        // Retain full N committee roster (party_id → node address) for the DKG aggregator
        // `committee_members` input, which must cover all `topNodes` regardless of honesty.
        let full_submission_order: Vec<(u64, String, ArcBytes)> = submission_order.clone();

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
                        error!("Failed to publish SignedProofFailed: {e}");
                    }
                }
                Err(e) => warn!(
                    "Could not recover address from C1 proof for party {}: {e}",
                    party_id
                ),
            }
        }

        if !audit.mismatched.is_empty() {
            warn!(
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

        // `party_nodes` covers the FULL registered committee (all N keyshare submitters),
        // not just the H honest set. The DKG aggregator circuit binds `committee_members`
        // to on-chain `topNodes` which always carries the full committee — so we must keep
        // the dishonest addresses available here to build the N-sized address vector.
        // `submission_order` here is the unfiltered list captured pre–C1 verification
        // (the original `VerifyingC1.submission_order`); `honest_entries` is the H subset.
        let party_nodes: HashMap<u64, String> = full_submission_order
            .iter()
            .map(|(pid, node, _)| (*pid, node.clone()))
            .collect();

        let circuit_committee_n = circuit_committee_n;
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

    fn handle_pk_aggregation_proof_signed(
        &mut self,
        msg: TypedEvent<PkAggregationProofSigned>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();

        if msg.e3_id != self.e3_id {
            return Ok(());
        }

        if !matches!(
            self.state.get(),
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

    fn handle_dkg_recursive_aggregation_complete(
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

    /// Dispatch the next [`ZkRequest::NodesFoldStep`] if the next slot's proof is buffered
    /// and no step is currently in flight. When all H slots are done, calls
    /// [`try_dispatch_dkg_aggregation`].
    fn try_dispatch_nodes_fold_step(&mut self, ec: &EventContext<Sequenced>) -> Result<()> {
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
    fn handle_nodes_fold_step_response(
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

    /// Dispatch [`ZkRequest::DkgAggregation`] once C5, all honest NodeFold proofs, and the
    /// streaming nodes_fold are all ready.
    fn try_dispatch_dkg_aggregation(&mut self, ec: &EventContext<Sequenced>) -> Result<()> {
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

        // `proof_aggregation_enabled` is an E3-level flag shared by all nodes, so honest-party
        // proofs should be uniformly Some (aggregation on) or uniformly None (aggregation off).
        // A mixed bag would silently truncate the dispatched request below; reject it explicitly.
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
        info!(
            "ORDER-DEBUG dispatch DkgAggregation: honest_party_ids(submission-idx)={:?} \
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
            // Proof aggregation disabled. Do NOT call `try_publish_complete` here — it
            // is the most common entry into this method, so re-entering it would create
            // unbounded mutual recursion (stack overflow in deployed nodes).
            info!("PublicKeyAggregator: proof aggregation disabled — skipping DkgAggregation");
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

    /// Publish `PublicKeyAggregated` when C5 (non-ZK recursive) and, if applicable, the EVM DkgAggregator proof are ready (or aggregation skipped).
    fn try_publish_complete(&mut self) -> Result<()> {
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

        info!(
            "Publishing PublicKeyAggregated (dkg_evm_proof={})",
            if dkg_aggregated_proof.is_some() {
                "present"
            } else {
                "skipped"
            }
        );

        let pk_commitment = extract_pk_commitment(c5_proof)?;

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
            None => None,
        };

        let event = PublicKeyAggregated {
            pubkey: public_key.clone(),
            e3_id: self.e3_id.clone(),
            nodes: nodes.clone(),
            committee_addresses: committee_addresses.clone(),
            honest_committee_addresses: honest_committee_addresses.clone(),
            pk_commitment,
            dkg_aggregator_proof: dkg_aggregated_proof.clone(),
            dkg_attestation_bundle,
        };
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

    fn handle_compute_response(&mut self, msg: TypedEvent<ComputeResponse>) -> Result<()> {
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
                    })
                })?;
                self.try_publish_complete()?;
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_compute_request_error(&mut self, msg: TypedEvent<ComputeRequestError>) -> Result<()> {
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

        Ok(())
    }

    pub fn handle_member_expelled(
        &mut self,
        node: &str,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        self.state.try_mutate(ec, |state| {
            PublicKeyAggregation::handle_member_expelled(state, node)
        })
    }
}

impl Actor for PublicKeyAggregator {
    type Context = Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

impl Handler<InterfoldEvent> for PublicKeyAggregator {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        match msg {
            InterfoldEventData::KeyshareCreated(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ShareVerificationComplete(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::PkAggregationProofSigned(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::DKGRecursiveAggregationComplete(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ComputeResponse(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ComputeRequestError(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::E3RequestComplete(_) => self.notify_sync(ctx, Die),
            InterfoldEventData::CommitteeMemberExpelled(data) => {
                // Only process raw events from chain (party_id not yet resolved).
                if data.party_id.is_some() {
                    return;
                }

                let node_addr = data.node.to_string();

                if data.e3_id != self.e3_id {
                    error!("Wrong e3_id sent to PublicKeyAggregator for expulsion. This should not happen.");
                    return;
                }

                info!(
                    "PublicKeyAggregator: committee member expelled: {} for e3_id={}",
                    node_addr, data.e3_id
                );
                trap(EType::PublickeyAggregation, &self.bus.with_ec(&ec), || {
                    let was_collecting = matches!(
                        self.state.get(),
                        Some(PublicKeyAggregatorState::Collecting { .. })
                    );

                    self.handle_member_expelled(&node_addr, &ec)?;

                    // If we just transitioned to VerifyingC1, dispatch C1 verification
                    // using the c1_proofs now stored in the VerifyingC1 state (already
                    // cleaned of the expelled node's entry).
                    if was_collecting {
                        if let Some(PublicKeyAggregatorState::VerifyingC1 {
                            submission_order,
                            c1_proofs,
                            ..
                        }) = self.state.get()
                        {
                            self.dispatch_c1_verification(
                                &submission_order,
                                &c1_proofs,
                                ec.clone(),
                            )?;
                        }
                    }
                    Ok(())
                });
            }
            _ => (),
        };
    }
}

impl Handler<TypedEvent<KeyshareCreated>> for PublicKeyAggregator {
    type Result = ();

    fn handle(
        &mut self,
        event: TypedEvent<KeyshareCreated>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let (event, ec) = event.into_components();
        trap(EType::PublickeyAggregation, &self.bus.with_ec(&ec), || {
            let e3_id = event.e3_id.clone();
            let pubkey = event.pubkey.clone();
            let node = event.node.clone();
            let party_id = event.party_id;
            let c1_proof = event.signed_pk_generation_proof.clone();

            if e3_id != self.e3_id {
                error!("Wrong e3_id sent to aggregator. This should not happen.");
                return Ok(());
            }

            self.add_keyshare(pubkey, node, party_id, c1_proof, &ec)?;

            // If we just transitioned to VerifyingC1, dispatch verification
            // using c1_proofs stored in the new state.
            if let Some(PublicKeyAggregatorState::VerifyingC1 {
                submission_order,
                c1_proofs,
                ..
            }) = self.state.get()
            {
                self.dispatch_c1_verification(&submission_order, &c1_proofs, ec)?;
            }

            Ok(())
        })
    }
}

impl Handler<TypedEvent<ShareVerificationComplete>> for PublicKeyAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ShareVerificationComplete>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::PublickeyAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_c1_verification_complete(msg),
        )
    }
}

impl Handler<TypedEvent<PkAggregationProofSigned>> for PublicKeyAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<PkAggregationProofSigned>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::PublickeyAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_pk_aggregation_proof_signed(msg),
        )
    }
}

impl Handler<TypedEvent<DKGRecursiveAggregationComplete>> for PublicKeyAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<DKGRecursiveAggregationComplete>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::PublickeyAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_dkg_recursive_aggregation_complete(msg),
        )
    }
}

impl Handler<TypedEvent<ComputeResponse>> for PublicKeyAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::PublickeyAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_compute_response(msg),
        )
    }
}

impl Handler<TypedEvent<ComputeRequestError>> for PublicKeyAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ComputeRequestError>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::PublickeyAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_compute_request_error(msg),
        )
    }
}

impl Handler<Die> for PublicKeyAggregator {
    type Result = ();
    fn handle(&mut self, _: Die, ctx: &mut Self::Context) -> Self::Result {
        ctx.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_data::{AutoPersist, DataStore, InMemStore, Repository};
    use e3_events::{
        CircuitName, ComputeRequestErrorKind, HistoryCollector, ProofPayload, ProofType,
        TakeEvents, Unsequenced, ZkError,
    };
    use e3_test_helpers::get_common_setup;
    use std::collections::BTreeSet;

    fn test_ctx(data: impl Into<InterfoldEventData>) -> EventContext<Sequenced> {
        EventContext::<Unsequenced>::from(data.into()).sequence(0)
    }

    fn test_state(
        initial_state: PublicKeyAggregatorState,
    ) -> Persistable<PublicKeyAggregatorState> {
        let repo = Repository::<PublicKeyAggregatorState>::new(DataStore::from_in_mem(
            &InMemStore::new(false).start(),
        ));
        repo.to_connector().send(Some(initial_state))
    }

    fn dummy_proof(circuit: CircuitName) -> Proof {
        Proof::new(
            circuit,
            ArcBytes::from_bytes(&[1]),
            ArcBytes::from_bytes(&[2]),
        )
    }

    fn generating_c5_state(correlation_id: CorrelationId) -> PublicKeyAggregatorState {
        PublicKeyAggregatorState::GeneratingC5Proof {
            public_key: ArcBytes::from_bytes(&[1, 2, 3]),
            keyshare_bytes: Vec::new(),
            nodes: OrderedSet::new(),
            party_nodes: HashMap::new(),
            dkg_node_proofs: HashMap::new(),
            dkg_fold_attestations: HashMap::new(),
            honest_party_ids: BTreeSet::new(),
            dishonest_parties: BTreeSet::new(),
            circuit_committee_n: 3,
            circuit_committee_h: 3,
            dkg_aggregation_correlation: Some(correlation_id),
            dkg_aggregated_proof: None,
            c5_proof_pending: Some(dummy_proof(CircuitName::PkAggregation)),
            last_ec: None,
            nodes_fold_accumulator: None,
            nodes_fold_completed_slots: 0,
            nodes_fold_step_correlation: None,
        }
    }

    async fn build_public_key_aggregator(
        initial_state: PublicKeyAggregatorState,
    ) -> Result<(
        PublicKeyAggregator,
        Addr<HistoryCollector<InterfoldEvent>>,
        E3id,
    )> {
        build_public_key_aggregator_with_committee(initial_state, CiphernodesCommitteeSize::Minimum)
            .await
    }

    async fn build_public_key_aggregator_with_committee(
        initial_state: PublicKeyAggregatorState,
        committee_size: CiphernodesCommitteeSize,
    ) -> Result<(
        PublicKeyAggregator,
        Addr<HistoryCollector<InterfoldEvent>>,
        E3id,
    )> {
        let (bus, rng, _seed, params, crp, _errors, history) =
            get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
        let e3_id = E3id::new("42", 1);
        let fhe = Arc::new(Fhe::new(params, crp, rng));
        let aggregator = PublicKeyAggregator::new(
            PublicKeyAggregatorParams {
                fhe,
                bus,
                e3_id: e3_id.clone(),
                params_preset: BfvPreset::InsecureThreshold512,
                committee_size,
            },
            test_state(initial_state),
        );

        Ok((aggregator, history, e3_id))
    }

    fn c1_proof_with_pk_commitment(e3_id: &E3id, pk_commitment: [u8; 32]) -> SignedProofPayload {
        let mut signals = vec![0u8; 96];
        signals[32..64].copy_from_slice(&pk_commitment);
        SignedProofPayload {
            payload: ProofPayload {
                e3_id: e3_id.clone(),
                proof_type: ProofType::C1PkGeneration,
                proof: Proof::new(
                    CircuitName::PkGeneration,
                    ArcBytes::from_bytes(&[1]),
                    ArcBytes::from_bytes(&signals),
                ),
            },
            signature: ArcBytes::from_bytes(&[0u8; 65]),
        }
    }

    fn verifying_c1_non_square_state(
        fhe: &Fhe,
        e3_id: &E3id,
    ) -> Result<(PublicKeyAggregatorState, usize, usize, usize)> {
        use fhe::bfv::SecretKey;
        use fhe::mbfv::PublicKeyShare;
        use fhe_traits::Serialize;

        let committee = CiphernodesCommitteeSize::Micro.values();
        let threshold_n = committee.n;
        let threshold_m = committee.threshold;
        let circuit_h = committee.h;
        assert_ne!(
            threshold_n, circuit_h,
            "test requires a non-square committee (N != H)"
        );

        let mut submission_order = Vec::with_capacity(threshold_n);
        let mut c1_proofs = Vec::with_capacity(threshold_n);
        let mut rng = rand::rng();

        for party_id in 0..threshold_n as u64 {
            let node = format!("0x{:040x}", party_id + 1);
            if party_id < circuit_h as u64 {
                let sk = SecretKey::random(&fhe.params, &mut rng);
                let pk_share = PublicKeyShare::new(&sk, fhe.crp.clone(), &mut rng)?;
                let ks_bytes = ArcBytes::from_bytes(&pk_share.to_bytes());
                let commitment = e3_zk_helpers::compute_pk_commitment_from_keyshare_bytes(
                    &ks_bytes,
                    &fhe.params,
                    &fhe.crp,
                )?;
                submission_order.push((party_id, node, ks_bytes));
                c1_proofs.push(Some(c1_proof_with_pk_commitment(e3_id, commitment)));
            } else {
                submission_order.push((party_id, node, ArcBytes::from_bytes(&[party_id as u8])));
                c1_proofs.push(None);
            }
        }

        Ok((
            PublicKeyAggregatorState::VerifyingC1 {
                submission_order,
                threshold_m,
                circuit_committee_n: threshold_n,
                circuit_committee_h: circuit_h,
                c1_proofs,
                no_proof_parties: vec![],
            },
            threshold_n,
            threshold_m,
            circuit_h,
        ))
    }

    async fn next_event(
        history: &Addr<HistoryCollector<InterfoldEvent>>,
    ) -> Result<InterfoldEvent> {
        let mut result = history.send(TakeEvents::<InterfoldEvent>::new(1)).await?;
        assert!(!result.timed_out, "timed out waiting for an event");
        Ok(result.events.pop().expect("expected one event"))
    }

    #[actix::test]
    async fn dkg_aggregation_compute_error_emits_e3_failed() -> Result<()> {
        let correlation_id = CorrelationId::new();
        let (mut aggregator, history, e3_id) =
            build_public_key_aggregator(generating_c5_state(correlation_id)).await?;

        let request = ComputeRequest::zk(
            ZkRequest::DkgAggregation(DkgAggregationRequest {
                node_fold_proofs: vec![dummy_proof(CircuitName::PkAggregation)],
                nodes_fold_proof: None,
                c5_proof: dummy_proof(CircuitName::PkAggregation),
                party_ids: vec![0],
                committee_addresses: vec!["0x0000000000000000000000000000000000000001"
                    .parse()
                    .expect("test address")],
                params_preset: BfvPreset::InsecureThreshold512,
                committee_size: CiphernodesCommitteeSize::Minimum,
            }),
            correlation_id,
            e3_id.clone(),
        );

        aggregator.handle_compute_request_error(TypedEvent::new(
            ComputeRequestError::new(
                ComputeRequestErrorKind::Zk(ZkError::ProofGenerationFailed("boom".to_string())),
                request,
            ),
            test_ctx(E3Failed {
                e3_id: e3_id.clone(),
                failed_at_stage: E3Stage::None,
                reason: FailureReason::None,
            }),
        ))?;

        let event = next_event(&history).await?;
        assert!(matches!(
            event.into_data(),
            InterfoldEventData::E3Failed(data)
                if data.e3_id == e3_id
                    && data.failed_at_stage == E3Stage::CommitteeFinalized
                    && data.reason == FailureReason::DKGInvalidShares
        ));

        let Some(PublicKeyAggregatorState::GeneratingC5Proof {
            dkg_aggregation_correlation,
            c5_proof_pending,
            ..
        }) = aggregator.state.get()
        else {
            panic!("expected GeneratingC5Proof state");
        };
        assert!(dkg_aggregation_correlation.is_none());
        assert!(c5_proof_pending.is_none());

        Ok(())
    }

    #[actix::test]
    async fn mixed_dkg_proofs_emit_e3_failed() -> Result<()> {
        let correlation_id = CorrelationId::new();
        let mut initial_state = generating_c5_state(correlation_id);
        let PublicKeyAggregatorState::GeneratingC5Proof {
            ref mut dkg_aggregation_correlation,
            ref mut dkg_node_proofs,
            ref mut honest_party_ids,
            ..
        } = initial_state
        else {
            unreachable!();
        };
        *dkg_aggregation_correlation = None;
        honest_party_ids.extend([0, 1]);
        dkg_node_proofs.insert(0, Some(dummy_proof(CircuitName::PkAggregation)));
        dkg_node_proofs.insert(1, None);

        let (mut aggregator, history, e3_id) = build_public_key_aggregator(initial_state).await?;
        let ec = test_ctx(E3Failed {
            e3_id: e3_id.clone(),
            failed_at_stage: E3Stage::None,
            reason: FailureReason::None,
        });

        aggregator.try_dispatch_dkg_aggregation(&ec)?;

        let event = next_event(&history).await?;
        assert!(matches!(
            event.into_data(),
            InterfoldEventData::E3Failed(data)
                if data.e3_id == e3_id
                    && data.failed_at_stage == E3Stage::CommitteeFinalized
                    && data.reason == FailureReason::DKGInvalidShares
        ));

        let Some(PublicKeyAggregatorState::GeneratingC5Proof {
            dkg_aggregation_correlation,
            c5_proof_pending,
            ..
        }) = aggregator.state.get()
        else {
            panic!("expected GeneratingC5Proof state");
        };
        assert!(dkg_aggregation_correlation.is_none());
        assert!(c5_proof_pending.is_none());

        Ok(())
    }

    #[actix::test]
    async fn honest_dkg_fold_without_attestation_is_not_buffered() -> Result<()> {
        let correlation_id = CorrelationId::new();
        let mut initial_state = generating_c5_state(correlation_id);
        let PublicKeyAggregatorState::GeneratingC5Proof {
            ref mut party_nodes,
            ref mut honest_party_ids,
            ..
        } = initial_state
        else {
            unreachable!();
        };
        honest_party_ids.insert(2);
        party_nodes.insert(2, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string());

        let (mut aggregator, _history, e3_id) = build_public_key_aggregator(initial_state).await?;
        let ec = test_ctx(DKGRecursiveAggregationComplete {
            e3_id: e3_id.clone(),
            party_id: 2,
            aggregated_proof: Some(dummy_proof(CircuitName::NodeFold)),
            fold_attestation: None,
        });

        aggregator.handle_dkg_recursive_aggregation_complete(TypedEvent::new(
            DKGRecursiveAggregationComplete {
                e3_id: e3_id.clone(),
                party_id: 2,
                aggregated_proof: Some(dummy_proof(CircuitName::NodeFold)),
                fold_attestation: None,
            },
            ec,
        ))?;

        let Some(PublicKeyAggregatorState::GeneratingC5Proof {
            dkg_node_proofs, ..
        }) = aggregator.state.get()
        else {
            panic!("expected GeneratingC5Proof state");
        };
        assert!(!dkg_node_proofs.contains_key(&2));

        Ok(())
    }

    #[actix::test]
    async fn pk_aggregation_proof_pending_carries_canonical_committee_dims() -> Result<()> {
        let (bus, rng, _seed, params, crp, _errors, history) =
            get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
        let e3_id = E3id::new("42", 1);
        let fhe = Arc::new(Fhe::new(params, crp, rng));
        let (initial_state, threshold_n, threshold_m, circuit_h) =
            verifying_c1_non_square_state(&fhe, &e3_id)?;

        let mut aggregator = PublicKeyAggregator::new(
            PublicKeyAggregatorParams {
                fhe,
                bus,
                e3_id: e3_id.clone(),
                params_preset: BfvPreset::InsecureThreshold512,
                committee_size: CiphernodesCommitteeSize::Micro,
            },
            test_state(initial_state),
        );

        let dishonest: BTreeSet<u64> = (circuit_h as u64..threshold_n as u64).collect();
        aggregator.handle_c1_verification_complete(TypedEvent::new(
            ShareVerificationComplete {
                e3_id: e3_id.clone(),
                kind: VerificationKind::PkGenerationProofs,
                dishonest_parties: dishonest,
            },
            test_ctx(ShareVerificationComplete {
                e3_id: e3_id.clone(),
                kind: VerificationKind::PkGenerationProofs,
                dishonest_parties: BTreeSet::new(),
            }),
        ))?;

        let event = next_event(&history).await?;
        assert!(matches!(
            event.into_data(),
            InterfoldEventData::PkAggregationProofPending(data)
                if data.e3_id == e3_id
                    && data.proof_request.committee_n == threshold_n
                    && data.proof_request.committee_h == circuit_h
                    && data.proof_request.committee_threshold == threshold_m
                    && data.proof_request.keyshare_bytes.len() == circuit_h
        ));

        Ok(())
    }
}
