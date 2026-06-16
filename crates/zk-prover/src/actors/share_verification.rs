// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Actor for C2/C3/C4 share proof verification.
//!
//! Follows the same pattern as [`ProofVerificationActor`] (for C0) — sits
//! between the raw proof data and the verified result, handling ECDSA validation
//! and ZK verification orchestration.
//!
//! ## Flow
//!
//! 1. Receives [`ShareVerificationDispatched`] from [`ThresholdKeyshare`].
//! 2. Performs ECDSA validation (signature recovery, signer consistency, e3_id,
//!    circuit name) — lightweight, no thread pool needed.
//! 3. Dispatches ZK-only verification to multithread via [`ComputeRequest`].
//! 4. Receives [`ComputeResponse`] from multithread with pure ZK results.
//! 5. Combines ECDSA + ZK results.
//! 6. Emits [`SignedProofFailed`] for any failing proofs.
//! 7. Publishes [`ShareVerificationComplete`] with dishonest party set.

use std::collections::{BTreeSet, HashMap, HashSet};

use actix::{Actor, Addr, Context, Handler};
use alloy::primitives::{keccak256, Address, Bytes};
use alloy::sol_types::SolValue;
use e3_events::{
    BusHandle, CommitmentConsistencyCheckComplete, CommitmentConsistencyCheckRequested,
    ComputeRequest, ComputeRequestError, ComputeResponse, ComputeResponseKind, CorrelationId, E3id,
    EventContext, EventPublisher, EventSubscriber, EventType, InterfoldEvent, InterfoldEventData,
    PartyVerificationResult, ProofType, ProofVerificationFailed, ProofVerificationPassed,
    Sequenced, ShareVerificationComplete, ShareVerificationDispatched, SignedProofFailed,
    SignedProofPayload, TypedEvent, VerificationKind, VerifyShareDecryptionProofsRequest,
    VerifyShareProofsRequest, ZkRequest, ZkResponse,
};
use e3_utils::utility_types::ArcBytes;
use e3_utils::NotifySync;
use tracing::{error, info, warn};

use crate::domain::share_verification::{
    filter_consistent, label_for, PendingConsistencyCheck, PendingVerification, ShareVerifier,
    VerifiableParty, ZkPartyEmission,
};

/// Actor that handles C1/C2/C3/C4/C6 share proof verification.
///
/// Three-stage pipeline:
/// 1. ECDSA validation (lightweight, done inline)
/// 2. Commitment consistency check (dispatched to per-E3 checker via event bus)
/// 3. ZK proof verification (heavyweight, delegated to multithread)
///
/// Emits [`SignedProofFailed`] for fault attribution and
/// [`ShareVerificationComplete`] with the final dishonest party set.
pub struct ShareVerificationActor {
    bus: BusHandle,
    /// Tracks pending ZK verifications by correlation ID.
    pending: HashMap<CorrelationId, PendingVerification>,
    /// Tracks pending consistency checks by correlation ID (between ECDSA and ZK).
    pending_consistency: HashMap<CorrelationId, PendingConsistencyCheck>,
}

impl ShareVerificationActor {
    pub fn new(bus: &BusHandle) -> Self {
        Self {
            bus: bus.clone(),
            pending: HashMap::new(),
            pending_consistency: HashMap::new(),
        }
    }

    pub fn setup(bus: &BusHandle) -> Addr<Self> {
        let addr = Self::new(bus).start();
        bus.subscribe(EventType::ShareVerificationDispatched, addr.clone().into());
        bus.subscribe(EventType::ComputeResponse, addr.clone().into());
        bus.subscribe(EventType::ComputeRequestError, addr.clone().into());
        bus.subscribe(
            EventType::CommitmentConsistencyCheckComplete,
            addr.clone().into(),
        );
        addr
    }

    fn handle_share_verification_dispatched(
        &mut self,
        msg: TypedEvent<ShareVerificationDispatched>,
    ) {
        let (msg, ec) = msg.into_components();
        let e3_id = msg.e3_id.clone();

        info!(
            "handling ShareVerificationDispatched {:?}, {:?}",
            e3_id, msg.kind
        );

        let params_preset = msg.params_preset;
        let committee_size = msg.committee_size;
        match msg.kind {
            VerificationKind::ShareProofs
            | VerificationKind::ThresholdDecryptionProofs
            | VerificationKind::PkGenerationProofs => {
                let kind = msg.kind.clone();
                self.verify_proofs(
                    e3_id,
                    kind.clone(),
                    msg.share_proofs,
                    msg.pre_dishonest,
                    ec,
                    params_preset,
                    committee_size,
                    |pending, passed| {
                        pending.ecdsa_passed_share_proofs = passed;
                    },
                );
            }
            VerificationKind::DecryptionProofs => {
                self.verify_proofs(
                    e3_id,
                    VerificationKind::DecryptionProofs,
                    msg.decryption_proofs,
                    msg.pre_dishonest,
                    ec,
                    params_preset,
                    committee_size,
                    |pending, passed| {
                        pending.ecdsa_passed_decryption_proofs = passed;
                    },
                );
            }
        }
    }

    /// Generic ECDSA validation + consistency check dispatch.
    ///
    /// After ECDSA validation, publishes [`CommitmentConsistencyCheckRequested`]
    /// and stores a [`PendingConsistencyCheck`]. ZK verification is deferred
    /// until the consistency check response arrives.
    #[allow(clippy::too_many_arguments)]
    fn verify_proofs<P: VerifiableParty>(
        &mut self,
        e3_id: E3id,
        kind: VerificationKind,
        party_proofs: Vec<P>,
        pre_dishonest: BTreeSet<u64>,
        ec: EventContext<Sequenced>,
        params_preset: e3_fhe_params::BfvPreset,
        committee_size: e3_zk_helpers::CiphernodesCommitteeSize,
        store_passed_proofs: impl FnOnce(&mut PendingConsistencyCheck, Vec<P>),
    ) {
        let e3_id_str = e3_id.to_string();
        let label = label_for(&kind);

        // Pure ECDSA validation + proof-commitment preparation lives in the
        // domain service; the actor only emits failures, stores pending state,
        // and publishes the consistency-check request.
        let outcome = ShareVerifier::validate_and_prepare(&party_proofs, &e3_id_str, label);

        for failure in &outcome.failures {
            self.emit_signed_proof_failed(
                &e3_id,
                &failure.signed,
                failure.recovered,
                failure.party_id,
                &ec,
            );
        }

        if outcome.ecdsa_passed_parties.is_empty() {
            // All parties failed ECDSA — publish result immediately
            let mut all_dishonest: BTreeSet<u64> = pre_dishonest;
            all_dishonest.extend(outcome.ecdsa_dishonest);
            self.publish_complete(e3_id, kind, all_dishonest, ec);
            return;
        }

        // Store pending consistency check with the original party proofs
        let correlation_id = CorrelationId::new();
        let mut pending = PendingConsistencyCheck {
            e3_id: e3_id.clone(),
            kind: kind.clone(),
            ec: ec.clone(),
            ecdsa_dishonest: outcome.ecdsa_dishonest,
            pre_dishonest,
            party_addresses: outcome.party_addresses,
            party_proof_hashes: outcome.party_proof_hashes,
            party_public_signals: outcome.party_public_signals,
            party_proof_data: outcome.party_proof_data,
            ecdsa_passed_share_proofs: Vec::new(),
            ecdsa_passed_decryption_proofs: Vec::new(),
            params_preset,
            committee_size,
        };
        store_passed_proofs(&mut pending, outcome.ecdsa_passed_parties);
        self.pending_consistency.insert(correlation_id, pending);

        // Publish consistency check request
        if let Err(err) = self.bus.publish(
            CommitmentConsistencyCheckRequested {
                e3_id: e3_id.clone(),
                kind: kind.clone(),
                correlation_id,
                party_proofs: outcome.consistency_party_data,
            },
            ec.clone(),
        ) {
            error!(
                "Failed to dispatch {} consistency check: {err} — treating all as dishonest",
                label
            );
            if let Some(pending) = self.pending_consistency.remove(&correlation_id) {
                let mut all_dishonest: BTreeSet<u64> = pending.pre_dishonest;
                all_dishonest.extend(pending.ecdsa_dishonest);
                for p in &pending.ecdsa_passed_share_proofs {
                    all_dishonest.insert(p.sender_party_id);
                }
                for p in &pending.ecdsa_passed_decryption_proofs {
                    all_dishonest.insert(p.sender_party_id);
                }
                self.publish_complete(e3_id, kind, all_dishonest, ec);
            }
        }
    }

    /// Handle consistency check response: add inconsistent parties to the
    /// dishonest set, then dispatch ZK verification for the remaining
    /// consistent parties.
    fn handle_consistency_check_complete(
        &mut self,
        msg: TypedEvent<CommitmentConsistencyCheckComplete>,
    ) {
        let (data, _ec) = msg.into_components();

        let Some(pending) = self.pending_consistency.remove(&data.correlation_id) else {
            return; // Not our correlation ID
        };

        let label = label_for(&pending.kind);

        if !data.inconsistent_parties.is_empty() {
            warn!(
                "{} consistency check found {} inconsistent parties for E3 {}: {:?}",
                label,
                data.inconsistent_parties.len(),
                pending.e3_id,
                data.inconsistent_parties
            );
        }

        // Accumulate all dishonest parties discovered so far
        let mut dishonest_so_far: BTreeSet<u64> = pending.pre_dishonest.clone();
        dishonest_so_far.extend(&pending.ecdsa_dishonest);
        dishonest_so_far.extend(&data.inconsistent_parties);

        // Filter ECDSA-passed proofs to only consistent parties and dispatch ZK
        let inconsistent = &data.inconsistent_parties;
        let zk_correlation_id = CorrelationId::new();

        let (request, dispatched_party_ids) = match pending.kind {
            VerificationKind::ShareProofs
            | VerificationKind::ThresholdDecryptionProofs
            | VerificationKind::PkGenerationProofs => {
                let Some((passed, ids)) =
                    filter_consistent(pending.ecdsa_passed_share_proofs, inconsistent, |p| {
                        p.sender_party_id
                    })
                else {
                    self.publish_complete(
                        pending.e3_id,
                        pending.kind,
                        dishonest_so_far,
                        pending.ec,
                    );
                    return;
                };
                let req = ComputeRequest::zk(
                    ZkRequest::VerifyShareProofs(VerifyShareProofsRequest {
                        party_proofs: passed,
                        params_preset: pending.params_preset,
                        committee_size: pending.committee_size,
                    }),
                    zk_correlation_id,
                    pending.e3_id.clone(),
                );
                (req, ids)
            }
            VerificationKind::DecryptionProofs => {
                let Some((passed, ids)) =
                    filter_consistent(pending.ecdsa_passed_decryption_proofs, inconsistent, |p| {
                        p.sender_party_id
                    })
                else {
                    self.publish_complete(
                        pending.e3_id,
                        pending.kind,
                        dishonest_so_far,
                        pending.ec,
                    );
                    return;
                };
                let req = ComputeRequest::zk(
                    ZkRequest::VerifyShareDecryptionProofs(VerifyShareDecryptionProofsRequest {
                        party_proofs: passed,
                        params_preset: pending.params_preset,
                        committee_size: pending.committee_size,
                    }),
                    zk_correlation_id,
                    pending.e3_id.clone(),
                );
                (req, ids)
            }
        };

        // Only keep proof hashes/signals/addresses for parties going to ZK
        let party_addresses: HashMap<u64, Address> = pending
            .party_addresses
            .into_iter()
            .filter(|(pid, _)| dispatched_party_ids.contains(pid))
            .collect();
        let party_proof_hashes: HashMap<u64, Vec<(ProofType, [u8; 32])>> = pending
            .party_proof_hashes
            .into_iter()
            .filter(|(pid, _)| dispatched_party_ids.contains(pid))
            .collect();
        let party_public_signals: HashMap<u64, Vec<(ProofType, ArcBytes)>> = pending
            .party_public_signals
            .into_iter()
            .filter(|(pid, _)| dispatched_party_ids.contains(pid))
            .collect();
        let party_proof_data: HashMap<u64, Vec<(ProofType, ArcBytes)>> = pending
            .party_proof_data
            .into_iter()
            .filter(|(pid, _)| dispatched_party_ids.contains(pid))
            .collect();

        // Store pending ZK verification state.
        // All prior dishonest parties (pre_dishonest + ECDSA + consistency) are
        // folded into `pre_dishonest` so that `handle_compute_response` produces
        // the correct final dishonest set when it adds ZK failures.
        self.pending.insert(
            zk_correlation_id,
            PendingVerification {
                e3_id: pending.e3_id.clone(),
                kind: pending.kind.clone(),
                ec: pending.ec.clone(),
                ecdsa_dishonest: HashSet::new(),
                pre_dishonest: dishonest_so_far,
                dispatched_party_ids: dispatched_party_ids.clone(),
                party_addresses,
                party_proof_hashes,
                party_public_signals,
                party_proof_data,
                params_preset: pending.params_preset,
                committee_size: pending.committee_size,
            },
        );

        if let Err(err) = self.bus.publish(request, pending.ec.clone()) {
            error!(
                "Failed to dispatch {} ZK verification after consistency check: {err}",
                label
            );
            if let Some(zk_pending) = self.pending.remove(&zk_correlation_id) {
                let mut all_dishonest: BTreeSet<u64> = zk_pending.pre_dishonest;
                all_dishonest.extend(zk_pending.ecdsa_dishonest);
                all_dishonest.extend(zk_pending.dispatched_party_ids);
                self.publish_complete(
                    zk_pending.e3_id,
                    zk_pending.kind,
                    all_dishonest,
                    zk_pending.ec,
                );
            }
        }
    }

    /// Handle ZK verification response from multithread.
    fn handle_compute_response(&mut self, msg: TypedEvent<ComputeResponse>) {
        let (msg, _ec) = msg.into_components();

        let correlation_id = msg.correlation_id;
        let Some(pending) = self.pending.remove(&correlation_id) else {
            return; // Not our correlation ID
        };

        let zk_results: Vec<PartyVerificationResult> = match (&pending.kind, msg.response) {
            (
                VerificationKind::ShareProofs
                | VerificationKind::ThresholdDecryptionProofs
                | VerificationKind::PkGenerationProofs,
                ComputeResponseKind::Zk(ZkResponse::VerifyShareProofs(r)),
            ) => r.party_results,
            (
                VerificationKind::DecryptionProofs,
                ComputeResponseKind::Zk(ZkResponse::VerifyShareDecryptionProofs(r)),
            ) => r.party_results,
            _ => {
                error!("Unexpected ComputeResponse kind for verification — treating all dispatched parties as dishonest");
                let mut all_dishonest: BTreeSet<u64> = pending.pre_dishonest;
                all_dishonest.extend(pending.ecdsa_dishonest);
                all_dishonest.extend(pending.dispatched_party_ids);
                self.publish_complete(pending.e3_id, pending.kind, all_dishonest, pending.ec);
                return;
            }
        };

        // Pure tally (dishonest accounting + emission decisions) lives in the
        // domain service; the actor performs the resulting bus publishes.
        let tally = ShareVerifier::tally_zk_results(
            pending.pre_dishonest,
            &pending.ecdsa_dishonest,
            &pending.dispatched_party_ids,
            &zk_results,
        );

        for emission in tally.emissions {
            match emission {
                ZkPartyEmission::Failed { party_id, signed } => {
                    let addr = pending.party_addresses.get(&party_id).copied();
                    self.emit_signed_proof_failed(
                        &pending.e3_id,
                        &signed,
                        addr,
                        party_id,
                        &pending.ec,
                    );
                }
                ZkPartyEmission::Passed { party_id } => {
                    // Emit ProofVerificationPassed for each proof type from this party
                    if let Some(hashes) = pending.party_proof_hashes.get(&party_id) {
                        let addr = pending
                            .party_addresses
                            .get(&party_id)
                            .copied()
                            .unwrap_or_default();
                        let signals = pending.party_public_signals.get(&party_id);
                        let datas = pending.party_proof_data.get(&party_id);
                        for (i, &(proof_type, data_hash)) in hashes.iter().enumerate() {
                            let public_signals = signals
                                .and_then(|s| s.get(i))
                                .map(|(_, ps)| ps.clone())
                                .unwrap_or_default();
                            let proof_data = datas
                                .and_then(|d| d.get(i))
                                .map(|(_, pd)| pd.clone())
                                .unwrap_or_default();
                            if let Err(err) = self.bus.publish(
                                ProofVerificationPassed {
                                    e3_id: pending.e3_id.clone(),
                                    party_id,
                                    address: addr,
                                    proof_type,
                                    data_hash,
                                    public_signals,
                                    proof_data,
                                },
                                pending.ec.clone(),
                            ) {
                                error!("Failed to publish ProofVerificationPassed: {err}");
                            }
                        }
                    }
                }
            }
        }

        self.publish_complete(pending.e3_id, pending.kind, tally.dishonest, pending.ec);
    }

    fn emit_signed_proof_failed(
        &self,
        e3_id: &E3id,
        signed_payload: &SignedProofPayload,
        recovered_addr: Option<Address>,
        party_id: u64,
        ec: &EventContext<Sequenced>,
    ) {
        let faulting_node = match recovered_addr {
            Some(addr) => addr,
            None => match signed_payload.recover_address() {
                Ok(addr) => addr,
                Err(err) => {
                    warn!(
                        "Signature recovery failed for party {} — using zero address for fault attribution: {err}",
                        party_id
                    );
                    Address::ZERO
                }
            },
        };

        if let Err(err) = self.bus.publish(
            SignedProofFailed {
                e3_id: e3_id.clone(),
                faulting_node,
                proof_type: signed_payload.payload.proof_type,
                signed_payload: signed_payload.clone(),
            },
            ec.clone(),
        ) {
            error!("Failed to publish SignedProofFailed: {err}");
        }

        // Also emit ProofVerificationFailed for AccusationManager
        let data_hash: [u8; 32] = {
            let msg = (
                Bytes::copy_from_slice(&signed_payload.payload.proof.data),
                Bytes::copy_from_slice(&signed_payload.payload.proof.public_signals),
            )
                .abi_encode();
            keccak256(&msg).into()
        };
        if let Err(err) = self.bus.publish(
            ProofVerificationFailed {
                e3_id: e3_id.clone(),
                accused_party_id: party_id,
                accused_address: faulting_node,
                proof_type: signed_payload.payload.proof_type,
                data_hash,
                signed_payload: signed_payload.clone(),
            },
            ec.clone(),
        ) {
            error!("Failed to publish ProofVerificationFailed: {err}");
        }
    }

    /// Handle computation error from multithread — clean up pending state and
    /// publish ShareVerificationComplete treating all dispatched parties as dishonest.
    fn handle_compute_request_error(&mut self, msg: TypedEvent<ComputeRequestError>) {
        let (msg, _ec) = msg.into_components();

        let correlation_id = msg.correlation_id();
        let Some(pending) = self.pending.remove(correlation_id) else {
            return;
        };

        error!(
            "ZK verification computation failed for E3 {} ({:?}): {} — treating all dispatched parties as dishonest",
            pending.e3_id, pending.kind, msg
        );

        let mut all_dishonest: BTreeSet<u64> = pending.pre_dishonest;
        all_dishonest.extend(pending.ecdsa_dishonest);
        all_dishonest.extend(pending.dispatched_party_ids);
        self.publish_complete(pending.e3_id, pending.kind, all_dishonest, pending.ec);
    }

    fn publish_complete(
        &self,
        e3_id: E3id,
        kind: VerificationKind,
        dishonest_parties: BTreeSet<u64>,
        ec: EventContext<Sequenced>,
    ) {
        if let Err(err) = self.bus.publish(
            ShareVerificationComplete {
                e3_id,
                kind,
                dishonest_parties,
            },
            ec,
        ) {
            error!("Failed to publish ShareVerificationComplete: {err}");
        }
    }
}

impl Actor for ShareVerificationActor {
    type Context = Context<Self>;
}

impl Handler<InterfoldEvent> for ShareVerificationActor {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        match msg {
            InterfoldEventData::ShareVerificationDispatched(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ComputeResponse(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ComputeRequestError(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CommitmentConsistencyCheckComplete(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            _ => (),
        }
    }
}

impl Handler<TypedEvent<ShareVerificationDispatched>> for ShareVerificationActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ShareVerificationDispatched>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_share_verification_dispatched(msg)
    }
}

impl Handler<TypedEvent<ComputeResponse>> for ShareVerificationActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_compute_response(msg)
    }
}

impl Handler<TypedEvent<ComputeRequestError>> for ShareVerificationActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ComputeRequestError>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_compute_request_error(msg)
    }
}

impl Handler<TypedEvent<CommitmentConsistencyCheckComplete>> for ShareVerificationActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<CommitmentConsistencyCheckComplete>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_consistency_check_complete(msg)
    }
}
