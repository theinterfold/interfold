// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Node-level DKG proof aggregation: buffer all inner proofs (C0–C4), then run one
//! [`ZkRequest::NodeDkgFold`] when [`ThresholdSharePending`] says the full set is ready.

use std::collections::{BTreeMap, HashMap};

use actix::{Actor, Addr, Context, Handler};
use alloy::primitives::Address;
use alloy::signers::local::PrivateKeySigner;
use e3_events::{
    BusHandle, ComputeRequest, ComputeRequestError, ComputeResponse, ComputeResponseKind,
    CorrelationId, DKGInnerProofReady, DKGRecursiveAggregationComplete, DkgFoldAttestationPayload,
    E3Failed, E3Stage, E3id, EventContext, EventPublisher, EventSubscriber, EventType,
    FailureReason, InterfoldEvent, InterfoldEventData, Proof, Sequenced, SignedDkgFoldAttestation,
    ThresholdSharePending, TypedEvent, ZkRequest, ZkResponse,
};
use e3_fhe_params::build_pair_for_preset;
use tracing::{error, info, warn};

use crate::domain::node_dkg_fold::{DkgProofCollectionState, NodeDkgFoldMeta};
use crate::node_fold_public::extract_node_fold_agg_commits;

/// Actor that collects DKG inner proofs and dispatches a single [`ZkRequest::NodeDkgFold`].
pub struct NodeProofAggregator {
    bus: BusHandle,
    signer: PrivateKeySigner,
    /// Per-chain `DkgFoldAttestationVerifier` address (EIP-712 `verifyingContract`).
    /// Looked up by `e3_id.chain_id()` when signing fold attestations.
    dkg_fold_attestation_verifiers_by_chain: HashMap<u64, Option<Address>>,
    states: HashMap<E3id, DkgProofCollectionState>,
    fold_correlation: HashMap<CorrelationId, E3id>,
    pending_inner_proofs: HashMap<E3id, BTreeMap<usize, Proof>>,
}

impl NodeProofAggregator {
    pub fn new(
        bus: &BusHandle,
        signer: PrivateKeySigner,
        dkg_fold_attestation_verifiers_by_chain: HashMap<u64, Option<Address>>,
    ) -> Self {
        Self {
            bus: bus.clone(),
            signer,
            dkg_fold_attestation_verifiers_by_chain,
            states: HashMap::new(),
            fold_correlation: HashMap::new(),
            pending_inner_proofs: HashMap::new(),
        }
    }

    pub fn setup(
        bus: &BusHandle,
        signer: PrivateKeySigner,
        dkg_fold_attestation_verifiers_by_chain: HashMap<u64, Option<Address>>,
    ) -> Addr<Self> {
        let addr = Self::new(bus, signer, dkg_fold_attestation_verifiers_by_chain).start();
        bus.subscribe(EventType::ThresholdSharePending, addr.clone().into());
        bus.subscribe(EventType::DKGInnerProofReady, addr.clone().into());
        bus.subscribe(EventType::ComputeResponse, addr.clone().into());
        bus.subscribe(EventType::ComputeRequestError, addr.clone().into());
        addr
    }

    fn handle_threshold_share_pending(&mut self, msg: TypedEvent<ThresholdSharePending>) {
        let (msg, ec) = msg.into_components();
        let e3_id = msg.e3_id.clone();

        if !msg.proof_aggregation_enabled {
            self.pending_inner_proofs.remove(&e3_id);
            info!(
                "NodeProofAggregator: proof aggregation disabled for E3 {} — skipping",
                e3_id
            );
            if let Err(err) = self.bus.publish(
                DKGRecursiveAggregationComplete {
                    e3_id: e3_id.clone(),
                    party_id: msg.full_share.party_id,
                    aggregated_proof: None,
                    fold_attestation: None,
                },
                ec,
            ) {
                error!(
                    "NodeProofAggregator: failed to publish DKGRecursiveAggregationComplete (skipped) for E3 {}: {err}",
                    e3_id
                );
            }
            return;
        }

        let sk_enc_count = msg.sk_share_encryption_requests.len();
        let e_sm_enc_count = msg.e_sm_share_encryption_requests.len();
        let total_expected = NodeDkgFoldMeta::total_expected_for(sk_enc_count, e_sm_enc_count);

        let committee = msg.proof_request.committee_size.values();
        let (committee_n, committee_h, n_moduli) =
            match build_pair_for_preset(msg.proof_request.params_preset) {
                Ok((threshold_params, _)) => {
                    (committee.n, committee.h, threshold_params.moduli().len())
                }
                Err(e) => {
                    self.pending_inner_proofs.remove(&e3_id);
                    error!(
                        "NodeProofAggregator: build_pair_for_preset failed for E3 {}: {e}",
                        e3_id
                    );
                    let _ = self.bus.publish(
                        E3Failed {
                            e3_id: e3_id.clone(),
                            failed_at_stage: E3Stage::CommitteeFinalized,
                            reason: FailureReason::DKGInvalidShares,
                        },
                        ec.clone(),
                    );
                    return;
                }
            };

        let meta = NodeDkgFoldMeta {
            party_id: msg.full_share.party_id,
            total_expected,
            sk_enc_count,
            e_sm_enc_count,
            sk_share_encryption_requests: msg.sk_share_encryption_requests.clone(),
            e_sm_share_encryption_requests: msg.e_sm_share_encryption_requests.clone(),
            committee_n,
            committee_h,
            n_moduli,
            params_preset: msg.proof_request.params_preset,
            committee_size: msg.proof_request.committee_size,
        };

        info!(
            "NodeProofAggregator: E3 {} party {} — expecting {} inner proofs (C0..C4) for NodeDkgFold",
            e3_id, meta.party_id, total_expected,
        );

        self.initialize_collection_state(e3_id, meta, ec);
    }

    fn handle_inner_proof_ready(&mut self, msg: TypedEvent<DKGInnerProofReady>) {
        let (msg, ec) = msg.into_components();
        let e3_id = msg.e3_id.clone();

        let Some(state) = self.states.get_mut(&e3_id) else {
            let pending = self.pending_inner_proofs.entry(e3_id.clone()).or_default();
            pending.insert(msg.seq, msg.proof);
            warn!(
                "NodeProofAggregator: received DKGInnerProofReady for E3 {} before ThresholdSharePending — prebuffered seq={} (have {})",
                e3_id,
                msg.seq,
                pending.len()
            );
            return;
        };

        if state.fold_correlation.is_some() {
            warn!(
                "NodeProofAggregator: seq={} arrived while NodeDkgFold in flight — dropped",
                msg.seq
            );
            return;
        }

        state.buffer.insert(msg.seq, msg.proof);
        state.last_ec = ec;

        info!(
            "NodeProofAggregator: buffered seq={} for E3 {} (have {}/{})",
            msg.seq,
            e3_id,
            state.buffer.len(),
            state.meta.total_expected
        );

        self.try_dispatch_node_dkg_fold(&e3_id);
    }

    fn initialize_collection_state(
        &mut self,
        e3_id: E3id,
        meta: NodeDkgFoldMeta,
        ec: EventContext<Sequenced>,
    ) {
        let mut buffer = self.pending_inner_proofs.remove(&e3_id).unwrap_or_default();
        if !buffer.is_empty() {
            info!(
                "NodeProofAggregator: recovered {} prebuffered inner proofs for E3 {}",
                buffer.len(),
                e3_id
            );
        }

        self.states.insert(
            e3_id.clone(),
            DkgProofCollectionState::new(meta, std::mem::take(&mut buffer), ec),
        );

        self.try_dispatch_node_dkg_fold(&e3_id);
    }

    fn try_dispatch_node_dkg_fold(&mut self, e3_id: &E3id) {
        let state = match self.states.get_mut(e3_id) {
            Some(s) => s,
            None => return,
        };
        if !state.is_ready() {
            return;
        }

        let req = state.build_fold_request();
        let corr = CorrelationId::new();
        let ec = state.last_ec.clone();
        let party_id = state.meta.party_id;

        state.fold_correlation = Some(corr);
        self.fold_correlation.insert(corr, e3_id.clone());

        info!(
            "NodeProofAggregator: dispatching NodeDkgFold for E3 {} party {}",
            e3_id, party_id
        );

        if let Err(err) = self.bus.publish(
            ComputeRequest::zk(ZkRequest::NodeDkgFold(req), corr, e3_id.clone()),
            ec,
        ) {
            error!(
                "NodeProofAggregator: failed to publish NodeDkgFold for E3 {}: {err}",
                e3_id
            );
            let _ = self.states.get_mut(e3_id).map(|s| {
                s.fold_correlation = None;
            });
            self.fold_correlation.remove(&corr);
        }
    }

    fn handle_node_dkg_response(&mut self, correlation_id: &CorrelationId, proof: Proof) {
        let Some(e3_id) = self.fold_correlation.remove(correlation_id) else {
            return;
        };

        let Some(state) = self.states.remove(&e3_id) else {
            error!(
                "NodeProofAggregator: NodeDkgFold response for unknown E3 {}",
                e3_id
            );
            return;
        };

        let party_id = state.meta.party_id;
        let committee_n = state.meta.committee_n;
        let committee_h = state.meta.committee_h;
        let n_moduli = state.meta.n_moduli;

        let fold_attestation = match extract_node_fold_agg_commits(
            &proof,
            committee_n,
            committee_h,
            n_moduli,
        ) {
            Ok((extracted_party, commits)) => {
                if extracted_party != party_id {
                    error!(
                        e3_id = %e3_id,
                        expected_party_id = party_id,
                        extracted_party_id = extracted_party,
                        "NodeFold public party_id does not match sortition party_id"
                    );
                    None
                } else if let Some(verifying_contract) =
                    self.dkg_fold_attestation_verifier_for(&e3_id)
                {
                    let payload = DkgFoldAttestationPayload {
                        e3_id: e3_id.clone(),
                        verifying_contract,
                        party_id,
                        agg_commits: commits,
                    };
                    match SignedDkgFoldAttestation::sign(payload, &self.signer) {
                        Ok(signed) => Some(signed),
                        Err(e) => {
                            error!(
                                e3_id = %e3_id,
                                party_id,
                                error = %e,
                                "failed to sign DkgFoldAttestation"
                            );
                            None
                        }
                    }
                } else {
                    error!(
                        e3_id = %e3_id,
                        party_id,
                        "NodeProofAggregator: cannot sign DkgFoldAttestation — CiphernodeRegistry.dkgFoldAttestationVerifier not configured"
                    );
                    None
                }
            }
            Err(e) => {
                error!(
                    e3_id = %e3_id,
                    party_id,
                    error = %e,
                    "failed to extract sk_agg/esm_agg from NodeFold proof"
                );
                None
            }
        };

        if fold_attestation.is_none() {
            error!(
                e3_id = %e3_id,
                party_id,
                "NodeDkgFold succeeded but fold attestation missing — failing E3"
            );
            if let Err(err) = self.bus.publish(
                E3Failed {
                    e3_id: e3_id.clone(),
                    failed_at_stage: E3Stage::CommitteeFinalized,
                    reason: FailureReason::DKGInvalidShares,
                },
                state.last_ec,
            ) {
                error!(
                    "NodeProofAggregator: failed to publish E3Failed for E3 {}: {err}",
                    e3_id
                );
            }
            return;
        }

        info!(
            "NodeProofAggregator: NodeDkgFold complete for E3 {} party {} — publishing DKGRecursiveAggregationComplete",
            e3_id, party_id
        );

        if let Err(err) = self.bus.publish(
            DKGRecursiveAggregationComplete {
                e3_id: e3_id.clone(),
                party_id,
                aggregated_proof: Some(proof),
                fold_attestation,
            },
            state.last_ec,
        ) {
            error!(
                "NodeProofAggregator: failed to publish DKGRecursiveAggregationComplete for E3 {}: {err}",
                e3_id
            );
        }
    }
}

impl Actor for NodeProofAggregator {
    type Context = Context<Self>;
}

impl Handler<InterfoldEvent> for NodeProofAggregator {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, _ctx: &mut Self::Context) -> Self::Result {
        let (data, ec) = msg.into_components();
        match data {
            InterfoldEventData::ThresholdSharePending(data) => {
                self.handle_threshold_share_pending(TypedEvent::new(data, ec));
            }
            InterfoldEventData::DKGInnerProofReady(data) => {
                self.handle_inner_proof_ready(TypedEvent::new(data, ec));
            }
            InterfoldEventData::ComputeResponse(data) => {
                self.handle_compute_response(TypedEvent::new(data, ec));
            }
            InterfoldEventData::ComputeRequestError(data) => {
                self.handle_compute_request_error(TypedEvent::new(data, ec));
            }
            _ => {}
        }
    }
}

impl Handler<TypedEvent<ThresholdSharePending>> for NodeProofAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ThresholdSharePending>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_threshold_share_pending(msg);
    }
}

impl Handler<TypedEvent<DKGInnerProofReady>> for NodeProofAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<DKGInnerProofReady>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_inner_proof_ready(msg);
    }
}

impl Handler<TypedEvent<ComputeResponse>> for NodeProofAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_compute_response(msg);
    }
}

impl Handler<TypedEvent<ComputeRequestError>> for NodeProofAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ComputeRequestError>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_compute_request_error(msg);
    }
}

impl NodeProofAggregator {
    fn dkg_fold_attestation_verifier_for(&self, e3_id: &E3id) -> Option<Address> {
        let chain_id = e3_id.chain_id();
        match self.dkg_fold_attestation_verifiers_by_chain.get(&chain_id) {
            Some(Some(addr)) => Some(*addr),
            Some(None) => None,
            None => {
                warn!(
                    chain_id,
                    "no dkgFoldAttestationVerifier configured for chain"
                );
                None
            }
        }
    }

    fn handle_compute_response(&mut self, msg: TypedEvent<ComputeResponse>) {
        let (msg, _ec) = msg.into_components();
        if let ComputeResponseKind::Zk(ZkResponse::NodeDkgFold(resp)) = msg.response {
            self.handle_node_dkg_response(&msg.correlation_id, resp.proof);
        }
    }

    fn handle_compute_request_error(&mut self, msg: TypedEvent<ComputeRequestError>) {
        let (msg, ec) = msg.into_components();
        if let Some(e3_id) = self.fold_correlation.remove(msg.correlation_id()) {
            error!(
                "NodeProofAggregator: NodeDkgFold failed for E3 {}: {:?} — aggregation aborted",
                e3_id,
                msg.get_err()
            );
            let state = self.states.remove(&e3_id);
            warn!(
                "NodeProofAggregator: E3 {} NodeDkgFold failed — publishing E3Failed",
                e3_id
            );

            if let Some(_state) = state {
                if let Err(err) = self.bus.publish(
                    E3Failed {
                        e3_id: e3_id.clone(),
                        failed_at_stage: E3Stage::CommitteeFinalized,
                        reason: FailureReason::DKGInvalidShares,
                    },
                    ec,
                ) {
                    error!(
                        "NodeProofAggregator: failed to publish E3Failed for E3 {}: {err}",
                        e3_id
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use e3_events::{
        CircuitName, ComputeRequestErrorKind, ComputeRequestKind, Event, HistoryCollector,
        NodeDkgFoldRequest, TakeEvents, Unsequenced, ZkError,
    };
    use e3_test_helpers::get_common_setup;
    use e3_zk_helpers::CiphernodesCommitteeSize;

    fn test_ctx(data: impl Into<InterfoldEventData>) -> EventContext<Sequenced> {
        EventContext::<Unsequenced>::from(data.into()).sequence(0)
    }

    fn test_signer() -> PrivateKeySigner {
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .expect("test signer")
    }

    fn dummy_proof(seed: u8) -> Proof {
        Proof::new(
            CircuitName::PkAggregation,
            e3_utils::ArcBytes::from_bytes(&[seed]),
            e3_utils::ArcBytes::from_bytes(&[seed.wrapping_add(1)]),
        )
    }

    async fn next_event(
        history: &Addr<HistoryCollector<InterfoldEvent>>,
    ) -> Result<InterfoldEvent> {
        let mut result = history.send(TakeEvents::<InterfoldEvent>::new(1)).await?;
        assert!(!result.timed_out, "timed out waiting for an event");
        Ok(result.events.pop().expect("expected one event"))
    }

    #[actix::test]
    async fn node_dkg_fold_compute_error_emits_e3_failed() -> Result<()> {
        let (bus, _rng, _seed, _params, _crp, _errors, history) = get_common_setup(None)?;
        let mut aggregator = NodeProofAggregator::new(&bus, test_signer(), HashMap::new());
        let e3_id = E3id::new("42", 1);
        let correlation_id = CorrelationId::new();

        aggregator.states.insert(
            e3_id.clone(),
            DkgProofCollectionState {
                meta: NodeDkgFoldMeta {
                    party_id: 7,
                    total_expected: 0,
                    sk_enc_count: 0,
                    e_sm_enc_count: 0,
                    sk_share_encryption_requests: Vec::new(),
                    e_sm_share_encryption_requests: Vec::new(),
                    committee_n: 0,
                    committee_h: 0,
                    n_moduli: 0,
                    params_preset: e3_fhe_params::BfvPreset::InsecureThreshold512,
                    committee_size: CiphernodesCommitteeSize::Minimum,
                },
                buffer: BTreeMap::new(),
                fold_correlation: Some(correlation_id),
                last_ec: test_ctx(DKGRecursiveAggregationComplete {
                    e3_id: e3_id.clone(),
                    party_id: 7,
                    aggregated_proof: None,
                    fold_attestation: None,
                }),
            },
        );
        aggregator
            .fold_correlation
            .insert(correlation_id, e3_id.clone());

        let request = ComputeRequest::zk(
            ZkRequest::NodeDkgFold(NodeDkgFoldRequest {
                c0_proof: dummy_proof(1),
                c1_proof: dummy_proof(2),
                c2a_proof: dummy_proof(3),
                c2b_proof: dummy_proof(4),
                c3a_inner_proofs: Vec::new(),
                c3b_inner_proofs: Vec::new(),
                c4a_proof: dummy_proof(5),
                c4b_proof: dummy_proof(6),
                c3_slot_indices_a: Vec::new(),
                c3_slot_indices_b: Vec::new(),
                c3_total_slots: 0,
                party_id: 7,
                params_preset: e3_fhe_params::BfvPreset::InsecureThreshold512,
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
            test_ctx(DKGRecursiveAggregationComplete {
                e3_id: e3_id.clone(),
                party_id: 7,
                aggregated_proof: None,
                fold_attestation: None,
            }),
        ));

        let event = next_event(&history).await?;
        assert!(matches!(
            event.into_data(),
            InterfoldEventData::E3Failed(data)
                if data.e3_id == e3_id
                    && data.failed_at_stage == E3Stage::CommitteeFinalized
                    && data.reason == FailureReason::DKGInvalidShares
        ));
        assert!(!aggregator.states.contains_key(&e3_id));
        assert!(aggregator.fold_correlation.is_empty());

        Ok(())
    }

    #[actix::test]
    async fn early_inner_proof_is_prebuffered_until_collection_starts() -> Result<()> {
        let (bus, _rng, _seed, _params, _crp, _errors, history) = get_common_setup(None)?;
        let mut aggregator = NodeProofAggregator::new(&bus, test_signer(), HashMap::new());
        let e3_id = E3id::new("43", 1);
        let early_proof = dummy_proof(10);

        aggregator.handle_inner_proof_ready(TypedEvent::new(
            DKGInnerProofReady {
                e3_id: e3_id.clone(),
                party_id: 7,
                proof: early_proof.clone(),
                seq: 0,
            },
            test_ctx(DKGInnerProofReady {
                e3_id: e3_id.clone(),
                party_id: 7,
                proof: early_proof.clone(),
                seq: 0,
            }),
        ));

        assert_eq!(
            aggregator
                .pending_inner_proofs
                .get(&e3_id)
                .map(BTreeMap::len),
            Some(1)
        );

        aggregator.initialize_collection_state(
            e3_id.clone(),
            NodeDkgFoldMeta {
                party_id: 7,
                total_expected: 6,
                sk_enc_count: 0,
                e_sm_enc_count: 0,
                sk_share_encryption_requests: Vec::new(),
                e_sm_share_encryption_requests: Vec::new(),
                committee_n: 0,
                committee_h: 0,
                n_moduli: 0,
                params_preset: e3_fhe_params::BfvPreset::InsecureThreshold512,
                committee_size: CiphernodesCommitteeSize::Minimum,
            },
            test_ctx(DKGRecursiveAggregationComplete {
                e3_id: e3_id.clone(),
                party_id: 7,
                aggregated_proof: None,
                fold_attestation: None,
            }),
        );

        assert!(!aggregator.pending_inner_proofs.contains_key(&e3_id));
        assert_eq!(
            aggregator
                .states
                .get(&e3_id)
                .map(|state| state.buffer.len()),
            Some(1)
        );

        for seq in 1..6 {
            let proof = dummy_proof((10 + seq) as u8);
            aggregator.handle_inner_proof_ready(TypedEvent::new(
                DKGInnerProofReady {
                    e3_id: e3_id.clone(),
                    party_id: 7,
                    proof: proof.clone(),
                    seq,
                },
                test_ctx(DKGInnerProofReady {
                    e3_id: e3_id.clone(),
                    party_id: 7,
                    proof,
                    seq,
                }),
            ));
        }

        let event = next_event(&history).await?;
        match event.into_data() {
            InterfoldEventData::ComputeRequest(request) => {
                assert_eq!(request.e3_id, e3_id);
                match request.request {
                    ComputeRequestKind::Zk(ZkRequest::NodeDkgFold(fold_request)) => {
                        assert_eq!(fold_request.c0_proof, early_proof);
                    }
                    other => panic!("expected NodeDkgFold request, got {other:?}"),
                }
            }
            other => panic!("expected ComputeRequest event, got {other:?}"),
        }

        assert!(aggregator
            .states
            .get(&e3_id)
            .and_then(|state| state.fold_correlation)
            .is_some());

        Ok(())
    }
}
