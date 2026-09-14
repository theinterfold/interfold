// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Node-level DKG proof aggregation: buffer all inner proofs (C0–C4), then run one
//! [`ZkRequest::NodeDkgFold`] when [`ThresholdSharePending`] says the full set is ready.

use std::collections::{BTreeMap, HashMap};

use actix::{Actor, Addr, Context, Handler};
use alloy::signers::local::PrivateKeySigner;
use e3_events::{
    BusHandle, ComputeRequest, ComputeRequestError, ComputeResponse, ComputeResponseKind,
    CorrelationId, DKGInnerProofReady, DKGRecursiveAggregationComplete, DkgFoldAttestationContext,
    DkgFoldAttestationContextEstablished, DkgFoldAttestationPayload, E3Failed, E3Stage, E3id,
    EventContext, EventPublisher, EventSubscriber, EventType, FailureReason, InterfoldEvent,
    InterfoldEventData, Proof, Sequenced, SignedDkgFoldAttestation, ThresholdSharePending,
    TypedEvent, ZkRequest, ZkResponse, DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION,
};
use e3_fhe_params::build_pair_for_preset;
use tracing::{debug, error, info, warn};

use crate::domain::node_dkg_fold::{DkgProofCollectionState, NodeDkgFoldMeta};
use crate::node_fold_public::extract_node_fold_agg_commits;
/// Actor that collects DKG inner proofs and dispatches a single [`ZkRequest::NodeDkgFold`].
pub struct NodeProofAggregator {
    bus: BusHandle,
    signer: PrivateKeySigner,
    proof_aggregation_enabled: bool,
    /// Request-time registry and verifier for each E3.
    dkg_fold_attestation_contexts_by_e3: HashMap<E3id, DkgFoldAttestationContext>,
    /// Compatibility context for synthetic events without an on-chain context event.
    dkg_fold_attestation_contexts_by_chain: HashMap<u64, Option<DkgFoldAttestationContext>>,
    states: HashMap<E3id, DkgProofCollectionState>,
    fold_correlation: HashMap<CorrelationId, E3id>,
    pending_inner_proofs: HashMap<E3id, BTreeMap<usize, Proof>>,
}

impl NodeProofAggregator {
    pub fn new(
        bus: &BusHandle,
        signer: PrivateKeySigner,
        dkg_fold_attestation_contexts_by_e3: HashMap<E3id, DkgFoldAttestationContext>,
        dkg_fold_attestation_contexts_by_chain: HashMap<u64, Option<DkgFoldAttestationContext>>,
        proof_aggregation_enabled: bool,
    ) -> Self {
        Self {
            bus: bus.clone(),
            signer,
            proof_aggregation_enabled,
            dkg_fold_attestation_contexts_by_e3,
            dkg_fold_attestation_contexts_by_chain,
            states: HashMap::new(),
            fold_correlation: HashMap::new(),
            pending_inner_proofs: HashMap::new(),
        }
    }

    pub fn setup(
        bus: &BusHandle,
        signer: PrivateKeySigner,
        dkg_fold_attestation_contexts_by_e3: HashMap<E3id, DkgFoldAttestationContext>,
        dkg_fold_attestation_contexts_by_chain: HashMap<u64, Option<DkgFoldAttestationContext>>,
        proof_aggregation_enabled: bool,
    ) -> Addr<Self> {
        let addr = Self::new(
            bus,
            signer,
            dkg_fold_attestation_contexts_by_e3,
            dkg_fold_attestation_contexts_by_chain,
            proof_aggregation_enabled,
        )
        .start();
        bus.subscribe(
            EventType::DkgFoldAttestationContextEstablished,
            addr.clone().into(),
        );
        bus.subscribe(EventType::ThresholdSharePending, addr.clone().into());
        bus.subscribe(EventType::DKGInnerProofReady, addr.clone().into());
        bus.subscribe(EventType::ComputeResponse, addr.clone().into());
        bus.subscribe(EventType::ComputeRequestError, addr.clone().into());
        addr
    }
}

#[path = "effects.rs"]
mod effects;
#[path = "handlers.rs"]
mod handlers;

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::Address;
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
    async fn request_context_events_survive_rotation_and_restart() -> Result<()> {
        let (bus, _rng, _seed, _params, _crp, _errors, _history) = get_common_setup(None)?;
        let old_e3 = E3id::new("41", 1);
        let new_e3 = E3id::new("42", 1);
        let old_context = DkgFoldAttestationContext {
            registry: Address::repeat_byte(0x11),
            verifying_contract: Address::repeat_byte(0x12),
        };
        let new_context = DkgFoldAttestationContext {
            registry: Address::repeat_byte(0x21),
            verifying_contract: Address::repeat_byte(0x22),
        };
        let startup_contexts = HashMap::from([(1, Some(new_context))]);

        let mut aggregator = NodeProofAggregator::new(
            &bus,
            test_signer(),
            HashMap::new(),
            startup_contexts.clone(),
            true,
        );
        for (e3_id, context) in [(old_e3.clone(), old_context), (new_e3.clone(), new_context)] {
            let event = DkgFoldAttestationContextEstablished {
                schema_version: DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION,
                e3_id,
                context,
            };
            aggregator.handle_dkg_fold_attestation_context(TypedEvent::new(
                event.clone(),
                test_ctx(event),
            ));
        }

        let restored_contexts = aggregator.dkg_fold_attestation_contexts_by_e3;
        let restarted = NodeProofAggregator::new(
            &bus,
            test_signer(),
            restored_contexts,
            startup_contexts,
            true,
        );

        assert_eq!(
            restarted.dkg_fold_attestation_context_for(&old_e3),
            Some(old_context)
        );
        assert_eq!(
            restarted.dkg_fold_attestation_context_for(&new_e3),
            Some(new_context)
        );

        Ok(())
    }

    #[actix::test]
    async fn node_dkg_fold_compute_error_emits_e3_failed() -> Result<()> {
        let (bus, _rng, _seed, _params, _crp, _errors, history) = get_common_setup(None)?;
        let mut aggregator =
            NodeProofAggregator::new(&bus, test_signer(), HashMap::new(), HashMap::new(), true);
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
        let mut aggregator =
            NodeProofAggregator::new(&bus, test_signer(), HashMap::new(), HashMap::new(), true);
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
