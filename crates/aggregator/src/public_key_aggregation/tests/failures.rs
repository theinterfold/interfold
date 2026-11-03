// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;

#[actix::test]
async fn member_removal_logs_identify_the_event_and_publication_boundary() -> Result<()> {
    use std::sync::Mutex;

    #[derive(Clone)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let logs = Arc::new(Mutex::new(Vec::new()));
    let writer = Captured(logs.clone());
    // A second dispatcher keeps callsite registration in parallel tests from using their
    // thread-local default instead of the subscriber registry.
    let _other_dispatch = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_writer(move || writer.clone())
            .finish(),
    );
    let node = Address::repeat_byte(0x11);
    for published in [false, true] {
        for (kind, proof_type) in [
            ("expelled", None),
            ("excluded", Some(ProofType::C6ThresholdShareDecryption)),
        ] {
            let state = PublicKeyAggregatorState::init(
                3,
                1,
                Seed([0; 32]),
                HashMap::from([(0, node.to_string())]),
            );
            let (aggregator, _history, e3_id) = build_public_key_aggregator(state).await?;
            let bus = aggregator.bus.clone();
            let actor = aggregator.start();
            if published {
                actor
                    .send(
                        bus.event_from(
                            e3_events::E3StageChanged {
                                e3_id: e3_id.clone(),
                                previous_stage: E3Stage::CommitteeFinalized,
                                new_stage: E3Stage::KeyPublished,
                            },
                            None,
                        )?
                        .into_sequenced(0),
                    )
                    .await?;
            }
            let removal: InterfoldEventData = match proof_type {
                Some(proof_type) => CommitteeMemberExcluded {
                    e3_id: e3_id.clone(),
                    node,
                    proof_type,
                    party_id: None,
                }
                .into(),
                None => CommitteeMemberExpelled {
                    e3_id: e3_id.clone(),
                    node,
                    reason: [0; 32],
                    active_count_after: 2,
                    party_id: None,
                }
                .into(),
            };
            logs.lock().unwrap().clear();
            actor
                .send(bus.event_from(removal, None)?.into_sequenced(0))
                .await?;
            let output = String::from_utf8(logs.lock().unwrap().clone())?;
            let records: Vec<_> = output
                .lines()
                .filter(|line| line.contains("removal="))
                .collect();
            assert_eq!(records.len(), 1, "{kind}, published={published}: {output}");
            let record = records[0];
            assert!(record.trim_start().starts_with("INFO "), "{record}");
            assert!(record.contains(&format!("removal={kind}")), "{record}");
            assert!(record.contains(&format!("node={node}")), "{record}");
            assert!(record.contains(&format!("e3_id={e3_id}")), "{record}");
            if let Some(proof_type) = proof_type {
                assert!(
                    record.contains(&format!("proof_type={proof_type}")),
                    "{record}"
                );
            } else {
                assert!(!record.contains("proof_type="), "{record}");
            }
            if published {
                assert!(record.contains("ignoring"), "{record}");
                assert!(record.contains("already published"), "{record}");
            } else {
                assert!(record.contains("processing"), "{record}");
            }
            actor.send(Die).await?;
        }
    }
    Ok(())
}

#[actix::test]
async fn dkg_aggregation_compute_error_preserves_pending_work() -> Result<()> {
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
            params_preset: BfvPreset::InsecureThreshold,
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

    actix::clock::sleep(std::time::Duration::from_millis(20)).await;
    assert!(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .is_empty());

    let Some(PublicKeyAggregatorState::GeneratingC5Proof {
        dkg_aggregation_correlation,
        c5_proof_pending,
        ..
    }) = aggregator.state.get()
    else {
        panic!("expected GeneratingC5Proof state");
    };
    assert_eq!(dkg_aggregation_correlation, Some(correlation_id));
    assert!(c5_proof_pending.is_some());

    Ok(())
}

#[actix::test]
async fn mixed_test_modes_preserve_work_without_failing_the_round() -> Result<()> {
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

    actix::clock::sleep(std::time::Duration::from_millis(20)).await;
    assert!(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .is_empty());

    let Some(PublicKeyAggregatorState::GeneratingC5Proof {
        dkg_aggregation_correlation,
        c5_proof_pending,
        ..
    }) = aggregator.state.get()
    else {
        panic!("expected GeneratingC5Proof state");
    };
    assert!(dkg_aggregation_correlation.is_none());
    assert!(c5_proof_pending.is_some());

    Ok(())
}
