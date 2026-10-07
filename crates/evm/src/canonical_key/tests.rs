// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use e3_events::{EventConstructorWithTimestamp, OrderedSet, Unsequenced};
use e3_fhe_params::{BfvParamSet, BfvPreset};

fn event(
    data: impl Into<InterfoldEventData>,
    source: EventSource,
    block: Option<u64>,
) -> InterfoldEvent {
    InterfoldEvent::<Unsequenced>::new_with_timestamp(data.into(), None, 1, block, source)
        .into_sequenced(1)
}

fn proof_observation(
    id: &E3id,
    nodes: Vec<Address>,
    commitment: [u8; 32],
) -> e3_events::EvmLogObserved {
    let mut inputs = vec![B256::ZERO; 12];
    inputs[3] = B256::from(U256::from(2).to_be_bytes::<32>());
    inputs[7] = B256::repeat_byte(3);
    inputs[8] = B256::repeat_byte(4);
    inputs[9] = B256::repeat_byte(5);
    inputs[10] = B256::repeat_byte(6);
    inputs[11] = commitment.into();
    let log = ICiphernodeRegistry::CommitteeProofPublished {
        e3Id: id.clone().try_into().unwrap(),
        nodes,
        pkCommitment: commitment.into(),
        proof: Bytes::from((Bytes::new(), inputs).abi_encode_params()),
    }
    .encode_log_data();
    e3_events::EvmLogObserved {
        contract: "CiphernodeRegistry".into(),
        chain_id: id.chain_id(),
        e3_id: Some(id.clone()),
        event_name: "CommitteeProofPublished".into(),
        signature: Some(ICiphernodeRegistry::CommitteeProofPublished::SIGNATURE.into()),
        known: true,
        topics: log.topics().iter().map(ToString::to_string).collect(),
        data: ArcBytes::from_bytes(&log.data),
    }
}

#[actix::test]
async fn confirmed_observations_admit_publications_in_either_order() -> Result<()> {
    let id = E3id::new("81", 1);
    let preset = BfvPreset::InsecureThreshold;
    let params = BfvParamSet::from(preset);
    let bytes = e3_bfv_client::client::generate_public_key(
        params.degree,
        params.plaintext_modulus,
        params.moduli.to_vec(),
    )?;
    let commitment = e3_bfv_client::compute_pk_commitment(
        bytes.clone(),
        params.degree,
        params.plaintext_modulus,
        params.moduli.to_vec(),
    )?;
    let nodes = vec![
        Address::repeat_byte(1),
        Address::repeat_byte(2),
        Address::repeat_byte(3),
    ];
    let publication = PublicKeyAggregated {
        e3_id: id.clone(),
        pubkey: ArcBytes::from_bytes(&bytes),
        nodes: OrderedSet::new(),
        committee_addresses: nodes.clone(),
        honest_committee_addresses: vec![nodes[0], nodes[2]],
        pk_commitment: commitment,
        dkg_aggregator_proof: None,
        dkg_attestation_bundle: None,
    };
    for publication_first in [true, false] {
        let keys = CanonicalPublicKeys::default();
        let mut projection = CanonicalKeyProjection::new(
            keys.clone(),
            HashMap::from([(1, Address::repeat_byte(9))]),
        );
        projection.observe(&event(
            E3Requested {
                e3_id: id.clone(),
                threshold_m: 1,
                threshold_n: 3,
                params_preset: preset,
                ..Default::default()
            },
            EventSource::Evm,
            Some(1),
        ))?;
        let mut orphaned = proof_observation(&id, nodes.clone(), [7; 32]);
        for (source, block) in [
            (EventSource::Net, Some(2)),
            (EventSource::Local, Some(2)),
            (EventSource::Evm, None),
        ] {
            projection.observe(&event(orphaned.clone(), source, block))?;
            assert!(
                keys.get(&id).is_none(),
                "unconfirmed or non-chain facts became authority"
            );
        }
        orphaned.contract = "Interfold".into();
        projection.observe(&event(orphaned, EventSource::Evm, Some(2)))?;
        assert!(keys.get(&id).is_none());
        if publication_first {
            projection.observe(&event(publication.clone(), EventSource::Net, None))?;
        }
        projection.observe(&event(
            proof_observation(&id, nodes.clone(), commitment),
            EventSource::Evm,
            Some(3),
        ))?;
        if !publication_first {
            projection.observe(&event(publication.clone(), EventSource::Net, None))?;
        }
        let key = keys.get(&id).expect("confirmed key authority");
        assert_eq!(key.committee, nodes);
        assert_eq!(key.honest_committee, vec![nodes[0], nodes[2]]);
        assert_eq!(key.sk_agg_commits, vec![[3; 32], [4; 32]]);
        assert_eq!(key.esm_agg_commits, vec![[5; 32], [6; 32]]);
        assert_eq!(keys.public_key(&id), Some(publication.pubkey.clone()));
        let mut mismatch = publication.clone();
        mismatch.pk_commitment = [7; 32];
        mismatch.committee_addresses.reverse();
        mismatch.honest_committee_addresses.reverse();
        projection.observe(&event(mismatch, EventSource::Net, None))?;
        assert_eq!(keys.get(&id), Some(key));
        assert_eq!(keys.public_key(&id), Some(publication.pubkey.clone()));
    }
    Ok(())
}

#[actix::test]
async fn awaiting_one_key_does_not_stop_other_request_delivery() -> Result<()> {
    use async_trait::async_trait;
    use e3_ciphernode_builder::EventSystem;
    use e3_request::{E3Context, E3ContextSnapshot, E3Extension, E3Router};
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };
    struct Observed(Arc<Mutex<Vec<E3id>>>);
    #[async_trait]
    impl E3Extension for Observed {
        fn on_event(&self, _: &mut E3Context, event: &InterfoldEvent) {
            if let InterfoldEventData::CiphertextOutputPublished(data) = event.get_data() {
                self.0.lock().unwrap().push(data.e3_id.clone());
            }
        }
        async fn hydrate(&self, _: &mut E3Context, _: &E3ContextSnapshot) -> Result<()> {
            Ok(())
        }
    }
    let system =
        EventSystem::new()
            .with_fresh_bus()
            .with_aggregate_config(e3_events::AggregateConfig::new(HashMap::from([(
                AggregateId::new(1),
                Duration::ZERO,
            )])));
    let bus = system.handle()?.enable("key-delivery");
    let keys = CanonicalPublicKeys::default();
    CanonicalKeyProjection::new(keys.clone(), HashMap::from([(1, Address::ZERO)]))
        .attach(&bus)
        .await?;
    let observed = Arc::new(Mutex::new(Vec::new()));
    let _router = E3Router::builder(&bus, system.store()?)
        .with(Box::new(Observed(observed.clone())))
        .build()
        .await?;
    let ids = [E3id::new("1", 1), E3id::new("2", 1)];
    for id in &ids {
        bus.publish_from_remote(
            E3Requested {
                e3_id: id.clone(),
                threshold_m: 1,
                threshold_n: 3,
                ..Default::default()
            },
            0,
            Some(1),
            EventSource::Evm,
        )?;
        bus.publish_from_remote(
            e3_events::CiphertextOutputPublished {
                e3_id: id.clone(),
                ciphertext_output: vec![],
                ciphertext_commitment: [0; 32],
            },
            0,
            Some(2),
            EventSource::Evm,
        )?;
    }
    actix::clock::timeout(Duration::from_secs(2), bus.flush_event_pipeline()).await??;
    assert_eq!(*observed.lock().unwrap(), ids);
    assert!(keys.get(&ids[0]).is_none());
    bus.publish_from_remote(
        proof_observation(
            &ids[1],
            vec![
                Address::repeat_byte(1),
                Address::repeat_byte(2),
                Address::repeat_byte(3),
            ],
            [9; 32],
        ),
        0,
        Some(3),
        EventSource::Evm,
    )?;
    actix::clock::timeout(Duration::from_secs(2), bus.flush_event_pipeline()).await??;
    assert_eq!(keys.get(&ids[1]).unwrap().pk_commitment, [9; 32]);
    Ok(())
}

#[actix::test]
async fn terminal_history_preserves_rosters_for_snapshot_hydration() -> Result<()> {
    use e3_ciphernode_builder::EventSystem;
    use e3_events::{AggregateConfig, E3Stage, E3StageChanged, EventBusFanout};
    use std::time::Duration;
    let aggregate = AggregateId::new(1);
    let system = EventSystem::new()
        .with_fresh_bus()
        .with_aggregate_config(AggregateConfig::new(HashMap::from([(
            aggregate,
            Duration::ZERO,
        )])));
    let bus = system.handle()?.enable("terminal-key-history");
    let ids = [E3id::new("84", 1), E3id::new("85", 1)];
    let nodes = vec![
        Address::repeat_byte(1),
        Address::repeat_byte(2),
        Address::repeat_byte(3),
    ];
    let terminal = |id: &E3id| E3StageChanged {
        e3_id: id.clone(),
        previous_stage: E3Stage::CiphertextReady,
        new_stage: E3Stage::Complete,
    };
    for id in &ids {
        for (block, data) in [
            (
                1,
                InterfoldEventData::from(E3Requested {
                    e3_id: id.clone(),
                    threshold_m: 1,
                    threshold_n: 3,
                    ..Default::default()
                }),
            ),
            (2, proof_observation(id, nodes.clone(), [8; 32]).into()),
            (3, terminal(id).into()),
        ] {
            bus.publish_from_remote(data, 0, Some(block), EventSource::Evm)?;
        }
    }
    bus.flush_event_pipeline().await?;
    let keys = CanonicalPublicKeys::default();
    let mut projection =
        CanonicalKeyProjection::new(keys.clone(), HashMap::from([(1, Address::ZERO)]));
    projection
        .recover(
            &system.eventstore_reader()?.seq(),
            &[aggregate],
            HashSet::from([ids[0].clone()]),
        )
        .await?;
    assert_eq!(keys.get(&ids[0]).expect("snapshot roster").committee, nodes);
    assert!(keys.get(&ids[1]).is_none());
    projection.attach(&bus).await?;
    bus.event_bus()
        .send(EventBusFanout(event(
            terminal(&ids[0]),
            EventSource::Evm,
            Some(3),
        )))
        .await??;
    assert!(keys.get(&ids[0]).is_none());
    Ok(())
}
