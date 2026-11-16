// SPDX-License-Identifier: LGPL-3.0-only

//! Confirmed-observation/read-model tests, not cryptographic proof acceptance.

use super::*;
use crate::contracts::ISynchronizedDkgPublication;
use e3_committee_hash::{hash_committee_addresses, DkgSetupContext};
use e3_events::{
    E3Stage, E3StageChanged, EvmLogObserved, SynchronizedDkgContext,
    SynchronizedDkgContextEstablished, SYNCHRONIZED_DKG_CONTEXT_SCHEMA_VERSION,
};

struct Fixture {
    request: E3Requested,
    context: SynchronizedDkgContextEstablished,
    authority: ISynchronizedDkgPublication::Authority,
    committee: Vec<Address>,
    fields: Vec<B256>,
    interfold: Address,
    bytes: ArcBytes,
}

impl Fixture {
    fn new() -> Result<Self> {
        let profile = BfvProfile::SyncDecInsecure64;
        let size = CiphernodesCommitteeSize::Minimum;
        let (params, _) = profile.build_pair()?;
        let bytes = e3_bfv_client::client::generate_public_key(
            params.degree(),
            params.plaintext(),
            params.moduli().to_vec(),
        )?;
        let commitment = e3_bfv_client::compute_pk_commitment(
            bytes.clone(),
            params.degree(),
            params.plaintext(),
            params.moduli().to_vec(),
        )?;
        let request = E3Requested {
            e3_id: E3id::new("90", 1),
            threshold_m: 1,
            threshold_n: 3,
            params_profile: profile,
            crypto_config_id: profile.crypto_config_id(size)?.0,
            params: ArcBytes::from_bytes(&e3_fhe_params::encode_bfv_params(&params)),
            ..Default::default()
        };
        let committee: Vec<_> = (1..=3).map(Address::repeat_byte).collect();
        let interfold = Address::repeat_byte(9);
        let binding = DkgSetupContext {
            interfold_address: interfold,
            committee_hash: hash_committee_addresses(&committee),
            crypto_config_id: request.crypto_config_id.into(),
        }
        .hash(1, request.e3_id.clone().try_into()?);
        let context = SynchronizedDkgContextEstablished {
            schema_version: SYNCHRONIZED_DKG_CONTEXT_SCHEMA_VERSION,
            e3_id: request.e3_id.clone(),
            context: SynchronizedDkgContext {
                registry: Address::repeat_byte(7),
                verifying_contract: Address::repeat_byte(8),
                crypto_config_id: request.crypto_config_id,
            },
        };
        let authority = ISynchronizedDkgPublication::Authority {
            version: 1,
            verifier: context.context.verifying_contract,
            cryptoConfigId: request.crypto_config_id.into(),
            setupBinding: binding,
            dealerBatch: B256::repeat_byte(2),
            pkCommitment: commitment.into(),
            partyIds: vec![U256::ZERO, U256::from(2)],
            thresholdPkCommits: vec![B256::repeat_byte(3), B256::repeat_byte(4)],
            skAggCommits: vec![B256::repeat_byte(5), B256::repeat_byte(6)],
            keyBundleCommits: vec![B256::repeat_byte(7), B256::repeat_byte(8)],
        };
        let mut fields = vec![B256::repeat_byte(1); 14];
        fields[2] = B256::from(U256::from_be_slice(&binding[..16]).to_be_bytes::<32>());
        fields[3] = B256::from(U256::from_be_slice(&binding[16..]).to_be_bytes::<32>());
        fields[4] = B256::ZERO;
        fields[5] = U256::from(2).to_be_bytes::<32>().into();
        fields[6] = authority.dealerBatch;
        fields[7..9].copy_from_slice(&authority.thresholdPkCommits);
        fields[9..11].copy_from_slice(&authority.skAggCommits);
        fields[11..13].copy_from_slice(&authority.keyBundleCommits);
        fields[13] = commitment.into();
        Ok(Self {
            request,
            context,
            authority,
            committee,
            fields,
            interfold,
            bytes: ArcBytes::from_bytes(&bytes),
        })
    }

    fn raw<E: SolEvent>(&self, name: &str, data: &E) -> EvmLogObserved {
        let log = data.encode_log_data();
        EvmLogObserved {
            contract: "CiphernodeRegistry".into(),
            chain_id: 1,
            e3_id: Some(self.request.e3_id.clone()),
            event_name: name.into(),
            signature: Some(E::SIGNATURE.into()),
            known: true,
            topics: log.topics().iter().map(ToString::to_string).collect(),
            data: ArcBytes::from_bytes(&log.data),
        }
    }

    fn proof(&self) -> EvmLogObserved {
        self.raw(
            "CommitteeProofPublished",
            &ICiphernodeRegistry::CommitteeProofPublished {
                e3Id: self.request.e3_id.clone().try_into().unwrap(),
                nodes: self.committee.clone(),
                pkCommitment: self.authority.pkCommitment,
                proof: Bytes::from((Bytes::from(vec![1]), self.fields.clone()).abi_encode_params()),
            },
        )
    }

    fn authority(&self) -> EvmLogObserved {
        self.raw(
            "SynchronizedDkgAuthorityPublished",
            &ISynchronizedDkgPublication::SynchronizedDkgAuthorityPublished {
                e3Id: self.request.e3_id.clone().try_into().unwrap(),
                authority: self.authority.clone(),
            },
        )
    }

    fn facts(&self) -> [InterfoldEventData; 4] {
        [
            self.request.clone().into(),
            self.context.clone().into(),
            self.proof().into(),
            self.authority().into(),
        ]
    }

    fn projection(&self) -> (CanonicalPublicKeys, CanonicalKeyProjection) {
        let keys = CanonicalPublicKeys::default();
        let projection =
            CanonicalKeyProjection::new(keys.clone(), HashMap::from([(1, self.interfold)]));
        (keys, projection)
    }
}

#[test]
fn synchronized_authority_waits_for_all_confirmed_prerequisites() -> Result<()> {
    let f = Fixture::new()?;
    let id = &f.request.e3_id;
    // The request precedes its publication in the chain journal. Context and authority joins must
    // also work when the independently delivered proof/byte observations arrive first.
    for order in [[1, 0, 2, 3], [0, 1, 3, 2], [0, 2, 3, 1], [0, 3, 2, 1]] {
        let (keys, mut projection) = f.projection();
        for (step, index) in order.into_iter().enumerate() {
            projection.observe(&event(
                f.facts()[index].clone(),
                EventSource::Evm,
                Some(index as u64 + 1),
            ))?;
            assert_eq!(keys.get(id).is_some(), step == 3);
        }
        let key = keys.get(id).unwrap();
        assert_eq!(key.committee, f.committee);
        assert_eq!(key.honest_committee, vec![f.committee[0], f.committee[2]]);
        let CanonicalDkgAnchors::Synchronized(authority) = &key.dkg_anchors else {
            panic!()
        };
        assert_eq!(authority.key_bundle_commits, vec![[7; 32], [8; 32]]);
        for data in f.facts() {
            projection.observe(&event(data, EventSource::Evm, Some(5)))?;
        }
        assert_eq!(keys.get(id), Some(key));
        assert!(!BfvProfile::SyncDecInsecure64.admission_enabled());
    }
    Ok(())
}

#[actix::test]
async fn unsupported_synchronized_versions_fail_live_pipeline_as_well_as_recovery() -> Result<()> {
    use e3_event_system::EventSystem;
    use std::time::Duration;
    for context_version in [true, false] {
        let mut f = Fixture::new()?;
        f.context.schema_version += 1;
        f.authority.version += 1;
        let data: InterfoldEventData = if context_version {
            f.context.clone().into()
        } else {
            f.authority().into()
        };
        let (_, mut replay) = f.projection();
        assert!(replay
            .observe(&event(data.clone(), EventSource::Evm, Some(1)))
            .is_err());

        let system = EventSystem::new().with_fresh_bus().with_aggregate_config(
            e3_events::AggregateConfig::new(HashMap::from([(AggregateId::new(1), Duration::ZERO)])),
        );
        let mut failure = system.failure_receiver();
        let bus = system.handle()?.enable("unsupported-authority");
        let (keys, projection) = f.projection();
        projection.attach(&bus).await?;
        bus.publish_from_remote(data.clone(), 1, Some(1), EventSource::Evm)?;
        actix::clock::timeout(Duration::from_secs(2), failure.changed()).await??;
        assert!(failure
            .borrow()
            .as_ref()
            .unwrap()
            .contains("unsupported synchronized"));
        assert!(keys.get(&f.request.e3_id).is_none());
        assert!(bus
            .publish_from_remote(data, 2, Some(2), EventSource::Evm)
            .is_err());
        bus.publish_shutdown_and_wait().await?;
    }
    Ok(())
}

#[test]
fn local_peer_unconfirmed_and_wrong_contract_facts_cannot_supply_sync_authority() -> Result<()> {
    let f = Fixture::new()?;
    for missing in 0..4 {
        for (source, block) in [
            (EventSource::Local, Some(1)),
            (EventSource::Net, Some(1)),
            (EventSource::Evm, None),
        ] {
            let (keys, mut projection) = f.projection();
            let facts = f.facts();
            projection.observe(&event(facts[missing].clone(), source, block))?;
            for (index, data) in facts
                .into_iter()
                .enumerate()
                .filter(|(index, _)| *index != missing)
            {
                projection.observe(&event(data, EventSource::Evm, Some(index as u64 + 1)))?;
            }
            assert!(keys.get(&f.request.e3_id).is_none());
        }
    }
    for is_proof in [true, false] {
        let (keys, mut projection) = f.projection();
        projection.observe(&event(f.request.clone(), EventSource::Evm, Some(1)))?;
        projection.observe(&event(f.context.clone(), EventSource::Evm, Some(1)))?;
        let mut wrong = if is_proof { f.proof() } else { f.authority() };
        wrong.contract = "Interfold".into();
        projection.observe(&event(wrong, EventSource::Evm, Some(2)))?;
        projection.observe(&event(
            if is_proof { f.authority() } else { f.proof() },
            EventSource::Evm,
            Some(2),
        ))?;
        assert!(keys.get(&f.request.e3_id).is_none());
    }
    let keys = CanonicalPublicKeys::default();
    let mut projection = CanonicalKeyProjection::new(keys.clone(), HashMap::new());
    for data in f.facts() {
        projection.observe(&event(data, EventSource::Evm, Some(1)))?;
    }
    assert!(keys.synchronized_context(&f.request.e3_id).is_none());
    Ok(())
}

#[test]
fn confirmed_sync_facts_are_immutable_and_proof_rows_must_match_authority() -> Result<()> {
    let f = Fixture::new()?;
    let (keys, mut projection) = f.projection();
    for data in f.facts() {
        projection.observe(&event(data, EventSource::Evm, Some(1)))?;
    }
    let original = keys.get(&f.request.e3_id);
    let mut changed = f.context.clone();
    changed.context.verifying_contract = Address::repeat_byte(6);
    assert!(projection
        .observe(&event(changed, EventSource::Evm, Some(2)))
        .is_err());
    let mut changed = f.request.clone();
    changed.request_block += 1;
    assert!(projection
        .observe(&event(changed, EventSource::Evm, Some(2)))
        .is_err());
    for change_authority in [true, false] {
        let mut changed = Fixture::new()?;
        // Use the same native PK; only change one joined fact, not random setup generation.
        changed.authority = f.authority.clone();
        changed.fields = f.fields.clone();
        if change_authority {
            changed.authority.keyBundleCommits[0] = B256::repeat_byte(9);
        } else {
            changed.fields[7] = B256::repeat_byte(9);
        }
        let data = if change_authority {
            changed.authority()
        } else {
            changed.proof()
        };
        assert!(projection
            .observe(&event(data.clone(), EventSource::Evm, Some(2)))
            .is_err());
        let (fresh_keys, mut fresh) = f.projection();
        fresh.observe(&event(f.request.clone(), EventSource::Evm, Some(1)))?;
        fresh.observe(&event(f.context.clone(), EventSource::Evm, Some(1)))?;
        fresh.observe(&event(data, EventSource::Evm, Some(2)))?;
        assert!(fresh
            .observe(&event(
                if change_authority {
                    f.proof()
                } else {
                    f.authority()
                },
                EventSource::Evm,
                Some(2)
            ))
            .is_err());
        assert!(fresh_keys.get(&f.request.e3_id).is_none());
    }
    assert_eq!(keys.get(&f.request.e3_id), original);
    Ok(())
}

#[actix::test]
async fn full_confirmed_journal_restores_dormant_setup_and_terminal_cleanup() -> Result<()> {
    use e3_event_system::EventSystem;
    use e3_events::{AggregateConfig, EventBusFanout};
    use std::time::Duration;
    let f = Fixture::new()?;
    let aggregate = AggregateId::new(1);
    let system = EventSystem::new()
        .with_fresh_bus()
        .with_aggregate_config(AggregateConfig::new(HashMap::from([(
            aggregate,
            Duration::ZERO,
        )])));
    let bus = system.handle()?.enable("synchronized-authority-history");
    for data in f.facts() {
        bus.publish_from_remote(data, 0, Some(1), EventSource::Evm)?;
    }
    bus.publish_from_remote(
        CommitteePublished {
            e3_id: f.request.e3_id.clone(),
            public_key: f.bytes.clone(),
            nodes: f.committee.iter().map(ToString::to_string).collect(),
            proof: ArcBytes::from_bytes(&[]),
        },
        0,
        Some(2),
        EventSource::Evm,
    )?;
    bus.flush_event_pipeline().await?;
    let (keys, mut projection) = f.projection();
    projection
        .recover(
            &system.eventstore_reader()?.seq(),
            &[aggregate],
            HashSet::new(),
        )
        .await?;
    assert_eq!(keys.public_key(&f.request.e3_id), Some(f.bytes.clone()));
    assert_eq!(
        keys.synchronized_context(&f.request.e3_id),
        Some(f.context.context)
    );
    projection.attach(&bus).await?;
    bus.event_bus()
        .send(EventBusFanout(event(
            E3StageChanged {
                e3_id: f.request.e3_id.clone(),
                previous_stage: E3Stage::CiphertextReady,
                new_stage: E3Stage::Complete,
            },
            EventSource::Evm,
            Some(3),
        )))
        .await??;
    for data in f.facts() {
        bus.event_bus()
            .send(EventBusFanout(event(data, EventSource::Evm, Some(1))))
            .await??;
    }
    assert!(keys.get(&f.request.e3_id).is_none());
    assert!(keys.synchronized_context(&f.request.e3_id).is_none());
    assert!(keys.public_key(&f.request.e3_id).is_none());
    Ok(())
}
