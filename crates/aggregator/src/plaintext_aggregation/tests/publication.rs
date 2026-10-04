// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use crate::{
    ext::{AggregatorRoleExtension, PublicKeyAggregatorExtension},
    DecryptionshareCreatedBuffer, KeyshareCreatedFilterBuffer, PublicKeyAggregator,
    PublicKeyAggregatorParams, PublicKeyAggregatorRecoveryState, PublicKeyAggregatorState,
    PublicKeyRepositoryFactory, TrBfvPlaintextRepositoryFactory,
};
use e3_data::RepositoriesFactory;
use e3_events::{
    CommitteeFinalized, CommitteePublished, E3StageChanged, EventType, OrderedSet,
    PublicKeyAggregated,
};
use e3_fhe::{ext::FHE_KEY, Fhe};
use e3_request::{
    ContextRepositoryFactory, E3Context, E3ContextParams, E3ContextSnapshot, E3Extension,
    E3LifecycleCoordinator, E3LifecycleRepositoryFactory, E3Meta, META_KEY,
};
use std::{sync::Arc, time::Duration};

#[derive(Clone, Copy, Debug)]
enum Publication {
    Stage,
    Committee,
}

impl Publication {
    fn event(self, e3_id: &E3id, committee: &[Address]) -> InterfoldEventData {
        match self {
            Self::Stage => E3StageChanged {
                e3_id: e3_id.clone(),
                previous_stage: E3Stage::CommitteeFinalized,
                new_stage: E3Stage::KeyPublished,
            }
            .into(),
            Self::Committee => CommitteePublished {
                e3_id: e3_id.clone(),
                nodes: committee.iter().map(ToString::to_string).collect(),
                public_key: ArcBytes::from_bytes(&[1, 2, 3]),
                proof: ArcBytes::from_bytes(&[]),
            }
            .into(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Removal {
    Expelled,
    Excluded,
}

impl Removal {
    fn event(self, e3_id: &E3id, node: Address) -> InterfoldEventData {
        match self {
            Self::Expelled => CommitteeMemberExpelled {
                e3_id: e3_id.clone(),
                node,
                reason: [0; 32],
                active_count_after: 18,
                party_id: None,
            }
            .into(),
            Self::Excluded => CommitteeMemberExcluded {
                e3_id: e3_id.clone(),
                node,
                proof_type: ProofType::C6ThresholdShareDecryption,
                party_id: None,
            }
            .into(),
        }
    }
}

async fn published_key_keeps_decryption(active: bool, restart: bool) -> Result<()> {
    let e3_id = E3id::new("42", 1);
    let mut signer_ids: Vec<u64> = (0..19).collect();
    signer_ids.sort_by_key(|party| test_signer(*party).address());
    let committee: Vec<_> = signer_ids
        .iter()
        .map(|party| test_signer(*party).address())
        .collect();
    let shares: Vec<_> = signer_ids
        .iter()
        .take(10)
        .enumerate()
        .map(|(party, signer_id)| {
            let (decryption_share, signed_decryption_proofs) =
                share_with_matching_commitment(&e3_id, *signer_id, &test_ciphertexts()[..1]);
            DecryptionshareCreated {
                e3_id: e3_id.clone(),
                party_id: party as u64,
                node: committee[party].to_string(),
                decryption_share,
                signed_decryption_proofs,
            }
        })
        .collect();
    for publication in [Publication::Stage, Publication::Committee] {
        for removal in [Removal::Expelled, Removal::Excluded] {
            let (bus, rng, seed, params, crp, errors, history) =
                get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
            let store = DataStore::from_in_mem(&InMemStore::new(false).start());
            let repositories = store.repositories();
            let publickey_repositories = repositories.context(&e3_id).repositories();
            let _lifecycle = E3LifecycleCoordinator::attach(&bus, store.clone()).await?;
            let honest = committee[..14].to_vec();
            let canonical_party_nodes = committee
                .iter()
                .enumerate()
                .map(|(party, node)| (party as u64, node.to_string()))
                .collect();
            let state = if active {
                PublicKeyAggregatorState::Complete {
                    public_key: ArcBytes::from_bytes(&[1, 2, 3]),
                    keyshares: OrderedSet::new(),
                    nodes: OrderedSet::new(),
                    committee_addresses: committee.clone(),
                    honest_committee_addresses: honest.clone(),
                }
            } else {
                PublicKeyAggregatorState::VerifyingC1 {
                    submission_order: honest
                        .iter()
                        .enumerate()
                        .map(|(party, node)| {
                            (party as u64, node.to_string(), ArcBytes::from_bytes(&[1]))
                        })
                        .collect(),
                    threshold_m: 9,
                    circuit_committee_n: 19,
                    circuit_committee_h: 14,
                    c1_proofs: vec![None; 14],
                    no_proof_parties: Vec::new(),
                    canonical_party_nodes,
                }
            };
            publickey_repositories
                .publickey(&e3_id)
                .write_sync(&state)
                .await?;
            publickey_repositories
                .publickey_recovery(&e3_id)
                .write_sync(&PublicKeyAggregatorRecoveryState {
                    selected_roster: Some((0..14).collect()),
                    pending_publication: active.then(|| PublicKeyAggregated {
                        e3_id: e3_id.clone(),
                        pubkey: ArcBytes::from_bytes(&[1, 2, 3]),
                        nodes: OrderedSet::new(),
                        committee_addresses: committee.clone(),
                        honest_committee_addresses: honest.clone(),
                        pk_commitment: [0; 32],
                        dkg_aggregator_proof: None,
                        dkg_attestation_bundle: None,
                    }),
                    ..Default::default()
                })
                .await?;
            let fhe = Arc::new(Fhe::new(params, crp, rng));
            let publickey = PublicKeyAggregator::new(
                PublicKeyAggregatorParams {
                    fhe: fhe.clone(),
                    bus: bus.clone(),
                    e3_id: e3_id.clone(),
                    params_preset: BfvPreset::InsecureThreshold512,
                    committee_size: CiphernodesCommitteeSize::Small,
                    dkg_fold_attestation_context: None,
                    recovery: publickey_repositories
                        .publickey_recovery(&e3_id)
                        .load()
                        .await?,
                    initial_is_aggregator: active,
                    initial_stage: E3Stage::CommitteeFinalized,
                    effects_enabled: true,
                },
                publickey_repositories.publickey(&e3_id).load().await?,
            )
            .start();
            let buffer = KeyshareCreatedFilterBuffer::new(publickey.clone()).start();
            bus.subscribe_all(&[EventType::All], buffer.clone().recipient());

            bus.publish_without_context(publication.event(&e3_id, &committee))?;
            bus.flush_event_pipeline().await?;
            if restart {
                // Stop the live actor. Hydration must recover publication without event replay.
                publickey.send(Die).await?;
                buffer.send(Die).await?;
                let mut ctx = E3Context::from_params(E3ContextParams {
                    repository: repositories.context(&e3_id),
                    e3_id: e3_id.clone(),
                    extensions: Arc::new(Vec::new()),
                });
                ctx.set_dependency(FHE_KEY, fhe);
                ctx.set_dependency(
                    META_KEY,
                    E3Meta {
                        threshold_m: 9,
                        threshold_n: 19,
                        seed,
                        params_preset: BfvPreset::InsecureThreshold512,
                        params: test_params(),
                        error_size: ArcBytes::from_bytes(&[]),
                    },
                );
                let snapshot = E3ContextSnapshot {
                    e3_id: e3_id.clone(),
                    recipients: vec!["publickey".into()],
                    dependencies: Vec::new(),
                };
                AggregatorRoleExtension::create(HashMap::from([(e3_id.clone(), active)]))
                    .hydrate(&mut ctx, &snapshot)
                    .await?;
                PublicKeyAggregatorExtension::create(&bus)
                    .hydrate(&mut ctx, &snapshot)
                    .await?;
                bus.subscribe_all(
                    &[EventType::All],
                    ctx.get_event_recipient("publickey").unwrap().clone(),
                );
            }

            let sortition = start_sortition(&bus);
            bus.subscribe_all(
                &[
                    EventType::CommitteeFinalized,
                    EventType::CommitteeMemberExpelled,
                    EventType::CommitteeMemberExcluded,
                    EventType::EffectsEnabled,
                ],
                sortition.clone().recipient(),
            );
            let plaintext_repo = repositories.trbfv_plaintext(&e3_id);
            let plaintext = ThresholdPlaintextAggregator::new(
                ThresholdPlaintextAggregatorParams {
                    bus: bus.clone(),
                    sortition,
                    e3_id: e3_id.clone(),
                    params_preset: BfvPreset::InsecureThreshold512,
                    committee_size: CiphernodesCommitteeSize::Small,
                    proof_aggregation_enabled: true,
                    initial_is_aggregator: active,
                    effects_enabled: true,
                    committee_addresses: committee.clone(),
                    honest_committee_addresses: honest,
                    decryption_domain: test_decryption_domain(),
                    recovery: repositories
                        .trbfv_plaintext_recovery(&e3_id)
                        .send(Some(ThresholdPlaintextAggregatorRecoveryState::default())),
                },
                plaintext_repo.send(Some(ThresholdPlaintextAggregatorState::init(
                    9,
                    19,
                    seed,
                    test_ciphertexts()[..1].to_vec(),
                    test_params(),
                ))),
            )
            .start();
            let plaintext_buffer = DecryptionshareCreatedBuffer::new(plaintext.clone()).start();
            bus.subscribe_all(&[EventType::All], plaintext_buffer.recipient());
            bus.publish_without_context(CommitteeFinalized {
                e3_id: e3_id.clone(),
                committee: committee.iter().map(ToString::to_string).collect(),
                scores: Vec::new(),
                chain_id: 1,
            })?;
            bus.publish_without_context(EffectsEnabled::new())?;
            bus.publish_without_context(removal.event(&e3_id, committee[13]))?;
            let removal_result = actix::clock::timeout(Duration::from_secs(30), async {
                loop {
                    bus.flush_event_pipeline().await?;
                    if matches!(plaintext_repo.read().await?,
                        Some(ThresholdPlaintextAggregatorState::Collecting(ref state))
                            if state.rejected_parties.contains(&13))
                    {
                        break;
                    }
                    actix::clock::sleep(Duration::from_millis(5)).await;
                }
                anyhow::Ok(())
            })
            .await;
            assert!(
                removal_result.is_ok(),
                "removal was not applied: {:?}; events: {:?}",
                plaintext_repo.read().await?,
                history.send(GetEvents::<InterfoldEvent>::new()).await?
            );
            removal_result??;

            for share in &shares {
                bus.publish_without_context(share.clone())?;
            }
            let batch_result = actix::clock::timeout(Duration::from_secs(60), async {
                loop {
                    if let Some(ThresholdPlaintextAggregatorState::VerifyingC6(batch)) =
                        plaintext_repo.read().await?
                    {
                        break anyhow::Ok(batch);
                    }
                    actix::clock::sleep(Duration::from_millis(5)).await;
                }
            })
            .await;
            assert!(
                batch_result.is_ok(),
                "C6 admission did not finish: {:?}; errors: {:?}",
                plaintext_repo.read().await?.map(|state| match state {
                    ThresholdPlaintextAggregatorState::Collecting(state) =>
                        state.shares.keys().copied().collect::<Vec<_>>(),
                    _ => Vec::new(),
                }),
                errors.send(GetEvents::<InterfoldEvent>::new()).await?
            );
            let batch = batch_result??;
            assert_eq!(
                batch.shares.keys().copied().collect::<Vec<_>>(),
                (0..10).collect::<Vec<_>>()
            );
            assert!(batch.rejected_parties.contains(&13));
            bus.flush_event_pipeline().await?;
            let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
            assert!(
                !events
                    .iter()
                    .any(|event| matches!(event.get_data(), InterfoldEventData::E3Failed(_))),
                "{publication:?}, {removal:?}, active={active}, restart={restart}"
            );
            assert_eq!(
                repositories
                    .e3_lifecycle()
                    .read()
                    .await?
                    .unwrap()
                    .get(&e3_id),
                Some(&E3Stage::KeyPublished)
            );
            assert!(errors
                .send(GetEvents::<InterfoldEvent>::new())
                .await?
                .is_empty());
            if active {
                let dispatched = events
                    .iter()
                    .find(|event| {
                        matches!(event.get_data(),
                    InterfoldEventData::ShareVerificationDispatched(data)
                        if data.kind == VerificationKind::ThresholdDecryptionProofs)
                    })
                    .expect("ten admitted shares must dispatch C6 verification");
                let result = ShareVerificationComplete {
                    e3_id: e3_id.clone(),
                    kind: VerificationKind::ThresholdDecryptionProofs,
                    dishonest_parties: BTreeSet::new(),
                };
                bus.publish(result, dispatched.get_ctx().clone())?;
                actix::clock::timeout(Duration::from_secs(30), async {
                    loop {
                        let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
                        if events.iter().any(|event| matches!(event.get_data(),
                            InterfoldEventData::ComputeRequest(data)
                                if matches!(data.request, ComputeRequestKind::TrBFV(TrBFVRequest::CalculateThresholdDecryption(_))))) {
                            break;
                        }
                        actix::clock::sleep(Duration::from_millis(5)).await;
                    }
                    anyhow::Ok(())
                }).await??;
            }

            // Canonical failures remain authoritative after publication.
            bus.publish_without_context(E3Failed {
                e3_id: e3_id.clone(),
                failed_at_stage: E3Stage::KeyPublished,
                reason: FailureReason::ComputeTimeout,
            })?;
            bus.flush_event_pipeline().await?;
            assert_eq!(
                repositories
                    .e3_lifecycle()
                    .read()
                    .await?
                    .unwrap()
                    .get(&e3_id),
                Some(&E3Stage::Failed)
            );
        }
    }
    Ok(())
}

#[actix::test]
async fn published_key_removal_keeps_active_decryption() -> Result<()> {
    published_key_keeps_decryption(true, false).await
}

#[actix::test]
async fn published_key_removal_keeps_standby_decryption() -> Result<()> {
    published_key_keeps_decryption(false, false).await
}

#[actix::test]
async fn hydrated_published_key_removal_keeps_active_decryption() -> Result<()> {
    published_key_keeps_decryption(true, true).await
}

#[actix::test]
async fn hydrated_published_key_removal_keeps_standby_decryption() -> Result<()> {
    published_key_keeps_decryption(false, true).await
}
