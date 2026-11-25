// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use crate::synchronized::SynchronizedSetupIntent;
use e3_data::{SledDb, SledStore};
use e3_events::{SynchronizedRecipientProofReady, SynchronizedSetupAnchors};
use e3_polynomial::CrtPolynomial;
use e3_polynomial_fhe::FromFhePolynomial;
use e3_request::canonical_key::CanonicalPublicKeys;
use fhe::mbfv::{Aggregate, PublicKeyShare};

/// Supply an already-admitted collector verdict below disabled admission. Real qualification uses
/// the same actor path with actual recipient proofs; this does not install a production bypass.
#[derive(Message)]
#[rtype(result = "Result<()>")]
pub(super) struct DriveSetup {
    pub result: Option<TypedEvent<SynchronizedRecipientProofReady>>,
    pub effects: bool,
}

impl Handler<DriveSetup> for ThresholdKeyshare {
    type Result = Result<()>;
    fn handle(&mut self, msg: DriveSetup, ctx: &mut Self::Context) -> Self::Result {
        self.effects_enabled = msg.effects;
        if let Some(result) = msg.result {
            self.accept_synchronized_setup_definition(result)?;
        }
        self.drive_synchronized_setup_definition(ctx)
    }
}

#[derive(Message)]
#[rtype(result = "Option<SynchronizedSetupIntent>")]
pub(super) struct SetupCheckpoint;

impl Handler<SetupCheckpoint> for ThresholdKeyshare {
    type Result = actix::MessageResult<SetupCheckpoint>;
    fn handle(&mut self, _: SetupCheckpoint, _: &mut Self::Context) -> Self::Result {
        actix::MessageResult(self.synchronized_setup.clone())
    }
}

#[derive(Message)]
#[rtype(result = "bool")]
struct SetupRetryPending;
impl Handler<SetupRetryPending> for ThresholdKeyshare {
    type Result = bool;
    fn handle(&mut self, _: SetupRetryPending, _: &mut Self::Context) -> Self::Result {
        self.synchronized_setup_retry.is_some()
    }
}

#[derive(Message)]
#[rtype(result = "bool")]
struct SetupStorageBlocked;

impl Handler<SetupStorageBlocked> for ThresholdKeyshare {
    type Result = bool;

    fn handle(&mut self, _: SetupStorageBlocked, _: &mut Self::Context) -> Self::Result {
        self.synchronized_setup_blocked
    }
}

#[derive(Message)]
#[rtype(result = "Result<()>")]
struct SaturateConsent;

impl Handler<SaturateConsent> for ThresholdKeyshare {
    type Result = Result<()>;

    fn handle(&mut self, _: SaturateConsent, ctx: &mut Self::Context) -> Self::Result {
        for _ in 0..e3_utils::MAILBOX_LIMIT_LARGE {
            self.bus.publish_without_context(EffectsEnabled::new())?;
        }
        self.effects_enabled = true;
        self.drive_synchronized_setup_definition(ctx)
    }
}

pub(super) async fn actor(
    store: &DataStore,
    root: ThresholdKeyshareRecoveryState,
    signer: PrivateKeySigner,
    cipher: Arc<Cipher>,
    interfold: Address,
    keys: CanonicalPublicKeys,
) -> Result<(
    Addr<ThresholdKeyshare>,
    BusHandle,
    Addr<HistoryCollector<InterfoldEvent>>,
)> {
    let selection = root
        .ciphernode_selected
        .as_ref()
        .context("missing selection")?;
    let e3 = selection.e3_id.clone();
    // Observe the producer, not the number of events that survived bus deduplication.
    let (bus, history) = test_bus_with_deduplication(false);
    let repos = store.repositories();
    let state = ThresholdKeyshareState::new(
        e3.clone(),
        selection.party_id,
        KeyshareState::Init,
        selection.threshold_m as u64,
        selection.threshold_n as u64,
        selection.params.clone(),
        signer.address().to_string(),
    );
    let actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        state: repos.threshold_keyshare(&e3).send(Some(state)),
        recovery: repos.threshold_keyshare_recovery(&e3).send(Some(root)),
        recovery_payloads: ThresholdKeyshareRecoveryPayloads::new(
            repos.threshold_keyshare_recovery_payloads(&e3),
        ),
        bus: bus.clone(),
        cipher,
        params_profile: PROFILE,
        interfold_address: interfold,
        signer,
        bfv_key: repos.threshold_keyshare_bfv_key(&e3),
        effects_enabled: false,
        dkg_timing_reader: Arc::new(|_| {
            Box::pin(async { anyhow::bail!("no timing effect expected") })
        }),
    })
    .with_canonical_keys(keys)
    .start();
    Ok((actor, bus, history))
}

pub(super) async fn consents(
    bus: &BusHandle,
    history: &Addr<HistoryCollector<InterfoldEvent>>,
) -> Result<Vec<InterfoldEvent>> {
    bus.flush_event_pipeline().await?;
    Ok(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .into_iter()
        .filter(|event| {
            matches!(
                event.get_data(),
                InterfoldEventData::SynchronizedDkgConsentPublished(_)
            )
        })
        .collect())
}

pub(super) fn result(
    setup: &Setup,
    material: &SynchronizedDkgRecovery,
    owner: usize,
) -> Result<SynchronizedRecipientProofReady> {
    let crp = create_deterministic_crp_from_default_seed(&setup.config.threshold);
    let shares = DEALERS
        .iter()
        .map(|&id| {
            PublicKeyShare::deserialize(
                &setup.pending[id as usize].full_share.pk_share,
                &setup.config.threshold,
                crp.clone(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let key = PublicKey::from_shares(shares.clone())?;
    let data = e3_zk_witness::threshold::pk_aggregation::PkAggregationCircuitData {
        public_key: key,
        pk0_shares: shares
            .iter()
            .map(|share| CrtPolynomial::from_fhe_polynomial(share.p0_share()))
            .collect(),
    };
    let input = e3_zk_witness::synchronized::publication::c5(&setup.config, &data)?;
    let anchors = SynchronizedSetupAnchors {
        binding: setup_binding(&material.context, &setup.selected[owner].e3_id)?,
        recipient: owner as u32,
        dealers: vec![0, 2],
        threshold_keys: input
            .expected_threshold_pk_commitments
            .iter()
            .map(commitment_field)
            .collect::<Result<_>>()?,
        dealer_batch: scalar(7)?,
        sk_commitment: material.sk_commitment.unwrap(),
        key_bundle: material.key_bundle.unwrap(),
    };
    let mut fields = vec![
        scalar(1)?,
        scalar(anchors.binding[0])?,
        scalar(anchors.binding[1])?,
        scalar(owner)?,
    ];
    fields.extend(
        anchors
            .dealers
            .iter()
            .map(|&id| scalar(id))
            .collect::<Result<Vec<_>>>()?,
    );
    fields.extend(&anchors.threshold_keys);
    fields.extend([
        anchors.dealer_batch,
        anchors.sk_commitment,
        anchors.key_bundle,
    ]);
    Ok(SynchronizedRecipientProofReady {
        e3_id: setup.selected[owner].e3_id.clone(),
        context: material.context.clone(),
        proof: Proof::new(
            CircuitName::NodesFold,
            ArcBytes::from_bytes(&[1]),
            ArcBytes::from_bytes(&fields.concat()),
        ),
        setup: anchors,
    })
}

#[actix::test]
async fn synchronized_setup_rejects_peer_and_substituted_native_anchors_before_retention(
) -> Result<()> {
    let setup = Setup::new().await?;
    let DecryptionKeyPlan::Proceed {
        synchronized: Some(material),
        ..
    } = setup.plan(0)?
    else {
        unreachable!()
    };
    let valid = result(&setup, &material, 0)?;
    let intent = |material, result| {
        SynchronizedSetupIntent::new(
            setup.selected[0].clone(),
            material,
            result,
            setup.interfold,
            &setup.cipher,
        )
    };
    for (mutation, expected) in [
        "setup intent is not this recipient's local verdict",
        "setup intent is not this recipient's local verdict",
        "verified setup does not match the recovered private material",
        "recipient setup differs from independently retained native PK shares",
        "saved synchronized native PK shares differ from the fixed roster",
        "recipient setup differs from independently retained native PK shares",
        "invalid synchronized public-signal layout",
        "local recipient proof differs from the setup verdict",
    ]
    .into_iter()
    .enumerate()
    {
        let mut material = material.clone();
        let mut candidate = valid.clone();
        let mut ec = test_ec(30);
        match mutation {
            0 => {
                ec = keyshare_event(candidate.clone(), 30, EventSource::Net)
                    .get_ctx()
                    .clone()
            }
            1 => candidate.e3_id = E3id::new("999", 1),
            2 => candidate.setup.key_bundle[31] ^= 1,
            3 => {
                candidate.setup.threshold_keys.swap(0, 1);
                let mut public = candidate.proof.public_signals.to_vec();
                let first = (4 + candidate.setup.dealers.len()) * 32;
                for byte in 0..32 {
                    public.swap(first + byte, first + 32 + byte);
                }
                candidate.proof.public_signals = ArcBytes::from_bytes(&public);
            }
            4 => {
                material.threshold_pk_shares.remove(&2);
            }
            5 => {
                material
                    .threshold_pk_shares
                    .insert(2, setup.pending[1].full_share.pk_share.clone());
            }
            6 => candidate.proof.public_signals = ArcBytes::from_bytes(&[]),
            _ => candidate.setup.dealer_batch[31] ^= 1,
        }
        let error = intent(material, TypedEvent::new(candidate, ec)).unwrap_err();
        assert!(
            error.to_string().contains(expected),
            "mutation {mutation}: {error:#}"
        );
    }
    assert!(intent(material, TypedEvent::new(valid, test_ec(30))).is_ok());
    Ok(())
}

#[actix::test]
async fn closed_setup_storage_is_not_corruption_and_is_ignored_at_shutdown() -> Result<()> {
    let setup = Setup::new().await?;
    for shutdown in [false, true] {
        let store = DataStore::from_in_mem(&InMemStore::new(false).start());
        let (node, bus, history) = actor(
            &store,
            ThresholdKeyshareRecoveryState {
                ciphernode_selected: Some(TypedEvent::new(setup.selected[0].clone(), test_ec(1))),
                ..Default::default()
            },
            setup.signers[0].clone(),
            setup.cipher.clone(),
            setup.interfold,
            CanonicalPublicKeys::default(),
        )
        .await?;
        // Close the setup store only after the actor's separate BFV-key startup read completes.
        assert!(!node.send(SetupStorageBlocked).await?);
        if shutdown {
            bus.publish_shutdown_and_wait()
                .await
                .context("fixture did not observe bus shutdown")?;
        }
        store.shutdown().await?;
        for _ in 0..2 {
            node.send(DriveSetup {
                result: None,
                effects: true,
            })
            .await
            .context("drive closed setup store")??;
            assert!(!node
                .send(SetupRetryPending)
                .await
                .context("check setup retry")?);
            assert_eq!(
                node.send(SetupStorageBlocked)
                    .await
                    .context("check setup block")?,
                !shutdown
            );
        }
        bus.flush_event_pipeline().await?;
        let events = history
            .send(GetEvents::<InterfoldEvent>::new())
            .await
            .context("read setup diagnostics")?;
        let errors: Vec<_> = events
            .iter()
            .filter_map(|event| match event.get_data() {
                InterfoldEventData::InterfoldError(error) => Some(error),
                _ => None,
            })
            .collect();
        assert_eq!(errors.len(), usize::from(!shutdown));
        if !shutdown {
            let error = errors[0];
            assert!(
                error.message.contains("setup storage is closed"),
                "{}",
                error.message
            );
            assert!(!error.message.contains("operator repair"));
        }
        node.send(Die).await.context("stop setup fixture")?;
    }
    Ok(())
}

#[actix::test]
async fn synchronized_setup_permanent_saved_errors_are_reported_once_without_redrive() -> Result<()>
{
    tokio::time::pause();
    let setup = Setup::new().await?;
    let DecryptionKeyPlan::Proceed {
        synchronized: Some(material),
        ..
    } = setup.plan(0)?
    else {
        unreachable!()
    };
    let intent = SynchronizedSetupIntent::new(
        setup.selected[0].clone(),
        material.clone(),
        TypedEvent::new(result(&setup, &material, 0)?, test_ec(30)),
        setup.interfold,
        &setup.cipher,
    )?;
    for malformed_bytes in [true, false] {
        let store = DataStore::from_in_mem(&InMemStore::new(false).start());
        let row = store
            .repositories()
            .threshold_keyshare_recovery_payloads(&setup.selected[0].e3_id)
            .scope("synchronized-setup");
        if malformed_bytes {
            row.write_sync([1_u8]).await?;
        } else {
            let mut encoded = bincode::serialize(&intent)?;
            assert_eq!(encoded[0], 1); // the durable intent's version byte
            encoded[0] = 2;
            row.write_sync(e3_utils::deserialize_exact::<SynchronizedSetupIntent>(
                &encoded,
            )?)
            .await?;
        }
        let (node, bus, history) = actor(
            &store,
            ThresholdKeyshareRecoveryState {
                ciphernode_selected: Some(TypedEvent::new(setup.selected[0].clone(), test_ec(1))),
                synchronized: Some(material.clone()),
                ..Default::default()
            },
            setup.signers[0].clone(),
            setup.cipher.clone(),
            setup.interfold,
            CanonicalPublicKeys::default(),
        )
        .await?;
        for seconds in [0, 2, 8, 40] {
            tokio::time::advance(std::time::Duration::from_secs(seconds)).await;
            node.send(DriveSetup {
                result: None,
                effects: true,
            })
            .await??;
            assert!(node.send(SetupCheckpoint).await?.is_none());
            assert!(
                !node.send(SetupRetryPending).await?,
                "malformed bytes: {malformed_bytes}"
            );
        }
        bus.flush_event_pipeline().await?;
        let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
        let errors = events
            .iter()
            .filter_map(|event| match event.get_data() {
                InterfoldEventData::InterfoldError(error) => Some(error.message.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(errors.len(), 1, "malformed bytes: {malformed_bytes}");
        assert!(errors[0].contains("saved setup cannot be decoded or validated"));
        assert!(consents(&bus, &history).await?.is_empty());
        node.send(Die).await?;
    }
    Ok(())
}

#[actix::test]
async fn refused_consent_retries_only_until_publication_or_shutdown() -> Result<()> {
    use std::time::Duration;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum AfterRefusal {
        Drain,
        KeyPublished,
        Shutdown,
    }

    tokio::time::pause();
    let setup = Setup::new().await?;
    let DecryptionKeyPlan::Proceed {
        synchronized: Some(material),
        ..
    } = setup.plan(0)?
    else {
        unreachable!()
    };
    let verdict = result(&setup, &material, 0)?;
    let id = verdict.e3_id.clone();
    let root = ThresholdKeyshareRecoveryState {
        ciphernode_selected: Some(TypedEvent::new(setup.selected[0].clone(), test_ec(1))),
        synchronized: Some(material),
        ..Default::default()
    };
    for after in [
        AfterRefusal::Drain,
        AfterRefusal::KeyPublished,
        AfterRefusal::Shutdown,
    ] {
        let keys = CanonicalPublicKeys::default();
        keys.remember_synchronized_context(
            id.clone(),
            e3_events::SynchronizedDkgContext {
                registry: Address::repeat_byte(1),
                verifying_contract: Address::repeat_byte(2),
                crypto_config_id: setup.selected[0].crypto_config_id,
            },
        )?;
        let store = DataStore::from_in_mem(&InMemStore::new(false).start());
        let (node, bus, _) = actor(
            &store,
            root.clone(),
            setup.signers[0].clone(),
            setup.cipher.clone(),
            setup.interfold,
            keys,
        )
        .await?;
        let history = HistoryCollector::<InterfoldEvent>::new().start();
        bus.event_bus()
            .send(e3_events::Subscribe::new(
                EventType::SynchronizedDkgConsentPublished,
                history.clone().recipient(),
            ))
            .await?;
        let ec = test_ec(30);
        node.send(DriveSetup {
            result: Some(TypedEvent::new(verdict.clone(), ec.clone())),
            effects: false,
        })
        .await??;
        let saved = node.send(SetupCheckpoint).await?.context("missing setup")?;
        node.send(SaturateConsent).await??;
        assert!(node.send(SetupRetryPending).await?);
        assert!(consents(&bus, &history).await?.is_empty());
        match after {
            AfterRefusal::KeyPublished => {
                node.send(keyshare_event(
                    E3StageChanged {
                        e3_id: id.clone(),
                        previous_stage: E3Stage::CommitteeFinalized,
                        new_stage: E3Stage::KeyPublished,
                    },
                    40,
                    EventSource::Evm,
                ))
                .await?;
            }
            AfterRefusal::Shutdown => {
                bus.publish_shutdown_and_wait().await?;
            }
            AfterRefusal::Drain => {
                let received = history
                    .send(TakeEvents::<InterfoldEvent>::with_per_evt_timeout(
                        1,
                        Duration::from_secs(5),
                    ))
                    .await?;
                assert!(!received.timed_out, "no automatic consent delivery");
                assert_eq!(received.events[0].get_ctx().causation_id(), ec.id());
                node.send(DriveSetup {
                    result: None,
                    effects: true,
                })
                .await??;
            }
        }
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(node.send(SetupCheckpoint).await?, Some(saved));
        assert!(!node.send(SetupRetryPending).await?);
        assert_eq!(
            consents(&bus, &history).await?.len(),
            usize::from(after == AfterRefusal::Drain)
        );
        node.send(Die).await?;
    }
    Ok(())
}

#[actix::test]
async fn synchronized_setup_flush_recovery_publishes_one_consent_without_new_input() -> Result<()> {
    use std::time::Duration;
    use tokio::sync::mpsc;

    tokio::time::pause();
    struct FailFlush {
        recovered: bool,
        attempts: u32,
        observed: mpsc::UnboundedSender<u32>,
    }
    impl Actor for FailFlush {
        type Context = actix::Context<Self>;
    }
    impl Handler<e3_events::Flush> for FailFlush {
        type Result = Result<()>;
        fn handle(&mut self, _: e3_events::Flush, _: &mut Self::Context) -> Self::Result {
            self.attempts += 1;
            let _ = self.observed.send(self.attempts);
            ensure!(
                self.recovered,
                "injected setup flush failure {}",
                self.attempts
            );
            Ok(())
        }
    }
    #[derive(Message)]
    #[rtype(result = "u32")]
    struct FlushAttempts;
    impl Handler<FlushAttempts> for FailFlush {
        type Result = u32;
        fn handle(&mut self, _: FlushAttempts, _: &mut Self::Context) -> Self::Result {
            self.attempts
        }
    }
    #[derive(Message)]
    #[rtype(result = "()")]
    struct RecoverFlush;
    impl Handler<RecoverFlush> for FailFlush {
        type Result = ();
        fn handle(&mut self, _: RecoverFlush, _: &mut Self::Context) {
            self.recovered = true;
        }
    }
    let setup = Setup::new().await?;
    let DecryptionKeyPlan::Proceed {
        synchronized: Some(material),
        ..
    } = setup.plan(0)?
    else {
        unreachable!()
    };
    let verdict = result(&setup, &material, 0)?;
    let keys = CanonicalPublicKeys::default();
    keys.remember_synchronized_context(
        setup.selected[0].e3_id.clone(),
        e3_events::SynchronizedDkgContext {
            registry: Address::repeat_byte(1),
            verifying_contract: Address::repeat_byte(2),
            crypto_config_id: setup.selected[0].crypto_config_id,
        },
    )?;
    let root = ThresholdKeyshareRecoveryState {
        ciphernode_selected: Some(TypedEvent::new(setup.selected[0].clone(), test_ec(1))),
        synchronized: Some(material),
        ..Default::default()
    };
    let (notify, mut observed) = mpsc::unbounded_channel();
    let flush = FailFlush {
        recovered: false,
        attempts: 0,
        observed: notify,
    }
    .start();
    let store = DataStore::from_in_mem(&InMemStore::new(false).start())
        .with_flush_recipient(flush.clone().recipient());
    let (node, bus, history) = actor(
        &store,
        root,
        setup.signers[0].clone(),
        setup.cipher.clone(),
        setup.interfold,
        keys,
    )
    .await?;
    node.send(DriveSetup {
        result: Some(TypedEvent::new(verdict.clone(), test_ec(30))),
        effects: true,
    })
    .await??;
    assert!(node.send(SetupCheckpoint).await?.is_none());
    assert!(consents(&bus, &history).await?.is_empty());
    assert_eq!(observed.try_recv()?, 1);
    node.send(DriveSetup {
        result: None,
        effects: true,
    })
    .await??;
    assert!(node.send(SetupCheckpoint).await?.is_none());
    assert_eq!(
        flush.send(FlushAttempts).await?,
        1,
        "an intervening drive must not retry storage before the backoff expires"
    );
    for (millis, expected, expect_retry) in [(1101, 2, true), (1000, 2, false), (1201, 3, true)] {
        tokio::time::advance(Duration::from_millis(millis)).await;
        if expect_retry {
            let attempt = tokio::time::timeout(Duration::from_millis(500), observed.recv())
                .await
                .context("flush retry did not run after its deadline")?;
            assert_eq!(attempt, Some(expected));
        }
        assert!(node.send(SetupCheckpoint).await?.is_none());
        assert_eq!(flush.send(FlushAttempts).await?, expected);
        assert!(consents(&bus, &history).await?.is_empty());
    }
    bus.flush_event_pipeline().await?;
    let errors = history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .into_iter()
        .filter(|event| matches!(event.get_data(), InterfoldEventData::InterfoldError(_)))
        .count();
    assert_eq!(errors, 1);
    flush.send(RecoverFlush).await?;
    tokio::time::advance(std::time::Duration::from_secs(5)).await;
    let consent = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let next = history
                .send(TakeEvents::<InterfoldEvent>::with_per_evt_timeout(
                    1,
                    std::time::Duration::from_secs(5),
                ))
                .await?;
            let Some(event) = next.events.into_iter().next() else {
                anyhow::bail!("setup flush recovery did not publish consent");
            };
            if let InterfoldEventData::SynchronizedDkgConsentPublished(consent) = event.get_data() {
                break Ok::<_, anyhow::Error>(consent.clone());
            }
        }
    })
    .await
    .context("setup flush recovery did not publish consent")??;
    assert_eq!(
        consent.attestation.recover_address()?,
        setup.signers[0].address()
    );
    let saved = node
        .send(SetupCheckpoint)
        .await?
        .context("missing durable setup after retry")?;
    assert_eq!(**saved.result(), verdict);
    let extra = history
        .send(TakeEvents::<InterfoldEvent>::with_per_evt_timeout(
            1,
            std::time::Duration::from_secs(2),
        ))
        .await?;
    assert!(extra.timed_out && extra.events.is_empty());
    assert_eq!(consents(&bus, &history).await?.len(), 1);
    node.send(Die).await?;
    Ok(())
}

#[actix::test]
async fn synchronized_confirmed_publication_suppresses_consent_until_terminal_cleanup() -> Result<()>
{
    let setup = Setup::new().await?;
    let DecryptionKeyPlan::Proceed {
        synchronized: Some(material),
        ..
    } = setup.plan(0)?
    else {
        unreachable!()
    };
    let verdict = result(&setup, &material, 0)?;
    let id = verdict.e3_id.clone();
    let root = ThresholdKeyshareRecoveryState {
        ciphernode_selected: Some(TypedEvent::new(setup.selected[0].clone(), test_ec(1))),
        synchronized: Some(material),
        ..Default::default()
    };
    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    let keys = CanonicalPublicKeys::default();
    keys.remember_synchronized_context(
        id.clone(),
        e3_events::SynchronizedDkgContext {
            registry: Address::repeat_byte(1),
            verifying_contract: Address::repeat_byte(2),
            crypto_config_id: setup.selected[0].crypto_config_id,
        },
    )?;
    let record = ThresholdKeyshareRecoveryPayloads::new(
        store
            .repositories()
            .threshold_keyshare_recovery_payloads(&id),
    )
    .synchronized_setup();
    let (node, bus, history) = actor(
        &store,
        root,
        setup.signers[0].clone(),
        setup.cipher.clone(),
        setup.interfold,
        keys,
    )
    .await?;
    node.send(DriveSetup {
        result: Some(TypedEvent::new(verdict, test_ec(30))),
        effects: false,
    })
    .await??;
    assert!(node.send(SetupCheckpoint).await?.is_some());
    node.send(keyshare_event(
        e3_events::E3StageChanged {
            e3_id: id.clone(),
            previous_stage: E3Stage::CommitteeFinalized,
            new_stage: E3Stage::KeyPublished,
        },
        40,
        EventSource::Evm,
    ))
    .await?;
    node.send(DriveSetup {
        result: None,
        effects: true,
    })
    .await??;
    assert!(node.send(SetupCheckpoint).await?.is_some());
    assert!(record.restore().await?.is_some());
    assert!(consents(&bus, &history).await?.is_empty());
    node.send(keyshare_event(
        E3RequestComplete { e3_id: id },
        50,
        EventSource::Evm,
    ))
    .await?;
    // Terminal cleanup completes before the waiting mailbox can process another message.
    assert!(node.send(SetupCheckpoint).await.is_err());
    assert!(record.restore().await?.is_none());
    Ok(())
}

#[actix::test]
async fn synchronized_consent_waits_for_context_and_effects_then_reopens_exact_intent() -> Result<()>
{
    let _exclusive = super::recovery::DISK_RECOVERY.lock().await;
    let setup = Setup::new().await?;
    for owner in 0..3 {
        let DecryptionKeyPlan::Proceed {
            synchronized: Some(material),
            ..
        } = setup.plan(owner)?
        else {
            unreachable!()
        };
        let verdict = result(&setup, &material, owner)?;
        let root = ThresholdKeyshareRecoveryState {
            ciphernode_selected: Some(TypedEvent::new(setup.selected[owner].clone(), test_ec(1))),
            synchronized: Some(material),
            ..Default::default()
        };
        let dir = tempfile::tempdir()?;
        let (bus, _) = test_bus();
        let store = DataStore::from_sled_store(&SledStore::new(&bus, &dir.path().to_path_buf())?);
        let keys = CanonicalPublicKeys::default();
        let (node, setup_bus, history) = actor(
            &store,
            root.clone(),
            setup.signers[owner].clone(),
            setup.cipher.clone(),
            setup.interfold,
            keys.clone(),
        )
        .await?;
        let peer = TypedEvent::new(
            verdict.clone(),
            keyshare_event(verdict.clone(), 30, EventSource::Net)
                .get_ctx()
                .clone(),
        );
        assert!(node
            .send(DriveSetup {
                result: Some(peer),
                effects: false
            })
            .await?
            .is_err());
        assert!(node.send(SetupCheckpoint).await?.is_none());
        // The public route remains disabled even for an otherwise valid local verdict.
        node.send(keyshare_event(verdict.clone(), 30, EventSource::Local))
            .await?;
        assert!(node.send(SetupCheckpoint).await?.is_none());
        node.send(DriveSetup {
            result: Some(TypedEvent::new(verdict, test_ec(30))),
            effects: false,
        })
        .await??;
        let saved = node
            .send(SetupCheckpoint)
            .await?
            .context("missing durable setup")?;
        assert!(consents(&setup_bus, &history).await?.is_empty());
        node.send(DriveSetup {
            result: None,
            effects: true,
        })
        .await??;
        node.send(SetupCheckpoint).await?;
        assert!(consents(&setup_bus, &history).await?.is_empty());
        keys.remember_synchronized_context(
            setup.selected[owner].e3_id.clone(),
            e3_events::SynchronizedDkgContext {
                registry: Address::repeat_byte(1),
                verifying_contract: Address::repeat_byte(2),
                crypto_config_id: setup.selected[owner].crypto_config_id,
            },
        )?;
        node.send(DriveSetup {
            result: None,
            effects: true,
        })
        .await??;
        node.send(SetupCheckpoint).await?;
        let before = consents(&setup_bus, &history).await?;
        assert_eq!(before.len(), usize::from(owner != 1));
        assert!(saved
            .confirmed_setup(setup.interfold, &keys, &setup.cipher)
            .is_err());
        node.send(Die).await?;
        drop(node);
        store.shutdown().await?;
        drop(store);
        SledDb::close_all_connections();
        let store = DataStore::from_sled_store(&SledStore::new(&bus, &dir.path().to_path_buf())?);
        let (node, setup_bus, history) = actor(
            &store,
            root,
            setup.signers[owner].clone(),
            setup.cipher.clone(),
            setup.interfold,
            keys.clone(),
        )
        .await?;
        let mut stale = (**saved.result()).clone();
        stale.proof.data = ArcBytes::from_bytes(&[88]);
        if owner == 1 {
            stale.setup.key_bundle[31] ^= 1;
        }
        node.send(DriveSetup {
            result: Some(TypedEvent::new(stale, test_ec(31))),
            effects: false,
        })
        .await??;
        assert_eq!(node.send(SetupCheckpoint).await?, Some(saved));
        assert!(consents(&setup_bus, &history).await?.is_empty());
        node.send(DriveSetup {
            result: None,
            effects: true,
        })
        .await??;
        node.send(SetupCheckpoint).await?;
        let after = consents(&setup_bus, &history).await?;
        assert_eq!(after.len(), before.len());
        if owner != 1 {
            assert_eq!(after[0].get_data(), before[0].get_data());
            assert_eq!(after[0].event_id(), before[0].event_id());
            assert_eq!(
                after[0].get_ctx().causation_id(),
                before[0].get_ctx().causation_id()
            );
        }
        node.send(Die).await?;
        drop(node);
        store.shutdown().await?;
        drop(store);
        SledDb::close_all_connections();
    }
    Ok(())
}
