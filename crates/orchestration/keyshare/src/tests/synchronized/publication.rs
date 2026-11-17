// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use crate::synchronized::SynchronizedSetupIntent;
use e3_data::SledStore;
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

pub(super) async fn actor(
    store: &DataStore,
    root: ThresholdKeyshareRecoveryState,
    signer: PrivateKeySigner,
    cipher: Arc<Cipher>,
    interfold: Address,
    keys: CanonicalPublicKeys,
) -> Result<(
    Addr<ThresholdKeyshare>,
    Addr<HistoryCollector<InterfoldEvent>>,
)> {
    let selection = root
        .ciphernode_selected
        .as_ref()
        .context("missing selection")?;
    let e3 = selection.e3_id.clone();
    let (bus, history) = test_bus();
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
        bus,
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
    Ok((actor, history))
}

pub(super) async fn consents(
    history: &Addr<HistoryCollector<InterfoldEvent>>,
) -> Result<Vec<InterfoldEvent>> {
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

fn result(
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
    for mutation in 0..7 {
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
            3 => candidate.setup.threshold_keys.swap(0, 1),
            4 => {
                material.threshold_pk_shares.remove(&2);
            }
            5 => {
                material
                    .threshold_pk_shares
                    .insert(2, setup.pending[1].full_share.pk_share.clone());
            }
            _ => candidate.proof.public_signals = ArcBytes::from_bytes(&[]),
        }
        assert!(intent(material, TypedEvent::new(candidate, ec)).is_err());
    }
    assert!(intent(material, TypedEvent::new(valid, test_ec(30))).is_ok());
    Ok(())
}

#[actix::test]
async fn synchronized_setup_storage_failure_cannot_publish_consent() -> Result<()> {
    struct FailFlush;
    impl Actor for FailFlush {
        type Context = actix::Context<Self>;
    }
    impl Handler<e3_events::Flush> for FailFlush {
        type Result = Result<()>;
        fn handle(&mut self, _: e3_events::Flush, _: &mut Self::Context) -> Self::Result {
            anyhow::bail!("injected setup flush failure")
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
    let store = DataStore::from_in_mem(&InMemStore::new(false).start())
        .with_flush_recipient(FailFlush.start().recipient());
    let (node, history) = actor(
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
        effects: true,
    })
    .await??;
    assert!(node.send(SetupCheckpoint).await?.is_none());
    assert!(consents(&history).await?.is_empty());
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
    let (node, history) = actor(
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
    assert!(consents(&history).await?.is_empty());
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
        let (node, history) = actor(
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
        assert!(consents(&history).await?.is_empty());
        node.send(DriveSetup {
            result: None,
            effects: true,
        })
        .await??;
        node.send(SetupCheckpoint).await?;
        assert!(consents(&history).await?.is_empty());
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
        let before = consents(&history).await?;
        assert_eq!(before.len(), usize::from(owner != 1));
        assert!(saved
            .confirmed_setup(setup.interfold, &keys, &setup.cipher)
            .is_err());
        node.send(Die).await?;
        drop(node);
        store.shutdown().await?;
        drop(store);
        let store = DataStore::from_sled_store(&SledStore::new(&bus, &dir.path().to_path_buf())?);
        let (node, history) = actor(
            &store,
            root,
            setup.signers[owner].clone(),
            setup.cipher.clone(),
            setup.interfold,
            keys.clone(),
        )
        .await?;
        node.send(DriveSetup {
            result: None,
            effects: false,
        })
        .await??;
        assert_eq!(node.send(SetupCheckpoint).await?, Some(saved));
        assert!(consents(&history).await?.is_empty());
        node.send(DriveSetup {
            result: None,
            effects: true,
        })
        .await??;
        node.send(SetupCheckpoint).await?;
        let after = consents(&history).await?;
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
    }
    Ok(())
}
