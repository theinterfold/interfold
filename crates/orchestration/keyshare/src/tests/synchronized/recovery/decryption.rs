// SPDX-License-Identifier: LGPL-3.0-only

//! Continue the same signed registry publication and reopened private actor inputs through C6,
//! standby promotion, the durable local plaintext intent and real request-bound EVM verification.
use super::*;
use crate::synchronized::SynchronizedSetupIntent;
use alloy::{providers::ext::AnvilApi, sol_types::SolEvent};
use e3_aggregator::synchronized_plaintext::FixedSetPlaintext;
use e3_events::{DecryptionshareCreated, PlaintextAggregated};
use e3_evm_contracts::IInterfold;
use e3_zk_prover::synchronized::fixed_set::DecryptionRuntime;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

sol! {
    #[sol(rpc)]
    interface Checkpoint {
        function seedCiphertext(uint256 id, bytes ct, bytes32 commitment, address verifier) external;
        function failureCondition(uint256 id) external view returns (bool expired, uint8 reason, uint256 deadline);
    }
}

struct Observe(UnboundedSender<InterfoldEvent>);
impl Actor for Observe {
    type Context = actix::Context<Self>;
}
impl Handler<InterfoldEvent> for Observe {
    type Result = ();
    fn handle(&mut self, event: InterfoldEvent, _: &mut Self::Context) {
        let _ = self.0.send(event);
    }
}
fn listen(bus: &BusHandle, ty: EventType) -> UnboundedReceiver<InterfoldEvent> {
    let (tx, rx) = mpsc::unbounded_channel();
    bus.subscribe(ty, Observe(tx).start().recipient());
    rx
}
async fn received(rx: &mut UnboundedReceiver<InterfoldEvent>) -> Result<InterfoldEvent> {
    actix::clock::timeout(Duration::from_secs(240), rx.recv())
        .await?
        .context("observation channel closed")
}

#[derive(Message)]
#[rtype(result = "Result<()>")]
struct Drive(bool);
impl Handler<Drive> for ThresholdKeyshare {
    type Result = Result<()>;
    fn handle(&mut self, msg: Drive, ctx: &mut Self::Context) -> Self::Result {
        self.effects_enabled = true;
        if msg.0 {
            let id = self.state.try_get()?.e3_id;
            let ec = self
                .canonical_keys
                .first_live_opening(&id)
                .context("historical output cannot reserve noise")?;
            self.observe_contribution_opening(&id, &ec);
        }
        self.drive_contribution_definition(ctx)
    }
}

#[allow(clippy::too_many_arguments)]
async fn local(
    owner: usize,
    first: bool,
    bus: &BusHandle,
    keys: &CanonicalPublicKeys,
    rt: &DecryptionRuntime,
    root: &Recovered,
    setup: &SynchronizedSetupIntent,
    signer: &PrivateKeySigner,
    directory: &Path,
) -> Result<DecryptionshareCreated> {
    let db = DataStore::from_sled_store(&SledStore::new(
        bus,
        &directory.join(format!("consent-{owner}")),
    )?);
    let repos = db.repositories();
    let selected = setup.selected();
    let id = &selected.e3_id;
    let state = ThresholdKeyshareState::new(
        id.clone(),
        owner as u64,
        KeyshareState::ReadyForDecryption(root.1.clone()),
        1,
        3,
        selected.params.clone(),
        signer.address().to_string(),
    );
    let payloads =
        ThresholdKeyshareRecoveryPayloads::new(repos.threshold_keyshare_recovery_payloads(id));
    let restored = payloads
        .synchronized_setup()
        .restore()
        .await?
        .context("lost setup intent")?;
    ensure!(&restored == setup);
    let mut node = ThresholdKeyshare::new(ThresholdKeyshareParams {
        state: repos.threshold_keyshare(id).send(Some(state)),
        recovery: repos
            .threshold_keyshare_recovery(id)
            .send(Some(root.0.clone())),
        recovery_payloads: payloads,
        bus: bus.clone(),
        cipher: cipher(owner).await?,
        params_profile: PROFILE,
        interfold_address: restored.result().context.setup.interfold_address,
        signer: signer.clone(),
        bfv_key: repos.threshold_keyshare_bfv_key(id),
        effects_enabled: false,
        dkg_timing_reader: Arc::new(|_| Box::pin(async { anyhow::bail!("unexpected DKG timing") })),
    })
    .with_canonical_keys(keys.clone())
    .with_decryption_runtime(Some(rt.clone()));
    node.synchronized_setup = Some(restored);
    let node = node.start();
    let mut output = listen(bus, EventType::DecryptionshareCreated);
    node.send(Drive(first)).await??;
    let InterfoldEventData::DecryptionshareCreated(bundle) =
        received(&mut output).await?.into_data()
    else {
        unreachable!()
    };
    ensure!(bundle.party_id == owner as u64);
    node.send(Die).await?;
    db.shutdown().await?;
    SledDb::close_all_connections();
    Ok(bundle)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn qualify(
    chain: &Chain,
    registry: Address,
    recovered: &[Recovered],
    setups: &[SynchronizedSetupIntent],
    signers: &[PrivateKeySigner],
    prover: &ZkProver,
    history: Vec<InterfoldEvent<Unsequenced>>,
    pk: &PublicKey,
    dir: &Path,
) -> Result<()> {
    let id = &setups[0].selected().e3_id;
    let numeric: U256 = id.clone().try_into()?;
    let controller = chain.controller;
    let honk: Value = serde_json::from_slice(&fs::read(dir.join("DecryptionHonk.json"))?)?;
    let mut libs = HashMap::new();
    for (name, compiled) in honk.as_object().unwrap() {
        if name != "DecryptionAggregatorVerifier" {
            libs.insert(
                name.clone(),
                deploy(&chain.provider, compiled, vec![], &libs).await?,
            );
        }
    }
    let verifier = deploy(
        &chain.provider,
        &honk["DecryptionAggregatorVerifier"],
        vec![],
        &libs,
    )
    .await?;
    let manifest: Value = serde_json::from_str(include_str!(
        "../../../../../../../circuits/qualification/sync-insecure-64/minimum/manifest.json"
    ))?;
    let pin = |i: usize| -> Result<B256> {
        Ok(manifest["circuits"][i]["vkHash"]
            .as_str()
            .unwrap()
            .parse()?)
    };
    let wrapper_artifact = artifact(
        "contracts/verifiers/bfv/SynchronizedDecryptionVerifier.sol/SynchronizedDecryptionVerifier.json",
    )?;
    let wrapper = deploy(
        &chain.provider,
        &wrapper_artifact,
        (verifier, registry, pin(0)?, pin(1)?).abi_encode_params(),
        &HashMap::new(),
    )
    .await?;
    let p = &pk.params;
    let ct = e3_bfv_client::bfv_encrypt(
        vec![37u64],
        pk.to_bytes(),
        p.degree(),
        p.plaintext(),
        p.moduli(),
    )?;
    let commitment = e3_bfv_client::compute_ct_commitment_with_params(&ct, p)?;
    let checkpoint = Checkpoint::new(controller, &chain.provider);
    let receipt = checkpoint
        .seedCiphertext(numeric, ct.clone().into(), commitment.into(), wrapper)
        .send()
        .await?
        .get_receipt()
        .await?;
    ensure!(receipt.status());
    let config = AggregateConfig::new(HashMap::from([(AggregateId::new(31337), Duration::ZERO)]));
    let system = EventSystem::new()
        .with_event_bus(EventBus::new(EventBusConfig { deduplicate: false }).start())
        .with_aggregate_config(config);
    let bus = system.handle()?.enable("standby");
    for event in history {
        bus.publish_from_remote(
            event.get_data().clone(),
            event.ts(),
            event.block(),
            event.source(),
        )?;
    }
    bus.flush_event_pipeline().await?;
    let keys = CanonicalPublicKeys::default();
    let journal = system.eventstore_reader()?.seq();
    let mut projection =
        CanonicalKeyProjection::new(keys.clone(), HashMap::from([(31337, controller)]));
    projection
        .recover(&journal, &[AggregateId::new(31337)], HashSet::new())
        .await?;
    projection.attach(&bus).await?;
    for log in receipt.logs() {
        ensure!(log.address() == controller);
        let data: InterfoldEventData = match log.topic0() {
            Some(topic) if *topic == IInterfold::CiphertextOutputPublished::SIGNATURE_HASH => {
                let fact = log
                    .log_decode::<IInterfold::CiphertextOutputPublished>()?
                    .inner
                    .data;
                ensure!(fact.e3Id == numeric);
                CiphertextOutputPublished {
                    e3_id: id.clone(),
                    ciphertext_output: vec![ArcBytes::from_bytes(&fact.ciphertextOutput)],
                    ciphertext_commitment: fact.ciphertextCommitment.0,
                }
                .into()
            }
            _ => {
                let stage = log.log_decode::<IInterfold::E3StageChanged>()?.inner.data;
                ensure!(stage.e3Id == numeric && stage.newStage == 4);
                E3StageChanged {
                    e3_id: id.clone(),
                    previous_stage: E3Stage::KeyPublished,
                    new_stage: E3Stage::CiphertextReady,
                }
                .into()
            }
        };
        bus.publish_from_remote(
            data,
            100 + u128::from(log.log_index.unwrap()),
            receipt.block_number,
            EventSource::Evm,
        )?;
    }
    bus.flush_event_pipeline().await?;
    let restarted = CanonicalPublicKeys::default();
    CanonicalKeyProjection::new(restarted.clone(), HashMap::from([(31337, controller)]))
        .recover(&journal, &[AggregateId::new(31337)], HashSet::new())
        .await?;
    ensure!(
        restarted.first_live_opening(id).is_none()
            && restarted.synchronized_opening(id) == keys.synchronized_opening(id)
    );
    let provider = e3_evm::EthProvider::new(chain.provider.clone()).await?;
    let reader = provider.clone();
    let rt = DecryptionRuntime {
        prover: prover.clone(),
        pool: e3_task_pool::TaskPool::new(2, 1),
        task_scope: "qualification-node".into(),
        deadline: Arc::new(move |id| {
            let p = reader.clone();
            Box::pin(async move { e3_evm::read_decryption_deadline(&p, controller, &id).await })
        }),
    };
    let deadline = (rt.deadline)(id.clone()).await?;
    let mut ready = listen(&bus, EventType::AggregationInputsReady);
    let mut results = listen(&bus, EventType::PlaintextAggregated);
    let mut candidates = listen(&bus, EventType::DecryptionshareCreated);
    let disk = dir.join("plaintext-checkpoints");
    let open =
        || -> Result<DataStore> { Ok(DataStore::from_sled_store(&SledStore::new(&bus, &disk)?)) };
    let db = open()?;
    let collector = |db: &DataStore, output_bus: &BusHandle, active, effects, through| {
        FixedSetPlaintext::new(
            output_bus.clone(),
            id.clone(),
            keys.clone(),
            rt.clone(),
            journal.clone(),
            db.scope("review-standby"),
            active,
            effects,
            through,
        )
        .start()
    };
    let standby = collector(&db, &bus, false, true, 0);
    bus.subscribe(
        EventType::DecryptionshareCreated,
        standby.clone().recipient(),
    );
    let produce = |owner: usize, first: bool| {
        let local_bus = test_bus_with_deduplication(false).0;
        let (rt, keys, root, saved, signer) = (
            &rt,
            if first { &keys } else { &restarted },
            &recovered[owner],
            &setups[owner],
            &signers[owner],
        );
        async move { local(owner, first, &local_bus, keys, rt, root, saved, signer, dir).await }
    };
    let a = produce(0, true).await?;
    ensure!(
        produce(0, false).await? == a,
        "restart emitted another signed contribution"
    );
    let send =
        |b: DecryptionshareCreated, ts| bus.publish_from_remote(b, ts, None, EventSource::Net);
    let mut outsider = a.clone();
    outsider.party_id = 1;
    send(outsider, 100)?;
    send(a.clone(), 101)?;
    send(a, 102)?;
    bus.flush_event_pipeline().await?;
    let _outsider = received(&mut candidates).await?;
    let first = received(&mut candidates).await?;
    let duplicate = received(&mut candidates).await?;
    ensure!(first.get_data() == duplicate.get_data() && first.seq() < duplicate.seq());
    // Same frozen request and one honest share: even a new coordinator cannot start.
    let snapshot = chain.provider.anvil_snapshot().await?;
    for (at, expired) in [(deadline, false), (deadline + 1, true)] {
        chain.provider.anvil_set_next_block_timestamp(at).await?;
        chain.provider.evm_mine(None).await?;
        let outcome = checkpoint.failureCondition(numeric).call().await?;
        ensure!(outcome.expired == expired && outcome.deadline == U256::from(deadline));
        if expired {
            ensure!(FailureReason::try_from(outcome.reason)? == FailureReason::DecryptionTimeout);
        }
    }
    ensure!(ready.try_recv().is_err() && results.try_recv().is_err());
    ensure!(chain.provider.anvil_revert(snapshot).await?);
    let b = produce(2, true).await?;
    let plan = keys
        .synchronized_decryption_definition(id, PROFILE, &[ArcBytes::from_bytes(&ct)])?
        .unwrap();
    ensure!(!keys.take_first_reservation(&plan, 0) && !keys.take_first_reservation(&plan, 2));
    ensure!(!restarted.take_first_reservation(&plan, 0));
    let mut mixed = b.clone();
    let mut payload = mixed.signed_decryption_proofs[0].payload.clone();
    let mut row = payload.proof.public_signals.to_vec();
    row[31] ^= 1;
    payload.proof.public_signals = ArcBytes::from_bytes(&row);
    mixed.signed_decryption_proofs[0] = SignedProofPayload::sign(payload, &signers[2])?;
    send(mixed, 103)?;
    let mut bad = b.clone();
    let mut payload = bad.signed_decryption_proofs[0].payload.clone();
    let mut wrong = payload.proof.data.to_vec();
    wrong[31] ^= 1;
    payload.proof.data = ArcBytes::from_bytes(&wrong);
    bad.signed_decryption_proofs[0] = SignedProofPayload::sign(payload, &signers[2])?;
    send(bad, 104)?;
    send(b, 105)?;
    let _mixed = received(&mut candidates).await?;
    let _bad = received(&mut candidates).await?;
    let second = received(&mut candidates).await?;
    let ready_event = received(&mut ready).await?;
    ensure!(results.try_recv().is_err());
    // Take the proving artifact offline: the former standby can commit to the batch,
    // but cannot possibly have checkpointed a final proof before it loses its role.
    let c7 = CircuitName::DecryptedSharesAggregation;
    let circuit = prover
        .circuits_dir(
            e3_zk_config::CircuitVariant::Recursive,
            &PROFILE.artifacts_dir_for_committee(COMMITTEE)?,
        )
        .join(c7.dir_path())
        .join(format!("{}.json", c7.as_str()));
    let offline = circuit.with_extension("offline");
    fs::rename(&circuit, &offline)?;
    let role = |active| AggregatorChanged {
        e3_id: id.clone(),
        active_party_id: Some(if active { 2 } else { 0 }),
        is_aggregator: active,
    };
    standby
        .send(keyshare_event(role(true), 199, EventSource::Local))
        .await?;
    let saved = db.scope("review-standby");
    let started = actix::clock::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(batch) = saved.scope("started").read_checked::<Vec<u64>>().await? {
                return Ok::<_, anyhow::Error>(batch);
            }
            actix::clock::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    ensure!(started == [first.seq(), second.seq()]);
    standby
        .send(keyshare_event(role(false), 200, EventSource::Local))
        .await?;
    standby
        .send(keyshare_event(e3_events::Shutdown, 201, EventSource::Local))
        .await?;
    db.shutdown().await?;
    SledDb::close_all_connections();
    let db = open()?;
    ensure!(db
        .scope("review-standby")
        .scope("result")
        .read_checked::<PlaintextAggregated>()
        .await?
        .is_none());
    fs::rename(&offline, &circuit)?;
    let resumed = collector(&db, &bus, false, false, ready_event.seq());
    ensure!(results.try_recv().is_err());
    resumed
        .send(keyshare_event(
            EffectsEnabled::new(),
            202,
            EventSource::Local,
        ))
        .await?;
    let InterfoldEventData::PlaintextAggregated(intent) = received(&mut results).await?.into_data()
    else {
        unreachable!()
    };
    ensure!(
        intent.decrypted_output[0][..8] == 37_u64.to_le_bytes()
            && intent.decrypted_output[0][8..].iter().all(|&b| b == 0)
    );
    resumed
        .send(keyshare_event(e3_events::Shutdown, 203, EventSource::Local))
        .await?;
    db.shutdown().await?;
    SledDb::close_all_connections();
    fs::rename(&circuit, &offline)?;
    let db = open()?;
    let replay_bus = test_bus_with_deduplication(false).0;
    let mut replayed = listen(&replay_bus, EventType::PlaintextAggregated);
    let cached = collector(&db, &replay_bus, false, true, ready_event.seq());
    ensure!(
        received(&mut replayed).await?.into_data()
            == InterfoldEventData::PlaintextAggregated(intent.clone()),
        "demoted restart must release the verified checkpoint without reproving C7"
    );
    cached
        .send(keyshare_event(e3_events::Shutdown, 204, EventSource::Local))
        .await?;
    db.shutdown().await?;
    fs::rename(&offline, &circuit)?;
    let writer = e3_evm::EthProvider::new(
        ProviderBuilder::new()
            .wallet(signers[0].clone())
            .connect_http(chain.anvil.endpoint_url()),
    )
    .await?;
    for i in [0, 32, 64, 128, 320] {
        let mut wrong = intent.clone();
        let proof = &mut wrong.decryption_aggregator_proofs[0];
        let mut public = proof.public_signals.to_vec();
        public[i + 31] ^= 1;
        proof.public_signals = ArcBytes::from_bytes(&public);
        ensure!(e3_evm::publish_synchronized_plaintext_definition(
            writer.clone(),
            &keys,
            controller,
            &wrong
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("confirmed request"));
    }
    let wrong = PlaintextAggregated {
        decrypted_output: vec![ArcBytes::from_bytes(&[0; 8])],
        ..intent.clone()
    };
    ensure!(e3_evm::publish_synchronized_plaintext_definition(
        writer.clone(),
        &keys,
        controller,
        &wrong
    )
    .await
    .is_err());
    let snapshot = chain.provider.anvil_snapshot().await?;
    chain
        .provider
        .anvil_set_next_block_timestamp(deadline + 1)
        .await?;
    chain.provider.evm_mine(None).await?;
    ensure!(e3_evm::publish_synchronized_plaintext_definition(
        writer.clone(),
        &keys,
        controller,
        &intent
    )
    .await?
    .is_none());
    ensure!(chain.provider.anvil_revert(snapshot).await?);
    chain
        .provider
        .anvil_set_next_block_timestamp(deadline)
        .await?;
    let mined = e3_evm::publish_synchronized_plaintext_definition(
        writer.clone(),
        &keys,
        controller,
        &intent,
    )
    .await?
    .context("expected first write")?;
    ensure!(
        mined.status()
            && chain
                .provider
                .get_block_by_number(mined.block_number.unwrap().into())
                .await?
                .unwrap()
                .header
                .timestamp
                == deadline
            && IInterfold::new(controller, &chain.provider)
                .getE3Stage(numeric)
                .call()
                .await?
                == 5
    );
    ensure!(
        e3_evm::publish_synchronized_plaintext_definition(writer, &keys, controller, &intent)
            .await?
            .is_none()
    );
    Ok(())
}
