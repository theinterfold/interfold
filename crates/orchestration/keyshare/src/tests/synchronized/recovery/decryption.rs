// SPDX-License-Identifier: LGPL-3.0-only

//! Continue the same signed registry publication and reopened private actor inputs through C6,
//! standby promotion, the durable local plaintext intent and real request-bound EVM verification.
use super::*;
use crate::synchronized::SynchronizedSetupIntent;
use alloy::providers::ext::AnvilApi;
use e3_aggregator::synchronized_plaintext::FixedSetPlaintext;
use e3_events::{DecryptionshareCreated, PlaintextAggregated};
use e3_evm_contracts::{decryption_errors::DecryptionHonk::ProofLengthWrongWithLogN, IInterfold};
use e3_zk_prover::synchronized::fixed_set::DecryptionRuntime;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

sol! {
    #[sol(rpc)]
    interface Checkpoint {
        function seedCiphertext(uint256 id, bytes32 contentHash, bytes32 commitment, address verifier) external;
        function failureCondition(uint256 id) external view returns (bool expired, uint8 reason, uint256 deadline);
    }
    #[sol(rpc)]
    interface RequestVerifier {
        function verify(uint256 e3Id, bytes32 domain, bytes32 plaintextHash, bytes32 committeeHash, bytes32 ciphertextCommitment, bytes proof) external view returns (bool);
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
struct DriveDefinition;
impl Handler<DriveDefinition> for ThresholdKeyshare {
    type Result = Result<()>;
    fn handle(&mut self, _: DriveDefinition, ctx: &mut Self::Context) -> Self::Result {
        // Only bypass request admission. The real opening and EffectsEnabled mailboxes
        // must have established every other prerequisite.
        self.drive_contribution_definition(ctx)
    }
}

struct Contributor {
    actor: actix::Addr<ThresholdKeyshare>,
    output: UnboundedReceiver<InterfoldEvent>,
    db: DataStore,
    owner: u64,
}

async fn contributor(
    owner: usize,
    keys: CanonicalPublicKeys,
    rt: &DecryptionRuntime,
    root: &Recovered,
    setup: &SynchronizedSetupIntent,
    signer: &PrivateKeySigner,
    directory: &Path,
) -> Result<Contributor> {
    let bus = test_bus_with_deduplication(false).0;
    let db = DataStore::from_sled_store(&SledStore::new(
        &bus,
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
        params_profile: selected.params_profile,
        interfold_address: restored.result().context.setup.interfold_address,
        signer: signer.clone(),
        bfv_key: repos.threshold_keyshare_bfv_key(id),
        effects_enabled: false,
        dkg_timing_reader: Arc::new(|_| Box::pin(async { anyhow::bail!("unexpected DKG timing") })),
    })
    .with_canonical_keys(keys)
    .with_decryption_runtime(Some(rt.clone()));
    node.synchronized_setup = Some(restored);
    Ok(Contributor {
        actor: node.start(),
        output: listen(&bus, EventType::DecryptionshareCreated),
        db,
        owner: owner as u64,
    })
}

impl Contributor {
    async fn signed(mut self) -> Result<DecryptionshareCreated> {
        self.actor.send(DriveDefinition).await??;
        let InterfoldEventData::DecryptionshareCreated(bundle) =
            received(&mut self.output).await?.into_data()
        else {
            unreachable!()
        };
        ensure!(bundle.party_id == self.owner);
        self.actor.send(Die).await?;
        self.db.shutdown().await?;
        SledDb::close_all_connections();
        Ok(bundle)
    }
}

#[path = "ciphertext_delivery.rs"]
mod ciphertext_delivery;

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
    key: super::cli::Publication<'_>,
) -> Result<()> {
    let selected = setups[0].selected();
    let id = &selected.e3_id;
    let profile = selected.params_profile;
    let numeric: U256 = id.clone().try_into()?;
    let controller = chain.controller;
    let wrapper = if let Some(cli) = &chain.cli {
        cli.decryption
    } else {
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
        let wrapper_artifact = artifact(
        "contracts/verifiers/bfv/SynchronizedDecryptionVerifier.sol/SynchronizedDecryptionVerifier.json",
    )?;
        deploy(
            &chain.provider,
            &wrapper_artifact,
            (verifier, registry, B256::from(selected.crypto_config_id)).abi_encode_params(),
            &HashMap::new(),
        )
        .await?
    };
    let p = &pk.params;
    // Compute one level-zero output under the published key.
    let encrypt = |value: u64| -> Result<Ciphertext> {
        let bytes = e3_bfv_client::bfv_encrypt(
            vec![value],
            pk.to_bytes(),
            p.degree(),
            p.plaintext(),
            p.moduli(),
        )?;
        Ok(Ciphertext::from_bytes(&bytes, p)?)
    };
    let ct = (&encrypt(19)? + &encrypt(18)?).to_bytes();
    let commitment = e3_bfv_client::compute_ct_commitment_with_params(&ct, p)?;
    let checkpoint = Checkpoint::new(controller, &chain.provider);
    let receipt = if chain.cli.is_some() {
        let lifecycle = IInterfold::new(controller, &chain.provider);
        let current = lifecycle.getE3(numeric).call().await?;
        ensure!(current.decryptionVerifier == wrapper);
        let now = chain
            .provider
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
            .await?
            .context("missing chain head")?
            .header
            .timestamp;
        if current.inputWindow[1] > U256::from(now) {
            chain
                .provider
                .anvil_set_next_block_timestamp(current.inputWindow[1].try_into()?)
                .await?;
            chain.provider.evm_mine(None).await?;
        }
        let reference = IInterfold::CiphertextOutputReference {
            contentHash: keccak256(&ct),
            ciphertextCommitment: commitment.into(),
            computeProof: Bytes::from_static(&[1]),
            availabilityProof: Bytes::copy_from_slice(&ct),
        };
        lifecycle
            .publishCiphertextOutput(numeric, reference.abi_encode().into())
            .send()
            .await?
            .get_receipt()
            .await?
    } else {
        checkpoint
            .seedCiphertext(numeric, keccak256(&ct), commitment.into(), wrapper)
            .send()
            .await?
            .get_receipt()
            .await?
    };
    let ciphertext_observed = std::time::Instant::now();
    ensure!(receipt.status());
    let node = DiskJournal::open(dir, "plaintext").await?;
    let bus = &node.bus;
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
    let mut projection =
        CanonicalKeyProjection::new(keys.clone(), HashMap::from([(31337, controller)]));
    projection
        .recover(&node.reader, &[AggregateId::new(31337)], HashSet::new())
        .await?;
    projection.attach(bus).await?;
    let provider = e3_evm::EthProvider::new(chain.provider.clone()).await?;
    let reader = provider.clone();
    let rt = DecryptionRuntime {
        prover: prover.clone(),
        pool: e3_task_pool::TaskPool::new(2, 1),
        task_scope: "qualification-node".into(),
        timing: Arc::new(move |id| {
            let p = reader.clone();
            Box::pin(async move { e3_evm::read_decryption_window(&p, controller, &id).await })
        }),
    };
    let deadline = rt.open_deadline(id, None).await?;
    let owner =
        |i: usize, keys| contributor(i, keys, &rt, &recovered[i], &setups[i], &signers[i], dir);
    let first_owner = owner(0, keys.clone()).await?;
    let last_owner = owner(2, keys.clone()).await?;
    for local in [&first_owner, &last_owner] {
        bus.subscribe_all(
            &[
                EventType::EffectsEnabled,
                EventType::CiphertextOutputPublished,
            ],
            local.actor.clone().recipient(),
        );
    }
    let opening = ciphertext_delivery::retrieve(chain, &receipt, &ct, &node, id, &keys).await?;
    let restarted = CanonicalPublicKeys::default();
    CanonicalKeyProjection::new(restarted.clone(), HashMap::from([(31337, controller)]))
        .recover(&node.reader, &[AggregateId::new(31337)], HashSet::new())
        .await?;
    ensure!(
        restarted.first_live_opening(id).is_none()
            && restarted.synchronized_opening(id) == keys.synchronized_opening(id)
    );
    let mut ready = listen(bus, EventType::AggregationInputsReady);
    let mut candidates = listen(bus, EventType::DecryptionshareCreated);
    let collector = |node: &DiskJournal, projection: &CanonicalPublicKeys, effects| {
        FixedSetPlaintext::new(
            node.bus.clone(),
            id.clone(),
            projection.clone(),
            rt.clone(),
            node.reader.clone(),
            node.db.scope("review-standby"),
            false,
            effects,
        )
        .start()
    };
    let standby = collector(&node, &keys, true);
    bus.subscribe(
        EventType::DecryptionshareCreated,
        standby.clone().recipient(),
    );
    let a = first_owner.signed().await?;
    let replacement = owner(0, restarted.clone()).await?;
    replacement.actor.send(opening).await?;
    replacement
        .actor
        .send(keyshare_event(EffectsEnabled::new(), 1, EventSource::Local))
        .await?;
    ensure!(
        replacement.signed().await? == a,
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
    let outsider = received(&mut candidates).await?;
    let first = received(&mut candidates).await?;
    let duplicate = received(&mut candidates).await?;
    ensure!(first.get_data() == duplicate.get_data() && first.seq() < duplicate.seq());
    // Same frozen request and one honest share: even a new coordinator cannot start.
    if chain.cli.is_none() {
        let snapshot = chain.provider.anvil_snapshot().await?;
        for (at, expired) in [(deadline, false), (deadline + 1, true)] {
            chain.provider.anvil_set_next_block_timestamp(at).await?;
            chain.provider.evm_mine(None).await?;
            let outcome = checkpoint.failureCondition(numeric).call().await?;
            let open = rt.open_deadline(id, Some(deadline)).await;
            if expired {
                ensure!(open.unwrap_err().to_string().contains("deadline expired"));
            } else {
                ensure!(open? == deadline);
            }
            ensure!(outcome.expired == expired && outcome.deadline == U256::from(deadline));
            if expired {
                ensure!(
                    FailureReason::try_from(outcome.reason)? == FailureReason::DecryptionTimeout
                );
            }
        }
        ensure!(chain.provider.anvil_revert(snapshot).await?);
    }
    let b = last_owner.signed().await?;
    let plan = keys
        .synchronized_decryption_definition(id, profile, &[ArcBytes::from_bytes(&ct)])?
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
    ensure!(
        received(&mut ready).await?.seq() > second.seq(),
        "readiness preceded the second designated row"
    );
    let saved = node.db.scope("review-standby");
    ensure!(
        saved
            .scope("started")
            .read_checked::<Vec<u64>>()
            .await?
            .is_none(),
        "standby started before promotion"
    );
    // Take the proving artifact offline: the former standby can commit to the batch,
    // but cannot possibly have checkpointed a final proof before it loses its role.
    let c7 = CircuitName::DecryptedSharesAggregation;
    let circuit = prover
        .circuits_dir(
            e3_zk_config::CircuitVariant::Recursive,
            &profile.artifacts_dir_for_committee(COMMITTEE)?,
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
    node.close().await?;
    let node = DiskJournal::open(dir, "plaintext").await?;
    let saved = node.db.scope("review-standby");
    ensure!(saved.scope("started").read_checked::<Vec<u64>>().await? == Some(started));
    for (owner, seq) in [(0, first.seq()), (2, second.seq())] {
        ensure!(
            saved
                .scope(format!("verified-{owner}"))
                .read_checked::<u64>()
                .await?
                == Some(seq),
            "reopen lost the pinned sequence for owner {owner}"
        );
    }
    ensure!(saved
        .scope("result")
        .read_checked::<PlaintextAggregated>()
        .await?
        .is_none());
    fs::rename(&offline, &circuit)?;
    let recovered_keys = CanonicalPublicKeys::default();
    CanonicalKeyProjection::new(recovered_keys.clone(), HashMap::from([(31337, controller)]))
        .recover(
            &node.reader,
            &[AggregateId::new(31337)],
            HashSet::from([id.clone()]),
        )
        .await?;
    ensure!(recovered_keys.synchronized_candidates(id) == Some((outsider.seq(), second.seq())));
    ensure!(recovered_keys.first_live_opening(id).is_none());
    let mut results = listen(&node.bus, EventType::PlaintextAggregated);
    let resumed = collector(&node, &recovered_keys, false);
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
    node.close().await?;
    fs::rename(&circuit, &offline)?;
    let node = DiskJournal::open(dir, "plaintext").await?;
    let keys = CanonicalPublicKeys::default();
    let mut projection =
        CanonicalKeyProjection::new(keys.clone(), HashMap::from([(31337, controller)]));
    projection
        .recover(
            &node.reader,
            &[AggregateId::new(31337)],
            HashSet::from([id.clone()]),
        )
        .await?;
    projection.attach(&node.bus).await?;
    let mut replayed = listen(&node.bus, EventType::PlaintextAggregated);
    let cached = collector(&node, &keys, true);
    ensure!(
        received(&mut replayed).await?.into_data()
            == InterfoldEventData::PlaintextAggregated(intent.clone()),
        "demoted restart must release the verified checkpoint without reproving C7"
    );
    fs::rename(&offline, &circuit)?;
    let writer = e3_evm::EthProvider::new(
        ProviderBuilder::new()
            .wallet(signers[0].clone())
            .connect_http(chain.anvil.endpoint_url()),
    )
    .await?;
    let final_proof = &intent.decryption_aggregator_proofs[0];
    let pins = e3_request::canonical_key::SynchronizedChildPins::for_profile(profile, COMMITTEE)?;
    let other_profile = if profile == PROFILE {
        BfvProfile::SyncDecSecure8192
    } else {
        PROFILE
    };
    let other =
        e3_request::canonical_key::SynchronizedChildPins::for_profile(other_profile, COMMITTEE)?;
    let lifecycle = IInterfold::new(controller, &chain.provider);
    let output = Bytes::copy_from_slice(&intent.decrypted_output[0]);
    if let Some(cli) = &chain.cli {
        plan.check_current(&keys, &ArcBytes::from_bytes(&ct))?;
        let mined =
            e3_evm::publish_synchronized_plaintext_definition(writer, &keys, controller, &intent)
                .await?
                .context("missing mined plaintext")?;
        let end_ms = super::cli::wall_ms()?;
        let plaintext_observed = std::time::Instant::now();
        let state = lifecycle.getE3(numeric).call().await?;
        ensure!(
            mined.status()
                && state.plaintextOutput == output
                && state.decryptionVerifier == cli.decryption
                && state.pkVerifier == cli.dkg
                && lifecycle.getE3Stage(numeric).call().await? == 5
        );
        ensure!(
            mined
                .logs()
                .iter()
                .filter(|log| log.address() == controller)
                .filter_map(|log| log
                    .log_decode::<IInterfold::PlaintextOutputPublished>()
                    .ok())
                .any(|log| log.inner.data.e3Id == numeric
                    && log.inner.data.plaintextOutput == output),
            "no mined plaintext for the CLI E3"
        );
        cli.record(
            controller,
            &plan,
            u64::from_le_bytes(state.plaintextOutput[..8].try_into()?),
            [
                key,
                super::cli::Publication {
                    receipt: &receipt,
                    observed: ciphertext_observed,
                },
                super::cli::Publication {
                    receipt: &mined,
                    observed: plaintext_observed,
                },
            ],
            end_ms,
        )?;
        node.close().await?;
        return Ok(());
    }
    use e3_evm_contracts::decryption_errors::SynchronizedDecryptionVerifier::{
        DomainBindingMismatch, VkHashMismatch,
    };
    for (c6, c7) in [
        (other.c6, pins.c7),
        (pins.c6, other.c7),
        (other.c6, other.c7),
    ] {
        let mut swapped = final_proof.clone();
        let mut fields = swapped.public_signals.to_vec();
        fields[..32].copy_from_slice(c6.as_slice());
        fields[32..64].copy_from_slice(c7.as_slice());
        swapped.public_signals = ArcBytes::from_bytes(&fields);
        let error = lifecycle
            .publishPlaintextOutput(numeric, output.clone(), e3_evm::encode_zk_proof(&swapped)?)
            .call()
            .await
            .expect_err("request verifier accepted a foreign child VK");
        ensure!(
            error.as_decoded_error::<VkHashMismatch>().is_some(),
            "{error:#}"
        );
    }
    if let Some(export) = std::env::var_os("E3_SYNC_OTHER_PROFILE_EXPORT") {
        let export = Path::new(&export);
        let fields = fs::read(export.join("public_inputs"))?;
        ensure!(
            fields.get(..32) == Some(other.c6.as_slice())
                && fields.get(32..64) == Some(other.c7.as_slice())
        );
        let foreign = Proof::new(
            final_proof.circuit,
            ArcBytes::from_bytes(&fs::read(export.join("proof"))?),
            ArcBytes::from_bytes(&fields),
        );
        let error = lifecycle
            .publishPlaintextOutput(numeric, output.clone(), e3_evm::encode_zk_proof(&foreign)?)
            .call()
            .await
            .expect_err("request verifier accepted the other profile's proof");
        ensure!(
            error.as_decoded_error::<VkHashMismatch>().is_some(),
            "{error:#}"
        );
    }
    // Leave the genuine proof and the lookup of the signed authority untouched. Change only
    // the E3 ID in the domain, so missing authority cannot explain the rejection.
    let context = keys
        .get(id)
        .context("missing published key")?
        .domain(controller);
    let verifier = RequestVerifier::new(wrapper, &chain.provider);
    let proof = e3_evm::encode_zk_proof(final_proof)?;
    let check_domain = |e3| {
        verifier.verify(
            numeric,
            e3_committee_hash::hash_decryption_domain(id.chain_id(), e3, context, keccak256(&ct)),
            keccak256(&output),
            context.committee_hash,
            commitment.into(),
            proof.clone(),
        )
    };
    ensure!(check_domain(numeric).call().await?);
    let error = check_domain(numeric + U256::from(1))
        .call()
        .await
        .expect_err("accepted the other E3's decryption domain");
    ensure!(
        error.as_decoded_error::<DomainBindingMismatch>().is_some(),
        "{error:#}"
    );
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
    // A valid public statement with a truncated proof passes Rust admission. The real Honk
    // verifier rejects it; this specific input can be replaced, unlike an ambiguous RPC error.
    let mut truncated = intent.clone();
    let proof = &mut truncated.decryption_aggregator_proofs[0];
    proof.data = ArcBytes::from_bytes(&proof.data[..32]);
    let rejection = e3_evm::publish_synchronized_plaintext_definition(
        writer.clone(),
        &keys,
        controller,
        &truncated,
    )
    .await
    .unwrap_err();
    ensure!(
        rejection.chain().any(|cause| cause
            .downcast_ref::<alloy::contract::Error>()
            .and_then(|error| error.as_decoded_error::<ProofLengthWrongWithLogN>())
            .is_some_and(|error| error.actualLength == U256::from(32))),
        "expected the Honk verifier to reject the truncated proof: {rejection:#}"
    );
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
    // The live writer is polled by its own actor. Signing inline here would nest its debug
    // crypto stack under the entire DKG, disk-recovery and decryption rehearsal.
    let mined = {
        let (writer, keys, intent) = (writer.clone(), keys.clone(), intent.clone());
        actix::spawn(async move {
            e3_evm::publish_synchronized_plaintext_definition(writer, &keys, controller, &intent)
                .await
        })
        .await??
        .context("expected first write")?
    };
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
    eprintln!(
        "{profile} plaintext 37, designated [0,2]: {} gas",
        mined.gas_used
    );
    ensure!(
        e3_evm::publish_synchronized_plaintext_definition(writer, &keys, controller, &intent)
            .await?
            .is_none()
    );
    let db = &node.db;
    let scope = db.scope("review-standby");
    let prefix = scope.scope("").scope_bytes().to_vec();
    ensure!(db.keys_with_prefix(prefix.clone()).await?.len() == 4);
    let sibling = db.scope("review-standby-other").scope("result");
    sibling.write_sync(37u64).await?;
    node.bus
        .subscribe(EventType::E3StageChanged, cached.clone().recipient());
    for event in chain.decode(&mined, controller).await? {
        node.bus.naked_dispatch(event)?;
    }
    node.bus.flush_event_pipeline().await?;
    ensure!(
        keys.get(id).is_none(),
        "mined completion did not retire canonical authority"
    );
    ensure!(cached
        .send(keyshare_event(e3_events::Shutdown, 205, EventSource::Local))
        .await
        .is_err());
    ensure!(
        db.keys_with_prefix(prefix).await?.is_empty()
            && sibling.read_checked::<u64>().await? == Some(37)
    );
    node.close().await?;
    if let Some(export) = std::env::var_os("E3_SYNC_DECRYPTION_EXPORT") {
        let export = Path::new(&export);
        fs::create_dir(export)?;
        fs::write(export.join("proof"), &final_proof.data[..])?;
        fs::write(
            export.join("public_inputs"),
            &final_proof.public_signals[..],
        )?;
        let mut publication: Value =
            serde_json::from_slice(&fs::read(dir.join("publication.json"))?)?;
        let object = publication.as_object_mut().context("missing publication")?;
        object.remove("vk");
        object.remove("decryption_vk");
        fs::write(
            export.join("publication.json"),
            serde_json::to_vec(&publication)?,
        )?;
        fs::copy(dir.join("SynchronizedHonk.sol"), export.join("DkgHonk.sol"))?;
    }
    Ok(())
}
