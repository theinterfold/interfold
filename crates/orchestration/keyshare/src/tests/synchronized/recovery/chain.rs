// SPDX-License-Identifier: LGPL-3.0-only

//! Real registry/proof/signature qualification below disabled request admission. Only the
//! finalized committee and controller lifecycle are harnessed. Decryption uses the writer effect.

use super::{publication::Recovered, *};
use alloy::{
    network::TransactionBuilder,
    node_bindings::{Anvil, AnvilInstance},
    primitives::{Bytes, B256, U256},
    providers::{DynProvider, Provider, ProviderBuilder},
    rpc::types::{TransactionReceipt, TransactionRequest},
    sol,
    sol_types::SolValue,
};
use e3_event_system::{EventStoreAddrs, EventSystem};
use e3_events::{AggregateConfig, AggregateId, E3Requested, SynchronizedSetupAnchors};
use e3_evm::{
    canonical_key::CanonicalKeyProjection, CiphernodeRegistrySolReader, EvmLog, InterfoldEvmEvent,
};
use e3_evm_contracts::{ICiphernodeRegistry, ISynchronizedDkgPublication};
use e3_request::canonical_key::{CanonicalDkgAnchors, CanonicalPublicKeys};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
    time::Duration,
};
use tokio::sync::mpsc;

sol! {
    #[sol(rpc)]
    interface FixtureController {
        function configure(uint256 e3Id, address registry, address verifier, bytes32 configId) external;
    }
    #[sol(rpc)]
    interface FixtureRegistry {
        function seed(uint256 e3Id, address controller, address[3] nodes) external;
    }
}

pub(super) struct Chain {
    anvil: AnvilInstance,
    provider: DynProvider,
    pub controller: Address,
}

fn package() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packages/interfold-contracts")
}

fn artifact(relative: &str) -> Result<Value> {
    let path = package().join("artifacts").join(relative);
    serde_json::from_slice(&fs::read(&path).with_context(|| {
        format!(
            "build contract artifacts before qualification: {}",
            path.display()
        )
    })?)
    .map_err(Into::into)
}

async fn deploy(
    provider: &DynProvider,
    artifact: &Value,
    args: Vec<u8>,
    libraries: &HashMap<String, Address>,
) -> Result<Address> {
    ensure!(
        artifact["deployedBytecode"]
            .as_str()
            .context("missing runtime")?
            .len()
            / 2
            - 1
            <= 24576,
        "qualification contract exceeds EIP-170"
    );
    let mut code = artifact["bytecode"]
        .as_str()
        .context("missing bytecode")?
        .trim_start_matches("0x")
        .to_owned();
    for file in artifact["linkReferences"]
        .as_object()
        .context("missing link references")?
        .values()
    {
        for (name, slots) in file.as_object().context("invalid library references")? {
            let address = libraries
                .get(name)
                .with_context(|| format!("missing linked library {name}"))?;
            for slot in slots.as_array().context("invalid library slots")? {
                let start = slot["start"].as_u64().context("missing link offset")? as usize * 2;
                ensure!(slot["length"] == 20, "unexpected library link width");
                code.replace_range(start..start + 40, &alloy::hex::encode(address));
            }
        }
    }
    let mut code = alloy::hex::decode(code).with_context(|| {
        format!(
            "unlinked qualification bytecode for {}",
            artifact["contractName"]
        )
    })?;
    code.extend(args);
    let receipt = provider
        .send_transaction(TransactionRequest::default().with_deploy_code(code))
        .await
        .with_context(|| format!("deploy qualification {}", artifact["contractName"]))?
        .get_receipt()
        .await?;
    ensure!(receipt.status(), "qualification deployment reverted");
    receipt
        .contract_address
        .context("qualification deployment has no address")
}

struct Decoded(mpsc::UnboundedSender<InterfoldEvmEvent>);
impl Actor for Decoded {
    type Context = actix::Context<Self>;
}
impl Handler<InterfoldEvmEvent> for Decoded {
    type Result = ();
    fn handle(&mut self, event: InterfoldEvmEvent, _: &mut Self::Context) {
        let _ = self.0.send(event);
    }
}
impl Handler<StopForReopen> for Decoded {
    type Result = Result<()>;
    fn handle(&mut self, _: StopForReopen, ctx: &mut Self::Context) -> Self::Result {
        ctx.stop();
        Ok(())
    }
}
impl Handler<StopForReopen> for CiphernodeRegistrySolReader<DynProvider> {
    type Result = Result<()>;
    fn handle(&mut self, _: StopForReopen, ctx: &mut Self::Context) -> Self::Result {
        ctx.stop();
        Ok(())
    }
}

impl Chain {
    pub async fn start() -> Result<Self> {
        let anvil = Anvil::new().chain_id(31337).try_spawn()?;
        let signer = PrivateKeySigner::from_slice(&anvil.keys()[0].to_bytes())?;
        let provider = ProviderBuilder::new()
            .wallet(signer)
            .connect_http(anvil.endpoint_url())
            .erased();
        let lifecycle = deploy(
            &provider,
            &artifact("contracts/lib/InterfoldLifecycle.sol/InterfoldLifecycle.json")?,
            vec![],
            &HashMap::new(),
        )
        .await?;
        let controller = deploy(&provider,
            &artifact("contracts/test/SynchronizedDecryptionControllerHarness.sol/SynchronizedDecryptionControllerHarness.json")?,
            vec![], &HashMap::from([("InterfoldLifecycle".to_string(),lifecycle)])).await?;
        Ok(Self {
            anvil,
            provider,
            controller,
        })
    }

    async fn decode(
        &self,
        receipt: &TransactionReceipt,
        registry: Address,
    ) -> Result<Vec<InterfoldEvent<Unsequenced>>> {
        ensure!(receipt.status(), "qualification transaction reverted");
        let (tx, mut rx) = mpsc::unbounded_channel();
        let collector = Decoded(tx).start();
        let reader = CiphernodeRegistrySolReader::setup_with_factory(
            &collector.clone().recipient(),
            e3_evm::EthProvider::new(self.provider.clone()).await?,
            None,
            0,
        );
        let mut events = Vec::new();
        for log in receipt
            .logs()
            .iter()
            .filter(|log| log.address() == registry)
        {
            let block = log.block_number.context("unmined qualification log")?;
            let timestamp = self
                .provider
                .get_block_by_number(block.into())
                .await?
                .context("missing qualification block")?
                .header
                .timestamp;
            reader
                .send(InterfoldEvmEvent::Log(EvmLog::new(
                    log.clone(),
                    31337,
                    timestamp,
                )))
                .await?;
            match actix::clock::timeout(Duration::from_secs(10), rx.recv())
                .await?
                .context("registry decoder stopped")?
            {
                InterfoldEvmEvent::Event(event) => {
                    let (data, ts, block) = event.split();
                    events.push(InterfoldEvent::new_with_timestamp(
                        data,
                        None,
                        ts,
                        Some(block),
                        EventSource::Evm,
                    ));
                }
                InterfoldEvmEvent::Processed(_) => (),
                other => anyhow::bail!("registry decoder rejected mined log: {other:?}"),
            }
        }
        reader.send(StopForReopen).await??;
        collector.send(StopForReopen).await??;
        Ok(events)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn qualify(
        &self,
        recovered: &[Recovered],
        setups: &[SynchronizedSetupAnchors],
        recipients: &[Proof],
        planned: &super::publication::PlannedPublication,
        public_key: &PublicKey,
        proof: &Proof,
        directory: &Path,
        signers: &[PrivateKeySigner],
        prover: &ZkProver,
    ) -> Result<()> {
        let selected = recovered[0]
            .0
            .ciphernode_selected
            .as_ref()
            .context("missing selection")?;
        let id = &selected.e3_id;
        let numeric_id: U256 = id.clone().try_into()?;
        let mut libraries = HashMap::new();
        for (name, path) in [
            (
                "PoseidonT3",
                "poseidon-solidity/PoseidonT3.sol/PoseidonT3.json",
            ),
            (
                "RegistrySortitionLib",
                "contracts/lib/RegistrySortitionLib.sol/RegistrySortitionLib.json",
            ),
            (
                "DkgPublicationLib",
                "contracts/lib/DkgPublicationLib.sol/DkgPublicationLib.json",
            ),
            (
                "SynchronizedDkgSeedLib",
                "contracts/test/SynchronizedDkgRegistryHarness.sol/SynchronizedDkgSeedLib.json",
            ),
        ] {
            let address = deploy(&self.provider, &artifact(path)?, vec![], &libraries).await?;
            libraries.insert(name.to_owned(), address);
        }
        let registry = deploy(&self.provider,
            &artifact("contracts/test/SynchronizedDkgRegistryHarness.sol/SynchronizedDkgRegistryHarness.json")?,
            vec![], &libraries).await?;
        let honk: Value =
            serde_json::from_slice(&fs::read(directory.join("SynchronizedHonk.json"))?)?;
        for (name, compiled) in honk
            .as_object()
            .context("missing generated verifier contracts")?
        {
            if name != "DkgAggregatorVerifier" {
                let address = deploy(&self.provider, compiled, vec![], &libraries).await?;
                libraries.insert(name.clone(), address);
            }
        }
        let verifier = deploy(
            &self.provider,
            &honk["DkgAggregatorVerifier"],
            vec![],
            &libraries,
        )
        .await?;
        let fixture: Value =
            serde_json::from_slice(&fs::read(directory.join("publication.json"))?)?;
        let tree: U256 = fixture["setup_tree"]
            .as_str()
            .context("missing setup VK pin")?
            .parse()?;
        let c5: U256 = fixture["c5_key_hash"]
            .as_str()
            .context("missing C5 VK pin")?
            .parse()?;
        let wrapper = deploy(&self.provider,
            &artifact("contracts/verifiers/bfv/SynchronizedDkgPublicationVerifier.sol/SynchronizedDkgPublicationVerifier.json")?,
            (verifier, self.controller, B256::from(selected.crypto_config_id), tree, c5, U256::from(3), U256::from(2)).abi_encode_params(),
            &HashMap::new()).await?;
        FixtureController::new(self.controller, &self.provider)
            .configure(
                numeric_id,
                registry,
                wrapper,
                selected.crypto_config_id.into(),
            )
            .send()
            .await
            .context("configure frozen qualification request")?
            .get_receipt()
            .await?;
        let committee = selected
            .committee
            .iter()
            .map(|member| member.parse::<Address>())
            .collect::<Result<Vec<_>, _>>()?;
        let receipt = FixtureRegistry::new(registry, &self.provider)
            .seed(
                numeric_id,
                self.controller,
                committee
                    .clone()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("N differs"))?,
            )
            .send()
            .await
            .context("seed finalized qualification committee")?
            .get_receipt()
            .await?;
        // The controller/finalized selection is seeded below disabled admission; actual signing
        // addresses come only from the mined registry event through the production decoder.
        let mut history = vec![InterfoldEvent::new_with_timestamp(
            E3Requested {
                e3_id: id.clone(),
                threshold_m: selected.threshold_m,
                threshold_n: selected.threshold_n,
                params_profile: selected.params_profile,
                crypto_config_id: selected.crypto_config_id,
                params: selected.params.clone(),
                ..Default::default()
            }
            .into(),
            None,
            1,
            receipt.block_number,
            EventSource::Evm,
        )];
        history.extend(self.decode(&receipt, registry).await?);
        // The test harness seeds finalized storage below admission, without emitting sortition.
        history.push(InterfoldEvent::new_with_timestamp(
            e3_events::CommitteeFinalized {
                e3_id: id.clone(),
                committee: selected.committee.clone(),
                scores: Vec::new(),
                chain_id: id.chain_id(),
            }
            .into(),
            None,
            2,
            receipt.block_number,
            EventSource::Evm,
        ));
        let prefix =
            EventSystem::new()
                .with_fresh_bus()
                .with_aggregate_config(AggregateConfig::new(HashMap::from([(
                    AggregateId::new(31337),
                    Duration::ZERO,
                )])));
        let bus = prefix.handle()?.enable("real-synchronized-context");
        for event in &history {
            bus.publish_from_remote(
                event.get_data().clone(),
                event.ts(),
                event.block(),
                EventSource::Evm,
            )?;
        }
        bus.flush_event_pipeline().await?;
        let keys = CanonicalPublicKeys::default();
        let mut projection =
            CanonicalKeyProjection::new(keys.clone(), HashMap::from([(31337, self.controller)]));
        projection
            .recover(
                &prefix.eventstore_reader()?.seq(),
                &[AggregateId::new(31337)],
                HashSet::new(),
            )
            .await?;
        ensure!(keys.get(id).is_none());
        let mut signatures = Vec::new();
        let mut intent = planned.intent.clone();
        let mut local_setups = Vec::new();
        for owner in 0..recovered.len() {
            use super::super::publication::{actor, consents, DriveSetup, SetupCheckpoint};
            let path = directory.join(format!("consent-{owner}"));
            let store = DataStore::from_sled_store(&SledStore::new(&bus, &path)?);
            let root = recovered[owner].0.clone();
            let material = root.synchronized.as_ref().context("missing material")?;
            let result = e3_events::SynchronizedRecipientProofReady {
                e3_id: id.clone(),
                context: material.context.clone(),
                proof: recipients[owner].clone(),
                setup: setups[owner].clone(),
            };
            let (node, setup_bus, history) = actor(
                &store,
                root.clone(),
                signers[owner].clone(),
                cipher(owner).await?,
                self.controller,
                keys.clone(),
            )
            .await?;
            node.send(DriveSetup {
                result: Some(TypedEvent::new(result, test_ec(700))),
                effects: false,
            })
            .await??;
            let saved = node
                .send(SetupCheckpoint)
                .await?
                .context("local setup was not retained")?;
            ensure!(consents(&setup_bus, &history).await?.is_empty());
            node.send(Die).await?;
            drop(node);
            store.shutdown().await?;
            drop(store);
            // The consent producer must recover its own verdict without another worker result.
            let store = DataStore::from_sled_store(&SledStore::new(&bus, &path)?);
            let (node, setup_bus, history) = actor(
                &store,
                root,
                signers[owner].clone(),
                cipher(owner).await?,
                self.controller,
                keys.clone(),
            )
            .await?;
            node.send(DriveSetup {
                result: None,
                effects: true,
            })
            .await??;
            ensure!(node.send(SetupCheckpoint).await?.as_ref() == Some(&saved));
            ensure!(saved
                .confirmed_setup(self.controller, &keys, &*cipher(owner).await?)
                .is_err());
            let output = consents(&setup_bus, &history).await?;
            ensure!(output.len() == usize::from(setups[0].dealers.contains(&(owner as u32))));
            if let Some(event) = output.first() {
                let InterfoldEventData::SynchronizedDkgConsentPublished(message) = event.get_data()
                else {
                    unreachable!()
                };
                ensure!(message.attestation.recover_address()? == committee[owner]);
                planned.plan.consent(
                    keys.synchronized_context(id)
                        .context("missing frozen consent context")?,
                    &planned.native,
                    &planned.peers,
                    &message.attestation,
                )?;
                signatures.push(Bytes::copy_from_slice(&message.attestation.signature));
                intent.consents.push(message.attestation.clone());
            }
            local_setups.push(saved);
            node.send(Die).await?;
            drop(node);
            store.shutdown().await?;
        }
        let setup = &setups[0];
        let commitment =
            e3_zk_witness::threshold::user_data_encryption::compute_public_key_commitment(
                &public_key.params,
                public_key,
            )?;
        let publication = ISynchronizedDkgPublication::Publication {
            pkCommitment: commitment.into(),
            dealerBatch: setup.dealer_batch.into(),
            partyIds: setup.dealers.iter().copied().map(U256::from).collect(),
            proof: e3_evm::encode_zk_proof(proof)?,
            signatures,
        };
        let contract = ISynchronizedDkgPublication::new(registry, &self.provider);
        let mut missing_consent = publication.clone();
        missing_consent.signatures.pop();
        let error = contract
            .publishSynchronizedCommittee(numeric_id, missing_consent)
            .call()
            .await
            .expect_err("publication without all H consents must revert");
        ensure!(
            error
                .as_decoded_error::<ISynchronizedDkgPublication::InvalidSynchronizedDkgPublication>(
                )
                .is_some(),
            "missing consent failed for an unrelated reason: {error:#}"
        );
        history.push(InterfoldEvent::new_with_timestamp(
            intent.clone().into(),
            None,
            3,
            None,
            EventSource::Local,
        ));
        let (writer_keys, pending) = reopen_history(
            &history,
            &directory.join("writer-recovery"),
            self.controller,
        )
        .await?;
        ensure!(pending == vec![intent.clone()] && writer_keys.get(id).is_none());
        self.provider
            .send_transaction(
                TransactionRequest::default()
                    .with_to(signers[0].address())
                    .with_value(U256::from(10u64).pow(U256::from(18))),
            )
            .await?
            .get_receipt()
            .await?;
        let publisher = ProviderBuilder::new()
            .wallet(signers[0].clone())
            .connect_http(self.anvil.endpoint_url());
        let publisher = e3_evm::EthProvider::new(publisher).await?;
        let receipts = e3_evm::publish_synchronized_committee_definition(
            publisher.clone(),
            &writer_keys,
            &pending[0],
        )
        .await?;
        ensure!(
            receipts.len() == 2,
            "expected proof and one native key chunk"
        );
        // Reuse the reopened pre-publication journal after a mined success that it has not yet
        // observed. The complete-authority preflight skips the proof and resumes only key bytes.
        let resumed =
            e3_evm::publish_synchronized_committee_definition(publisher, &writer_keys, &pending[0])
                .await?;
        ensure!(resumed.len() == 1, "settled proof was submitted again");
        let authority = contract
            .getSynchronizedDkgAuthority(numeric_id)
            .call()
            .await
            .context("read confirmed synchronized authority")?;
        ensure!(
            authority.version == 1
                && authority.verifier == wrapper
                && authority.pkCommitment.0 == commitment
                && authority.keyBundleCommits
                    == setup
                        .dealers
                        .iter()
                        .map(|&party| B256::from(setups[party as usize].key_bundle))
                        .collect::<Vec<_>>()
        );
        for receipt in receipts {
            history.extend(self.decode(&receipt, registry).await?);
        }
        ensure!(
            ICiphernodeRegistry::new(registry, &self.provider)
                .committeePublicKey(numeric_id)
                .call()
                .await?
                .0
                == commitment
        );
        let bytes = public_key.to_bytes();
        // Receipt success alone did not install authority in the shared projection.
        ensure!(writer_keys.get(id).is_none());
        let (recovered_keys, pending) =
            reopen_history(&history, directory, self.controller).await?;
        ensure!(pending.is_empty());
        ensure!(recovered_keys.public_key(id).as_deref() == Some(bytes.as_slice()));
        let key = recovered_keys
            .get(id)
            .context("lost confirmed synchronized authority")?;
        let CanonicalDkgAnchors::Synchronized(authority) = key.dkg_anchors else {
            anyhow::bail!("SS authority substituted");
        };
        ensure!(
            authority.party_ids == setup.dealers
                && authority.threshold_pk_commits == setup.threshold_keys
        );
        for (owner, (root, _)) in recovered.iter().enumerate() {
            let saved = root.synchronized.as_ref().unwrap();
            let selection = root.ciphernode_selected.as_ref().unwrap();
            let cipher = cipher(owner).await?;
            let handoff =
                local_setups[owner].confirmed_setup(self.controller, &recovered_keys, &cipher)?;
            ensure!(
                handoff.recipient() == owner as u32
                    && handoff.public_key()[..] == bytes
                    && handoff.sk_commitment() == setups[owner].sk_commitment
                    && handoff.key_bundle() == setups[owner].key_bundle
            );
            let mut changed = setups[owner].clone();
            changed.dealer_batch[31] ^= 1;
            ensure!(saved
                .confirmed_setup(
                    selection,
                    self.controller,
                    &recovered_keys,
                    &changed,
                    &cipher
                )
                .is_err());
            ensure!(saved
                .confirmed_setup(
                    selection,
                    self.controller,
                    &recovered_keys,
                    &setups[owner],
                    &*super::cipher((owner + 1) % 3).await?
                )
                .is_err());
            if !setup.dealers.contains(&(owner as u32)) {
                ensure!(saved
                    .attest_publication(
                        selection,
                        self.controller,
                        &recovered_keys,
                        &setups[owner],
                        public_key,
                        &signers[owner],
                        &cipher
                    )
                    .is_err());
            }
        }
        ensure!(recovered_keys.decryption_domains(id).is_none() && !PROFILE.admission_enabled());
        decryption::qualify(
            self,
            registry,
            recovered,
            &local_setups,
            signers,
            prover,
            history,
            public_key,
            directory,
        )
        .await?;
        Ok(())
    }
}

#[path = "decryption.rs"]
mod decryption;

async fn reopen_history(
    history: &[InterfoldEvent<Unsequenced>],
    directory: &Path,
    controller: Address,
) -> Result<(
    CanonicalPublicKeys,
    Vec<e3_events::SynchronizedDkgPublicationReady>,
)> {
    let logs = directory.join("authority-journal");
    let index = directory.join("authority-index");
    let chain = AggregateId::new(31337);
    let config = AggregateConfig::new(HashMap::from([(chain, Duration::ZERO)]));
    {
        let system = EventSystem::persisted(logs.clone(), index.clone())
            .with_fresh_bus()
            .with_aggregate_config(config.clone());
        let store = system.store()?;
        let reader = system.eventstore_reader()?.seq();
        let fresh =
            e3_sync::preflight_schema_version(&store.repositories(), &config, &reader).await?;
        e3_sync::preflight_node_role(&store.repositories(), fresh, e3_sync::NodeRole::Full).await?;
        let bus = system
            .handle()?
            .enable("real-synchronized-authority-journal");
        for event in history {
            bus.publish_from_remote(
                event.get_data().clone(),
                event.ts(),
                event.block(),
                event.source(),
            )?;
        }
        bus.flush_event_pipeline().await?;
        system
            .buffer()?
            .send(e3_events::FlushPendingSnapshots)
            .await??;
        if let EventStoreAddrs::Persisted(stores) = system.eventstore_addrs()? {
            for actor in stores.values() {
                actor.send(StopForReopen).await??;
            }
        }
        store.shutdown().await?;
    }
    SledDb::close_all_connections();
    let system = EventSystem::persisted(logs, index)
        .with_fresh_bus()
        .with_aggregate_config(config);
    let keys = CanonicalPublicKeys::default();
    let mut projection =
        CanonicalKeyProjection::new(keys.clone(), HashMap::from([(31337, controller)]));
    projection
        .recover(&system.eventstore_reader()?.seq(), &[chain], HashSet::new())
        .await?;
    let pending =
        e3_evm::recover_synchronized_publications(&system.eventstore_reader()?.seq(), 31337, &keys)
            .await?;
    if let EventStoreAddrs::Persisted(stores) = system.eventstore_addrs()? {
        for actor in stores.values() {
            actor.send(StopForReopen).await??;
        }
    }
    system.store()?.shutdown().await?;
    SledDb::close_all_connections();
    Ok((keys, pending))
}
