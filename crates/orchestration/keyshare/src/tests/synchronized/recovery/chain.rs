// SPDX-License-Identifier: LGPL-3.0-only

//! Real registry/proof/signature qualification below disabled request admission. Only the
//! finalized committee and controller lifecycle are harnessed. Decryption uses the writer effect.

use super::{
    publication::{RecipientJoinWork, Recovered},
    *,
};
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
use e3_events::{AggregateConfig, AggregateId, E3Requested, SynchronizedRecipientProofReady};
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
    pub cli: Option<cli::CliRequest>,
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
            cli: None,
        })
    }

    async fn decode(
        &self,
        receipt: &TransactionReceipt,
        contract: Address,
    ) -> Result<Vec<InterfoldEvent<Unsequenced>>> {
        ensure!(receipt.status(), "qualification transaction reverted");
        self.decode_logs(receipt.logs(), contract).await
    }

    async fn decode_logs(
        &self,
        logs: &[alloy::rpc::types::Log],
        contract: Address,
    ) -> Result<Vec<InterfoldEvent<Unsequenced>>> {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let collector = Decoded(tx).start();
        let next = collector.clone().recipient();
        let reader = if contract == self.controller {
            e3_evm::InterfoldSolReader::setup(&next).recipient()
        } else {
            CiphernodeRegistrySolReader::setup_with_factory(
                &next,
                e3_evm::EthProvider::new(self.provider.clone()).await?,
                None,
                0,
            )
            .recipient()
        };
        let mut events = Vec::new();
        for log in logs.iter().filter(|log| log.address() == contract) {
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
                .context("contract decoder stopped")?
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
                other => anyhow::bail!("contract decoder rejected mined log: {other:?}"),
            }
        }
        collector.send(StopForReopen).await??;
        Ok(events)
    }

    async fn seeded_history(
        &self,
        selected: &CiphernodeSelected,
        committee: &[Address],
        directory: &Path,
    ) -> Result<(Address, Address, Vec<InterfoldEvent<Unsequenced>>)> {
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
        let configured = FixtureController::new(self.controller, &self.provider)
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
        ensure!(configured.status());
        let receipt = FixtureRegistry::new(registry, &self.provider)
            .seed(
                numeric_id,
                self.controller,
                committee
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
        Ok((registry, wrapper, history))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn qualify(
        &self,
        recovered: &[Recovered],
        recipients: &BTreeMap<u32, SynchronizedRecipientProofReady>,
        late: &RecipientJoinWork,
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
        let committee = selected
            .committee
            .iter()
            .map(|member| member.parse::<Address>())
            .collect::<Result<Vec<_>, _>>()?;
        let (registry, wrapper, mut history) = match &self.cli {
            Some(cli) => (cli.registry, cli.dkg, cli.history.clone()),
            None => self.seeded_history(selected, &committee, directory).await?,
        };
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
        let mut local_setups = BTreeMap::new();
        let setup = &recipients[&0].setup;
        ensure!(recipients.keys().copied().eq(setup.dealers.iter().copied()));
        for (&party, result) in recipients {
            let owner = party as usize;
            use super::super::publication::{actor, consents, DriveSetup, SetupCheckpoint};
            let path = directory.join(format!("consent-{owner}"));
            let store = DataStore::from_sled_store(&SledStore::new(&bus, &path)?);
            let root = recovered[owner].0.clone();
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
                result: Some(TypedEvent::new(result.clone(), test_ec(700))),
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
            let [event] = output.as_slice() else {
                anyhow::bail!("expected one H consent")
            };
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
            local_setups.insert(owner, saved);
            node.send(Die).await?;
            drop(node);
            store.shutdown().await?;
        }
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
        // A second finalized E3 with the same committee, profile and verifier cannot reuse
        // this publication. No missing verifier, different roster or absent request explains it.
        if self.cli.is_none() {
            let other = numeric_id + U256::from(1);
            let configured = FixtureController::new(self.controller, &self.provider)
                .configure(other, registry, wrapper, selected.crypto_config_id.into())
                .send()
                .await?
                .get_receipt()
                .await?;
            let finalized = FixtureRegistry::new(registry, &self.provider)
                .seed(
                    other,
                    self.controller,
                    committee.clone().try_into().unwrap(),
                )
                .send()
                .await?
                .get_receipt()
                .await?;
            ensure!(configured.status() && finalized.status());
            let error = contract
                .publishSynchronizedCommittee(other, publication.clone())
                .call()
                .await
                .expect_err("a different finalized E3 accepted the signed publication");
            ensure!(
                error
                    .as_decoded_error::<ISynchronizedDkgPublication::InvalidPublication>()
                    .is_some(),
                "{error:#}"
            );
        }
        if let Some(export) = std::env::var_os("E3_SYNC_OTHER_PROFILE_EXPORT") {
            let dkg: Value =
                serde_json::from_slice(&fs::read(Path::new(&export).join("publication.json"))?)?;
            let foreign_id: B256 = serde_json::from_value(dkg["crypto_config_id"].clone())?;
            let other_profile = if selected.params_profile == PROFILE {
                BfvProfile::SyncDecSecure8192
            } else {
                PROFILE
            };
            ensure!(foreign_id == other_profile.crypto_config_id(COMMITTEE)?);
            let raw: Bytes = serde_json::from_value(dkg["proof"].clone())?;
            let fields: Vec<B256> = serde_json::from_value(dkg["public_inputs"].clone())?;
            let mut foreign = publication.clone();
            foreign.proof = (raw, fields).abi_encode_params().into();
            let error = contract
                .publishSynchronizedCommittee(numeric_id, foreign)
                .call()
                .await
                .expect_err("accepted another profile's DKG proof");
            ensure!(
                error
                    .as_decoded_error::<ISynchronizedDkgPublication::InvalidPublication>()
                    .is_some(),
                "{error:#}"
            );
        }
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
        let writer_keys = CanonicalPublicKeys::default();
        let pending = reopen_history(
            &history,
            &directory.join("writer-recovery"),
            self.controller,
            &writer_keys,
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
        let in_flight = late_setup::dispatch(late.clone(), prover.clone(), id.clone());
        let receipts = e3_evm::publish_synchronized_committee_definition(
            publisher.clone(),
            &writer_keys,
            &pending[0],
        )
        .await?;
        let published_key = e3_test_support::BenchmarkInstant::now();
        ensure!(
            receipts.len() == 2,
            "expected the proof receipt and final key-chunk receipt"
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
                && authority.cryptoConfigId == B256::from(selected.crypto_config_id)
                && authority.pkCommitment.0 == commitment
                && authority.keyBundleCommits
                    == setup
                        .dealers
                        .iter()
                        .map(|party| B256::from(recipients[party].setup.key_bundle))
                        .collect::<Vec<_>>()
        );
        let controller_logs = self.decode(&receipts[0], self.controller).await?;
        let stage = controller_logs
            .iter()
            .find(|event| {
                matches!(event.get_data(),
            InterfoldEventData::E3StageChanged(change) if &change.e3_id == id
                && change.new_stage == E3Stage::KeyPublished)
            })
            .context("publication receipt has no KeyPublished callback")?
            .clone();
        history.extend(controller_logs);
        // The writer returns the final key-chunk receipt. Confirmed history must include
        // every earlier chunk, too, when the secure public key spans transactions.
        let logs = self
            .provider
            .get_logs(
                &alloy::rpc::types::Filter::new()
                    .address(registry)
                    .from_block(receipts[0].block_number.context("unmined DKG")?)
                    .to_block(receipts[1].block_number.context("unmined public key")?),
            )
            .await?;
        history.extend(self.decode_logs(&logs, registry).await?);
        eprintln!(
            "{} signed DKG: {} gas, {} public key bytes",
            selected.params_profile,
            receipts[0].gas_used,
            public_key.to_bytes().len()
        );
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
        let outside = late.request.context.party_id as usize;
        ensure!(outside == 1 && !local_setups.contains_key(&outside));
        let recovered_keys = CanonicalPublicKeys::default();
        let saved = Box::pin(late_setup::qualify(
            late,
            in_flight,
            prover,
            &recovered[outside].0,
            &signers[outside],
            stage,
            &history,
            &recovered_keys,
            directory,
            &bus,
        ))
        .await?;
        local_setups.insert(outside, saved);
        ensure!(recovered_keys.public_key(id).as_deref() == Some(bytes.as_slice()));
        let key = recovered_keys
            .get(id)
            .context("lost confirmed synchronized authority")?;
        let CanonicalDkgAnchors::Synchronized(authority) = &key.dkg_anchors else {
            anyhow::bail!("SS authority substituted");
        };
        ensure!(
            authority.party_ids == setup.dealers
                && authority.threshold_pk_commits == setup.threshold_keys
        );
        let local_setups: Vec<_> = local_setups.into_values().collect();
        for (owner, (root, _)) in recovered.iter().enumerate() {
            let saved = root.synchronized.as_ref().unwrap();
            let selection = root.ciphernode_selected.as_ref().unwrap();
            let cipher = cipher(owner).await?;
            let handoff =
                local_setups[owner].confirmed_setup(self.controller, &recovered_keys, &cipher)?;
            let anchors = &local_setups[owner].result().setup;
            ensure!(
                handoff.recipient() == owner as u32
                    && handoff.public_key()[..] == bytes
                    && handoff.sk_commitment() == saved.sk_commitment.unwrap()
                    && handoff.key_bundle() == saved.key_bundle.unwrap()
            );
            let mut changed = anchors.clone();
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
                    anchors,
                    &*super::cipher((owner + 1) % 3).await?
                )
                .is_err());
            if !setup.dealers.contains(&(owner as u32)) {
                ensure!(saved
                    .attest_publication(
                        selection,
                        self.controller,
                        &recovered_keys,
                        anchors,
                        public_key,
                        &signers[owner],
                        &cipher
                    )
                    .is_err());
            }
        }
        ensure!(
            recovered_keys.decryption_domains(id).is_none()
                && !selected.params_profile.admission_enabled()
        );
        Box::pin(decryption::qualify(
            self,
            registry,
            recovered,
            &local_setups,
            signers,
            prover,
            history,
            public_key,
            directory,
            cli::Publication {
                receipt: &receipts[0],
                observed: published_key,
            },
        ))
        .await?;
        Ok(())
    }
}

#[path = "cli.rs"]
mod cli;
#[path = "decryption.rs"]
mod decryption;
#[path = "late_setup.rs"]
mod late_setup;

/// Reopen both the commit log and the Sled stores (sequence index, snapshots and plaintext pins).
struct DiskJournal {
    system: EventSystem,
    db: DataStore,
    bus: BusHandle,
    reader: actix::Recipient<e3_events::EventStoreQueryBy<e3_events::SeqAgg>>,
}

impl DiskJournal {
    async fn open(directory: &Path, name: &str) -> Result<Self> {
        let config =
            AggregateConfig::new(HashMap::from([(AggregateId::new(31337), Duration::ZERO)]));
        let system = EventSystem::persisted(
            directory.join(format!("{name}-journal")),
            directory.join(format!("{name}-index")),
        )
        .with_event_bus(EventBus::new(EventBusConfig { deduplicate: false }).start())
        .with_aggregate_config(config.clone());
        let db = system.store()?;
        let reader = system.eventstore_reader()?.seq();
        let fresh = e3_sync::preflight_schema_version(&db.repositories(), &config, &reader).await?;
        e3_sync::preflight_node_role(&db.repositories(), fresh, e3_sync::NodeRole::Full).await?;
        let bus = system
            .enable_handle_with_hlc(e3_events::hlc::Hlc::new(7))
            .await?;
        Ok(Self {
            system,
            db,
            bus,
            reader,
        })
    }

    async fn close(self) -> Result<()> {
        self.bus.publish_shutdown_and_wait().await?;
        self.bus.flush_event_pipeline().await?;
        let EventStoreAddrs::Persisted(stores) = self.system.eventstore_addrs()? else {
            anyhow::bail!("qualification requires a disk journal");
        };
        for actor in stores.values() {
            actor.send(StopForReopen).await??;
        }
        self.db.shutdown().await?;
        drop(self);
        SledDb::close_all_connections();
        Ok(())
    }
}

async fn reopen_history(
    history: &[InterfoldEvent<Unsequenced>],
    directory: &Path,
    controller: Address,
    keys: &CanonicalPublicKeys,
) -> Result<Vec<e3_events::SynchronizedDkgPublicationReady>> {
    let chain = AggregateId::new(31337);
    let node = DiskJournal::open(directory, "authority").await?;
    for event in history {
        node.bus.publish_from_remote(
            event.get_data().clone(),
            event.ts(),
            event.block(),
            event.source(),
        )?;
    }
    node.close().await?;
    let node = DiskJournal::open(directory, "authority").await?;
    let mut projection =
        CanonicalKeyProjection::new(keys.clone(), HashMap::from([(31337, controller)]));
    projection
        .recover(&node.reader, &[chain], HashSet::new())
        .await?;
    let pending = e3_evm::recover_synchronized_publications(&node.reader, 31337, keys).await?;
    node.close().await?;
    Ok(pending)
}
