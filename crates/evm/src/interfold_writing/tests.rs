// SPDX-License-Identifier: LGPL-3.0-only

//! Publication recovery through the production startup replay path.

use super::*;
use alloy::{
    network::EthereumWallet, providers::ProviderBuilder, signers::local::PrivateKeySigner,
    transports::mock::Asserter,
};
use e3_ciphernode_builder::EventSystem;
use e3_data::{Repositories, RepositoriesFactory};
use e3_events::{
    AggregateConfig, AggregateId, CiphertextOutputPublished, CircuitName, EventSource,
    EventStoreQueryBy, EvmEventConfig, EvmEventConfigChain, HistoricalEvmEventsReceived, SeqAgg,
    Unsequenced,
};
use e3_fhe_params::BfvPreset;
use e3_request::canonical_key::CanonicalPublicKey;
use e3_utils::ArcBytes;
use e3_zk_helpers::CiphernodesCommitteeSize;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[derive(Message)]
#[rtype(result = "(usize, usize)")]
struct PlaintextWork;

impl<P: Provider + WalletProvider + Clone + 'static> Handler<PlaintextWork>
    for InterfoldSolWriter<P>
{
    type Result = MessageResult<PlaintextWork>;

    fn handle(&mut self, _: PlaintextWork, _: &mut Self::Context) -> Self::Result {
        MessageResult((
            self.deferred_plaintexts.len(),
            self.publication.pending_keys().len(),
        ))
    }
}

struct EmptyChainHistory;

impl Actor for EmptyChainHistory {
    type Context = Context<Self>;
}

impl Handler<InterfoldEvent> for EmptyChainHistory {
    type Result = ();

    fn handle(&mut self, event: InterfoldEvent, _: &mut Self::Context) {
        if let InterfoldEventData::HistoricalEvmSyncStart(start) = event.into_data() {
            start
                .sender
                .unwrap()
                .try_send(HistoricalEvmEventsReceived::new(vec![], 1))
                .unwrap();
        }
    }
}

struct QueryCounter {
    store: Recipient<EventStoreQueryBy<SeqAgg>>,
    count: Arc<AtomicUsize>,
}

impl Actor for QueryCounter {
    type Context = Context<Self>;
}

impl Handler<EventStoreQueryBy<SeqAgg>> for QueryCounter {
    type Result = ResponseFuture<()>;

    fn handle(&mut self, query: EventStoreQueryBy<SeqAgg>, _: &mut Self::Context) -> Self::Result {
        assert_eq!(query.limit(), Some(1024));
        assert_eq!(query.max_bytes(), Some(16 * 1024 * 1024));
        self.count.fetch_add(1, Ordering::SeqCst);
        let store = self.store.clone();
        Box::pin(async move { store.send(query).await.unwrap() })
    }
}

struct ReplayFixture {
    source: EventSystem,
    source_bus: BusHandle,
    bus: BusHandle,
    repositories: Repositories,
    config: AggregateConfig,
    next_timestamp: u128,
}

impl ReplayFixture {
    async fn new() -> Result<Self> {
        let config = AggregateConfig::new(HashMap::from([(AggregateId::new(1), Duration::ZERO)]));
        let source = EventSystem::new()
            .with_fresh_bus()
            .with_aggregate_config(config.clone());
        let source_bus = source.handle()?.enable("publication-history");
        let destination = EventSystem::new()
            .with_fresh_bus()
            .with_aggregate_config(config.clone());
        let bus = destination.handle()?.enable("publication-restart");
        let repositories = destination.store()?.repositories();
        e3_sync::preflight_schema_version(
            &repositories,
            &config,
            &destination.eventstore_reader()?.seq(),
        )
        .await?;
        e3_request::ensure_request_router_checkpoint(&repositories, config.aggregates()).await?;
        bus.subscribe(
            EventType::HistoricalEvmSyncStart,
            EmptyChainHistory.start().recipient(),
        );
        Ok(Self {
            source,
            source_bus,
            bus,
            repositories,
            config,
            next_timestamp: 1,
        })
    }

    async fn store(
        &mut self,
        data: impl Into<InterfoldEventData>,
        source: EventSource,
        block: Option<u64>,
    ) -> Result<()> {
        let event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
            data.into(),
            None,
            self.next_timestamp,
            block,
            source,
        );
        self.next_timestamp += 1;
        self.source_bus.naked_dispatch_async(event).await
    }

    async fn replay(&self) -> Result<()> {
        self.source_bus.flush_event_pipeline().await?;
        let mut config = EvmEventConfig::new();
        config.insert(1, EvmEventConfigChain::new(0));
        // Pause startup after ReplaySpool delivery and before enabling external effects.
        let result = e3_sync::sync_with_net_ready(
            &self.bus,
            &config,
            &self.repositories,
            &self.config,
            &self.source.eventstore_reader()?.seq(),
            std::future::ready(Err(anyhow::anyhow!("network readiness pending"))),
        )
        .await;
        assert_eq!(result.unwrap_err().to_string(), "network readiness pending");
        Ok(())
    }
}

async fn provider() -> Result<EthProvider<impl Provider + WalletProvider + Clone + 'static>> {
    let asserter = Asserter::new();
    asserter.push_success(&"0x1");
    EthProvider::new(
        ProviderBuilder::new()
            .wallet(EthereumWallet::from(PrivateKeySigner::random()))
            .connect_mocked_client(asserter),
    )
    .await
}

fn key() -> CanonicalPublicKey {
    CanonicalPublicKey {
        pk_commitment: [7; 32],
        committee: vec![Address::repeat_byte(1); 3],
        honest_committee: vec![Address::repeat_byte(1); 2],
        params_preset: BfvPreset::InsecureThreshold512,
        committee_size: CiphernodesCommitteeSize::Minimum,
        interfold_address: Address::repeat_byte(9),
        sk_agg_commits: vec![],
        esm_agg_commits: vec![],
    }
}

fn intent(id: &E3id, keys: &CanonicalPublicKeys, value: u64) -> PlaintextAggregated {
    let mut signals = vec![0; 7 * 32];
    if let Some(domains) = keys.decryption_domains(id) {
        signals[4 * 32..5 * 32].copy_from_slice(&U256::from(domains[0].hi).to_be_bytes::<32>());
        signals[5 * 32..6 * 32].copy_from_slice(&U256::from(domains[0].lo).to_be_bytes::<32>());
    }
    PlaintextAggregated {
        e3_id: id.clone(),
        decrypted_output: vec![ArcBytes::from_bytes(&value.to_be_bytes())],
        decryption_aggregator_proofs: vec![Proof::new(
            CircuitName::DecryptionAggregator,
            ArcBytes::from_bytes(&[1]),
            ArcBytes::from_bytes(&signals),
        )],
    }
}

#[actix::test]
async fn replay_retires_terminal_plaintext_work() -> Result<()> {
    for stage in [E3Stage::Complete, E3Stage::Failed] {
        for recovered_authority in [false, true] {
            let mut fixture = ReplayFixture::new().await?;
            let id = E3id::new("42", 1);
            let waiting = E3id::new("43", 1);
            let keys = CanonicalPublicKeys::default();
            keys.insert(id.clone(), key())?;
            keys.remember_ciphertexts(&id, &[ArcBytes::from_bytes(&[3])])?;
            fixture
                .store(intent(&id, &keys, 1), EventSource::Local, None)
                .await?;
            fixture
                .store(
                    E3RequestComplete { e3_id: id.clone() },
                    EventSource::Local,
                    None,
                )
                .await?;
            fixture
                .store(
                    E3StageChanged {
                        e3_id: id.clone(),
                        previous_stage: E3Stage::CiphertextReady,
                        new_stage: stage.clone(),
                    },
                    EventSource::Evm,
                    Some(42),
                )
                .await?;
            fixture
                .store(intent(&id, &keys, 2), EventSource::Local, None)
                .await?;
            fixture
                .store(intent(&waiting, &keys, 3), EventSource::Local, None)
                .await?;
            for (source, block) in [(EventSource::Net, Some(42)), (EventSource::Evm, None)] {
                fixture
                    .store(
                        E3StageChanged {
                            e3_id: waiting.clone(),
                            previous_stage: E3Stage::CiphertextReady,
                            new_stage: E3Stage::Complete,
                        },
                        source,
                        block,
                    )
                    .await?;
            }
            fixture.source_bus.flush_event_pipeline().await?;
            let mut projection = crate::canonical_key::CanonicalKeyProjection::new(
                keys.clone(),
                HashMap::from([(1, key().interfold_address)]),
            );
            if recovered_authority {
                projection
                    .recover(
                        &fixture.source.eventstore_reader()?.seq(),
                        &[AggregateId::new(1)],
                        HashSet::new(),
                    )
                    .await?;
                assert!(keys.get(&id).is_none());
            }
            let terminal_e3s = projection.confirmed_terminal_e3s();
            assert_eq!(terminal_e3s.contains(&id), recovered_authority);
            assert!(!terminal_e3s.contains(&waiting));
            projection.attach(&fixture.bus).await?;
            let writer = InterfoldSolWriter::new_with_recovery(
                &fixture.bus,
                provider().await?,
                key().interfold_address,
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashSet::new(),
                terminal_e3s,
                keys,
                fixture.source.eventstore_reader()?.seq(),
            )?
            .start();
            fixture
                .bus
                .subscribe(EventType::All, writer.clone().recipient());
            fixture.replay().await?;
            assert_eq!(
                writer.send(PlaintextWork).await?,
                (1, 0),
                "terminal {stage:?} work survived replay"
            );
        }
    }
    Ok(())
}

#[actix::test]
async fn many_completed_e3s_keep_only_active_plaintext_history_ranges() -> Result<()> {
    let mut fixture = ReplayFixture::new().await?;
    let keys = CanonicalPublicKeys::default();
    let mut stages = HashMap::new();
    for number in 1..=128 {
        let id = E3id::new(number.to_string(), 1);
        fixture
            .store(intent(&id, &keys, number), EventSource::Local, None)
            .await?;
        fixture
            .store(
                E3StageChanged {
                    e3_id: id.clone(),
                    previous_stage: E3Stage::CiphertextReady,
                    new_stage: E3Stage::Complete,
                },
                EventSource::Evm,
                Some(42),
            )
            .await?;
        stages.insert(id, E3Stage::Complete);
    }
    let waiting = E3id::new("129", 1);
    let expected_keys = CanonicalPublicKeys::default();
    expected_keys.insert(waiting.clone(), key())?;
    let ciphertext = vec![ArcBytes::from_bytes(&[3])];
    expected_keys.remember_ciphertexts(&waiting, &ciphertext)?;
    for number in 1..=1025 {
        let authority = if number == 1025 {
            &expected_keys
        } else {
            &keys
        };
        fixture
            .store(
                intent(&waiting, authority, number),
                EventSource::Local,
                None,
            )
            .await?;
    }
    let count = Arc::new(AtomicUsize::new(0));
    let store = QueryCounter {
        store: fixture.source.eventstore_reader()?.seq(),
        count: count.clone(),
    }
    .start()
    .recipient();
    let writer = InterfoldSolWriter::new_with_recovery(
        &fixture.bus,
        provider().await?,
        key().interfold_address,
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        HashSet::new(),
        stages.into_keys().collect(),
        keys.clone(),
        store,
    )?
    .start();
    fixture
        .bus
        .subscribe(EventType::All, writer.clone().recipient());
    fixture.replay().await?;
    assert_eq!(
        writer.send(PlaintextWork).await?,
        (1, 0),
        "completed intents or repeated waiting payloads were retained"
    );
    assert_eq!(count.load(Ordering::SeqCst), 0);

    keys.insert(waiting.clone(), key())?;
    keys.remember_ciphertexts(&waiting, &ciphertext)?;
    let output = CiphertextOutputPublished {
        e3_id: waiting,
        ciphertext_output: ciphertext,
        ciphertext_commitment: [0; 32],
    };
    writer
        .send(
            InterfoldEvent::<Unsequenced>::new_with_timestamp(
                output.into(),
                None,
                2048,
                Some(43),
                EventSource::Evm,
            )
            .into_sequenced(2048),
        )
        .await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if writer.send(PlaintextWork).await.unwrap() == (0, 1) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(
        count.load(Ordering::SeqCst),
        2,
        "deferred history was not paged once"
    );
    Ok(())
}
