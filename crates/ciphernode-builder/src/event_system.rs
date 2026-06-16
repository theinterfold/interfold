// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::get_interfold_event_bus;
use crate::global_eventstore_cache::{share_eventstore_reader, EventStoreReader};
use crate::global_store_cache::share_store;
use actix::{Actor, Addr, Handler, Recipient};
use anyhow::{anyhow, Result};
use e3_data::{
    CommitLogEventLog, DataStore, InMemEventLog, InMemSequenceIndex, InMemStore, SledSequenceIndex,
    SledStore,
};
use e3_events::hlc_factory::HlcFactory;
use e3_events::{
    AggregateConfig, BusHandle, Disabled, EventBus, EventBusConfig, EventStore, EventStoreRouter,
    EventSubscriber, EventType, InsertBatch, InterfoldEvent, Sequencer, SnapshotBuffer,
    StoreEventRequested, UpdateDestination,
};
use e3_utils::enumerate_path;
use once_cell::sync::OnceCell;
use std::collections::HashMap;
use std::path::PathBuf;

struct InMemBackend {
    eventstores: OnceCell<HashMap<usize, Addr<EventStore<InMemSequenceIndex, InMemEventLog>>>>,
    store: OnceCell<Addr<InMemStore>>,
}

impl InMemBackend {
    fn get_or_init_store(&self) -> Addr<InMemStore> {
        self.store
            .get_or_init(|| InMemStore::new(true).start())
            .clone()
    }
}

/// Hold the Persistent EventStore instance and SledStore
struct PersistedBackend {
    log_path: PathBuf,
    sled_path: PathBuf,
    eventstores: OnceCell<HashMap<usize, Addr<EventStore<SledSequenceIndex, CommitLogEventLog>>>>,
    store: OnceCell<Addr<SledStore>>,
}

impl PersistedBackend {
    fn get_or_init_store(&self, handle: &BusHandle<Disabled>) -> Result<Addr<SledStore>> {
        self.store
            .get_or_try_init(|| SledStore::new(handle, &self.sled_path))
            .cloned()
    }
}

/// An EventSystemBackend is holding the potentially persistent structures for the system
enum EventSystemBackend {
    InMem(InMemBackend),
    Persisted(PersistedBackend),
}

#[derive(Clone)]
pub enum EventStoreAddrs {
    InMem(HashMap<usize, Addr<EventStore<InMemSequenceIndex, InMemEventLog>>>),
    Persisted(HashMap<usize, Addr<EventStore<SledSequenceIndex, CommitLogEventLog>>>),
}

/// EventSystem holds interconnected references to the components that manage events and
/// persistence within the node. The EventSystem connects:
///
/// - **BusHandle** for interacting with the event system
/// - **EventBus** for managing publishing of events to listeners
/// - **EventStore** for managing persistence of events
/// - **Sequencer** for managing sequencing of event persistence and snapshot coordination
/// - **WriteBuffer** for batching inserts from actors into a snapshot
///
pub struct EventSystem {
    /// EventSystem backend either persisted or in memory
    backend: EventSystemBackend,
    /// WriteBuffer for batching inserts from actors into a snapshot
    buffer: OnceCell<Addr<SnapshotBuffer>>,
    /// EventSystem Sequencer
    sequencer: OnceCell<Addr<Sequencer>>,
    /// EventSystem eventbus
    eventbus: OnceCell<Addr<EventBus<InterfoldEvent>>>,
    /// EventSystem BusHandle
    handle: OnceCell<BusHandle<Disabled>>,
    /// Central configuration for aggregates, including delays and other settings
    aggregate_config: OnceCell<AggregateConfig>,
    /// Cached EventStoreAddrs for idempotency
    eventstore_addrs: OnceCell<EventStoreAddrs>,
    /// Global shared store. This can allow commands to access the database while a node is running.
    global_shared_store: bool,
    /// Global shared eventstore. This can allow commands to access the eventstore while a node is
    /// running.
    global_shared_eventstore: bool,
}

impl Default for EventSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl EventSystem {
    /// Create a new in memory EventSystem with default settings
    pub fn new() -> Self {
        EventSystem::in_mem()
    }

    /// Create an in memory EventSystem
    pub fn in_mem() -> Self {
        Self {
            backend: EventSystemBackend::InMem(InMemBackend {
                eventstores: OnceCell::new(),
                store: OnceCell::new(),
            }),
            buffer: OnceCell::new(),
            sequencer: OnceCell::new(),
            eventbus: OnceCell::new(),
            handle: OnceCell::new(),
            aggregate_config: OnceCell::new(),
            eventstore_addrs: OnceCell::new(),
            global_shared_store: false,
            global_shared_eventstore: false,
        }
    }

    /// Create an in memory EventSystem with a given store
    pub fn in_mem_from_store(store: &Addr<InMemStore>) -> Self {
        Self {
            backend: EventSystemBackend::InMem(InMemBackend {
                eventstores: OnceCell::new(),
                store: OnceCell::from(store.to_owned()),
            }),
            buffer: OnceCell::new(),
            sequencer: OnceCell::new(),
            eventbus: OnceCell::new(),
            handle: OnceCell::new(),
            aggregate_config: OnceCell::new(),
            eventstore_addrs: OnceCell::new(),
            global_shared_store: false,
            global_shared_eventstore: false,
        }
    }

    /// Create a persisted EventSystem with datafiles at the given paths
    pub fn persisted(log_path: PathBuf, sled_path: PathBuf) -> Self {
        Self {
            backend: EventSystemBackend::Persisted(PersistedBackend {
                log_path,
                sled_path,
                eventstores: OnceCell::new(),
                store: OnceCell::new(),
            }),
            buffer: OnceCell::new(),
            sequencer: OnceCell::new(),
            eventbus: OnceCell::new(),
            handle: OnceCell::new(),
            aggregate_config: OnceCell::new(),
            eventstore_addrs: OnceCell::new(),
            global_shared_store: false,
            global_shared_eventstore: false,
        }
    }

    /// Pass in a specific given event bus
    pub fn with_event_bus(self, bus: Addr<EventBus<InterfoldEvent>>) -> Self {
        let _ = self.eventbus.set(bus);
        self
    }

    /// Use a fresh event bus that is not the default singleton instance
    pub fn with_fresh_bus(self) -> Self {
        let _ = self
            .eventbus
            .set(EventBus::new(EventBusConfig { deduplicate: true }).start());
        self
    }

    /// Add aggregate configuration including delays and other settings
    pub fn with_aggregate_config(self, config: AggregateConfig) -> Self {
        let _ = self.aggregate_config.set(config);
        self
    }

    /// Share the store with other processes
    pub fn with_global_shared_store(mut self, value: bool) -> Self {
        self.global_shared_store = value;
        self
    }

    /// Share the store with other processes
    pub fn with_global_shared_eventstore(mut self, value: bool) -> Self {
        self.global_shared_eventstore = value;
        self
    }

    /// Get the eventbus address
    pub fn eventbus(&self) -> Addr<EventBus<InterfoldEvent>> {
        self.eventbus.get_or_init(get_interfold_event_bus).clone()
    }

    /// Get the aggregate configuration
    pub fn aggregate_config(&self) -> AggregateConfig {
        self.aggregate_config
            .get_or_init(|| AggregateConfig::new(HashMap::new()))
            .clone()
    }

    /// Get the buffer address
    pub fn buffer(&self) -> Result<Addr<SnapshotBuffer>> {
        self.buffer
            .get_or_try_init(|| {
                SnapshotBuffer::spawn(&self.aggregate_config(), NoopBatchReceiver::new().start())
            })
            .cloned()
    }

    /// Get the sequencer address
    pub fn sequencer(&self) -> Result<Addr<Sequencer>> {
        self.sequencer
            .get_or_try_init(|| {
                let router = self.eventstore_router()?;
                Ok(Sequencer::new(&self.eventbus(), router).start())
            })
            .cloned()
    }

    /// Get the EventStore addresses
    pub fn eventstore_addrs(&self) -> Result<EventStoreAddrs> {
        self.eventstore_addrs
            .get_or_try_init(|| {
                match &self.backend {
                    EventSystemBackend::InMem(b) => {
                        let config = self.aggregate_config();
                        let indexes = config.indexed_ids();

                        let addrs = b
                            .eventstores
                            .get_or_init(|| {
                                let mut eventstore_map = HashMap::new();
                                for &index in &indexes {
                                    eventstore_map.insert(
                                        index,
                                        EventStore::new(
                                            InMemSequenceIndex::new(),
                                            InMemEventLog::new(),
                                        )
                                        .start(),
                                    );
                                }
                                eventstore_map
                            })
                            .clone();
                        Ok(EventStoreAddrs::InMem(addrs))
                    }
                    EventSystemBackend::Persisted(b) => {
                        let config = self.aggregate_config();
                        let indexes = config.indexed_ids();

                        let addrs = b
                            .eventstores
                            .get_or_try_init(|| -> Result<_> {
                                let mut eventstore_map = HashMap::new();
                                for &index in &indexes {
                                    // Enumerate the log path for each eventstore
                                    let enumerated_log_path = enumerate_path(&b.log_path, index);
                                    let tree_name = format!("sequence_index.{}", index);
                                    let index_store =
                                        SledSequenceIndex::new(&b.sled_path, &tree_name)?;
                                    let log = CommitLogEventLog::new(&enumerated_log_path)?;
                                    eventstore_map
                                        .insert(index, EventStore::new(index_store, log).start());
                                }
                                Ok(eventstore_map)
                            })?
                            .clone();
                        Ok(EventStoreAddrs::Persisted(addrs))
                    }
                }
            })
            .cloned()
    }

    /// Get an EventStoreRouter for InMem backend
    pub fn in_mem_eventstore_router(
        &self,
    ) -> Result<Addr<EventStoreRouter<InMemSequenceIndex, InMemEventLog>>> {
        let eventstores = self.eventstore_addrs()?;
        if let EventStoreAddrs::InMem(addrs) = eventstores {
            let router = EventStoreRouter::new(addrs);
            Ok(router.start())
        } else {
            Err(anyhow!("Expected InMem backend but got Persisted"))
        }
    }

    /// Get an EventStoreRouter for Persisted backend
    pub fn persisted_eventstore_router(
        &self,
    ) -> Result<Addr<EventStoreRouter<SledSequenceIndex, CommitLogEventLog>>> {
        let eventstores = self.eventstore_addrs()?;
        if let EventStoreAddrs::Persisted(addrs) = eventstores {
            let router = EventStoreRouter::new(addrs);
            Ok(router.start())
        } else {
            Err(anyhow!("Expected Persisted backend but got InMem"))
        }
    }

    /// Get an EventStoreRouter Recipient
    pub fn eventstore_router(&self) -> Result<Recipient<StoreEventRequested>> {
        let eventstores = self.eventstore_addrs()?;
        match &eventstores {
            EventStoreAddrs::InMem(_) => Ok(self.in_mem_eventstore_router()?.recipient()),
            EventStoreAddrs::Persisted(_) => Ok(self.persisted_eventstore_router()?.recipient()),
        }
    }

    pub fn eventstore_reader(&self) -> Result<EventStoreReader> {
        let eventstores = self.eventstore_addrs()?;
        let reader = match &eventstores {
            EventStoreAddrs::InMem(_) => {
                let router = self.in_mem_eventstore_router()?;
                EventStoreReader::new(router.clone().recipient(), router.recipient())
            }
            EventStoreAddrs::Persisted(_) => {
                let router = self.persisted_eventstore_router()?;
                EventStoreReader::new(router.clone().recipient(), router.recipient())
            }
        };

        if self.global_shared_eventstore {
            share_eventstore_reader(&reader);
        }

        Ok(reader)
    }

    /// Get the BusHandle
    pub fn handle(&self) -> Result<BusHandle<Disabled>> {
        self.handle
            .get_or_try_init(|| {
                let handle = BusHandle::new(self.eventbus(), self.sequencer()?, HlcFactory::new());
                // Buffer subscribes to all events first
                // This is important so as to open up a batch for each sequence
                handle.subscribe(EventType::All, self.buffer()?.recipient());
                Ok(handle)
            })
            .cloned()
    }

    /// Get the DataStore
    pub fn store(&self) -> Result<DataStore> {
        let store = match &self.backend {
            EventSystemBackend::InMem(b) => {
                let base = b.get_or_init_store();
                let buffer = self.buffer()?;
                buffer.try_send(UpdateDestination::new(base.clone()))?;
                DataStore::from_in_mem_with_buffer(&base, self.buffer()?)
            }
            EventSystemBackend::Persisted(b) => {
                let base = b.get_or_init_store(&self.handle()?)?;
                let buffer = self.buffer()?;
                buffer.try_send(UpdateDestination::new(base))?;

                DataStore::from_sled_store_with_buffer(
                    &b.get_or_init_store(&self.handle()?)?,
                    self.buffer()?,
                )
            }
        };

        if self.global_shared_store {
            share_store(&store)
        }

        Ok(store)
    }
}

struct NoopBatchReceiver;

impl NoopBatchReceiver {
    pub fn new() -> Self {
        Self {}
    }
}
impl Actor for NoopBatchReceiver {
    type Context = actix::Context<Self>;
}

impl Handler<InsertBatch> for NoopBatchReceiver {
    type Result = ();
    fn handle(&mut self, _: InsertBatch, _: &mut Self::Context) -> Self::Result {
        // do nothing
    }
}

#[cfg(test)]
mod tests {
    use e3_data::AutoPersist;
    use e3_data::Persistable;
    use e3_data::Repository;
    use e3_events::EventContext;
    use e3_events::EventId;
    use e3_events::EventSource;
    use e3_events::StoreKeys;
    use e3_events::SyncEnded;
    use e3_events::Tick;
    use e3_events::TsAgg;
    use e3_test_helpers::with_tracing;
    use std::time::Duration;
    use tracing::info;

    use super::*;
    use actix::Actor;
    use actix::Handler;
    use actix::Message;

    use e3_events::prelude::*;
    use e3_events::CorrelationId;
    use e3_events::InterfoldEventData;

    use e3_events::EventStoreQueryBy;
    use e3_events::EventStoreQueryResponse;
    use e3_events::EventType;
    use e3_events::TestEvent;
    use tempfile::TempDir;
    use tokio::time::sleep;

    // Setup Listener for the test
    #[derive(Message, Debug)]
    #[rtype("Vec<String>")]
    struct GetLogs;

    #[derive(Message, Debug)]
    #[rtype("Vec<String>")]
    struct GetEvents;

    struct Listener {
        logs: Vec<String>,
        events: Vec<InterfoldEvent>,
    }

    impl Handler<InterfoldEvent> for Listener {
        type Result = ();
        fn handle(&mut self, msg: InterfoldEvent, _: &mut Self::Context) -> Self::Result {
            if let InterfoldEventData::TestEvent(TestEvent { msg, .. }) = msg.into_data() {
                self.logs.push(msg);
            }
        }
    }

    impl Handler<GetLogs> for Listener {
        type Result = Vec<String>;
        fn handle(&mut self, _: GetLogs, _: &mut Self::Context) -> Self::Result {
            self.logs.clone()
        }
    }

    impl Handler<GetEvents> for Listener {
        type Result = Vec<String>;
        fn handle(&mut self, _: GetEvents, _: &mut Self::Context) -> Self::Result {
            self.events
                .iter()
                .filter_map(|event| {
                    if let InterfoldEventData::TestEvent(evt) = event.get_data() {
                        return Some(evt.msg.clone());
                    }
                    None
                })
                .collect::<Vec<_>>()
        }
    }

    impl Handler<EventStoreQueryResponse> for Listener {
        type Result = ();
        fn handle(&mut self, msg: EventStoreQueryResponse, _: &mut Self::Context) -> Self::Result {
            self.events = msg.into_events();
        }
    }

    impl Actor for Listener {
        type Context = actix::Context<Self>;
    }

    #[actix::test]
    async fn test_persisted() -> Result<()> {
        let _guard = with_tracing("debug");
        let tmp = TempDir::new().unwrap();
        let system = EventSystem::persisted(tmp.path().join("log"), tmp.path().join("sled"));
        let _handle = system.handle().expect("Failed to get handle");
        system.store().expect("Failed to get store");
        Ok(())
    }

    #[actix::test]
    async fn test_in_mem() {
        let eventbus = EventBus::<InterfoldEvent>::default().start();
        let system = EventSystem::in_mem().with_event_bus(eventbus);

        let _handle = system.handle().expect("Failed to get handle");
        system.store().expect("Failed to get store");
    }

    #[actix::test]
    async fn test_event_system() -> Result<()> {
        let _guard = with_tracing("debug");

        // This sets up the aggregation delays
        let mut delays = HashMap::new();
        // Here we delay AggregationId(0) for 1 second
        delays.insert(AggregateId::new(0), Duration::from_secs(1)); // Ag0 is default
        let config = AggregateConfig::new(delays);

        let system = EventSystem::in_mem()
            .with_fresh_bus()
            .with_aggregate_config(config);

        let handle = system.handle()?.enable("test");
        let datastore = system.store()?;
        let buffer = system.buffer()?;

        let listener = Listener {
            logs: Vec::new(),
            events: Vec::new(),
        }
        .start();

        // Sequence 1, Aggregate 0
        let ec = EventContext::new_origin(
            EventId::hash(1),
            10,
            AggregateId::new(0),
            None,
            EventSource::Local,
        )
        .sequence(1);

        // Send all evts to the listener
        handle.subscribe(EventType::All, listener.clone().into());

        // Publish an event seq 1
        info!("Publishing an event seq 1");
        handle.publish_without_context(TestEvent::new("pink", 1))?;

        // Lets store some data on a plain datastore
        info!("Writing to /foo/name with no context");
        datastore.scope("/foo/name").write("Fred".to_string());
        // Note there is some eventual consistency here we have to wait
        assert_eq!(datastore.scope("/foo/name").read::<String>().await?, None);
        info!("Wait one tick");

        // Let's wait until all events are settled only takes a tick
        sleep(Duration::from_millis(1)).await;

        // These inserts should not be buffered and should be available
        assert_eq!(
            datastore.scope("/foo/name").read::<String>().await?,
            Some("Fred".to_string())
        );
        info!("Data was written now");

        // Ok lets get a persistable
        let mut persistable: Persistable<String> =
            Repository::new(datastore.scope("/foo/name")).load().await?;

        // We have the data in our persistable
        assert_eq!(persistable.get(), Some("Fred".to_string()));

        info!("Data was loaded from persistable now mutating state...");

        persistable.try_mutate(&ec, |_| Ok("Mary".to_string()))?;

        // Local state has changed straight away
        assert_eq!(persistable.get(), Some("Mary".to_string()));

        // But disk state is still the same because the SnapshotBuffer is not on
        assert_eq!(
            datastore.scope("/foo/name").read::<String>().await?,
            Some("Fred".to_string())
        );
        info!("Local state was mutated however disk state was not");

        info!("Publishing SyncEnded event to turn on SnapshotBuffer. This should send the seq=1 batch to the timelock...");
        // Publishing SyncEnded should turn on the SnapshotBuffer seq 2
        handle.publish(SyncEnded::new(), ec.clone())?;

        sleep(Duration::from_millis(1)).await;

        info!("Mutating persistable state to create inserts using seq=2");

        let ec = EventContext::new_origin(
            EventId::hash(1),
            10,
            AggregateId::new(0),
            None,
            EventSource::Local,
        )
        .sequence(2);

        persistable.try_mutate(&ec, |_| Ok("Liz".to_string()))?;
        sleep(Duration::from_millis(1)).await;
        info!("Mutation complete");
        // SnapshotBuffer is not cleared unless new events are published

        // Get a timestamp for the events below
        let ts = handle.ts()?;

        // Push a few other events seq 3
        // This sends the previous batch for seq2 to the timelock queue
        handle.publish_without_context(TestEvent::new("yellow", 1))?;

        // Wait a second for the timelock to be checked
        sleep(Duration::from_secs(2)).await;
        buffer.try_send(Tick)?;

        // Check now
        info!("Reading from /foo/name and expecting it to be correct.");
        assert_eq!(
            datastore.scope("/foo/name").read::<String>().await?,
            Some("Liz".to_string())
        );

        assert_eq!(
            datastore
                .scope(StoreKeys::aggregate_seq(AggregateId::new(0)))
                .read::<u64>()
                .await?,
            Some(2)
        );

        // Publish a few other events
        handle.publish_without_context(TestEvent::new("red", 1))?;
        handle.publish_without_context(TestEvent::new("white", 1))?;
        sleep(Duration::from_millis(100)).await;

        // Get the event logs from the listener
        let logs = listener.send(GetLogs).await?;
        assert_eq!(logs, vec!["pink", "yellow", "red", "white"]);

        // Get the in mem eventstore router
        let router = system.in_mem_eventstore_router()?;

        // Get all events after the given timestamp using the router
        use e3_events::AggregateId;
        let mut ts_map = HashMap::new();
        ts_map.insert(AggregateId::new(0), ts);
        let sender: Recipient<EventStoreQueryResponse> = listener.clone().into();
        let get_events_msg = EventStoreQueryBy::<TsAgg>::new(CorrelationId::new(), ts_map, sender);
        router.do_send(get_events_msg);
        sleep(Duration::from_millis(100)).await;

        // Pull the events off the listsner since the timestamp
        let events = listener.send(GetEvents).await?;
        assert_eq!(events, vec!["yellow", "red", "white"]);
        Ok(())
    }

    #[actix::test]
    async fn test_multiple_eventstores() -> Result<()> {
        use e3_events::AggregateId;

        // Create an AggregateConfig with multiple AggregateIds
        let mut delays = HashMap::new();
        delays.insert(AggregateId::new(0), Duration::from_micros(1000)); // 1ms delay
        delays.insert(AggregateId::new(1), Duration::from_micros(2000)); // 2ms delay
        delays.insert(AggregateId::new(2), Duration::from_micros(3000)); // 3ms delay
        let aggregate_config = AggregateConfig::new(delays);

        // Test in-memory eventstores
        let system = EventSystem::in_mem().with_aggregate_config(aggregate_config);
        let Ok(EventStoreAddrs::InMem(addrs)) = system.eventstore_addrs() else {
            panic!("Expected InMem event store addrs");
        };

        // Should create 3 eventstores for 3 AggregateIds
        assert_eq!(addrs.len(), 3);
        // Test that we can access the first eventstore (index 0)
        assert!(addrs.contains_key(&0));
        assert!(addrs.contains_key(&1));
        assert!(addrs.contains_key(&2));

        // Test persistent eventstores
        let tmp = TempDir::new().unwrap();
        let persisted_system =
            EventSystem::persisted(tmp.path().join("log"), tmp.path().join("sled"))
                .with_aggregate_config(AggregateConfig::new(HashMap::new()));

        let Ok(EventStoreAddrs::Persisted(addrs)) = persisted_system.eventstore_addrs() else {
            panic!("Expected Persisted event store addrs");
        };

        assert_eq!(addrs.len(), 1);
        assert!(addrs.contains_key(&0));

        Ok(())
    }
}
