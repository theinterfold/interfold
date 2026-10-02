// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::net_interface_handle::{NetEventChannel, NetEventSubscriber};
use std::{collections::HashMap, num::NonZero, sync::Arc, time::Duration};

use super::*;
use crate::events::NetCommand;
use crate::{domain::EventConversionService, ContentHash};
use actix::Addr;
use anyhow::{bail, Result};
use chrono::Utc;
use e3_ciphernode_builder::EventSystem;
use e3_events::{
    AggregateConfig, AggregateId, BusHandle, CiphernodeSelected, DocumentKind, DocumentMeta, E3id,
    EncryptionKey, EncryptionKeyCreated, GetEvents, HistoryCollector, InterfoldError,
    InterfoldEvent, PublishDocumentRequested, TakeEvents,
};
use e3_utils::ArcBytes;
use libp2p::kad::{GetRecordError, PutRecordError, RecordKey};
use std::time::Instant;
use tokio::{
    sync::mpsc,
    time::{sleep, timeout},
};
use tracing::subscriber::DefaultGuard;

#[derive(actix::Message)]
#[rtype(result = "()")]
struct PublisherBarrier;

impl actix::Handler<PublisherBarrier> for DocumentPublisher {
    type Result = ();

    fn handle(&mut self, _message: PublisherBarrier, _context: &mut Self::Context) {}
}

/// Reports the documents being fetched and the documents waiting to be fetched.
#[derive(actix::Message)]
#[rtype(result = "(usize, usize)")]
struct FetchBacklog;

impl actix::Handler<FetchBacklog> for DocumentPublisher {
    type Result = actix::MessageResult<FetchBacklog>;

    fn handle(&mut self, _message: FetchBacklog, _context: &mut Self::Context) -> Self::Result {
        actix::MessageResult((self.fetching.len(), self.fetch_queue.len()))
    }
}

type TestSetup = (
    DefaultGuard,
    BusHandle,
    mpsc::Sender<NetCommand>,
    mpsc::Receiver<NetCommand>,
    NetEventChannel,
    NetEventSubscriber,
    Addr<HistoryCollector<InterfoldEvent>>,
    Addr<HistoryCollector<InterfoldEvent>>,
    Addr<DocumentPublisher>,
);

/// A publisher that runs its effects at once.
fn setup_test() -> Result<TestSetup> {
    setup_test_with(|bus, tx, rx| DocumentPublisher::setup(bus, tx, rx, "topic"))
}

/// A publisher as a node starts it: before `EffectsEnabled`, with the state recovered from the
/// event log.
fn setup_startup_test(recovered: RecoveredDocumentState) -> Result<TestSetup> {
    setup_test_with(|bus, tx, rx| {
        DocumentPublisher::setup_before_effects(bus, tx, rx, "topic", HashMap::new(), recovered)
    })
}

fn setup_test_with(
    start: impl FnOnce(
        &BusHandle,
        &mpsc::Sender<NetCommand>,
        &NetEventSubscriber,
    ) -> Addr<DocumentPublisher>,
) -> Result<TestSetup> {
    use tracing_subscriber::{fmt, EnvFilter};

    let subscriber = fmt()
        .with_env_filter(EnvFilter::new("debug"))
        .with_test_writer()
        .finish();

    let guard = tracing::subscriber::set_default(subscriber);

    let aggregate_config =
        AggregateConfig::new(HashMap::from([(AggregateId::new(1), Duration::ZERO)]));
    let system = EventSystem::new()
        .with_fresh_bus()
        .with_aggregate_config(aggregate_config);
    let bus = system.handle()?.enable("test");
    let (net_cmd_tx, net_cmd_rx) = mpsc::channel(100);
    let net_evt_tx = NetEventChannel::new(100);
    let net_evt_rx = NetEventSubscriber::from(&net_evt_tx);
    let history = HistoryCollector::<InterfoldEvent>::new().start();
    let error = HistoryCollector::<InterfoldEvent>::new().start();
    bus.subscribe(EventType::All, history.clone().recipient());
    bus.subscribe(EventType::InterfoldError, error.clone().recipient());
    let publisher = start(&bus, &net_cmd_tx, &net_evt_rx);

    Ok((
        guard, bus, net_cmd_tx, net_cmd_rx, net_evt_tx, net_evt_rx, history, error, publisher,
    ))
}

mod notifications;
mod publishing;

fn is_between(instant: Instant, start: Instant, end: Instant) -> bool {
    let (min, max) = if start <= end {
        (start, end)
    } else {
        (end, start)
    };
    instant >= min && instant <= max
}

fn days_from_now(days: u64) -> Instant {
    Instant::now() + Duration::from_secs(60 * 60 * 24 * days)
}
