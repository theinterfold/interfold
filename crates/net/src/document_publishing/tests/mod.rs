// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::net_interface_handle::NetEventSubscriber;
use std::{collections::HashMap, num::NonZero, sync::Arc, time::Duration};

use super::*;
use crate::events::GossipPublishFailure;
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
    sync::{broadcast, mpsc},
    time::{sleep, timeout},
};
use tracing::subscriber::DefaultGuard;

#[allow(clippy::type_complexity)]
fn setup_test() -> Result<(
    DefaultGuard,
    BusHandle,
    mpsc::Sender<NetCommand>,
    mpsc::Receiver<NetCommand>,
    broadcast::Sender<NetEvent>,
    NetEventSubscriber,
    Addr<HistoryCollector<InterfoldEvent>>,
    Addr<HistoryCollector<InterfoldEvent>>,
    Addr<DocumentPublisher>,
)> {
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
    let (net_evt_tx, _net_evt_rx) = broadcast::channel(100);
    let net_evt_rx = NetEventSubscriber::from(&net_evt_tx);
    let history = HistoryCollector::<InterfoldEvent>::new().start();
    let error = HistoryCollector::<InterfoldEvent>::new().start();
    bus.subscribe(EventType::All, history.clone().recipient());
    bus.subscribe(EventType::InterfoldError, error.clone().recipient());
    let publisher = DocumentPublisher::setup(&bus, &net_cmd_tx, &net_evt_rx, "topic");

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
