// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;

#[actix::test]
async fn historical_evm_collection_fails_when_any_chain_disconnects() {
    let (sender, receiver) = tokio::sync::mpsc::channel(2);
    sender.send(historical_batch(1, 2)).await.unwrap();
    drop(sender);

    let error = collect_historical_evm_events(receiver, &evm_config(&[1, 2, 3]))
        .await
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "historical EVM event channel closed before chains reported: [2, 3]"
    );
}

#[actix::test]
async fn historical_evm_collection_returns_only_after_every_chain_reports() {
    let (sender, receiver) = tokio::sync::mpsc::channel(2);
    sender.send(historical_batch(2, 3)).await.unwrap();
    sender.send(historical_batch(1, 2)).await.unwrap();

    let events = collect_historical_evm_events(receiver, &evm_config(&[1, 2]))
        .await
        .unwrap();

    assert_eq!(events.len(), 5);
}

/// Answers a peer-history request with a failure, as the network does when no peer serves the
/// history that startup requires.
struct FailingPeerHistory;

impl actix::Actor for FailingPeerHistory {
    type Context = actix::Context<Self>;
}

impl actix::Handler<InterfoldEvent> for FailingPeerHistory {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, _: &mut Self::Context) -> Self::Result {
        if let InterfoldEventData::HistoricalNetSyncStart(start) = msg.into_data() {
            if let Some(failure) = start.failure {
                failure
                    .try_send(HistoricalNetSyncFailed {
                        reason: "no peer served aggregate 1".to_string(),
                    })
                    .unwrap();
            }
        }
    }
}

#[actix::test]
async fn failed_peer_history_fetch_stops_startup_at_once() -> anyhow::Result<()> {
    use actix::Actor;

    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test-failed-peer-history");
    bus.subscribe(
        EventType::HistoricalNetSyncStart,
        FailingPeerHistory.start().recipient(),
    );

    let error = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        fetch_peer_history(
            &bus,
            BTreeMap::from([(AggregateId::new(1), 0)]),
            Default::default(),
        ),
    )
    .await?
    .unwrap_err();

    assert_eq!(
        error.to_string(),
        "startup peer history fetch failed: no peer served aggregate 1"
    );
    Ok(())
}

#[actix::test]
async fn peer_history_wait_ignores_a_closed_failure_channel() -> anyhow::Result<()> {
    // A successful fetch drops the failure recipient, which can close the channel before the
    // history arrives.
    let (failure, failed) = tokio::sync::oneshot::channel::<HistoricalNetSyncFailed>();
    drop(failure);
    let historical = InterfoldEvent::<Unsequenced>::test_event("historical")
        .id(1)
        .build();
    let received = InterfoldEvent::<Unsequenced>::test_event("net-history")
        .data(HistoricalNetSyncEventsReceived::new(vec![historical]))
        .seq(1)
        .build();
    let history = async move {
        tokio::task::yield_now().await;
        Ok(received)
    };

    let events = await_peer_history(history, failed).await?;

    assert_eq!(events.len(), 1);
    Ok(())
}

/// Records the timestamps that a peer-history request reserves, and answers with a failure.
struct ReservedRecorder(std::sync::Arc<std::sync::Mutex<Option<e3_events::ReservedTimestamps>>>);

impl actix::Actor for ReservedRecorder {
    type Context = actix::Context<Self>;
}

impl actix::Handler<InterfoldEvent> for ReservedRecorder {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, _: &mut Self::Context) -> Self::Result {
        if let InterfoldEventData::HistoricalNetSyncStart(start) = msg.into_data() {
            *self.0.lock().unwrap() = Some(start.reserved.as_ref().clone());
            if let Some(failure) = start.failure {
                let _ = failure.try_send(HistoricalNetSyncFailed {
                    reason: "recorded".to_string(),
                });
            }
        }
    }
}

/// Startup publishes its historical EVM events with the peer history, so the peer-history request
/// reserves their timestamps.
#[actix::test]
async fn peer_history_reserves_the_timestamps_of_the_evm_history() -> anyhow::Result<()> {
    use actix::Actor;

    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test-reserved-timestamps");
    let recorded = std::sync::Arc::new(std::sync::Mutex::new(None));
    bus.subscribe(
        EventType::HistoricalNetSyncStart,
        ReservedRecorder(recorded.clone()).start().recipient(),
    );
    let evm = historical_batch(1, 2).events;
    let expected: e3_events::ReservedTimestamps = evm.iter().fold(
        Default::default(),
        |mut reserved: e3_events::ReservedTimestamps, event| {
            reserved
                .entry(event.aggregate_id())
                .or_default()
                .insert(event.ts(), e3_events::TimestampClaim::of(event));
            reserved
        },
    );

    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        fetch_peer_history(
            &bus,
            BTreeMap::from([(AggregateId::new(1), 0)]),
            reserved_timestamps(&evm),
        ),
    )
    .await?;

    assert!(!expected.is_empty());
    assert_eq!(recorded.lock().unwrap().clone(), Some(expected));
    Ok(())
}
