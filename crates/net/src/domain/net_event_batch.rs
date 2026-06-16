// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::fmt::Debug;

use anyhow::{Context, Result};
use e3_events::AggregateId;
use tracing::info;

use crate::{
    direct_requester::{DirectRequester, WithPeer, WithoutPeer},
    events::PeerTarget,
};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub enum BatchCursor {
    Done,
    Next(u128),
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct EventBatch<E: Debug> {
    pub events: Vec<E>,
    pub next: BatchCursor,
    pub aggregate_id: AggregateId,
}

impl<E: Debug> TryFrom<Vec<u8>> for EventBatch<E>
where
    E: serde::de::DeserializeOwned,
{
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        bincode::deserialize(&value).context("failed to deserialize EventBatch")
    }
}

impl<E: Debug> TryFrom<EventBatch<E>> for Vec<u8>
where
    E: serde::Serialize,
{
    type Error = anyhow::Error;

    fn try_from(value: EventBatch<E>) -> Result<Self> {
        bincode::serialize(&value).context("failed to serialize EventBatch")
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct FetchEventsSince {
    aggregate_id: AggregateId,
    since: u128,
    limit: usize,
}

impl FetchEventsSince {
    pub fn new(aggregate_id: AggregateId, since: u128, limit: usize) -> Self {
        Self {
            aggregate_id,
            since,
            limit,
        }
    }

    pub fn aggregate_id(&self) -> AggregateId {
        self.aggregate_id
    }

    pub fn since(&self) -> u128 {
        self.since
    }

    pub fn limit(&self) -> usize {
        self.limit
    }
}

impl TryFrom<FetchEventsSince> for Vec<u8> {
    type Error = anyhow::Error;

    fn try_from(value: FetchEventsSince) -> Result<Self> {
        bincode::serialize(&value).context("failed to serialize FetchEventsSince")
    }
}

impl TryFrom<Vec<u8>> for FetchEventsSince {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        bincode::deserialize(&value).context("failed to deserialize FetchEventsSince")
    }
}

pub async fn fetch_events_since<E>(
    requester: &DirectRequester<WithPeer>,
    request: FetchEventsSince,
) -> Result<EventBatch<E>>
where
    E: Debug + TryFrom<Vec<u8>> + Send + Sync + 'static,
    EventBatch<E>: TryFrom<Vec<u8>>,
{
    requester.request(request).await
}

pub async fn fetch_all_batched_events<E>(
    requester: DirectRequester<WithoutPeer>,
    peer: PeerTarget,
    aggregate_id: AggregateId,
    since: u128,
    batch_size: usize,
) -> Result<Vec<E>>
where
    E: Debug + TryFrom<Vec<u8>> + Send + Sync + 'static,
    EventBatch<E>: TryFrom<Vec<u8>>,
{
    let requester = requester.to(peer);
    let mut all_events = Vec::new();
    let mut cursor = since;

    loop {
        let request = FetchEventsSince::new(aggregate_id, cursor, batch_size);
        info!(
            "Fetching batch aggregate={} cursor={} batch_size={}",
            aggregate_id, cursor, batch_size
        );
        let batch = fetch_events_since(&requester, request).await?;
        info!(
            "Batch received with {} events for aggregate={} cursor={}",
            batch.events.len(),
            aggregate_id,
            cursor
        );

        all_events.extend(batch.events);

        match batch.next {
            BatchCursor::Done => break,
            BatchCursor::Next(next_cursor) => cursor = next_cursor,
        }
    }

    info!("Batch is done returning {} events", all_events.len());

    Ok(all_events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::direct_requester::DirectRequesterTester;
    use crate::events::{NetCommand, NetEvent, PeerTarget};
    use std::sync::Arc;
    use tokio::sync::{broadcast, mpsc};

    #[tokio::test]
    async fn test_fetch_all_batched_events() {
        let (net_cmds_tx, net_cmds_rx) = mpsc::channel::<NetCommand>(16);
        let (net_events_tx, net_events_rx) = broadcast::channel::<NetEvent>(16);
        let net_events = Arc::new(net_events_rx);

        let requester = DirectRequester::builder(net_cmds_tx, net_events).build();

        let batch1 = EventBatch {
            events: vec![b"event1".to_vec(), b"event2".to_vec()],
            next: BatchCursor::Next(100),
            aggregate_id: AggregateId::new(1),
        };
        let batch2 = EventBatch {
            events: vec![b"event3".to_vec()],
            next: BatchCursor::Done,
            aggregate_id: AggregateId::new(1),
        };

        let handle = DirectRequesterTester::new(net_cmds_rx, net_events_tx)
            .expect_request(FetchEventsSince::new(AggregateId::new(1), 0, 100))
            .respond_with(batch1)
            .expect_request(FetchEventsSince::new(AggregateId::new(1), 100, 100))
            .respond_with(batch2)
            .spawn();

        let events: Vec<Vec<u8>> =
            fetch_all_batched_events(requester, PeerTarget::Random, AggregateId::new(1), 0, 100)
                .await
                .unwrap();

        handle.await.unwrap();

        assert_eq!(
            events,
            vec![b"event1".to_vec(), b"event2".to_vec(), b"event3".to_vec(),]
        );
    }

    #[tokio::test]
    async fn test_no_duplicate_events_across_batches() {
        let (net_cmds_tx, net_cmds_rx) = mpsc::channel::<NetCommand>(16);
        let (net_events_tx, net_events_rx) = broadcast::channel::<NetEvent>(16);
        let net_events = Arc::new(net_events_rx);

        let requester = DirectRequester::builder(net_cmds_tx, net_events).build();

        let batch1 = EventBatch {
            events: vec![b"event1".to_vec(), b"event2".to_vec()],
            next: BatchCursor::Next(2),
            aggregate_id: AggregateId::new(1),
        };
        let batch2 = EventBatch {
            events: vec![b"event3".to_vec()],
            next: BatchCursor::Done,
            aggregate_id: AggregateId::new(1),
        };

        let handle = DirectRequesterTester::new(net_cmds_rx, net_events_tx)
            .expect_request(FetchEventsSince::new(AggregateId::new(1), 0, 100))
            .respond_with(batch1)
            .expect_request(FetchEventsSince::new(AggregateId::new(1), 2, 100))
            .respond_with(batch2)
            .spawn();

        let events: Vec<Vec<u8>> =
            fetch_all_batched_events(requester, PeerTarget::Random, AggregateId::new(1), 0, 100)
                .await
                .unwrap();

        handle.await.unwrap();

        let unique: Vec<_> = events
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        assert_eq!(
            events.len(),
            unique.len(),
            "Found duplicate events: total={}, unique={}",
            events.len(),
            unique.len()
        );
        assert_eq!(
            events,
            vec![b"event1".to_vec(), b"event2".to_vec(), b"event3".to_vec()]
        );
    }

    #[tokio::test]
    async fn test_cursor_correctly_excludes_last_event_on_batch_boundary() {
        let (net_cmds_tx, net_cmds_rx) = mpsc::channel::<NetCommand>(16);
        let (net_events_tx, net_events_rx) = broadcast::channel::<NetEvent>(16);
        let net_events = Arc::new(net_events_rx);

        let requester = DirectRequester::builder(net_cmds_tx, net_events).build();

        let batch1 = EventBatch {
            events: vec![b"event1".to_vec()],
            next: BatchCursor::Next(100),
            aggregate_id: AggregateId::new(1),
        };
        let batch2 = EventBatch {
            events: vec![b"event2".to_vec()],
            next: BatchCursor::Done,
            aggregate_id: AggregateId::new(1),
        };

        let handle = DirectRequesterTester::new(net_cmds_rx, net_events_tx)
            .expect_request(FetchEventsSince::new(AggregateId::new(1), 0, 1))
            .respond_with(batch1)
            .expect_request(FetchEventsSince::new(AggregateId::new(1), 100, 1))
            .respond_with(batch2)
            .spawn();

        let events: Vec<Vec<u8>> =
            fetch_all_batched_events(requester, PeerTarget::Random, AggregateId::new(1), 0, 1)
                .await
                .unwrap();

        handle.await.unwrap();

        assert_eq!(events.len(), 2);
        assert_eq!(events[0], b"event1");
        assert_eq!(events[1], b"event2");
    }

    #[tokio::test]
    async fn test_single_batch_with_limit_exactly_matched_returns_done() {
        let (net_cmds_tx, net_cmds_rx) = mpsc::channel::<NetCommand>(16);
        let (net_events_tx, net_events_rx) = broadcast::channel::<NetEvent>(16);
        let net_events = Arc::new(net_events_rx);

        let requester = DirectRequester::builder(net_cmds_tx, net_events).build();

        let batch = EventBatch {
            events: vec![b"event1".to_vec()],
            next: BatchCursor::Done,
            aggregate_id: AggregateId::new(1),
        };

        let handle = DirectRequesterTester::new(net_cmds_rx, net_events_tx)
            .expect_request(FetchEventsSince::new(AggregateId::new(1), 0, 1))
            .respond_with(batch)
            .spawn();

        let events: Vec<Vec<u8>> =
            fetch_all_batched_events(requester, PeerTarget::Random, AggregateId::new(1), 0, 1)
                .await
                .unwrap();

        handle.await.unwrap();

        assert_eq!(events, vec![b"event1".to_vec()]);
    }

    #[tokio::test]
    async fn test_three_batches_with_cursor_continuity() {
        let (net_cmds_tx, net_cmds_rx) = mpsc::channel::<NetCommand>(16);
        let (net_events_tx, net_events_rx) = broadcast::channel::<NetEvent>(16);
        let net_events = Arc::new(net_events_rx);

        let requester = DirectRequester::builder(net_cmds_tx, net_events).build();

        let batch1 = EventBatch {
            events: vec![b"a".to_vec(), b"b".to_vec()],
            next: BatchCursor::Next(200),
            aggregate_id: AggregateId::new(1),
        };
        let batch2 = EventBatch {
            events: vec![b"c".to_vec(), b"d".to_vec()],
            next: BatchCursor::Next(400),
            aggregate_id: AggregateId::new(1),
        };
        let batch3 = EventBatch {
            events: vec![b"e".to_vec()],
            next: BatchCursor::Done,
            aggregate_id: AggregateId::new(1),
        };

        let handle = DirectRequesterTester::new(net_cmds_rx, net_events_tx)
            .expect_request(FetchEventsSince::new(AggregateId::new(1), 0, 2))
            .respond_with(batch1)
            .expect_request(FetchEventsSince::new(AggregateId::new(1), 200, 2))
            .respond_with(batch2)
            .expect_request(FetchEventsSince::new(AggregateId::new(1), 400, 2))
            .respond_with(batch3)
            .spawn();

        let events: Vec<Vec<u8>> =
            fetch_all_batched_events(requester, PeerTarget::Random, AggregateId::new(1), 0, 2)
                .await
                .unwrap();

        handle.await.unwrap();

        let expected = vec![
            b"a".to_vec(),
            b"b".to_vec(),
            b"c".to_vec(),
            b"d".to_vec(),
            b"e".to_vec(),
        ];
        assert_eq!(events.len(), expected.len());
        assert_eq!(events, expected);
    }
}
