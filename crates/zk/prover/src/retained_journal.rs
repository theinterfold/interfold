// SPDX-License-Identifier: LGPL-3.0-only

//! Bounded startup reads of the retained journal, including the snapshotted prefix.

use actix::Recipient;
use anyhow::{ensure, Context, Result};
use e3_events::{
    AggregateId, CorrelationId, EventContextAccessors, EventContextSeq, EventStoreQueryBy,
    EventStoreQueryResponse, InterfoldEvent, SeqAgg,
};
use e3_utils::actix::channel;
use std::time::Duration;

async fn read_page(
    eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
    aggregate: AggregateId,
    cursor: u64,
    limit: u64,
    purpose: &str,
) -> Result<(Vec<InterfoldEvent>, u64)> {
    let (recipient, response) = channel::oneshot::<EventStoreQueryResponse>();
    tokio::time::timeout(Duration::from_secs(60), async {
        eventstore
            .send(
                EventStoreQueryBy::<SeqAgg>::new(
                    CorrelationId::new(),
                    [(aggregate, cursor)].into(),
                    recipient,
                )
                .with_limit(limit)
                .with_max_bytes(16 * 1024 * 1024),
            )
            .await?;
        let response = response.await?;
        let head = response.log_head();
        let events = response.into_events()?;
        Ok((
            events,
            head.with_context(|| format!("{purpose} event-store log head is missing"))?,
        ))
    })
    .await
    .with_context(|| format!("{purpose} event-store query timed out"))?
}

pub(crate) async fn visit(
    eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
    aggregate: AggregateId,
    purpose: &str,
    mut event: impl FnMut(InterfoldEvent) -> Result<()>,
) -> Result<()> {
    let mut cursor = 1u64;
    let mut limit = 1_024;
    let advance = |cursor: u64| {
        cursor
            .checked_add(1)
            .with_context(|| format!("{purpose} sequence overflow"))
    };
    loop {
        let (events, head) = read_page(eventstore, aggregate, cursor, limit, purpose).await?;
        if events.is_empty() {
            if cursor > head {
                return Ok(());
            }
            // A filtered count- or byte-limited page does not prove the log has ended.
            if limit != 1 {
                limit = 1;
                continue;
            }
            cursor = advance(cursor)?;
            continue;
        }
        limit = 1_024;
        for item in events {
            // One-event reads are empty for quarantined legacy records. Probe each skipped
            // sequence instead of accepting an unfiltered gap.
            while cursor < item.seq() {
                ensure!(
                    read_page(eventstore, aggregate, cursor, 1, purpose)
                        .await?
                        .0
                        .is_empty(),
                    "{purpose} event-store sequence gap"
                );
                cursor = advance(cursor)?;
            }
            ensure!(
                item.aggregate_id() == aggregate && item.seq() == cursor,
                "{purpose} event-store sequence gap"
            );
            cursor = advance(cursor)?;
            event(item)?;
        }
    }
}
