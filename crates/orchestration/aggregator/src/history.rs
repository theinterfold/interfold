// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Restart recovery reads of an E3's event history.

use actix::Recipient;
use anyhow::{ensure, Result};
use e3_events::{
    prelude::*, AggregateId, CorrelationId, E3id, EventStoreQueryBy, EventStoreQueryResponse,
    InterfoldEvent, SeqAgg,
};
use std::collections::HashMap;

/// Read the full E3 history, including events covered by snapshot cursors.
pub(crate) async fn visit_e3_history(
    store: &Recipient<EventStoreQueryBy<SeqAgg>>,
    e3_id: &E3id,
    mut visit: impl FnMut(&InterfoldEvent) -> Result<()>,
) -> Result<()> {
    visit_e3_history_range(store, e3_id, 1..=u64::MAX, |event| {
        std::future::ready(visit(&event))
    })
    .await
}

pub(crate) async fn visit_e3_history_range<F, Fut>(
    store: &Recipient<EventStoreQueryBy<SeqAgg>>,
    e3_id: &E3id,
    range: std::ops::RangeInclusive<u64>,
    mut visit: F,
) -> Result<()>
where
    F: FnMut(InterfoldEvent) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let aggregate = AggregateId::from_chain_id(Some(e3_id.chain_id()));
    let mut cursor = *range.start();
    while cursor <= *range.end() {
        let (recipient, response) = e3_utils::actix::channel::oneshot::<EventStoreQueryResponse>();
        store
            .send(
                EventStoreQueryBy::<SeqAgg>::new(
                    CorrelationId::new(),
                    HashMap::from([(aggregate, cursor)]),
                    recipient,
                )
                .with_limit(1024)
                .with_max_bytes(16 * 1024 * 1024),
            )
            .await?;
        let events = response.await?.into_events()?;
        if events.is_empty() {
            return Ok(());
        }
        for event in events {
            if event.seq() > *range.end() {
                return Ok(());
            }
            ensure!(
                event.aggregate_id() == aggregate && event.seq() == cursor,
                "E3 history event-store sequence gap"
            );
            cursor += 1;
            if event.get_e3_id().as_ref() == Some(e3_id) {
                visit(event).await?;
            }
        }
    }
    Ok(())
}
