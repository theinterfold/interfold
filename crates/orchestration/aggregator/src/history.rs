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
    let mut pages = E3HistoryPages::new(store, e3_id, range);
    while let Some(page) = pages.next().await? {
        for event in page {
            visit(event).await?;
        }
    }
    Ok(())
}

pub(crate) struct E3HistoryPages<'a> {
    store: &'a Recipient<EventStoreQueryBy<SeqAgg>>,
    id: &'a E3id,
    cursor: u64,
    end: u64,
}

impl<'a> E3HistoryPages<'a> {
    pub(crate) fn new(
        store: &'a Recipient<EventStoreQueryBy<SeqAgg>>,
        id: &'a E3id,
        range: std::ops::RangeInclusive<u64>,
    ) -> Self {
        Self {
            store,
            id,
            cursor: *range.start(),
            end: *range.end(),
        }
    }
    pub(crate) fn reached_end(&self) -> bool {
        self.cursor > self.end
    }
    pub(crate) async fn next(&mut self) -> Result<Option<Vec<InterfoldEvent>>> {
        if self.reached_end() {
            return Ok(None);
        }
        let aggregate = AggregateId::from_chain_id(Some(self.id.chain_id()));
        let (recipient, response) = e3_utils::actix::channel::oneshot::<EventStoreQueryResponse>();
        self.store
            .send(
                EventStoreQueryBy::<SeqAgg>::new(
                    CorrelationId::new(),
                    HashMap::from([(aggregate, self.cursor)]),
                    recipient,
                )
                .with_limit(1024)
                .with_max_bytes(16 * 1024 * 1024),
            )
            .await?;
        let events = response.await?.into_events()?;
        if events.is_empty() {
            return Ok(None);
        }
        let mut page = Vec::new();
        for event in events {
            ensure!(
                event.aggregate_id() == aggregate && event.seq() == self.cursor,
                "E3 history event-store sequence gap"
            );
            self.cursor += 1;
            if event.get_e3_id().as_ref() == Some(self.id) {
                page.push(event);
            }
            if self.cursor > self.end {
                break;
            }
        }
        Ok(Some(page))
    }
}
