// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use clap::Subcommand;
use e3_config::AppConfig;
use e3_console::{log, Console};
use e3_entrypoint::helpers::datastore::get_eventstore_reader;
use e3_event_system::global_eventstore_cache::EventStoreReader;
use e3_events::{
    AggregateId, CorrelationId, EventContextSeq, EventStoreQueryBy, EventStoreQueryResponse,
    InterfoldEvent, SeqAgg,
};
use e3_utils::actix::channel as actix_toolbox;
use std::collections::HashMap;

#[derive(Subcommand, Clone, Debug)]
pub enum EventsCommands {
    /// Query events
    Query {
        /// Aggregate ID - will default to 0
        #[arg(long)]
        agg: Option<usize>,

        /// Sequence to read from will read from 0 if absent
        #[arg(long)]
        since: Option<u64>,

        /// Max limit to read at a time. If this is greater than the internal limit the internal
        /// limit will be respected.
        #[arg(long)]
        limit: Option<u64>,
    },
}

pub async fn execute(out: Console, command: EventsCommands, config: &AppConfig) -> Result<()> {
    match command {
        EventsCommands::Query { agg, since, limit } => {
            query_events(out, config, agg, since, limit).await?
        }
    }
    Ok(())
}

async fn query_events(
    out: Console,
    config: &AppConfig,
    aggregate: Option<usize>,
    since: Option<u64>,
    limit: Option<u64>,
) -> Result<()> {
    let eventstore = get_eventstore_reader(config)?;
    let (events, next) = fetch_events(eventstore, aggregate, since, limit).await?;
    print_events(out.clone(), events)?;
    log!(out, "{}", serde_json::to_string(&next)?);
    Ok(())
}

async fn fetch_events(
    eventstore: EventStoreReader,
    aggregate: Option<usize>,
    since: Option<u64>,
    limit: Option<u64>,
) -> Result<(Vec<InterfoldEvent>, SeqCursor)> {
    let aggregate = aggregate.unwrap_or(0);
    let since = since.unwrap_or(0);
    let limit = limit.unwrap_or(10);
    let (addr, rx) = actix_toolbox::oneshot::<EventStoreQueryResponse>();

    let msg = EventStoreQueryBy::<SeqAgg>::new(
        CorrelationId::new(),
        HashMap::from([(AggregateId::new(aggregate), since)]),
        addr,
    )
    .with_limit(limit);

    eventstore.seq().do_send(msg);
    let events = rx.await?.into_events()?;
    let next = compute_seq_cursor(&events, limit as usize);

    Ok((events, next))
}

fn print_events(out: Console, events: Vec<InterfoldEvent>) -> Result<()> {
    for event in events {
        log!(out, "{}", serde_json::to_string(&event)?);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
enum SeqCursor {
    Done,
    Next(u64),
}

fn compute_seq_cursor<T: EventContextSeq>(events: &[T], limit: usize) -> SeqCursor {
    if events.len() == limit {
        let last_seq = events.last().map(|e| e.seq()).unwrap_or(0);
        SeqCursor::Next(last_seq)
    } else {
        SeqCursor::Done
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockEvent(u64);
    impl EventContextSeq for MockEvent {
        fn seq(&self) -> u64 {
            self.0
        }
    }

    #[test]
    fn the_cursor_is_done_below_the_limit_and_points_at_the_last_seq_at_it() {
        let cases: [(&[u64], usize, SeqCursor); 3] = [
            (&[], 10, SeqCursor::Done),
            (&[1, 2], 10, SeqCursor::Done),
            (&[100, 200, 300], 3, SeqCursor::Next(300)),
        ];

        for (seqs, limit, expected) in cases {
            let events: Vec<MockEvent> = seqs.iter().copied().map(MockEvent).collect();
            assert_eq!(
                compute_seq_cursor(&events, limit),
                expected,
                "seqs={seqs:?} limit={limit}"
            );
        }
    }
}
