// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use clap::Subcommand;
use e3_ciphernode_builder::global_eventstore_cache::EventStoreReader;
use e3_config::AppConfig;
use e3_console::{log, Console};
use e3_entrypoint::helpers::datastore::get_eventstore_reader;
use e3_events::{compute_seq_cursor, CorrelationId, InterfoldEvent, SeqAgg, SeqCursor};
use e3_events::{AggregateId, EventStoreQueryBy, EventStoreQueryResponse};
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
    let since_seq = since.unwrap_or(0);

    // Build per-aggregate cursor map. When no specific aggregate is requested,
    // query all configured chain stores so E3 events (stored under chain_id aggregate)
    // are included alongside system events stored under AggregateId(0).
    let aggregate_map: HashMap<AggregateId, u64> = if let Some(agg) = aggregate {
        HashMap::from([(AggregateId::new(agg), since_seq)])
    } else {
        let mut map = HashMap::from([(AggregateId::new(0), since_seq)]);
        for chain in config.chains() {
            if let Some(chain_id) = chain.chain_id {
                map.insert(AggregateId::new(chain_id as usize), since_seq);
            }
        }
        map
    };

    let (events, next) = fetch_events(eventstore, aggregate_map, limit).await?;
    print_events(out.clone(), events)?;
    log!(out, "{}", serde_json::to_string(&next)?);
    Ok(())
}

async fn fetch_events(
    eventstore: EventStoreReader,
    aggregate_map: HashMap<AggregateId, u64>,
    limit: Option<u64>,
) -> Result<(Vec<InterfoldEvent>, SeqCursor)> {
    let aggregate = aggregate.unwrap_or(0);
    let since = since.unwrap_or(0);
    let limit = limit.unwrap_or(10);
    let (addr, rx) = actix_toolbox::oneshot::<EventStoreQueryResponse>();

    let msg = EventStoreQueryBy::<SeqAgg>::new(CorrelationId::new(), aggregate_map, addr)
        .with_limit(limit);

    eventstore.seq().do_send(msg);
    let events = rx.await?.into_events();
    let next = compute_seq_cursor(&events, limit as usize);

    Ok((events, next))
}

fn print_events(out: Console, events: Vec<InterfoldEvent>) -> Result<()> {
    for event in events {
        log!(out, "{}", serde_json::to_string(&event)?);
    }
    Ok(())
}
