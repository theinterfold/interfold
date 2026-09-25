// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::{
    collect_historical_evm_events, has_schema_governed_kv_state, preflight_schema_version,
    project_restart_state_backfill, publish_reconciled_history,
    reconcile_request_router_checkpoint,
};
use crate::{SyncRepositoryFactory, SCHEMA_VERSION};
use e3_ciphernode_builder::EventSystem;
use e3_data::Repositories;
use e3_events::{
    hlc::{Hlc, HlcTimestamp},
    AccusationOutcome, AccusationQuorumReached, AggregateId, CommitteeMemberExcluded,
    CommitteeRequested, E3Requested, E3Stage, E3StageChanged, E3id, EffectsEnabled, Event,
    EventContextAccessors, EventPublisher, EventSubscriber, EventType, EvmEventConfig,
    EvmEventConfigChain, GetEvents, HistoricalEvmEventsReceived, HistoricalEvmSyncStart,
    HistoricalNetSyncEventsReceived, HistoricalNetSyncStart, InterfoldEvent, InterfoldEventData,
    NetReady, ProofType, RequestRouterCheckpoint, Seed, SlashExecuted, StoreKeys, SyncEffect,
    SyncEnded, TakeEvents, TicketGenerated, TicketId, Unsequenced,
};
use e3_utils::MAILBOX_LIMIT_LARGE;
use std::collections::BTreeMap;

fn make_historical_evm_sync_start() -> HistoricalEvmSyncStart {
    HistoricalEvmSyncStart {
        evm_config: EvmEventConfig::new(),
        sender: None,
    }
}

fn evm_config(chains: &[u64]) -> EvmEventConfig {
    EvmEventConfig::from_config(
        chains
            .iter()
            .map(|chain_id| (*chain_id, EvmEventConfigChain::new(0)))
            .collect::<BTreeMap<_, _>>(),
    )
}

fn historical_batch(chain_id: u64, event_count: usize) -> HistoricalEvmEventsReceived {
    let events = (0..event_count)
        .map(|index| {
            InterfoldEvent::<Unsequenced>::test_event("historical")
                .id(index as u64 + 1)
                .build()
        })
        .collect();
    HistoricalEvmEventsReceived::new(events, chain_id)
}

mod gates;
#[path = "history.rs"]
mod historical;
mod replay;
mod schema;
