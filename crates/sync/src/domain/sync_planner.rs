// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_events::{
    AggregateId, E3id, Event, EventContextAccessors, InterfoldEvent, InterfoldEventData,
    Unsequenced,
};
use std::collections::BTreeMap;

/// Decision returned for each event encountered during EventStore replay.
///
/// Infrastructure events (`SyncEnded`, `EffectsEnabled`, `HistoricalEvmSyncStart`,
/// `HistoricalNetSyncStart`) are re-published by the sync process itself, so replaying them
/// would poison the EventBus bloom-filter dedup. They must be skipped during replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayDecision {
    /// Forward the event to listeners.
    Replay,
    /// Skip: this is an infrastructure event re-published later by the sync flow.
    SkipInfrastructure,
}

/// Pure sync coordination/planning logic.
///
/// Holds no state and performs no I/O — it turns already-loaded snapshot/event data into the
/// decisions the sync orchestrator acts on (what to replay, where to resume net sync, ordering).
pub struct SyncPlanner;

impl SyncPlanner {
    /// Decide whether an event should be replayed to listeners during EventStore replay.
    pub fn classify_replay(event: &InterfoldEvent) -> ReplayDecision {
        if Self::is_infrastructure_event(event) {
            ReplayDecision::SkipInfrastructure
        } else {
            ReplayDecision::Replay
        }
    }

    /// True for events the sync flow re-publishes itself (steps 5/8/10) and therefore must not
    /// replay from the EventStore.
    pub fn is_infrastructure_event(event: &InterfoldEvent) -> bool {
        matches!(
            event.get_data(),
            InterfoldEventData::SyncEnded(_)
                | InterfoldEventData::EffectsEnabled(_)
                | InterfoldEventData::HistoricalEvmSyncStart(_)
                | InterfoldEventData::HistoricalNetSyncStart(_)
        )
    }

    /// Build the net sync cursor: the aggregates that still need libp2p syncing mapped to the
    /// original snapshot HLC timestamps.
    ///
    /// We use [`Self::find_net_hlc`] to determine WHICH aggregates need syncing (filtering closed
    /// E3s), but replace the timestamps with the original ones from the snapshot. Re-read EVM
    /// events get NEW HLC timestamps from a fresh-on-restart HLC, which would be later than what
    /// ciphernodes stored and cause the sync query to return 0 events.
    pub fn net_sync_cursor(
        historical_evm_events: &[InterfoldEvent<Unsequenced>],
        snapshot_net_config: &BTreeMap<AggregateId, u128>,
    ) -> BTreeMap<AggregateId, u128> {
        Self::find_net_hlc(historical_evm_events)
            .into_keys()
            .map(|id| {
                let ts = snapshot_net_config.get(&id).copied().unwrap_or(0);
                (id, ts)
            })
            .collect()
    }

    /// Sort historical events (evm + libp2p combined) by their HLC timestamp.
    pub fn sort_by_timestamp(events: &mut [InterfoldEvent<Unsequenced>]) {
        events.sort_by_key(|event| event.ts());
    }

    /// For every still-open aggregate, find the latest HLC timestamp observed in the events.
    /// Aggregates whose E3 has completed or failed are excluded.
    pub fn find_net_hlc(events: &[InterfoldEvent<Unsequenced>]) -> BTreeMap<AggregateId, u128> {
        // find all E3s that are closed
        let e3s: Vec<E3id> = events
            .iter()
            .filter_map(|e| match e.get_data() {
                InterfoldEventData::E3Failed(d) => Some(d.e3_id.clone()),
                InterfoldEventData::E3RequestComplete(d) => Some(d.e3_id.clone()),
                _ => None,
            })
            .collect();
        events
            .iter()
            .filter(|e| e.get_e3_id().is_none_or(|id| !e3s.contains(&id)))
            .fold(BTreeMap::new(), |mut acc, e| {
                acc.entry(e.aggregate_id())
                    .and_modify(|ts| *ts = (*ts).max(e.ts()))
                    .or_insert(e.ts());
                acc
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::{
        E3Failed, E3RequestComplete, E3Stage, E3id, EffectsEnabled, EvmEventConfig, FailureReason,
        HistoricalEvmSyncStart, InterfoldEvent, SyncEnded, Unsequenced,
    };

    fn make_historical_evm_sync_start() -> HistoricalEvmSyncStart {
        HistoricalEvmSyncStart {
            evm_config: EvmEventConfig::new(),
            sender: None,
        }
    }

    #[test]
    fn infrastructure_events_are_detected() {
        let sync_ended = InterfoldEvent::<Unsequenced>::test_event("sync")
            .data(SyncEnded::new())
            .seq(1)
            .build();
        let effects_enabled = InterfoldEvent::<Unsequenced>::test_event("fx")
            .data(EffectsEnabled::new())
            .seq(2)
            .build();
        let evm_sync_start = InterfoldEvent::<Unsequenced>::test_event("evm")
            .data(make_historical_evm_sync_start())
            .seq(3)
            .build();
        let test_event = InterfoldEvent::<Unsequenced>::test_event("hello")
            .id(42)
            .seq(4)
            .build();

        assert!(SyncPlanner::is_infrastructure_event(&sync_ended));
        assert!(SyncPlanner::is_infrastructure_event(&effects_enabled));
        assert!(SyncPlanner::is_infrastructure_event(&evm_sync_start));
        assert!(!SyncPlanner::is_infrastructure_event(&test_event));
    }

    #[test]
    fn classify_replay_skips_infrastructure_and_replays_the_rest() {
        let sync_ended = InterfoldEvent::<Unsequenced>::test_event("sync")
            .data(SyncEnded::new())
            .seq(1)
            .build();
        let test_event = InterfoldEvent::<Unsequenced>::test_event("hello")
            .id(42)
            .seq(2)
            .build();

        assert_eq!(
            SyncPlanner::classify_replay(&sync_ended),
            ReplayDecision::SkipInfrastructure
        );
        assert_eq!(
            SyncPlanner::classify_replay(&test_event),
            ReplayDecision::Replay
        );
    }

    #[test]
    fn test_find_net_hlc() {
        let closed_1 = E3id::new("1", 1);
        let closed_2 = E3id::new("2", 2);
        let open_1 = E3id::new("3", 3);
        let open_2 = E3id::new("4", 4);

        let events = vec![
            // closed e3s -> should be filtered out
            InterfoldEvent::<Unsequenced>::test_event("a")
                .e3_id(closed_1.clone())
                .ts(1000)
                .build(),
            InterfoldEvent::<Unsequenced>::test_event("a")
                .e3_id(closed_1.clone())
                .ts(2000)
                .build(),
            InterfoldEvent::<Unsequenced>::test_event("complete")
                .data(E3RequestComplete {
                    e3_id: closed_1.clone(),
                })
                .ts(3000)
                .build(),
            InterfoldEvent::<Unsequenced>::test_event("b")
                .e3_id(closed_2.clone())
                .ts(1500)
                .build(),
            InterfoldEvent::<Unsequenced>::test_event("failed")
                .data(E3Failed {
                    e3_id: closed_2.clone(),
                    failed_at_stage: E3Stage::CommitteeFinalized,
                    reason: FailureReason::InsufficientCommitteeMembers,
                })
                .ts(2500)
                .build(),
            // open e3s -> should be kept
            InterfoldEvent::<Unsequenced>::test_event("c")
                .e3_id(open_1.clone())
                .ts(4000)
                .build(),
            InterfoldEvent::<Unsequenced>::test_event("c")
                .e3_id(open_1.clone())
                .ts(5000)
                .build(),
            InterfoldEvent::<Unsequenced>::test_event("d")
                .e3_id(open_2.clone())
                .ts(6000)
                .build(),
            // no e3_id -> aggregate 0, always kept
            InterfoldEvent::<Unsequenced>::test_event("e")
                .ts(7000)
                .build(),
            InterfoldEvent::<Unsequenced>::test_event("e")
                .ts(8000)
                .build(),
        ];

        let result = SyncPlanner::find_net_hlc(&events);

        // closed e3s excluded
        assert!(!result.contains_key(&AggregateId::new(1)));
        assert!(!result.contains_key(&AggregateId::new(2)));

        // open e3s kept with max ts
        assert_eq!(result[&AggregateId::new(3)], 5000);
        assert_eq!(result[&AggregateId::new(4)], 6000);

        // no-e3 events kept with max ts
        assert_eq!(result[&AggregateId::new(0)], 8000);

        assert_eq!(result.len(), 3);
    }

    #[test]
    fn net_sync_cursor_remaps_open_aggregates_to_snapshot_timestamps() {
        let open = E3id::new("3", 3);
        let events = vec![
            InterfoldEvent::<Unsequenced>::test_event("c")
                .e3_id(open.clone())
                .ts(5000)
                .build(),
            InterfoldEvent::<Unsequenced>::test_event("e")
                .ts(8000)
                .build(),
        ];

        let mut snapshot_net_config = BTreeMap::new();
        // original snapshot timestamp for aggregate 3 differs from the re-read HLC (5000).
        snapshot_net_config.insert(AggregateId::new(3), 42);
        // aggregate 0 missing from snapshot -> defaults to 0.

        let cursor = SyncPlanner::net_sync_cursor(&events, &snapshot_net_config);

        assert_eq!(cursor[&AggregateId::new(3)], 42);
        assert_eq!(cursor[&AggregateId::new(0)], 0);
        assert_eq!(cursor.len(), 2);
    }

    #[test]
    fn sort_by_timestamp_orders_ascending() {
        let mut events = vec![
            InterfoldEvent::<Unsequenced>::test_event("c")
                .ts(5000)
                .build(),
            InterfoldEvent::<Unsequenced>::test_event("a")
                .ts(1000)
                .build(),
            InterfoldEvent::<Unsequenced>::test_event("b")
                .ts(3000)
                .build(),
        ];

        SyncPlanner::sort_by_timestamp(&mut events);

        let timestamps: Vec<u128> = events.iter().map(|e| e.ts()).collect();
        assert_eq!(timestamps, vec![1000, 3000, 5000]);
    }
}
