// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{PostForward, RequestRouter, RoutingDecision};
use e3_events::{
    AggregateId, EventContextAccessors, EventContextSeq, InterfoldEvent, RequestRouterCheckpoint,
};
use std::collections::HashMap;

/// Record the highest durable sequence observed for one aggregate.
///
/// Replay preserves per-aggregate sequence, but contextual writes can still be delivered late.
/// A cursor is a covered prefix and must therefore never move backwards.
pub(in super::super) fn advance_request_router_cursor(
    cursors: &mut HashMap<AggregateId, u64>,
    aggregate_id: AggregateId,
    sequence: u64,
) {
    cursors
        .entry(aggregate_id)
        .and_modify(|cursor| *cursor = (*cursor).max(sequence))
        .or_insert(sequence);
}

/// Apply one durable event to the request-router recovery projection.
///
/// This projection changes only router admission state. It does not start actors or run effects.
pub fn project_request_router_event(
    checkpoint: &mut RequestRouterCheckpoint,
    event: &InterfoldEvent,
) {
    let has_context = event
        .get_e3_id()
        .is_some_and(|e3_id| checkpoint.contexts.contains(&e3_id));

    match RequestRouter::route_with_context(event, &checkpoint.completed, has_context) {
        RoutingDecision::Process {
            e3_id,
            post_forward: PostForward::Teardown | PostForward::PublishComplete,
        } => {
            // The live router publishes E3RequestComplete after PublishComplete and then
            // tears the context down. Recovery projects the resulting terminal state directly
            // so it does not depend on that derived local event being present in an older log.
            checkpoint.contexts.retain(|context| context != &e3_id);
            checkpoint.completed.insert(e3_id);
        }
        RoutingDecision::Process { e3_id, .. } => {
            if !checkpoint.contexts.contains(&e3_id) {
                checkpoint.contexts.push(e3_id);
            }
        }
        RoutingDecision::Broadcast
        | RoutingDecision::Ignore
        | RoutingDecision::AlreadyCompleted(_)
        | RoutingDecision::UnadmittedNetworkEvent(_) => {}
    }

    let sequence = event.seq();
    advance_request_router_cursor(
        &mut checkpoint.replay_cursors,
        event.aggregate_id(),
        sequence,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_never_moves_backward() {
        let aggregate_id = e3_events::AggregateId::new(7);
        let mut cursors = HashMap::new();

        advance_request_router_cursor(&mut cursors, aggregate_id, 2);
        advance_request_router_cursor(&mut cursors, aggregate_id, 1);

        assert_eq!(cursors.get(&aggregate_id), Some(&2));
    }
}
