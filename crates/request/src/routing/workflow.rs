// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_events::{
    E3Stage, E3id, Event, EventContextAccessors, EventSource, InterfoldEvent, InterfoldEventData,
};
use std::collections::HashSet;

/// The completion action a router should perform *after* running extension hooks and
/// forwarding an event to the request's context.
#[derive(Debug, PartialEq, Eq)]
pub enum PostForward {
    /// Publish an `E3RequestComplete` event to the bus: the request has finished.
    PublishComplete,
    /// Tear down the context for this request and mark it as completed.
    Teardown,
    /// No completion action is required.
    None,
}

/// The decision the router makes when an event arrives, computed without performing any
/// actix message passing, persistence, or context mutation.
#[derive(Debug, PartialEq, Eq)]
pub enum RoutingDecision {
    /// A shutdown event: broadcast it immediately to every active context.
    Broadcast,
    /// The event carries no `e3_id` and should be ignored.
    Ignore,
    /// The event targets a request that has already completed; this is an error.
    AlreadyCompleted(E3id),
    /// A network event targets an E3 that was not admitted by canonical chain state.
    UnadmittedNetworkEvent(E3id),
    /// Process the event for the given request, applying `post_forward` after forwarding.
    Process {
        e3_id: E3id,
        post_forward: PostForward,
    },
}

/// Pure routing logic for the E3 request router.
///
/// Classifies an incoming [`InterfoldEvent`] into a [`RoutingDecision`] based purely on the
/// event data and the set of already-completed requests. This contains no actix, persistence
/// or I/O concerns so it can be unit tested in isolation; the actor executes the decision.
pub struct RequestRouter;

impl RequestRouter {
    /// Decide how an incoming event should be routed without an existing request context.
    #[cfg(test)]
    pub fn route(msg: &InterfoldEvent, completed: &HashSet<E3id>) -> RoutingDecision {
        Self::route_with_context(msg, completed, false)
    }

    /// Decide how an incoming event should be routed.
    pub fn route_with_context(
        msg: &InterfoldEvent,
        completed: &HashSet<E3id>,
        has_context: bool,
    ) -> RoutingDecision {
        // Broadcast non-E3-scoped lifecycle signals to every active context:
        //   * `Shutdown` so children can tear themselves down, and
        //   * `EffectsEnabled` so a hydrated request can re-drive its own in-flight work
        //     once side effects are switched on at the end of boot sync.
        // Both carry no `e3_id`, so without this they would be `Ignore`d and never reach the
        // per-E3 child actors.
        if matches!(
            msg.get_data(),
            InterfoldEventData::Shutdown(_) | InterfoldEventData::EffectsEnabled(_)
        ) {
            return RoutingDecision::Broadcast;
        }

        // Durable observational EVM facts are consumed directly by projections
        // and global observers. They describe an E3, but they do not drive its
        // per-E3 actors. Routing them into a context would create contexts for
        // historical observations and report expected post-settlement receipts
        // as errors after teardown.
        if matches!(
            msg.get_data(),
            InterfoldEventData::InputPublished(_)
                | InterfoldEventData::RewardsDistributed(_)
                | InterfoldEventData::RewardCredited(_)
                | InterfoldEventData::RewardClaimed(_)
                | InterfoldEventData::CommitteeFormationFailed(_)
                | InterfoldEventData::CommitteeActivationChanged(_)
                | InterfoldEventData::CommitteeViabilityUpdated(_)
                | InterfoldEventData::EvmLogObserved(_)
        ) {
            return RoutingDecision::Ignore;
        }

        // Only process events with e3_ids.
        let Some(e3_id) = msg.get_e3_id() else {
            return RoutingDecision::Ignore;
        };

        // If this e3 round has already been completed then this event is unexpected.
        if completed.contains(&e3_id) {
            // On-chain confirmation events that lag behind local teardown are expected and
            // should be silently ignored rather than treated as an error.
            let is_late_terminal = match msg.get_data() {
                // A canonical terminal stage can arrive after another canonical terminal event
                // has already removed the local context.
                InterfoldEventData::E3StageChanged(data)
                    if matches!(data.new_stage, E3Stage::Complete | E3Stage::Failed) =>
                {
                    true
                }
                // E3Failed from on-chain markE3Failed may arrive after a local timeout already
                // cleaned up the context.
                InterfoldEventData::E3Failed(data) if data.reason.ends_without_slashing() => true,
                // Settlement receipts (PlaintextOutputPublished, etc.) can arrive in the same
                // EVM block after E3StageChanged(Complete) already tore down the context.
                InterfoldEventData::PlaintextOutputPublished(_) => true,
                _ => false,
            };
            if is_late_terminal {
                return RoutingDecision::Ignore;
            }
            // Duplicate or overlapping EVM history cannot reopen a completed local context.
            if msg.source() == EventSource::Evm {
                return RoutingDecision::Ignore;
            }
            return RoutingDecision::AlreadyCompleted(e3_id);
        }

        // Chain events create request contexts. Peer events can only contribute to a request
        // that the node already admitted from canonical chain state or restored from a snapshot.
        if msg.source() == EventSource::Net && !has_context {
            return RoutingDecision::UnadmittedNetworkEvent(e3_id);
        }

        let post_forward = match msg.get_data() {
            InterfoldEventData::E3StageChanged(data)
                if msg.source() == EventSource::Evm
                    && matches!(data.new_stage, E3Stage::Complete) =>
            {
                PostForward::PublishComplete
            }
            // Timeout failures have no accusation/slashing lifecycle, so the context can be
            // torn down immediately. Misbehaviour failures (DKGInvalidShares, etc.) still need
            // the accusation/slashing lifecycle to complete before teardown.
            InterfoldEventData::E3Failed(data) if data.reason.ends_without_slashing() => {
                PostForward::PublishComplete
            }
            InterfoldEventData::E3RequestComplete(_) => PostForward::Teardown,
            _ => PostForward::None,
        };

        RoutingDecision::Process {
            e3_id,
            post_forward,
        }
    }
}

#[cfg(test)]
#[path = "workflow_tests.rs"]
mod tests;
