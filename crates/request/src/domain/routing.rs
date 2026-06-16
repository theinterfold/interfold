// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_events::{E3Stage, E3id, Event, InterfoldEvent, InterfoldEventData};
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
    /// Decide how an incoming event should be routed given the set of completed requests.
    pub fn route(msg: &InterfoldEvent, completed: &HashSet<E3id>) -> RoutingDecision {
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

        // Only process events with e3_ids.
        let Some(e3_id) = msg.get_e3_id() else {
            return RoutingDecision::Ignore;
        };

        // If this e3 round has already been completed then this event is unexpected.
        if completed.contains(&e3_id) {
            // On-chain confirmation events that lag behind local teardown are expected and
            // should be silently ignored rather than treated as an error.
            let is_late_terminal = match msg.get_data() {
                // E3StageChanged(Complete) always lags local PlaintextAggregated completion.
                InterfoldEventData::E3StageChanged(data)
                    if matches!(data.new_stage, E3Stage::Complete | E3Stage::Failed) =>
                {
                    true
                }
                // E3Failed from on-chain markE3Failed may arrive after a local timeout already
                // cleaned up the context.
                InterfoldEventData::E3Failed(data) if data.reason.is_timeout() => true,
                _ => false,
            };
            if is_late_terminal {
                return RoutingDecision::Ignore;
            }
            return RoutingDecision::AlreadyCompleted(e3_id);
        }

        let post_forward = match msg.get_data() {
            // Receiving the PlaintextAggregated event means the request is complete and we can
            // notify everyone. This might change as we consider other completion factors.
            InterfoldEventData::PlaintextAggregated(_) => PostForward::PublishComplete,
            InterfoldEventData::E3StageChanged(data)
                if matches!(data.new_stage, E3Stage::Complete) =>
            {
                PostForward::PublishComplete
            }
            // Timeout failures have no accusation/slashing lifecycle, so the context can be
            // torn down immediately. Misbehaviour failures (DKGInvalidShares, etc.) still need
            // the accusation/slashing lifecycle to complete before teardown.
            InterfoldEventData::E3Failed(data) if data.reason.is_timeout() => {
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
mod tests {
    use super::*;
    use e3_events::{
        E3Failed, E3RequestComplete, E3Stage, E3StageChanged, FailureReason, InterfoldEvent,
        PlaintextAggregated, Sequenced, Shutdown,
    };

    fn e3id() -> E3id {
        E3id::new("1", 1)
    }

    fn with_e3_id(label: &str, id: E3id) -> InterfoldEvent {
        InterfoldEvent::<Sequenced>::test_event(label)
            .e3_id(id)
            .seq(1)
            .build()
    }

    fn from_data(data: impl Into<InterfoldEventData>) -> InterfoldEvent {
        InterfoldEvent::<Sequenced>::test_event("x")
            .data(data)
            .seq(1)
            .build()
    }

    #[test]
    fn shutdown_broadcasts() {
        let msg = from_data(Shutdown);
        assert_eq!(
            RequestRouter::route(&msg, &HashSet::new()),
            RoutingDecision::Broadcast
        );
    }

    #[test]
    fn effects_enabled_broadcasts() {
        // EffectsEnabled has no e3_id but must reach every hydrated context so each can
        // re-drive its own in-flight work after a restart.
        let msg = from_data(e3_events::EffectsEnabled::new());
        assert_eq!(
            RequestRouter::route(&msg, &HashSet::new()),
            RoutingDecision::Broadcast
        );
    }

    #[test]
    fn event_without_e3_id_is_ignored() {
        let msg = InterfoldEvent::<Sequenced>::test_event("no-id")
            .seq(1)
            .build();
        assert_eq!(
            RequestRouter::route(&msg, &HashSet::new()),
            RoutingDecision::Ignore
        );
    }

    #[test]
    fn completed_request_is_an_error() {
        let id = e3id();
        let mut completed = HashSet::new();
        completed.insert(id.clone());
        let msg = with_e3_id("late", id.clone());
        assert_eq!(
            RequestRouter::route(&msg, &completed),
            RoutingDecision::AlreadyCompleted(id)
        );
    }

    #[test]
    fn stage_changed_to_complete_ignored_when_already_completed() {
        // E3StageChanged(Complete) arriving from the EVM after local teardown is expected —
        // the on-chain confirmation lags behind local completion. It should be silently
        // ignored, not treated as an error.
        let id = e3id();
        let mut completed = HashSet::new();
        completed.insert(id.clone());
        let msg = from_data(E3StageChanged {
            e3_id: id.clone(),
            previous_stage: E3Stage::CiphertextReady,
            new_stage: E3Stage::Complete,
        });
        assert_eq!(
            RequestRouter::route(&msg, &completed),
            RoutingDecision::Ignore
        );
    }

    #[test]
    fn stage_changed_to_failed_ignored_when_completed() {
        // E3StageChanged(Failed) from the EVM can arrive after a local timeout already cleaned up
        // the context. Treat it as a silent no-op, the same way we handle E3StageChanged(Complete).
        let id = e3id();
        let mut completed = HashSet::new();
        completed.insert(id.clone());
        let msg = from_data(E3StageChanged {
            e3_id: id.clone(),
            previous_stage: E3Stage::CiphertextReady,
            new_stage: E3Stage::Failed,
        });
        assert_eq!(
            RequestRouter::route(&msg, &completed),
            RoutingDecision::Ignore
        );
    }

    #[test]
    fn plaintext_aggregated_publishes_complete() {
        let id = e3id();
        let msg = from_data(PlaintextAggregated {
            e3_id: id.clone(),
            decrypted_output: vec![],
            decryption_aggregator_proofs: vec![],
        });
        assert_eq!(
            RequestRouter::route(&msg, &HashSet::new()),
            RoutingDecision::Process {
                e3_id: id,
                post_forward: PostForward::PublishComplete,
            }
        );
    }

    #[test]
    fn stage_changed_to_complete_publishes_complete() {
        let id = e3id();
        let msg = from_data(E3StageChanged {
            e3_id: id.clone(),
            previous_stage: E3Stage::CiphertextReady,
            new_stage: E3Stage::Complete,
        });
        assert_eq!(
            RequestRouter::route(&msg, &HashSet::new()),
            RoutingDecision::Process {
                e3_id: id,
                post_forward: PostForward::PublishComplete,
            }
        );
    }

    #[test]
    fn stage_changed_to_failed_does_not_complete() {
        let id = e3id();
        let msg = from_data(E3StageChanged {
            e3_id: id.clone(),
            previous_stage: E3Stage::CiphertextReady,
            new_stage: E3Stage::Failed,
        });
        assert_eq!(
            RequestRouter::route(&msg, &HashSet::new()),
            RoutingDecision::Process {
                e3_id: id,
                post_forward: PostForward::None,
            }
        );
    }

    #[test]
    fn e3_request_complete_triggers_teardown() {
        // InterfoldEventData::get_e3_id() now returns Some(e3_id) for E3RequestComplete,
        // so the event reaches the Teardown arm of the router.
        let id = e3id();
        let msg = from_data(E3RequestComplete { e3_id: id.clone() });
        assert_eq!(
            RequestRouter::route(&msg, &HashSet::new()),
            RoutingDecision::Process {
                e3_id: id,
                post_forward: PostForward::Teardown,
            }
        );
    }

    #[test]
    fn generic_event_with_e3_id_has_no_completion() {
        let id = e3id();
        let msg = with_e3_id("generic", id.clone());
        assert_eq!(
            RequestRouter::route(&msg, &HashSet::new()),
            RoutingDecision::Process {
                e3_id: id,
                post_forward: PostForward::None,
            }
        );
    }

    // --- timeout-triggered E3Failed tests ---

    fn e3_failed(id: E3id, reason: FailureReason) -> InterfoldEvent {
        from_data(E3Failed {
            e3_id: id,
            failed_at_stage: E3Stage::CommitteeFinalized,
            reason,
        })
    }

    #[test]
    fn e3_failed_dkg_timeout_publishes_complete() {
        let id = e3id();
        let msg = e3_failed(id.clone(), FailureReason::DKGTimeout);
        assert_eq!(
            RequestRouter::route(&msg, &HashSet::new()),
            RoutingDecision::Process {
                e3_id: id,
                post_forward: PostForward::PublishComplete,
            }
        );
    }

    #[test]
    fn e3_failed_committee_formation_timeout_publishes_complete() {
        let id = e3id();
        let msg = e3_failed(id.clone(), FailureReason::CommitteeFormationTimeout);
        assert_eq!(
            RequestRouter::route(&msg, &HashSet::new()),
            RoutingDecision::Process {
                e3_id: id,
                post_forward: PostForward::PublishComplete,
            }
        );
    }

    #[test]
    fn e3_failed_compute_timeout_publishes_complete() {
        let id = e3id();
        let msg = e3_failed(id.clone(), FailureReason::ComputeTimeout);
        assert_eq!(
            RequestRouter::route(&msg, &HashSet::new()),
            RoutingDecision::Process {
                e3_id: id,
                post_forward: PostForward::PublishComplete,
            }
        );
    }

    #[test]
    fn e3_failed_decryption_timeout_publishes_complete() {
        let id = e3id();
        let msg = e3_failed(id.clone(), FailureReason::DecryptionTimeout);
        assert_eq!(
            RequestRouter::route(&msg, &HashSet::new()),
            RoutingDecision::Process {
                e3_id: id,
                post_forward: PostForward::PublishComplete,
            }
        );
    }

    #[test]
    fn e3_failed_invalid_shares_does_not_complete() {
        // Slashable failures must NOT trigger E3RequestComplete — the accusation/slashing
        // lifecycle must be allowed to finish first.
        let id = e3id();
        let msg = e3_failed(id.clone(), FailureReason::DKGInvalidShares);
        assert_eq!(
            RequestRouter::route(&msg, &HashSet::new()),
            RoutingDecision::Process {
                e3_id: id,
                post_forward: PostForward::None,
            }
        );
    }

    #[test]
    fn e3_failed_timeout_ignored_when_already_completed() {
        let id = e3id();
        let mut completed = HashSet::new();
        completed.insert(id.clone());
        let msg = e3_failed(id.clone(), FailureReason::DKGTimeout);
        assert_eq!(
            RequestRouter::route(&msg, &completed),
            RoutingDecision::Ignore
        );
    }

    #[test]
    fn stage_changed_to_failed_ignored_when_already_completed() {
        let id = e3id();
        let mut completed = HashSet::new();
        completed.insert(id.clone());
        let msg = from_data(E3StageChanged {
            e3_id: id.clone(),
            previous_stage: E3Stage::CommitteeFinalized,
            new_stage: E3Stage::Failed,
        });
        assert_eq!(
            RequestRouter::route(&msg, &completed),
            RoutingDecision::Ignore
        );
    }
}
