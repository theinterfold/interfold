// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use e3_events::{
    E3Failed, E3RequestComplete, E3Stage, E3StageChanged, EventContextAccessors, EventSource,
    FailureReason, InterfoldEvent, PlaintextAggregated, RewardCredited, Sequenced, Shutdown,
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
    let msg = with_e3_id("late", id.clone()).with_source(EventSource::Local);
    assert_eq!(
        RequestRouter::route(&msg, &completed),
        RoutingDecision::AlreadyCompleted(id)
    );
}

#[test]
fn canonical_evm_history_for_completed_request_is_ignored() {
    let id = e3id();
    let mut completed = HashSet::new();
    completed.insert(id.clone());
    let msg = with_e3_id("historical-chain-event", id).with_source(EventSource::Evm);

    assert_eq!(
        RequestRouter::route(&msg, &completed),
        RoutingDecision::Ignore
    );
}

#[test]
fn settlement_receipt_is_not_routed_to_completed_context() {
    let id = e3id();
    let mut completed = HashSet::new();
    completed.insert(id.clone());
    let msg = from_data(RewardCredited {
        e3_id: id,
        account: "0x01".into(),
        token: "0x02".into(),
        amount: "10".into(),
    });

    assert_eq!(
        RequestRouter::route(&msg, &completed),
        RoutingDecision::Ignore
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
fn plaintext_aggregated_waits_for_chain_completion() {
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
            post_forward: PostForward::None,
        }
    );
}

#[test]
fn peer_event_cannot_create_an_unknown_request_context() {
    let id = e3id();
    let msg = with_e3_id("peer-artifact", id.clone()).with_source(EventSource::Net);

    assert_eq!(
        RequestRouter::route_with_context(&msg, &HashSet::new(), false),
        RoutingDecision::UnadmittedNetworkEvent(id)
    );
}

#[test]
fn peer_event_can_enter_an_admitted_request_context() {
    let id = e3id();
    let msg = with_e3_id("peer-artifact", id.clone()).with_source(EventSource::Net);

    assert_eq!(
        RequestRouter::route_with_context(&msg, &HashSet::new(), true),
        RoutingDecision::Process {
            e3_id: id,
            post_forward: PostForward::None,
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
fn non_evm_stage_change_cannot_complete_a_request() {
    let id = e3id();
    let msg = from_data(E3StageChanged {
        e3_id: id.clone(),
        previous_stage: E3Stage::CiphertextReady,
        new_stage: E3Stage::Complete,
    })
    .with_source(EventSource::Local);

    assert_eq!(
        RequestRouter::route(&msg, &HashSet::new()),
        RoutingDecision::Process {
            e3_id: id,
            post_forward: PostForward::None,
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
fn requester_cancellation_publishes_complete() {
    let id = e3id();
    let msg = e3_failed(id.clone(), FailureReason::RequesterCancelled);
    assert_eq!(
        RequestRouter::route(&msg, &HashSet::new()),
        RoutingDecision::Process {
            e3_id: id,
            post_forward: PostForward::PublishComplete,
        }
    );
}

#[test]
fn requester_and_provider_failures_publish_complete() {
    for reason in [
        FailureReason::NoInputsReceived,
        FailureReason::ComputeProviderExpired,
        FailureReason::ComputeProviderFailed,
    ] {
        let id = e3id();
        let msg = e3_failed(id.clone(), reason);
        assert_eq!(
            RequestRouter::route(&msg, &HashSet::new()),
            RoutingDecision::Process {
                e3_id: id,
                post_forward: PostForward::PublishComplete,
            }
        );
    }
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
