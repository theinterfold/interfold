// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use e3_events::{
    CommitteePublished, E3Failed, E3Requested, E3StageChanged, FailureReason, PlaintextAggregated,
    PublicKeyAggregated,
};
use e3_utils::ArcBytes;

fn id(n: &str) -> E3id {
    E3id::new(n, 1)
}

fn requested(n: &str) -> InterfoldEventData {
    InterfoldEventData::E3Requested(E3Requested {
        e3_id: id(n),
        ..Default::default()
    })
}

fn stage_changed(n: &str, from: E3Stage, to: E3Stage) -> InterfoldEventData {
    InterfoldEventData::E3StageChanged(E3StageChanged {
        e3_id: id(n),
        previous_stage: from,
        new_stage: to,
    })
}

fn failed(n: &str, stage: E3Stage) -> InterfoldEventData {
    InterfoldEventData::E3Failed(E3Failed {
        e3_id: id(n),
        failed_at_stage: stage,
        reason: FailureReason::DKGTimeout,
    })
}

#[test]
fn unknown_e3_is_stage_none() {
    let svc = E3LifecycleService::new();
    assert_eq!(E3Stage::None, svc.stage(&id("x")));
}

#[test]
fn requested_advances_from_none() {
    let mut svc = E3LifecycleService::new();
    let decision = svc.observe(&requested("a"));
    assert_eq!(
        LifecycleDecision::Advanced {
            e3_id: id("a"),
            from: E3Stage::None,
            to: E3Stage::Requested
        },
        decision
    );
    assert_eq!(E3Stage::Requested, svc.stage(&id("a")));
}

#[test]
fn stage_advances_monotonically() {
    let mut svc = E3LifecycleService::new();
    svc.observe(&requested("a"));
    let d = svc.observe(&stage_changed(
        "a",
        E3Stage::Requested,
        E3Stage::KeyPublished,
    ));
    assert!(matches!(d, LifecycleDecision::Advanced { .. }));
    assert_eq!(E3Stage::KeyPublished, svc.stage(&id("a")));
}

#[test]
fn out_of_order_earlier_stage_is_regressed_and_ignored() {
    let mut svc = E3LifecycleService::new();
    svc.observe(&stage_changed("a", E3Stage::None, E3Stage::KeyPublished));
    let d = svc.observe(&requested("a"));
    assert_eq!(
        LifecycleDecision::Regressed {
            e3_id: id("a"),
            current: E3Stage::KeyPublished,
            attempted: E3Stage::Requested
        },
        d
    );
    // Tracked stage is unchanged.
    assert_eq!(E3Stage::KeyPublished, svc.stage(&id("a")));
}

#[test]
fn same_stage_is_unchanged() {
    let mut svc = E3LifecycleService::new();
    svc.observe(&requested("a"));
    let d = svc.observe(&requested("a"));
    assert_eq!(
        LifecycleDecision::Unchanged {
            e3_id: id("a"),
            stage: E3Stage::Requested
        },
        d
    );
}

#[test]
fn failure_is_terminal_and_frozen() {
    let mut svc = E3LifecycleService::new();
    svc.observe(&requested("a"));
    let d = svc.observe(&failed("a", E3Stage::Requested));
    assert_eq!(
        LifecycleDecision::Terminal {
            e3_id: id("a"),
            stage: E3Stage::Failed
        },
        d
    );
    // Further lifecycle events do not move a terminal E3.
    let d2 = svc.observe(&stage_changed("a", E3Stage::Failed, E3Stage::Complete));
    assert_eq!(
        LifecycleDecision::Unchanged {
            e3_id: id("a"),
            stage: E3Stage::Failed
        },
        d2
    );
    assert_eq!(E3Stage::Failed, svc.stage(&id("a")));
}

#[test]
fn active_excludes_terminal_e3s() {
    let mut svc = E3LifecycleService::new();
    svc.observe(&requested("a"));
    svc.observe(&requested("b"));
    svc.observe(&failed("b", E3Stage::Requested));
    let active = svc.active();
    assert_eq!(vec![id("a")], active);
}

#[test]
fn non_lifecycle_event_is_ignored() {
    let mut svc = E3LifecycleService::new();
    let d = svc.observe(&InterfoldEventData::Shutdown(e3_events::Shutdown));
    assert_eq!(LifecycleDecision::NotLifecycle, d);
}

#[test]
fn plaintext_aggregation_is_not_canonical_completion() {
    let mut svc = E3LifecycleService::new();
    svc.observe(&requested("a"));

    let decision = svc.observe(&InterfoldEventData::PlaintextAggregated(
        PlaintextAggregated {
            e3_id: id("a"),
            decrypted_output: vec![ArcBytes::from_bytes(b"result")],
            decryption_aggregator_proofs: vec![],
        },
    ));

    assert_eq!(LifecycleDecision::NotLifecycle, decision);
    assert_eq!(E3Stage::Requested, svc.stage(&id("a")));
}

#[test]
fn only_confirmed_committee_publication_advances_the_key_stage() {
    let mut svc = E3LifecycleService::new();
    svc.observe(&requested("a"));

    let local_decision = svc.observe(&InterfoldEventData::PublicKeyAggregated(
        PublicKeyAggregated {
            pubkey: ArcBytes::from_bytes(b"public-key"),
            e3_id: id("a"),
            nodes: Default::default(),
            committee_addresses: vec![],
            honest_committee_addresses: vec![],
            pk_commitment: [0u8; 32],
            dkg_aggregator_proof: None,
            dkg_attestation_bundle: None,
        },
    ));

    assert_eq!(LifecycleDecision::NotLifecycle, local_decision);
    assert_eq!(E3Stage::Requested, svc.stage(&id("a")));

    let chain_decision = svc.observe(&InterfoldEventData::CommitteePublished(
        CommitteePublished {
            e3_id: id("a"),
            nodes: vec![],
            public_key: ArcBytes::from_bytes(b"public-key"),
            proof: ArcBytes::from_bytes(b"proof"),
        },
    ));

    assert_eq!(
        LifecycleDecision::Advanced {
            e3_id: id("a"),
            from: E3Stage::Requested,
            to: E3Stage::KeyPublished,
        },
        chain_decision
    );
}

#[test]
fn snapshot_roundtrip_preserves_stages() {
    let mut svc = E3LifecycleService::new();
    svc.observe(&requested("a"));
    svc.observe(&stage_changed(
        "a",
        E3Stage::Requested,
        E3Stage::CiphertextReady,
    ));
    svc.observe(&requested("b"));

    let snap = svc.snapshot();
    let restored = E3LifecycleService::from_snapshot(snap);
    assert_eq!(E3Stage::CiphertextReady, restored.stage(&id("a")));
    assert_eq!(E3Stage::Requested, restored.stage(&id("b")));
}
