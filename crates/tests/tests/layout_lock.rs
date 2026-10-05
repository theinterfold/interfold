// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Locks the encoded layout of the event log, the keyshare recovery payloads, the gossip payload,
//! and every value behind a public repository accessor.
//!
//! A release either reads the event log and the snapshots that the previous release wrote, or it
//! raises `SCHEMA_VERSION` so that each node resets its state. During a rollout, peers on two
//! releases decode each other's messages. The lock makes each format change visible, so that the
//! change comes with the version change that it needs.
//!
//! `e3_layout_lock` builds samples of each type and records their encodings. The fixture holds the
//! current formats. When a format changes on purpose, re-record the fixture in the same change, and
//! change the version that the failure message names.
//!
//! Other roots are locked in their own crates: the commitment consistency snapshot in
//! `e3-slashing`, the node proof recovery records in `e3-zk-prover`, and the DHT document payload
//! in `e3-net`. `e3-net` also locks sample sync messages and their request-response frames.
//!
//! Not covered:
//! - roots that this test does not list. The list is kept by hand: add each new persisted or wire
//!   type;
//! - the store keys under which the repositories write their values. The test binds each accessor to
//!   its value type and does not call it;
//! - formats written by hand, such as commit-log framing and event-blob references;
//! - values stored inside opaque bytes, such as the encrypted `SharedSecret` shares in the keyshare
//!   snapshot and the fhe.rs keys in `SensitiveBytes`. The lock sees only the byte string.
//!
//! Rewrite the fixture after an intended change with
//! `LAYOUT_LOCK_UPDATE=1 cargo test -p e3-tests --test layout_lock`.

use std::path::Path;

use e3_aggregator::{
    CommitteeFinalizerRepositoryFactory, PublicKeyRepositoryFactory,
    TrBfvPlaintextRepositoryFactory,
};
use e3_data::{Repositories, Repository};
use e3_events::{
    AggregateId, E3id, Event, EventConstructorWithTimestamp, EventSource, InterfoldEvent,
    ThresholdShareCreated, ThresholdSharePending, TypedEvent, Unsequenced,
};
use e3_evm::{
    DataAvailabilityRepositoryFactory, EthPrivateKeyRepositoryFactory,
    SlashingWriterRepositoryFactory,
};
use e3_fhe::FheRepositoryFactory;
use e3_keyshare::ThresholdKeyshareRepositoryFactory;
use e3_layout_lock::{assert_fixture, sample_rows};
use e3_net::events::GossipData;
use e3_net::NetRepositoryFactory;
use e3_request::{
    ContextRepositoryFactory, DkgFoldAttestationContextRepositoryFactory,
    E3LifecycleRepositoryFactory, MetaRepositoryFactory, RouterRepositoryFactory,
};
use e3_sortition::{
    AggregatorFailoverRepositoryFactory, CiphernodeSelectorFactory,
    FinalizedCommitteesRepositoryFactory, NodeStateRepositoryFactory,
    SortitionRecoveryRepositoryFactory, SortitionRepositoryFactory,
};
use e3_sync::SyncRepositoryFactory;
use serde::de::DeserializeOwned;
use serde::Serialize;

fn e3() -> E3id {
    E3id::new("1", 1)
}

fn none<T>(_: &T) -> String {
    String::new()
}

/// Locks the value type of a repository accessor. The accessor is never called; it binds `T` to
/// the type that the node reads and writes.
fn repository<T: Serialize + DeserializeOwned>(
    root: &str,
    _accessor: fn(&Repositories) -> Repository<T>,
    rows: &mut Vec<String>,
) {
    rows.extend(sample_rows::<T, _>(root, none));
}

/// The event ID that production assigns to the payload.
fn event_id(event: &InterfoldEvent<Unsequenced>) -> String {
    let (payload, _) = event.clone().into_components();
    let fresh = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        payload,
        None,
        1,
        None,
        EventSource::Local,
    );
    format!("\t{}", hex::encode(fresh.event_id().0))
}

fn layout_rows() -> Vec<String> {
    let mut rows = Vec::new();

    // The event log stores unsequenced events, and peers gossip and sync the same type.
    rows.extend(sample_rows::<InterfoldEvent<Unsequenced>, _>(
        "event_log",
        event_id,
    ));
    rows.extend(sample_rows::<GossipData, _>("gossip_payload", none));

    // Keyshare recovery payloads, stored beside the keyshare snapshot.
    rows.extend(sample_rows::<TypedEvent<ThresholdSharePending>, _>(
        "keyshare_pending_payload",
        none,
    ));
    rows.extend(sample_rows::<TypedEvent<ThresholdShareCreated>, _>(
        "keyshare_share_payload",
        none,
    ));

    // e3-keyshare
    repository(
        "threshold_keyshare",
        |r| r.threshold_keyshare(&e3()),
        &mut rows,
    );
    repository(
        "threshold_keyshare_recovery",
        |r| r.threshold_keyshare_recovery(&e3()),
        &mut rows,
    );
    // This node's BFV keypair, which `threshold_keyshare_bfv_key` records directly.
    rows.extend(sample_rows::<e3_keyshare::BfvKeyIntent, _>(
        "threshold_keyshare_bfv_key",
        none,
    ));
    // e3-aggregator
    repository(
        "committee_finalizer_recovery",
        |r| r.committee_finalizer_recovery(),
        &mut rows,
    );
    repository("trbfv_plaintext", |r| r.trbfv_plaintext(&e3()), &mut rows);
    repository(
        "trbfv_plaintext_recovery",
        |r| r.trbfv_plaintext_recovery(&e3()),
        &mut rows,
    );
    repository("publickey", |r| r.publickey(&e3()), &mut rows);
    repository(
        "publickey_recovery",
        |r| r.publickey_recovery(&e3()),
        &mut rows,
    );
    // e3-fhe
    repository("fhe", |r| r.fhe(&e3()), &mut rows);
    // e3-sortition
    repository("sortition", |r| r.sortition(), &mut rows);
    repository(
        "sortition_admission",
        |r| r.sortition_admission(),
        &mut rows,
    );
    repository("sortition_recovery", |r| r.sortition_recovery(), &mut rows);
    repository(
        "sortition_bond_owners",
        |r| r.sortition_bond_owners(),
        &mut rows,
    );
    repository(
        "ciphernode_selector",
        |r| r.ciphernode_selector(),
        &mut rows,
    );
    repository(
        "aggregator_failover",
        |r| r.aggregator_failover(),
        &mut rows,
    );
    repository("node_state", |r| r.node_state(), &mut rows);
    repository(
        "finalized_committees",
        |r| r.finalized_committees(),
        &mut rows,
    );
    // e3-evm
    repository("eth_private_key", |r| r.eth_private_key(), &mut rows);
    repository(
        "slashing_writer_recovery",
        |r| r.slashing_writer_recovery(1),
        &mut rows,
    );
    repository(
        "data_availability_recovery",
        |r| r.data_availability_recovery(1),
        &mut rows,
    );
    // e3-net
    repository("libp2p_keypair", |r| r.libp2p_keypair(), &mut rows);
    // e3-sync
    repository("schema_version", |r| r.schema_version(), &mut rows);
    repository("node_role", |r| r.node_role(), &mut rows);
    repository(
        "aggregate_seq",
        |r| r.aggregate_seq(AggregateId::new(1)),
        &mut rows,
    );
    repository(
        "aggregate_block",
        |r| r.aggregate_block(AggregateId::new(1)),
        &mut rows,
    );
    repository(
        "aggregate_ts",
        |r| r.aggregate_ts(AggregateId::new(1)),
        &mut rows,
    );
    repository(
        "restart_input_cursors",
        |r| r.restart_input_cursors(),
        &mut rows,
    );
    repository(
        "request_router_checkpoint",
        SyncRepositoryFactory::request_router_checkpoint,
        &mut rows,
    );
    // e3-request
    repository("meta", |r| r.meta(&e3()), &mut rows);
    repository(
        "dkg_fold_attestation_context",
        |r| r.dkg_fold_attestation_context(&e3()),
        &mut rows,
    );
    repository("context", |r| r.context(&e3()), &mut rows);
    repository("router", |r| r.router(), &mut rows);
    repository(
        "router_request_checkpoint",
        RouterRepositoryFactory::request_router_checkpoint,
        &mut rows,
    );
    repository("e3_lifecycle", |r| r.e3_lifecycle(), &mut rows);

    rows
}

#[test]
fn persisted_layouts_match_the_locked_fixture() {
    assert_fixture(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/layout_lock.txt"),
        &layout_rows(),
    );
}
