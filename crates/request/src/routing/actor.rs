// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::ContextRepositoryFactory;
use crate::E3Context;
use crate::E3ContextParams;
use crate::E3MetaExtension;
use crate::EventBuffer;
use crate::PostForward;
use crate::RequestRouter;
use crate::RouterRepositoryFactory;
use crate::RoutingDecision;
use actix::{Actor, Addr, Context, Handler};
use anyhow::*;
use async_trait::async_trait;
use e3_data::DataStore;
use e3_data::FromSnapshotWithParams;
use e3_data::RepositoriesFactory;
use e3_data::Repository;
use e3_data::Snapshot;
use e3_events::prelude::*;
use e3_events::trap;
use e3_events::BusHandle;
use e3_events::E3RequestComplete;
use e3_events::EType;
use e3_events::EventType;
use e3_events::{AggregateId, CiphernodeSelected, E3id, InterfoldEvent, RequestRouterCheckpoint};
use e3_utils::MAILBOX_LIMIT;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;
use std::{collections::HashMap, sync::Arc};

/// An Extension interface for the E3Router system that listens and responds to InterfoldEvents.
///
/// # Responsibilities
/// - Listens for broadcast InterfoldEvents
/// - Instantiates appropriate actors based on received events
/// - Manages actor state persistence and reconstruction
/// - Handles event streaming to registered recipients
///
/// # Usage
/// Extensions implement the `on_event` handler to define which events they respond to.
/// When an event is received, the extension typically:
/// 1. Uses the request's context to construct required actors
/// 2. Saves actor addresses to the context using `set_event_recipient`
/// 3. Manages event streaming from buffers to registered recipients
///
/// Extensions can also reconstruct actors from persisted state using context
/// snapshots and repositories. They can check for dependencies in the context
/// before constructing new extensions.
#[async_trait]
pub trait E3Extension: Send + Sync + 'static {
    /// This function is triggered when an InterfoldEvent is sent to the router. Use this to
    /// initialize the receiver using `ctx.set_event_receiver(my_address.into())`. Typically this
    /// means filtering for specific e3_id enabled events that give rise to actors that have to
    /// handle certain behaviour.
    fn on_event(&self, ctx: &mut E3Context, evt: &InterfoldEvent);

    /// This function it triggered when the request context is being hydrated from snapshot.
    async fn hydrate(&self, ctx: &mut E3Context, snapshot: &crate::E3ContextSnapshot)
        -> Result<()>;
}

/// Routes E3_id-specific contexts to registered extensions and manages message forwarding.
///
/// # Core Functions
/// - Maintains contexts for each E3 request
/// - Lazily registers extension instances with appropriate dependencies per E3_id
/// - Forwards incoming messages to registered instances
/// - Manages request lifecycle and completion
///
/// Extensions receive an E3_id-specific context and can handle specific
/// message types. The router ensures proper message delivery and context management
/// throughout the request lifecycle.
///
/// This actor is a thin message-passing shell: all routing decisions are computed by the
/// pure [`RequestRouter`] service; the actor only performs the resulting actix I/O.
// TODO: setup so that we have to place extensions within correct order of dependencies
pub struct E3Router {
    /// The context for every E3 request
    contexts: HashMap<E3id, E3Context>,
    /// A list of completed requests
    completed: HashSet<E3id>,
    /// The extensions this instance of the router is configured to listen for
    extensions: Arc<Vec<Box<dyn E3Extension>>>,
    /// A buffer for events to send to the
    buffer: EventBuffer,
    /// The EventBus
    bus: BusHandle,
    /// A repository for storing snapshots
    store: Repository<E3RouterSnapshot>,
    /// Per-aggregate cursor covered by the self-consistent router recovery checkpoint.
    replay_cursors: HashMap<AggregateId, u64>,
    recovery_store: Repository<RequestRouterCheckpoint>,
    recovered_selections: Vec<CiphernodeSelected>,
    /// Slashably-failed E3s and the unix second at which each context is torn down.
    /// Persisted in the checkpoint so a restart re-arms the timers.
    teardown_deadlines: HashMap<E3id, u64>,
    /// How long a slashably-failed E3's context stays alive after `E3Failed`.
    teardown_grace: std::time::Duration,
}

/// Default for how long a slashably-failed E3's context stays alive after `E3Failed`.
///
/// The accusation manager can still initiate or vote on an accusation for up to the
/// on-chain `accusationVoteValidity` window (30 min by default) plus the local vote timeout
/// (5 min) after the failure. Two hours covers the largest window governance can set with
/// margin; the leak this bounds used to be permanent.
pub const SLASHABLE_FAILURE_TEARDOWN_GRACE: std::time::Duration =
    std::time::Duration::from_secs(2 * 60 * 60);

/// Upper bound on how many completed E3 ids the router remembers.
///
/// `completed` exists to reject late events for finished requests, and it is serialized
/// into the recovery checkpoint on **every** routed event. Unbounded, it grows by one
/// `E3id` (a `String` plus a `u64`) per E3 for the life of the data directory, so the
/// per-event checkpoint write grows with total E3 history. Late events for an E3 arrive
/// within blocks of its completion, never thousands of E3s later; keeping the most recent
/// completions preserves the guard where it matters.
pub const MAX_REMEMBERED_COMPLETIONS: usize = 4096;

/// Drop the oldest completions once `completed` exceeds [`MAX_REMEMBERED_COMPLETIONS`].
///
/// On-chain E3 ids are allocated by an increasing counter, so the numerically lowest ids
/// are the oldest; pruning by id keeps the checkpoint schema unchanged (no separate order
/// list to persist). Ids that do not parse as integers sort first and go before any that
/// do, which only affects non-chain test fixtures.
pub(crate) fn prune_completed(completed: &mut HashSet<E3id>) {
    let excess = completed.len().saturating_sub(MAX_REMEMBERED_COMPLETIONS);
    if excess == 0 {
        return;
    }
    let mut by_age: Vec<E3id> = completed.iter().cloned().collect();
    by_age.sort_by_cached_key(|id| {
        (
            id.e3_id().parse::<u128>().ok(),
            id.chain_id(),
            id.e3_id().to_owned(),
        )
    });
    for oldest in by_age.into_iter().take(excess) {
        completed.remove(&oldest);
    }
}

pub struct E3RouterParams {
    extensions: Arc<Vec<Box<dyn E3Extension>>>,
    bus: BusHandle,
    store: Repository<E3RouterSnapshot>,
    replay_cursors: HashMap<AggregateId, u64>,
    recovery_store: Repository<RequestRouterCheckpoint>,
    recovered_selections: Vec<CiphernodeSelected>,
    teardown_deadlines: HashMap<E3id, u64>,
    teardown_grace: std::time::Duration,
}

impl E3Router {
    pub fn builder(bus: &BusHandle, store: DataStore) -> E3RouterBuilder {
        let repositories = store.repositories();
        let builder = E3RouterBuilder {
            bus: bus.clone(),
            extensions: vec![],
            recovered_selections: vec![],
            recovery_store: repositories.request_router_checkpoint(),
            store: repositories.router(),
            teardown_grace: SLASHABLE_FAILURE_TEARDOWN_GRACE,
        };

        // Everything needs the committe meta factory so adding it here by default
        builder.with(E3MetaExtension::create())
    }

    pub fn from_params(params: E3RouterParams) -> Self {
        Self {
            extensions: params.extensions,
            bus: params.bus.clone(),
            store: params.store.clone(),
            completed: HashSet::new(),
            contexts: HashMap::new(),
            buffer: EventBuffer::default(),
            replay_cursors: params.replay_cursors,
            recovery_store: params.recovery_store,
            recovered_selections: params.recovered_selections,
            teardown_deadlines: params.teardown_deadlines,
            teardown_grace: params.teardown_grace,
        }
    }
}

#[path = "effects/mod.rs"]
mod effects;
#[path = "handlers.rs"]
mod handlers;

pub use effects::{
    load_dkg_fold_attestation_contexts, project_request_router_event, E3RouterBuilder,
    E3RouterSnapshot,
};

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
