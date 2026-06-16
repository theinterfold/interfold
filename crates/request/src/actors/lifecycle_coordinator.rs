// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Thin actix shell around the pure [`E3LifecycleService`].
//!
//! [`E3LifecycleCoordinator`] is an additive, durable observer over the event
//! bus. It does not drive the protocol or emit events — the node remains
//! choreographed. Its sole job is to keep a persisted, single-source-of-truth
//! map of every E3's [`E3Stage`] so the node can report progress and resume
//! awareness of in-flight E3s after a restart, and log its known state on
//! shutdown.
//!
//! All decision logic lives in [`E3LifecycleService`]; this actor only performs
//! the resulting actix/persistence I/O.

use crate::E3LifecycleRepositoryFactory;
use crate::{E3LifecycleService, LifecycleDecision};
use actix::{Actor, ActorContext, Addr, Context, Handler};
use anyhow::Result;
use e3_data::{AutoPersist, DataStore, Persistable, RepositoriesFactory, Repository};
use e3_events::prelude::*;
use e3_events::{BusHandle, E3Stage, E3id, EventType, InterfoldEvent, InterfoldEventData};
use e3_utils::MAILBOX_LIMIT;
use std::collections::HashMap;
use tracing::{info, warn};

/// Persisted snapshot type for the lifecycle coordinator.
pub type E3LifecycleSnapshot = HashMap<E3id, E3Stage>;

/// Events whose observation can change an E3's tracked stage.
const LIFECYCLE_EVENTS: &[EventType] = &[
    EventType::E3Requested,
    EventType::CommitteePublished,
    EventType::CommitteeFinalized,
    EventType::PublicKeyAggregated,
    EventType::CiphertextOutputPublished,
    EventType::PlaintextAggregated,
    EventType::PlaintextOutputPublished,
    EventType::E3RequestComplete,
    EventType::E3Failed,
    EventType::E3StageChanged,
];

/// Thin message-passing shell that durably tracks E3 lifecycle stages.
pub struct E3LifecycleCoordinator {
    /// Pure, in-memory source of truth for per-E3 stage.
    service: E3LifecycleService,
    /// Durable mirror of [`E3LifecycleService::snapshot`].
    store: Persistable<E3LifecycleSnapshot>,
}

impl E3LifecycleCoordinator {
    /// Loads (or initializes) persisted stage state, starts the actor, and
    /// subscribes it to all lifecycle-bearing events plus `Shutdown`.
    pub async fn attach(bus: &BusHandle, store: DataStore) -> Result<Addr<Self>> {
        let repositories = store.repositories();
        Self::attach_with_repo(bus, repositories.e3_lifecycle()).await
    }

    /// Variant used in tests where a specific repository is supplied.
    pub async fn attach_with_repo(
        bus: &BusHandle,
        repo: Repository<E3LifecycleSnapshot>,
    ) -> Result<Addr<Self>> {
        let store = repo.load_or_default(HashMap::new()).await?;
        let service = E3LifecycleService::from_snapshot(store.get().unwrap_or_default());

        let addr = Self { service, store }.start();

        let mut subscriptions = LIFECYCLE_EVENTS.to_vec();
        subscriptions.push(EventType::Shutdown);
        bus.subscribe_all(&subscriptions, addr.clone().into());

        info!("E3 lifecycle coordinator started");
        Ok(addr)
    }

    /// Persists the current in-memory snapshot.
    fn persist(&mut self) {
        let snapshot = self.service.snapshot();
        self.store.set(snapshot);
    }
}

impl Actor for E3LifecycleCoordinator {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

impl Handler<InterfoldEvent> for E3LifecycleCoordinator {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (data, _ec) = msg.into_components();

        if let InterfoldEventData::Shutdown(_) = data {
            let active = self.service.active();
            if active.is_empty() {
                info!("E3 lifecycle coordinator shutting down; no active E3s");
            } else {
                info!(
                    active_count = active.len(),
                    "E3 lifecycle coordinator shutting down with active E3s: {:?}",
                    active
                        .iter()
                        .map(|id| (id.to_string(), self.service.stage(id)))
                        .collect::<Vec<_>>()
                );
            }
            self.persist();
            ctx.stop();
            return;
        }

        match self.service.observe(&data) {
            LifecycleDecision::Advanced { e3_id, from, to } => {
                info!(%e3_id, ?from, ?to, "E3 lifecycle advanced");
                self.persist();
            }
            LifecycleDecision::Terminal { e3_id, stage } => {
                info!(%e3_id, ?stage, "E3 lifecycle reached terminal stage");
                self.persist();
            }
            LifecycleDecision::Regressed {
                e3_id,
                current,
                attempted,
            } => {
                warn!(
                    %e3_id,
                    ?current,
                    ?attempted,
                    "Ignoring out-of-order lifecycle event implying an earlier stage"
                );
            }
            LifecycleDecision::Unchanged { .. } | LifecycleDecision::NotLifecycle => {}
        }
    }
}
