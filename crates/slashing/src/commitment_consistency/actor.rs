// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Actor that cross-checks commitment values across different circuit proofs.
//!
//! Has two roles:
//!
//! 1. **Pre-ZK gating** (request/response): Subscribes to
//!    [`CommitmentConsistencyCheckRequested`] from [`ShareVerificationActor`],
//!    caches each party's public signals, evaluates all registered
//!    [`CommitmentLink`]s, and responds with
//!    [`CommitmentConsistencyCheckComplete`]. Inconsistent parties are excluded
//!    from ZK verification.
//!
//! 2. **Post-ZK cross-circuit checking**: Subscribes to
//!    [`ProofVerificationPassed`] events and, for each registered link,
//!    compares commitment values across different circuit proofs. On mismatch,
//!    publishes [`CommitmentConsistencyViolation`] for the accusation pipeline.
//!
//! ## Architecture
//!
//! This file is a **thin actix shell**. All consistency-checking logic lives in
//! the plain, synchronous [`CommitmentConsistency`] service
//! ([`crate::domain::commitment_consistency`]). The actor's only job is to
//! translate inbound [`InterfoldEvent`]s into service calls and to publish the
//! [`CommitmentConsistencyViolation`]s and [`CommitmentConsistencyCheckComplete`]
//! responses the service returns.
//!
//! [`CommitmentConsistencyCheckComplete`]: e3_events::CommitmentConsistencyCheckComplete
//! [`CommitmentConsistencyViolation`]: e3_events::CommitmentConsistencyViolation

use actix::{Actor, Addr, Context, Handler};
use e3_data::Repository;
use e3_events::{
    BusHandle, CommitmentConsistencyCheckRequested, CommitmentLink, E3id, EventPublisher,
    EventSubscriber, EventType, InterfoldEvent, InterfoldEventData, ProofVerificationPassed,
    TypedEvent,
};
use e3_utils::NotifySync;
use tracing::{error, info};

use crate::domain::commitment_consistency::{CommitmentConsistency, CommitmentConsistencySnapshot};

/// Per-E3 actor that enforces cross-circuit commitment consistency.
///
/// Thin actix shell around the [`CommitmentConsistency`] domain service, which
/// owns the verified-proof cache and the registered links.
pub struct CommitmentConsistencyChecker {
    bus: BusHandle,
    e3_id: E3id,
    /// Plain, synchronous consistency core. Owns the proof cache and links.
    consistency: CommitmentConsistency,
    /// Durable copy of the verified-proof cache; written after every mutation. `None` only
    /// in tests that never restart. See [`CommitmentConsistencySnapshot`] for why.
    snapshot_repo: Option<Repository<CommitmentConsistencySnapshot>>,
}

impl CommitmentConsistencyChecker {
    pub fn new(
        bus: &BusHandle,
        e3_id: E3id,
        links: Vec<Box<dyn CommitmentLink>>,
        committee_h: usize,
    ) -> Self {
        Self {
            bus: bus.clone(),
            e3_id: e3_id.clone(),
            consistency: CommitmentConsistency::new(e3_id, links, committee_h),
            snapshot_repo: None,
        }
    }

    /// Attach the durable cache. If `restored` is given the cache starts from it.
    pub fn with_snapshot(
        mut self,
        repo: Repository<CommitmentConsistencySnapshot>,
        restored: Option<CommitmentConsistencySnapshot>,
    ) -> Self {
        if let Some(snapshot) = restored {
            self.consistency.restore(snapshot);
            info!(
                "CommitmentConsistencyChecker for E3 {} restored {} cached proof(s)",
                self.e3_id,
                self.consistency.cached_proof_count()
            );
        }
        self.snapshot_repo = Some(repo);
        self
    }

    fn persist(&self) {
        if let Some(repo) = &self.snapshot_repo {
            repo.write(&self.consistency.snapshot());
        }
    }

    pub fn setup(
        bus: &BusHandle,
        e3_id: E3id,
        links: Vec<Box<dyn CommitmentLink>>,
        committee_h: usize,
    ) -> Addr<Self> {
        let actor = Self::new(bus, e3_id, links, committee_h);
        let addr = actor.start();
        bus.subscribe(
            EventType::CommitmentConsistencyCheckRequested,
            addr.clone().into(),
        );
        bus.subscribe(EventType::ProofVerificationPassed, addr.clone().into());
        addr
    }
}

impl Actor for CommitmentConsistencyChecker {
    type Context = Context<Self>;

    fn started(&mut self, _ctx: &mut Self::Context) {
        info!(
            "CommitmentConsistencyChecker started for E3 {} with {} link(s)",
            self.e3_id,
            self.consistency.link_count()
        );
    }
}

impl Handler<InterfoldEvent> for CommitmentConsistencyChecker {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        match msg {
            InterfoldEventData::CommitmentConsistencyCheckRequested(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ProofVerificationPassed(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            _ => (),
        }
    }
}

impl Handler<TypedEvent<ProofVerificationPassed>> for CommitmentConsistencyChecker {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ProofVerificationPassed>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let (data, ec) = msg.into_components();
        let violations = self.consistency.on_proof_verified(data);
        self.persist();
        for violation in violations {
            if let Err(err) = self.bus.publish(violation, ec.clone()) {
                error!(
                    e3_id = %self.e3_id,
                    "Failed to publish CommitmentConsistencyViolation: {err}"
                );
            }
        }
    }
}

impl Handler<TypedEvent<CommitmentConsistencyCheckRequested>> for CommitmentConsistencyChecker {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<CommitmentConsistencyCheckRequested>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let (data, ec) = msg.into_components();
        let Some(outcome) = self.consistency.on_check_requested(data) else {
            return;
        };
        self.persist();

        for violation in outcome.violations {
            if let Err(err) = self.bus.publish(violation, ec.clone()) {
                error!(
                    e3_id = %self.e3_id,
                    "Failed to publish CommitmentConsistencyViolation: {err}"
                );
            }
        }

        // Respond to ShareVerificationActor.
        if let Err(err) = self.bus.publish(outcome.complete, ec) {
            error!(
                e3_id = %self.e3_id,
                "Failed to publish CommitmentConsistencyCheckComplete: {err}"
            );
        }
    }
}
