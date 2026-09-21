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
    BusHandle, CommitmentConsistencyCheckRequested, CommitmentLink, CommitmentRosterSelected,
    E3RequestComplete, E3id, EventContext, EventPublisher, EventSubscriber, EventType,
    InterfoldEvent, InterfoldEventData, ProofVerificationPassed, Sequenced, TypedEvent,
};
use e3_fhe_params::BfvPreset;
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
    /// Durable state written atomically with each event that changes the checker.
    snapshot_repo: Option<Repository<CommitmentConsistencySnapshot>>,
}

impl CommitmentConsistencyChecker {
    pub fn new(
        bus: &BusHandle,
        e3_id: E3id,
        links: Vec<Box<dyn CommitmentLink>>,
        committee_h: usize,
        params_preset: BfvPreset,
    ) -> Self {
        Self {
            bus: bus.clone(),
            e3_id: e3_id.clone(),
            consistency: CommitmentConsistency::new_for_preset(
                e3_id,
                links,
                committee_h,
                params_preset,
            ),
            snapshot_repo: None,
        }
    }

    pub(crate) fn with_snapshot(
        mut self,
        repo: Repository<CommitmentConsistencySnapshot>,
        restored: Option<CommitmentConsistencySnapshot>,
    ) -> anyhow::Result<Self> {
        if let Some(snapshot) = restored {
            self.consistency.restore(snapshot)?;
            info!(
                e3_id = %self.e3_id,
                proofs = self.consistency.cached_proof_count(),
                "Restored commitment-consistency state"
            );
        }
        self.snapshot_repo = Some(repo);
        Ok(self)
    }

    fn persist(&mut self, context: &EventContext<Sequenced>) {
        let Some(repo) = &self.snapshot_repo else {
            return;
        };
        let Some(snapshot) = self.consistency.take_snapshot_if_changed() else {
            return;
        };
        if let Err(err) = repo.write_with_context(&snapshot, context) {
            self.consistency.retry_snapshot();
            error!(
                e3_id = %self.e3_id,
                error = %err,
                "Failed to persist commitment-consistency state"
            );
        }
    }

    fn clear_persisted(&self, context: &EventContext<Sequenced>) {
        let Some(repo) = &self.snapshot_repo else {
            return;
        };
        let store = e3_data::DataStore::from(repo);
        if let Err(err) =
            store.write_with_context(Option::<CommitmentConsistencySnapshot>::None, context)
        {
            error!(
                e3_id = %self.e3_id,
                error = %err,
                "Failed to clear completed commitment-consistency state"
            );
        }
    }

    #[cfg(test)]
    pub(crate) fn cached_proof_count(&self) -> usize {
        self.consistency.cached_proof_count()
    }

    #[cfg(test)]
    pub(crate) fn accepted_roster(&self) -> Option<&[u64]> {
        self.consistency.accepted_roster()
    }

    pub fn setup(
        bus: &BusHandle,
        e3_id: E3id,
        links: Vec<Box<dyn CommitmentLink>>,
        committee_h: usize,
        params_preset: BfvPreset,
    ) -> Addr<Self> {
        let actor = Self::new(bus, e3_id, links, committee_h, params_preset);
        let addr = actor.start();
        bus.subscribe(
            EventType::CommitmentConsistencyCheckRequested,
            addr.clone().into(),
        );
        bus.subscribe(EventType::ProofVerificationPassed, addr.clone().into());
        bus.subscribe(EventType::CommitmentRosterSelected, addr.clone().into());
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
            InterfoldEventData::CommitmentRosterSelected(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::E3RequestComplete(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            _ => (),
        }
    }
}

impl Handler<TypedEvent<E3RequestComplete>> for CommitmentConsistencyChecker {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<E3RequestComplete>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let (data, ec) = msg.into_components();
        if data.e3_id == self.e3_id {
            self.clear_persisted(&ec);
        }
    }
}

impl Handler<TypedEvent<CommitmentRosterSelected>> for CommitmentConsistencyChecker {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<CommitmentRosterSelected>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let (data, ec) = msg.into_components();
        let violations = self.consistency.on_roster_selected(data);
        self.persist(&ec);
        for violation in violations {
            if let Err(err) = self.bus.publish(violation, ec.clone()) {
                error!("Failed to publish CommitmentConsistencyViolation: {err}");
            }
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
        self.persist(&ec);
        for violation in violations {
            if let Err(err) = self.bus.publish(violation, ec.clone()) {
                error!("Failed to publish CommitmentConsistencyViolation: {err}");
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
        self.persist(&ec);

        for violation in outcome.violations {
            if let Err(err) = self.bus.publish(violation, ec.clone()) {
                error!("Failed to publish CommitmentConsistencyViolation: {err}");
            }
        }

        // Respond to ShareVerificationActor.
        if let Err(err) = self.bus.publish(outcome.complete, ec) {
            error!("Failed to publish CommitmentConsistencyCheckComplete: {err}");
        }
    }
}
