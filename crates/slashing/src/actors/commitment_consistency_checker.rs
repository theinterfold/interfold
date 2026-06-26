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
//! ## Restart safety
//!
//! The per-E3 actor is (re)created on `CommitteeFinalized`, which on a restart is
//! replayed *after* the boot sequence has already re-delivered the earlier
//! `ProofVerificationPassed` events (C0 encryption-key proofs, etc.). A freshly
//! created checker would therefore evaluate cross-circuit links (e.g. C0→C3)
//! against an empty cache and false-accuse honest peers. To prevent this it
//! rehydrates its cache from the EventStore on startup — loading every persisted
//! `ProofVerificationPassed` for its E3 — and buffers any inbound consistency
//! check until that rehydration completes.
//!
//! ## Architecture
//!
//! This file is a **thin actix shell**. All consistency-checking logic lives in
//! the plain, synchronous [`CommitmentConsistency`] service
//! ([`crate::domain::commitment_consistency`]).
//!
//! [`CommitmentConsistencyCheckComplete`]: e3_events::CommitmentConsistencyCheckComplete
//! [`CommitmentConsistencyViolation`]: e3_events::CommitmentConsistencyViolation

use actix::{Actor, Addr, AsyncContext, Context, Handler, Recipient};
use e3_events::{
    AggregateId, BusHandle, CommitmentConsistencyCheckRequested, CommitmentLink, CorrelationId,
    E3id, EventPublisher, EventSource, EventStoreFilter, EventStoreQueryBy,
    EventStoreQueryResponse, EventSubscriber, EventType, InterfoldEvent, InterfoldEventData,
    ProofVerificationPassed, TsAgg, TypedEvent,
};
use e3_utils::NotifySync;
use std::collections::HashMap;
use tracing::{error, info};

use crate::domain::commitment_consistency::CommitmentConsistency;

/// Per-E3 actor that enforces cross-circuit commitment consistency.
///
/// Thin actix shell around the [`CommitmentConsistency`] domain service, which
/// owns the verified-proof cache and the registered links.
pub struct CommitmentConsistencyChecker {
    bus: BusHandle,
    e3_id: E3id,
    /// Plain, synchronous consistency core. Owns the proof cache and links.
    consistency: CommitmentConsistency,
    /// EventStore reader used to rehydrate the verified-proof cache after a restart.
    eventstore: Recipient<EventStoreQueryBy<TsAgg>>,
    /// `false` until the startup rehydration query has been answered. While false,
    /// consistency checks are buffered (the cache is not yet complete) and live
    /// `ProofVerificationPassed` events are cached without link evaluation.
    rehydrated: bool,
    /// Correlation id of the in-flight rehydration query.
    rehydrate_query_id: Option<CorrelationId>,
    /// Check requests received before rehydration completes; replayed afterwards.
    pending_checks: Vec<TypedEvent<CommitmentConsistencyCheckRequested>>,
}

impl CommitmentConsistencyChecker {
    pub fn new(
        bus: &BusHandle,
        eventstore: Recipient<EventStoreQueryBy<TsAgg>>,
        e3_id: E3id,
        links: Vec<Box<dyn CommitmentLink>>,
        committee_h: usize,
    ) -> Self {
        Self {
            bus: bus.clone(),
            e3_id: e3_id.clone(),
            consistency: CommitmentConsistency::new(e3_id, links, committee_h),
            eventstore,
            rehydrated: false,
            rehydrate_query_id: None,
            pending_checks: Vec::new(),
        }
    }

    pub fn setup(
        bus: &BusHandle,
        eventstore: Recipient<EventStoreQueryBy<TsAgg>>,
        e3_id: E3id,
        links: Vec<Box<dyn CommitmentLink>>,
        committee_h: usize,
    ) -> Addr<Self> {
        let actor = Self::new(bus, eventstore, e3_id, links, committee_h);
        let addr = actor.start();
        bus.subscribe(
            EventType::CommitmentConsistencyCheckRequested,
            addr.clone().into(),
        );
        bus.subscribe(EventType::ProofVerificationPassed, addr.clone().into());
        addr
    }

    /// Evaluate a consistency check request against the (now-complete) cache and
    /// publish the resulting violations + completion response.
    fn process_check_request(&mut self, msg: TypedEvent<CommitmentConsistencyCheckRequested>) {
        let (data, ec) = msg.into_components();
        let Some(outcome) = self.consistency.on_check_requested(data) else {
            return;
        };
        for violation in outcome.violations {
            if let Err(err) = self.bus.publish(violation, ec.clone()) {
                error!("Failed to publish CommitmentConsistencyViolation: {err}");
            }
        }
        if let Err(err) = self.bus.publish(outcome.complete, ec) {
            error!("Failed to publish CommitmentConsistencyCheckComplete: {err}");
        }
    }
}

impl Actor for CommitmentConsistencyChecker {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        info!(
            "CommitmentConsistencyChecker started for E3 {} with {} link(s); rehydrating cache",
            self.e3_id,
            self.consistency.link_count()
        );
        // Rehydrate the verified-proof cache from the EventStore so cross-circuit links evaluate
        // against the full set of proofs verified before any restart.
        let id = CorrelationId::new();
        self.rehydrate_query_id = Some(id);
        let since: HashMap<AggregateId, u128> = HashMap::from([(
            AggregateId::from_chain_id(Some(self.e3_id.chain_id())),
            0u128,
        )]);
        if let Err(e) = self.eventstore.try_send(
            EventStoreQueryBy::<TsAgg>::new(id, since, ctx.address().recipient())
                .with_filter(EventStoreFilter::Source(EventSource::Local)),
        ) {
            error!("Failed to query EventStore for consistency-checker rehydration: {e}");
            // Proceed without rehydration rather than buffering checks forever.
            self.rehydrate_query_id = None;
            self.rehydrated = true;
        }
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

/// Rehydration response: cache every persisted `ProofVerificationPassed` for this E3, then drain
/// any consistency checks that arrived while rehydrating.
impl Handler<EventStoreQueryResponse> for CommitmentConsistencyChecker {
    type Result = ();

    fn handle(&mut self, msg: EventStoreQueryResponse, _ctx: &mut Self::Context) -> Self::Result {
        if Some(msg.id()) != self.rehydrate_query_id {
            return;
        }
        self.rehydrate_query_id = None;

        let mut count = 0usize;
        for event in msg.into_events() {
            let (data, _ec) = event.into_components();
            if let InterfoldEventData::ProofVerificationPassed(data) = data {
                self.consistency.cache_verified_proof(data);
                count += 1;
            }
        }
        info!(
            "CommitmentConsistencyChecker for E3 {} rehydrated {count} verified proof(s); \
             processing {} buffered check(s)",
            self.e3_id,
            self.pending_checks.len()
        );
        self.rehydrated = true;

        for msg in std::mem::take(&mut self.pending_checks) {
            self.process_check_request(msg);
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
        // While rehydrating, cache without evaluating links — the cache is incomplete, so a link
        // evaluation could false-accuse. Genuine inconsistencies are still caught by the buffered
        // pre-ZK checks once the cache is complete.
        if !self.rehydrated {
            self.consistency.cache_verified_proof(data);
            return;
        }
        for violation in self.consistency.on_proof_verified(data) {
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
        // Defer until the cache is rehydrated, otherwise cross-circuit links evaluate against an
        // incomplete cache and false-accuse honest peers.
        if !self.rehydrated {
            self.pending_checks.push(msg);
            return;
        }
        self.process_check_request(msg);
    }
}
