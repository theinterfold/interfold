// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::time::Duration;

use actix::{Actor, ActorContext, Addr, AsyncContext, Handler, Message, SpawnHandle};
use e3_events::{
    E3id, EventContext, Sequenced, ThresholdShareCollectionFailed, ThresholdShareCreated,
    TypedEvent,
};
use e3_trbfv::PartyId;
use e3_utils::MAILBOX_LIMIT;
use tracing::{info, warn};

use crate::actors::threshold_keyshare::{AllThresholdSharesCollected, ThresholdKeyshare};
use crate::domain::timeout_policy::ThresholdShareSchedule;
use crate::domain::{ReceivedShareProofs, ShareCollectOutcome, ThresholdShareCollection};

/// Marks the point when collection may continue with an available H-party set.
#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct ThresholdShareCollectionCutoff;

/// Marks the canonical DKG deadline for threshold-share collection.
#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct ThresholdShareCollectionTimeout;

/// Remove this party from `todo` so collection finishes without it.
#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct ExpelPartyFromShareCollection {
    pub party_id: PartyId,
    pub ec: EventContext<Sequenced>,
}

/// Thin actix shell around [`ThresholdShareCollection`]; owns the mailbox,
/// cutoff and deadline timers, and the handle to the parent keyshare actor.
pub struct ThresholdShareCollector {
    e3_id: E3id,
    parent: Addr<ThresholdKeyshare>,
    collection: ThresholdShareCollection,
    cutoff_delay: Duration,
    deadline_delay: Duration,
    cutoff_reached: bool,
    minimum_external: usize,
    last_ec: Option<EventContext<Sequenced>>,
    cutoff_handle: Option<SpawnHandle>,
    deadline_handle: Option<SpawnHandle>,
}

impl ThresholdShareCollector {
    /// Excludes `own_party_id` from `todo` (own share is consumed locally for C4).
    pub(crate) fn setup(
        parent: Addr<ThresholdKeyshare>,
        total: u64,
        own_party_id: u64,
        minimum_external: usize,
        e3_id: E3id,
        schedule: ThresholdShareSchedule,
    ) -> Addr<Self> {
        Self::create(|ctx| {
            ctx.set_mailbox_capacity(MAILBOX_LIMIT);
            Self {
                collection: ThresholdShareCollection::new(e3_id.clone(), total, own_party_id),
                e3_id,
                parent,
                cutoff_delay: schedule.cutoff_delay,
                deadline_delay: schedule.deadline_delay,
                cutoff_reached: schedule.cutoff_reached,
                minimum_external,
                last_ec: None,
                cutoff_handle: None,
                deadline_handle: None,
            }
        })
    }

    fn complete_at_cutoff(&mut self, ctx: &mut actix::Context<Self>) -> bool {
        let Some(ec) = self.last_ec.clone() else {
            return false;
        };
        let Some(outcome) = self.collection.complete_at_cutoff(self.minimum_external) else {
            return false;
        };

        info!(
            e3_id = %self.e3_id,
            minimum_external = self.minimum_external,
            "Continuing DKG with available threshold shares"
        );
        self.complete(ctx, ec, outcome);
        true
    }

    fn complete(
        &mut self,
        ctx: &mut actix::Context<Self>,
        ec: EventContext<Sequenced>,
        outcome: ShareCollectOutcome,
    ) {
        if let ShareCollectOutcome::Completed { shares, proofs } = outcome {
            info!(e3_id = %self.e3_id, shares = shares.len(), "Threshold share collection completed");
            if let Some(handle) = self.cutoff_handle.take() {
                ctx.cancel_future(handle);
            }
            if let Some(handle) = self.deadline_handle.take() {
                ctx.cancel_future(handle);
            }
            let event: TypedEvent<AllThresholdSharesCollected> =
                TypedEvent::new(AllThresholdSharesCollected::new(shares, proofs), ec);
            self.parent.do_send(event);
            ctx.stop();
        }
    }
}

impl Actor for ThresholdShareCollector {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        if self.cutoff_reached {
            info!(
                e3_id = %self.e3_id,
                "Threshold-share soft cutoff already passed; collecting until H shares arrive"
            );
        } else {
            info!(
                e3_id = %self.e3_id,
                cutoff = ?self.cutoff_delay,
                "ThresholdShareCollector scheduled the soft cutoff"
            );
            self.cutoff_handle =
                Some(ctx.notify_later(ThresholdShareCollectionCutoff, self.cutoff_delay));
        }
        info!(
            e3_id = %self.e3_id,
            deadline = ?self.deadline_delay,
            "ThresholdShareCollector scheduled the canonical DKG deadline"
        );
        self.deadline_handle =
            Some(ctx.notify_later(ThresholdShareCollectionTimeout, self.deadline_delay));
    }
}

impl Handler<TypedEvent<ThresholdShareCreated>> for ThresholdShareCollector {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<ThresholdShareCreated>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        info!("ThresholdShareCollector: ThresholdShareCreated received by collector");
        let proofs = ReceivedShareProofs {
            signed_c2a_proof: msg.signed_c2a_proof,
            signed_c2b_proof: msg.signed_c2b_proof,
            signed_c3a_proofs: msg.signed_c3a_proofs,
            signed_c3b_proofs: msg.signed_c3b_proofs,
        };
        let outcome = self.collection.receive(msg.share, proofs);
        if !matches!(&outcome, ShareCollectOutcome::Ignored) {
            self.last_ec = Some(ec.clone());
        }
        if matches!(&outcome, ShareCollectOutcome::Pending) && self.cutoff_reached {
            self.complete_at_cutoff(ctx);
        } else {
            self.complete(ctx, ec, outcome);
        }
    }
}

impl Handler<ThresholdShareCollectionCutoff> for ThresholdShareCollector {
    type Result = ();
    fn handle(
        &mut self,
        _: ThresholdShareCollectionCutoff,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        self.cutoff_handle = None;
        self.cutoff_reached = true;
        if self.complete_at_cutoff(ctx) {
            return;
        }

        info!(
            e3_id = %self.e3_id,
            minimum_external = self.minimum_external,
            "Threshold-share soft cutoff reached below H; collection remains active"
        );
    }
}

impl Handler<ThresholdShareCollectionTimeout> for ThresholdShareCollector {
    type Result = ();
    fn handle(
        &mut self,
        _: ThresholdShareCollectionTimeout,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        self.deadline_handle = None;
        if self.complete_at_cutoff(ctx) {
            return;
        }

        let Some(missing_parties) = self.collection.timeout() else {
            return;
        };

        warn!(
            e3_id = %self.e3_id,
            missing_parties = ?missing_parties,
            "Threshold share collection reached the canonical DKG deadline, {} parties missing",
            missing_parties.len()
        );

        self.parent.do_send(ThresholdShareCollectionFailed {
            e3_id: self.e3_id.clone(),
            reason: format!(
                "Canonical DKG deadline reached while waiting for threshold shares from {} parties",
                missing_parties.len()
            ),
            missing_parties,
        });

        ctx.stop();
    }
}

impl Handler<ExpelPartyFromShareCollection> for ThresholdShareCollector {
    type Result = ();
    fn handle(
        &mut self,
        msg: ExpelPartyFromShareCollection,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let outcome = self.collection.expel(msg.party_id);
        if matches!(outcome, ShareCollectOutcome::Completed { .. }) {
            info!(
                e3_id = %self.e3_id,
                "All remaining threshold shares collected after party expulsion!"
            );
        }
        if matches!(&outcome, ShareCollectOutcome::Pending) && self.cutoff_reached {
            self.last_ec = Some(msg.ec);
            self.complete_at_cutoff(ctx);
        } else {
            self.complete(ctx, msg.ec, outcome);
        }
    }
}
