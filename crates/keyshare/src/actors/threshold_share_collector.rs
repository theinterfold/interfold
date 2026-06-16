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
use crate::domain::{ReceivedShareProofs, ShareCollectOutcome, ThresholdShareCollection};

/// Message sent when threshold share collection times out.
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
/// timeout timer and the handle to the parent keyshare actor.
pub struct ThresholdShareCollector {
    e3_id: E3id,
    parent: Addr<ThresholdKeyshare>,
    collection: ThresholdShareCollection,
    timeout: Duration,
    timeout_handle: Option<SpawnHandle>,
}

impl ThresholdShareCollector {
    /// Excludes `own_party_id` from `todo` (own share is consumed locally for C4).
    pub fn setup(
        parent: Addr<ThresholdKeyshare>,
        total: u64,
        own_party_id: u64,
        e3_id: E3id,
        timeout: Duration,
    ) -> Addr<Self> {
        let collector = Self {
            collection: ThresholdShareCollection::new(e3_id.clone(), total, own_party_id),
            e3_id,
            parent,
            timeout,
            timeout_handle: None,
        };
        collector.start()
    }

    fn complete(
        &mut self,
        ctx: &mut actix::Context<Self>,
        ec: EventContext<Sequenced>,
        outcome: ShareCollectOutcome,
    ) {
        if let ShareCollectOutcome::Completed { shares, proofs } = outcome {
            info!(e3_id = %self.e3_id, "We have received all threshold shares");
            if let Some(handle) = self.timeout_handle.take() {
                ctx.cancel_future(handle);
            }
            let event: TypedEvent<AllThresholdSharesCollected> =
                TypedEvent::new(AllThresholdSharesCollected::new(shares, proofs), ec);
            self.parent.do_send(event);
        }
    }
}

impl Actor for ThresholdShareCollector {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
        info!(
            e3_id = %self.e3_id,
            "ThresholdShareCollector started, scheduling timeout in {:?}",
            self.timeout
        );
        // Schedule timeout
        let handle = ctx.notify_later(ThresholdShareCollectionTimeout, self.timeout);
        self.timeout_handle = Some(handle);
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
        self.complete(ctx, ec, outcome);
    }
}

impl Handler<ThresholdShareCollectionTimeout> for ThresholdShareCollector {
    type Result = ();
    fn handle(
        &mut self,
        _: ThresholdShareCollectionTimeout,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let Some(missing_parties) = self.collection.timeout() else {
            return;
        };

        warn!(
            e3_id = %self.e3_id,
            missing_parties = ?missing_parties,
            "Threshold share collection timed out, {} parties missing",
            missing_parties.len()
        );

        self.parent.do_send(ThresholdShareCollectionFailed {
            e3_id: self.e3_id.clone(),
            reason: format!(
                "Timeout waiting for threshold shares from {} parties",
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
        self.complete(ctx, msg.ec, outcome);
    }
}
