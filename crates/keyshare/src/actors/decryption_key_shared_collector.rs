// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use actix::{Actor, ActorContext, Addr, AsyncContext, Handler, Message, SpawnHandle};
use e3_events::{DecryptionKeyShared, E3id, EventContext, Sequenced, TypedEvent};
use e3_utils::MAILBOX_LIMIT;
use tracing::{info, warn};

use crate::actors::threshold_keyshare::ThresholdKeyshare;
use crate::domain::{DecryptionKeySharedCollection, DecryptionShareOutcome};

/// Message sent when all expected DecryptionKeyShared events have been collected.
#[derive(Message)]
#[rtype(result = "()")]
pub struct AllDecryptionKeySharesCollected {
    pub shares: HashMap<u64, DecryptionKeyShared>,
}

/// Message sent when DecryptionKeyShared collection times out.
#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct DecryptionKeySharedCollectionTimeout;

/// Message sent when DecryptionKeyShared collection fails.
#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct DecryptionKeySharedCollectionFailed {
    pub e3_id: E3id,
    pub reason: String,
    pub missing_parties: Vec<u64>,
}

/// Removes this party from the `expected` set so decryption can proceed with
/// N-1 shares instead of waiting for a share that will never arrive.
#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct ExpelPartyFromDecryptionKeySharedCollection {
    pub party_id: u64,
    pub ec: EventContext<Sequenced>,
}

/// Thin actix shell around [`DecryptionKeySharedCollection`] (Exchange #3).
///
/// Once all expected events are collected, sends `AllDecryptionKeySharesCollected`
/// to the parent `ThresholdKeyshare` actor for C4 proof verification.
pub struct DecryptionKeySharedCollector {
    e3_id: E3id,
    parent: Addr<ThresholdKeyshare>,
    collection: DecryptionKeySharedCollection,
    timeout: Duration,
    timeout_handle: Option<SpawnHandle>,
}

impl DecryptionKeySharedCollector {
    pub fn setup(
        parent: Addr<ThresholdKeyshare>,
        expected_parties: HashSet<u64>,
        e3_id: E3id,
        timeout: Duration,
    ) -> Addr<Self> {
        let collector = Self {
            collection: DecryptionKeySharedCollection::new(e3_id.clone(), expected_parties),
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
        outcome: DecryptionShareOutcome,
    ) {
        if let DecryptionShareOutcome::Completed(shares) = outcome {
            info!(e3_id = %self.e3_id, "All DecryptionKeyShared events collected");
            if let Some(handle) = self.timeout_handle.take() {
                ctx.cancel_future(handle);
            }
            let event: TypedEvent<AllDecryptionKeySharesCollected> =
                TypedEvent::new(AllDecryptionKeySharesCollected { shares }, ec);
            self.parent.do_send(event);
            ctx.stop();
        }
    }
}

impl Actor for DecryptionKeySharedCollector {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
        info!(
            e3_id = %self.e3_id,
            "DecryptionKeySharedCollector started, expecting {} parties, timeout {:?}",
            self.collection.expected_len(),
            self.timeout
        );
        let handle = ctx.notify_later(DecryptionKeySharedCollectionTimeout, self.timeout);
        self.timeout_handle = Some(handle);
    }
}

impl Handler<TypedEvent<DecryptionKeyShared>> for DecryptionKeySharedCollector {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<DecryptionKeyShared>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        let outcome = self.collection.receive(msg);
        self.complete(ctx, ec, outcome);
    }
}

impl Handler<DecryptionKeySharedCollectionTimeout> for DecryptionKeySharedCollector {
    type Result = ();
    fn handle(
        &mut self,
        _: DecryptionKeySharedCollectionTimeout,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let Some(missing_parties) = self.collection.timeout() else {
            return;
        };

        warn!(
            e3_id = %self.e3_id,
            missing_parties = ?missing_parties,
            "DecryptionKeyShared collection timed out, {} parties missing",
            missing_parties.len()
        );

        self.parent.do_send(DecryptionKeySharedCollectionFailed {
            e3_id: self.e3_id.clone(),
            reason: format!(
                "Timeout waiting for DecryptionKeyShared from {} parties",
                missing_parties.len()
            ),
            missing_parties,
        });

        ctx.stop();
    }
}

impl Handler<ExpelPartyFromDecryptionKeySharedCollection> for DecryptionKeySharedCollector {
    type Result = ();
    fn handle(
        &mut self,
        msg: ExpelPartyFromDecryptionKeySharedCollection,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let outcome = self.collection.expel(msg.party_id);
        if matches!(outcome, DecryptionShareOutcome::Completed(_)) {
            info!(
                e3_id = %self.e3_id,
                "All remaining decryption key shares collected after party expulsion!"
            );
        }
        self.complete(ctx, msg.ec, outcome);
    }
}
