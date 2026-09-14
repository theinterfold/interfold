// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{collections::HashMap, sync::Arc, time::Duration};

use actix::{Actor, ActorContext, Addr, AsyncContext, Handler, Message, SpawnHandle};
use e3_events::{
    E3id, EncryptionKey, EncryptionKeyCollectionFailed, EncryptionKeyCreated, EventContext,
    Sequenced, TypedEvent,
};
use e3_trbfv::PartyId;
use e3_utils::MAILBOX_LIMIT;
use tracing::{info, warn};

use crate::actors::threshold_keyshare::ThresholdKeyshare;
use crate::domain::{CollectOutcome, CutoffOutcome, EncryptionKeyCollection};

/// Message sent when the encryption-key phase is complete.
///
/// This contains the BFV public keys of every party that delivered before the cutoff,
/// sorted by party_id, ready to be used for encrypting shares.
#[derive(Message)]
#[rtype(result = "()")]
pub struct AllEncryptionKeysCollected {
    /// All collected encryption keys, sorted by party_id
    pub keys: Vec<Arc<EncryptionKey>>,
}

impl From<HashMap<u64, Arc<EncryptionKey>>> for AllEncryptionKeysCollected {
    fn from(value: HashMap<u64, Arc<EncryptionKey>>) -> Self {
        // Sort by party_id for deterministic ordering
        let mut keys: Vec<_> = value.into_values().collect();
        keys.sort_by_key(|k| k.party_id);
        AllEncryptionKeysCollected { keys }
    }
}

/// Message sent when the encryption-key collection cutoff is reached.
#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct EncryptionKeyCollectionTimeout;

/// Removes this party from the `todo` set so the DKG can complete with
/// N-1 keys instead of waiting for a key that will never arrive.
#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct ExpelPartyFromKeyCollection {
    pub party_id: PartyId,
    pub ec: EventContext<Sequenced>,
}

/// Thin actix shell around [`EncryptionKeyCollection`].
///
/// Once all keys are collected, or the cutoff is reached with at least the committee `H`
/// keys, it sends `AllEncryptionKeysCollected` to the parent `ThresholdKeyshare` actor. If
/// the cutoff is reached with fewer keys, it sends `EncryptionKeyCollectionFailed`. If a
/// party is expelled (slashed), it is removed from the expected set so the collection can
/// complete with N-1 parties.
pub struct EncryptionKeyCollector {
    e3_id: E3id,
    parent: Addr<ThresholdKeyshare>,
    collection: EncryptionKeyCollection,
    timeout: Duration,
    timeout_handle: Option<SpawnHandle>,
    /// Causal context of the last accepted key. A cutoff completion continues from it.
    last_ec: Option<EventContext<Sequenced>>,
}

impl EncryptionKeyCollector {
    pub fn setup(
        parent: Addr<ThresholdKeyshare>,
        total: u64,
        minimum: usize,
        e3_id: E3id,
        timeout: Duration,
    ) -> Addr<Self> {
        Self::create(|ctx| {
            ctx.set_mailbox_capacity(MAILBOX_LIMIT);
            Self {
                collection: EncryptionKeyCollection::new(e3_id.clone(), total, minimum),
                e3_id,
                parent,
                timeout,
                timeout_handle: None,
                last_ec: None,
            }
        })
    }

    fn complete(
        &mut self,
        ctx: &mut actix::Context<Self>,
        ec: EventContext<Sequenced>,
        outcome: CollectOutcome,
    ) {
        if let CollectOutcome::Completed(keys) = outcome {
            self.finish(ctx, ec, keys);
        }
    }

    fn finish(
        &mut self,
        ctx: &mut actix::Context<Self>,
        ec: EventContext<Sequenced>,
        keys: Vec<Arc<EncryptionKey>>,
    ) {
        info!(e3_id = %self.e3_id, "All encryption keys collected!");
        if let Some(handle) = self.timeout_handle.take() {
            ctx.cancel_future(handle);
        }
        let event: TypedEvent<AllEncryptionKeysCollected> =
            TypedEvent::new(AllEncryptionKeysCollected { keys }, ec);
        self.parent.do_send(event);
    }
}

impl Actor for EncryptionKeyCollector {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        info!(
            e3_id = %self.e3_id,
            "EncryptionKeyCollector started, scheduling timeout in {:?}",
            self.timeout
        );

        let handle = ctx.notify_later(EncryptionKeyCollectionTimeout, self.timeout);
        self.timeout_handle = Some(handle);
    }
}

impl Handler<TypedEvent<EncryptionKeyCreated>> for EncryptionKeyCollector {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<EncryptionKeyCreated>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        info!("EncryptionKeyCollector: EncryptionKeyCreated received");
        let outcome = self.collection.receive(msg.key);
        if !matches!(outcome, CollectOutcome::Ignored) {
            self.last_ec = Some(ec.clone());
        }
        self.complete(ctx, ec, outcome);
    }
}

impl Handler<EncryptionKeyCollectionTimeout> for EncryptionKeyCollector {
    type Result = ();
    fn handle(
        &mut self,
        _: EncryptionKeyCollectionTimeout,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        match self.collection.cutoff() {
            CutoffOutcome::Inert => {}
            CutoffOutcome::Completed(keys) => {
                // A completion requires at least one accepted key, so a context exists.
                if let Some(ec) = self.last_ec.clone() {
                    self.finish(ctx, ec, keys);
                    ctx.stop();
                } else {
                    warn!(
                        e3_id = %self.e3_id,
                        "Encryption key cutoff completed without a causal context; treating as failed"
                    );
                    self.fail(ctx, Vec::new());
                }
            }
            CutoffOutcome::Failed(missing_parties) => self.fail(ctx, missing_parties),
        }
    }
}

impl EncryptionKeyCollector {
    fn fail(&mut self, ctx: &mut actix::Context<Self>, missing_parties: Vec<PartyId>) {
        warn!(
            e3_id = %self.e3_id,
            missing_parties = ?missing_parties,
            "Encryption key collection timed out, {} parties missing",
            missing_parties.len()
        );

        self.parent.do_send(EncryptionKeyCollectionFailed {
            e3_id: self.e3_id.clone(),
            reason: format!(
                "Timeout waiting for encryption keys from {} parties",
                missing_parties.len()
            ),
            missing_parties,
        });

        ctx.stop();
    }
}

impl Handler<ExpelPartyFromKeyCollection> for EncryptionKeyCollector {
    type Result = ();
    fn handle(
        &mut self,
        msg: ExpelPartyFromKeyCollection,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let outcome = self.collection.expel(msg.party_id);
        if matches!(outcome, CollectOutcome::Completed(_)) {
            info!(
                e3_id = %self.e3_id,
                "All remaining encryption keys collected after party expulsion!"
            );
        }
        self.complete(ctx, msg.ec, outcome);
    }
}
