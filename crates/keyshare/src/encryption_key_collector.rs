// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use actix::{Actor, ActorContext, Addr, AsyncContext, Handler, Message, SpawnHandle};
use e3_events::{
    E3id, EncryptionKey, EncryptionKeyCollectionFailed, EncryptionKeyCreated, EventContext,
    Sequenced, TypedEvent,
};
use e3_trbfv::PartyId;
use e3_utils::MAILBOX_LIMIT;
use tracing::{info, warn};

use crate::ThresholdKeyshare;

/// State of the collector
pub enum CollectorState {
    /// Currently collecting keys
    Collecting,
    /// All keys have been collected
    Finished,
    /// Collection timed out
    TimedOut,
}

/// Message sent when all encryption keys have been collected.
///
/// This contains all parties' BFV public keys, sorted by party_id,
/// ready to be used for encrypting shares.
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

/// Message sent when encryption key collection times out.
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

/// Actor that collects BFV encryption keys from all parties.
///
/// Once all keys are collected, it sends `AllEncryptionKeysCollected` to the parent
/// `ThresholdKeyshare` actor. If collection times out, it sends `EncryptionKeyCollectionFailed`.
/// If a party is expelled (slashed), it is removed from the expected set so the
/// collection can complete with N-1 parties.
pub struct EncryptionKeyCollector {
    e3_id: E3id,
    todo: HashSet<PartyId>,
    parent: Addr<ThresholdKeyshare>,
    state: CollectorState,
    keys: HashMap<PartyId, Arc<EncryptionKey>>,
    timeout: Duration,
    timeout_handle: Option<SpawnHandle>,
}

impl EncryptionKeyCollector {
    pub fn setup(
        parent: Addr<ThresholdKeyshare>,
        total: u64,
        e3_id: E3id,
        timeout: Duration,
    ) -> Addr<Self> {
        let collector = Self {
            e3_id,
            todo: (0..total).collect(),
            parent,
            state: CollectorState::Collecting,
            keys: HashMap::new(),
            timeout,
            timeout_handle: None,
        };
        collector.start()
    }
}

impl Actor for EncryptionKeyCollector {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
        info!(
            e3_id = %self.e3_id,
            expected_parties = ?self.todo,
            expected_count = self.todo.len(),
            timeout = ?self.timeout,
            "EncryptionKeyCollector started — expecting BFV public keys from {} parties",
            self.todo.len()
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
        let start = Instant::now();
        let pid = msg.key.party_id;
        info!(
            e3_id = %self.e3_id,
            party_id = pid,
            "EncryptionKeyCollector: EncryptionKeyCreated received"
        );

        // Ignore if already finished or timed out
        if !matches!(self.state, CollectorState::Collecting) {
            warn!(
                e3_id = %self.e3_id,
                party_id = pid,
                state = match self.state {
                    CollectorState::Collecting => "Collecting",
                    CollectorState::Finished => "Finished",
                    CollectorState::TimedOut => "TimedOut",
                },
                "EncryptionKeyCollector: not collecting, ignoring late EncryptionKeyCreated"
            );
            return;
        }

        let Some(_) = self.todo.take(&pid) else {
            warn!(
                e3_id = %self.e3_id,
                party_id = pid,
                expected_parties = ?self.todo,
                "EncryptionKeyCollector: received key from unexpected party — not in expected set"
            );
            return;
        };

        let collected = self.keys.len() + 1;
        let total = collected + self.todo.len();
        info!(
            e3_id = %self.e3_id,
            party_id = pid,
            collected,
            total,
            remaining_parties = ?self.todo,
            "EncryptionKeyCollector: key received ({collected}/{total}), still waiting on {} parties",
            self.todo.len()
        );
        self.keys.insert(pid, msg.key);

        if self.todo.is_empty() {
            info!(
                e3_id = %self.e3_id,
                total,
                "EncryptionKeyCollector: all {} encryption keys collected",
                total
            );
            self.state = CollectorState::Finished;

            // Cancel the timeout since we're done
            if let Some(handle) = self.timeout_handle.take() {
                ctx.cancel_future(handle);
            }

            let event: TypedEvent<AllEncryptionKeysCollected> =
                TypedEvent::new(self.keys.clone().into(), ec);
            self.parent.do_send(event);
        }

        info!(
            "Finished processing EncryptionKeyCreated in {:?}",
            start.elapsed()
        );
    }
}

impl Handler<EncryptionKeyCollectionTimeout> for EncryptionKeyCollector {
    type Result = ();
    fn handle(
        &mut self,
        _: EncryptionKeyCollectionTimeout,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        // Only handle timeout if we're still collecting
        if !matches!(self.state, CollectorState::Collecting) {
            return;
        }

        warn!(
            e3_id = %self.e3_id,
            missing_parties = ?self.todo,
            "Encryption key collection timed out, {} parties missing",
            self.todo.len()
        );

        self.state = CollectorState::TimedOut;

        // Notify parent of failure
        let missing_parties: Vec<PartyId> = self.todo.iter().copied().collect();
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
        // Only handle if we're still collecting
        if !matches!(self.state, CollectorState::Collecting) {
            return;
        }

        let party_id = msg.party_id;

        // Remove expelled party from the todo set
        if !self.todo.remove(&party_id) {
            // Party already delivered their key — remove it from collected keys
            if self.keys.remove(&party_id).is_some() {
                info!(
                    e3_id = %self.e3_id,
                    party_id = party_id,
                    "Expelled party {} already delivered key — removed from collected keys",
                    party_id
                );
            } else {
                info!(
                    e3_id = %self.e3_id,
                    party_id = party_id,
                    "Expelled party {} was not in todo set and had no collected key",
                    party_id
                );
            }
            return;
        }

        info!(
            e3_id = %self.e3_id,
            party_id = party_id,
            remaining = self.todo.len(),
            "Removed expelled party {} from encryption key collection, {} remaining",
            party_id,
            self.todo.len()
        );

        // Check if all remaining keys have been collected
        if self.todo.is_empty() {
            info!(
                e3_id = %self.e3_id,
                "All remaining encryption keys collected after party expulsion!"
            );
            self.state = CollectorState::Finished;

            // Cancel the timeout since we're done
            if let Some(handle) = self.timeout_handle.take() {
                ctx.cancel_future(handle);
            }

            let event: TypedEvent<AllEncryptionKeysCollected> =
                TypedEvent::new(self.keys.clone().into(), msg.ec.clone());
            self.parent.do_send(event);
        }
    }
}
