// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use actix::{Actor, ActorContext, Addr, AsyncContext, Handler, Message, SpawnHandle};
use e3_events::{DecryptionKeyShared, E3id, EventContext, Sequenced, TypedEvent};
use e3_utils::MAILBOX_LIMIT;
use tracing::{info, warn};

use crate::ThresholdKeyshare;

enum CollectorState {
    Collecting,
    Finished,
    TimedOut,
}

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

/// Collects `DecryptionKeyShared` events from expected parties in H (Exchange #3).
///
/// Once all expected events are collected, sends `AllDecryptionKeySharesCollected`
/// to the parent `ThresholdKeyshare` actor for C4 proof verification.
pub struct DecryptionKeySharedCollector {
    e3_id: E3id,
    /// Party IDs we expect to receive from (H minus self).
    expected: HashSet<u64>,
    parent: Addr<ThresholdKeyshare>,
    state: CollectorState,
    shares: HashMap<u64, DecryptionKeyShared>,
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
            e3_id,
            expected: expected_parties,
            parent,
            state: CollectorState::Collecting,
            shares: HashMap::new(),
            timeout,
            timeout_handle: None,
        };
        collector.start()
    }
}

impl Actor for DecryptionKeySharedCollector {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
        info!(
            e3_id = %self.e3_id,
            expected_parties = ?self.expected,
            expected_count = self.expected.len(),
            timeout = ?self.timeout,
            "DecryptionKeySharedCollector started — expecting decryption key shares from {} parties",
            self.expected.len()
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
        let start = Instant::now();

        if !matches!(self.state, CollectorState::Collecting) {
            return;
        }

        let pid = msg.party_id;
        if !self.expected.remove(&pid) {
            warn!(
                e3_id = %self.e3_id,
                party_id = pid,
                expected_parties = ?self.expected,
                "DecryptionKeySharedCollector: received share from unexpected party — not in expected set"
            );
            return;
        }

        let collected = self.shares.len() + 1;
        let total = collected + self.expected.len();
        info!(
            e3_id = %self.e3_id,
            party_id = pid,
            collected,
            total,
            remaining_parties = ?self.expected,
            "DecryptionKeySharedCollector: share received ({collected}/{total}), still waiting on {} parties",
            self.expected.len()
        );
        self.shares.insert(pid, msg);

        if self.expected.is_empty() {
            info!(
                e3_id = %self.e3_id,
                total,
                "DecryptionKeySharedCollector: all {} decryption key shares collected",
                total
            );
            self.state = CollectorState::Finished;

            if let Some(handle) = self.timeout_handle.take() {
                ctx.cancel_future(handle);
            }

            let event: TypedEvent<AllDecryptionKeySharesCollected> = TypedEvent::new(
                AllDecryptionKeySharesCollected {
                    shares: std::mem::take(&mut self.shares),
                },
                ec,
            );
            self.parent.do_send(event);
            ctx.stop();
        }

        info!(
            "Finished processing DecryptionKeyShared in {:?}",
            start.elapsed()
        );
    }
}

impl Handler<DecryptionKeySharedCollectionTimeout> for DecryptionKeySharedCollector {
    type Result = ();
    fn handle(
        &mut self,
        _: DecryptionKeySharedCollectionTimeout,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        if !matches!(self.state, CollectorState::Collecting) {
            return;
        }

        warn!(
            e3_id = %self.e3_id,
            missing_parties = ?self.expected,
            "DecryptionKeyShared collection timed out, {} parties missing",
            self.expected.len()
        );

        self.state = CollectorState::TimedOut;

        let missing_parties: Vec<u64> = self.expected.iter().copied().collect();
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
        if !matches!(self.state, CollectorState::Collecting) {
            return;
        }

        let party_id = msg.party_id;

        if !self.expected.remove(&party_id) {
            // Party already delivered their share — remove from collected data
            if self.shares.remove(&party_id).is_some() {
                info!(
                    e3_id = %self.e3_id,
                    party_id = party_id,
                    "Expelled party {} already delivered decryption key share — removed from collected data",
                    party_id
                );
            } else {
                info!(
                    e3_id = %self.e3_id,
                    party_id = party_id,
                    "Expelled party {} was not in expected set and had no collected data",
                    party_id
                );
            }
            return;
        }

        info!(
            e3_id = %self.e3_id,
            party_id = party_id,
            remaining = self.expected.len(),
            "Removed expelled party {} from decryption key shared collection, {} remaining",
            party_id,
            self.expected.len()
        );

        if self.expected.is_empty() {
            info!(
                e3_id = %self.e3_id,
                "All remaining decryption key shares collected after party expulsion!"
            );
            self.state = CollectorState::Finished;

            if let Some(handle) = self.timeout_handle.take() {
                ctx.cancel_future(handle);
            }

            let event: TypedEvent<AllDecryptionKeySharesCollected> = TypedEvent::new(
                AllDecryptionKeySharesCollected {
                    shares: std::mem::take(&mut self.shares),
                },
                msg.ec.clone(),
            );
            self.parent.do_send(event);
            ctx.stop();
        }
    }
}
