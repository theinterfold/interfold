// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use core::time;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use actix::{Actor, ActorContext, Addr, AsyncContext, Handler, Message, SpawnHandle};
use e3_events::{
    E3id, EventContext, Sequenced, SignedProofPayload, ThresholdShare,
    ThresholdShareCollectionFailed, ThresholdShareCreated, TypedEvent,
};
use e3_trbfv::PartyId;
use e3_utils::MAILBOX_LIMIT;
use tracing::{info, warn};

use crate::{AllThresholdSharesCollected, ThresholdKeyshare};

/// Proofs received alongside a threshold share from a sender.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ReceivedShareProofs {
    /// Signed C2a proof (sk share computation) from the sender.
    pub signed_c2a_proof: Option<SignedProofPayload>,
    /// Signed C2b proof (e_sm share computation) from the sender.
    pub signed_c2b_proof: Option<SignedProofPayload>,
    /// Signed C3a proofs (sk share encryption per modulus row).
    pub signed_c3a_proofs: Vec<SignedProofPayload>,
    /// Signed C3b proofs (e_sm share encryption per modulus row).
    pub signed_c3b_proofs: Vec<SignedProofPayload>,
}

pub(crate) enum CollectorState {
    Collecting,
    Finished,
    TimedOut,
}

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

pub struct ThresholdShareCollector {
    /// The E3id for the round
    e3_id: E3id,
    /// The partys the collector expects to receive from
    todo: HashSet<PartyId>,
    /// The parent actor that has requested collection
    parent: Addr<ThresholdKeyshare>,
    /// The current state of the collector
    state: CollectorState,
    /// The shares collected
    shares: HashMap<PartyId, Arc<ThresholdShare>>,
    /// Proofs received alongside each party's shares
    share_proofs: HashMap<PartyId, ReceivedShareProofs>,
    timeout: Duration,
    /// A timeout handle for when this collector will report failure
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
            e3_id,
            todo: (0..total).filter(|p| *p != own_party_id).collect(),
            parent,
            state: CollectorState::Collecting,
            shares: HashMap::new(),
            share_proofs: HashMap::new(),
            timeout,
            timeout_handle: None,
        };
        collector.start()
    }
}

impl Actor for ThresholdShareCollector {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
        info!(
            e3_id = %self.e3_id,
            expected_parties = ?self.todo,
            expected_count = self.todo.len(),
            timeout = ?self.timeout,
            "ThresholdShareCollector started — expecting threshold shares from {} parties (excluding self)",
            self.todo.len()
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
        let start = Instant::now();
        let pid = msg.share.party_id;
        info!(
            e3_id = %self.e3_id,
            party_id = pid,
            "ThresholdShareCollector: ThresholdShareCreated received"
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
                "ThresholdShareCollector: not collecting, ignoring late ThresholdShareCreated"
            );
            return;
        }

        let Some(_) = self.todo.take(&pid) else {
            warn!(
                e3_id = %self.e3_id,
                party_id = pid,
                expected_parties = ?self.todo,
                "ThresholdShareCollector: received share from unexpected party — not in expected set"
            );
            return;
        };
        let collected = self.shares.len() + 1;
        let total = collected + self.todo.len();
        info!(
            e3_id = %self.e3_id,
            party_id = pid,
            collected,
            total,
            remaining_parties = ?self.todo,
            "ThresholdShareCollector: share received ({collected}/{total}), still waiting on {} parties",
            self.todo.len()
        );
        self.share_proofs.insert(
            pid,
            ReceivedShareProofs {
                signed_c2a_proof: msg.signed_c2a_proof,
                signed_c2b_proof: msg.signed_c2b_proof,
                signed_c3a_proofs: msg.signed_c3a_proofs,
                signed_c3b_proofs: msg.signed_c3b_proofs,
            },
        );
        self.shares.insert(pid, msg.share);

        if self.todo.is_empty() {
            info!(
                e3_id = %self.e3_id,
                total,
                "ThresholdShareCollector: all {} threshold shares collected",
                total
            );
            self.state = CollectorState::Finished;

            // Cancel the timeout since we're done
            if let Some(handle) = self.timeout_handle.take() {
                ctx.cancel_future(handle);
            }

            let proofs = std::mem::take(&mut self.share_proofs);
            let event: TypedEvent<AllThresholdSharesCollected> = TypedEvent::new(
                AllThresholdSharesCollected::new(self.shares.clone(), proofs),
                ec,
            );
            self.parent.do_send(event);
        }
        info!(
            "Finished processing ThresholdShareCreated in {:?}",
            start.elapsed()
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
        // Only handle timeout if we're still collecting
        if !matches!(self.state, CollectorState::Collecting) {
            return;
        }

        warn!(
            e3_id = %self.e3_id,
            missing_parties = ?self.todo,
            "Threshold share collection timed out, {} parties missing",
            self.todo.len()
        );

        self.state = CollectorState::TimedOut;

        // Notify parent of failure
        let missing_parties: Vec<PartyId> = self.todo.iter().copied().collect();
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
        // Only handle if we're still collecting
        if !matches!(self.state, CollectorState::Collecting) {
            return;
        }

        let party_id = msg.party_id;

        // Remove expelled party from the todo set
        if !self.todo.remove(&party_id) {
            // Party already delivered their share — remove from collected data
            let had_share = self.shares.remove(&party_id).is_some();
            let had_proofs = self.share_proofs.remove(&party_id).is_some();
            if had_share || had_proofs {
                info!(
                    e3_id = %self.e3_id,
                    party_id = party_id,
                    "Expelled party {} already delivered share — removed from collected data",
                    party_id
                );
            } else {
                info!(
                    e3_id = %self.e3_id,
                    party_id = party_id,
                    "Expelled party {} was not in share collection todo set and had no collected data",
                    party_id
                );
            }
            return;
        }

        info!(
            e3_id = %self.e3_id,
            party_id = party_id,
            remaining = self.todo.len(),
            "Removed expelled party {} from threshold share collection, {} remaining",
            party_id,
            self.todo.len()
        );

        // Check if all remaining shares have been collected
        if self.todo.is_empty() {
            info!(
                e3_id = %self.e3_id,
                "All remaining threshold shares collected after party expulsion!"
            );
            self.state = CollectorState::Finished;

            // Cancel the timeout since we're done
            if let Some(handle) = self.timeout_handle.take() {
                ctx.cancel_future(handle);
            }

            let proofs = std::mem::take(&mut self.share_proofs);
            let event: TypedEvent<AllThresholdSharesCollected> = TypedEvent::new(
                AllThresholdSharesCollected::new(self.shares.clone(), proofs),
                msg.ec,
            );
            self.parent.do_send(event);
        }
    }
}
