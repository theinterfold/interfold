// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! One E3 at this node: its stage, its DKG from the committee's finalization, and its decryption
//! from the key's publication.

use crate::{
    decryption::{Decryption, Handover, PublishedKey},
    dkg::{AttestationContext, Dkg, DkgTiming},
    node::{
        Body, CommitteeRequest, CryptoParams, DataRef, Effect, PeerMessage, Purpose, Stage,
        Submission, Transaction, WorkResult,
    },
    resend::Resend,
    BlobRef, E3Id, UnixSecs,
};
use alloy_primitives::{Address, Bytes, B256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct E3 {
    id: E3Id,
    me: Address,
    pub stage: Stage,
    pub params: CryptoParams,
    /// The Interfold contract that holds the request.
    pub interfold: Address,
    pub attestation: AttestationContext,
    /// From the committee's finalization on; a node outside the committee ends the E3 instead.
    pub dkg: Option<Dkg>,
    /// From the key's publication on.
    pub decryption: Option<Decryption>,
    pub request: CommitteeRequest,
    ticket: Option<Ticket>,
    resend: Resend,
    /// The deadline of each stage whose failure this node watches, as the contract counts it.
    deadlines: BTreeMap<Stage, UnixSecs>,
    /// This node's turn to mark the E3 failed and to settle it: its party ID in the committee,
    /// before that its place among the request's eligible operators.
    slot: Option<u64>,
    /// The stage whose failure this node asked for.
    marked: Option<Stage>,
    failure: Option<Failure>,
}

/// The chain failed the E3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Failure {
    at: UnixSecs,
    /// Accusations can still need the E3's work until then.
    accusable_until: UnixSecs,
    settle_sent: bool,
    settled: bool,
}

/// This node's ticket, its rank among the candidates, and the committee deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Ticket {
    number: u64,
    rank: usize,
    deadline: UnixSecs,
    finalize_sent: bool,
}

/// Nodes that can make the same call take turns, 30 seconds apart from one second after its
/// deadline, because any of them can stay silent; the contract takes the first call. Places past
/// the twentieth never call.
const TURN: UnixSecs = 30;
const TURNS: u64 = 20;

fn turn(deadline: UnixSecs, place: u64) -> Option<UnixSecs> {
    (place < TURNS).then(|| deadline + 1 + TURN * place)
}

/// How long a node that settles a failed E3 keeps it if the settlement never lands, which happens
/// only when the writer gives the call up. With a committee, the contract opens settlement a day
/// after the E3's lifecycle deadline and keeps it closed while accusations are open, which appeals
/// can stretch to 37 days; this bound assumes a lifecycle under three weeks.
const SETTLEMENT_WAIT: UnixSecs = 60 * 24 * 60 * 60;

impl E3 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: E3Id,
        me: Address,
        params: CryptoParams,
        interfold: Address,
        attestation: AttestationContext,
        request: CommitteeRequest,
        committee_deadline: UnixSecs,
        slot: Option<u64>,
    ) -> Self {
        Self {
            id,
            me,
            stage: Stage::Requested,
            params,
            interfold,
            attestation,
            dkg: None,
            decryption: None,
            request,
            ticket: None,
            resend: Resend::default(),
            deadlines: BTreeMap::from([(Stage::Requested, committee_deadline)]),
            slot,
            marked: None,
            failure: None,
        }
    }

    /// Once the registry accepts the randomness, the finalizer ends the Requested stage:
    /// `finalizeCommittee` fails a committee short of its threshold.
    pub(crate) fn seeded(&mut self) {
        self.deadlines.remove(&Stage::Requested);
    }

    /// The chain moved the E3 to `stage`, unless it already moved it past.
    pub(crate) fn advance(&mut self, stage: Stage) {
        self.stage = self.stage.max(stage);
    }

    /// A stage the chain reached, with the deadline after which the contract fails it.
    fn reach(&mut self, stage: Stage, deadline: UnixSecs) {
        self.advance(stage);
        self.deadlines.insert(stage, deadline);
    }

    pub(crate) fn failed(&mut self, at: UnixSecs, accusable_until: UnixSecs) {
        self.advance(Stage::Failed);
        self.failure.get_or_insert(Failure {
            at,
            accusable_until,
            settle_sent: false,
            settled: false,
        });
    }

    pub(crate) fn settled(&mut self) {
        if let Some(failure) = &mut self.failure {
            failure.settled = true;
        }
    }

    /// When the node lets a failed E3 go: once accusations cannot need its work, and, if this
    /// node settles it, once the chain settled it.
    pub(crate) fn ends_at(&self) -> Option<UnixSecs> {
        let failure = self.failure?;
        let settles = self
            .slot
            .is_some_and(|slot| turn(failure.at, slot).is_some());
        let settlement = match settles && !failure.settled {
            true => failure.at + SETTLEMENT_WAIT,
            false => failure.at,
        };
        Some(failure.accusable_until.max(settlement))
    }

    pub(crate) fn finalize(
        &mut self,
        now: UnixSecs,
        members: Vec<Address>,
        timing: DkgTiming,
    ) -> Vec<Effect> {
        self.reach(Stage::CommitteeFinalized, timing.deadline);
        self.slot = members
            .iter()
            .position(|member| *member == self.me)
            .map(|party| party as u64);
        let (dkg, effects) = Dkg::start(
            self.id,
            self.me,
            members,
            self.params,
            timing,
            self.attestation,
            now,
        );
        self.dkg = Some(dkg);
        self.sent(now, effects)
    }

    /// The chain's key, committee order, and roster are the authority for decryption. This node's
    /// DKG supplies its sealed decryption key only if it summed that key over the same roster;
    /// shares from a key over another roster would not combine.
    pub(crate) fn key_published(
        &mut self,
        committee: Vec<Address>,
        roster: Vec<Address>,
        commitment: B256,
        compute_deadline: UnixSecs,
    ) {
        self.reach(Stage::KeyPublished, compute_deadline);
        let Some(dkg) = &mut self.dkg else {
            return;
        };
        dkg.key_published();
        let same_roster = dkg.roster_members().as_ref() == Some(&roster);
        let key = dkg.decryption_key().filter(|_| same_roster);
        let handover = Handover {
            roster,
            key,
            expelled: dkg.expelled().clone(),
        };
        let published = PublishedKey {
            interfold: self.interfold,
            committee,
            commitment,
        };
        let members = dkg.members().to_vec();
        self.decryption = Some(Decryption::new(
            self.id,
            self.me,
            members,
            self.params,
            handover,
            published,
        ));
    }

    pub(crate) fn ciphertext_ready(
        &mut self,
        now: UnixSecs,
        ciphertext: DataRef,
        deadline: UnixSecs,
    ) -> Vec<Effect> {
        self.reach(Stage::CiphertextReady, deadline);
        let effects = match self.decryption_mut() {
            Some(decryption) => decryption.ciphertext_ready(ciphertext, deadline),
            None => Vec::new(),
        };
        self.sent(now, effects)
    }

    pub(crate) fn fetched(&mut self, now: UnixSecs, blob: BlobRef) -> Vec<Effect> {
        let effects = match self.decryption_mut() {
            Some(decryption) => decryption.ciphertext_fetched(now, blob),
            None => Vec::new(),
        };
        self.sent(now, effects)
    }

    pub(crate) fn ticket(&self) -> Option<u64> {
        self.ticket.map(|ticket| ticket.number)
    }

    pub(crate) fn submit_ticket(
        &mut self,
        number: u64,
        rank: usize,
        deadline: UnixSecs,
    ) -> Vec<Effect> {
        self.ticket = Some(Ticket {
            number,
            rank,
            deadline,
            finalize_sent: false,
        });
        vec![self.submit(Transaction::SubmitTicket { ticket: number })]
    }

    /// Whether a message of `body`'s kind has its handler here yet; until then it waits in the
    /// hold.
    pub(crate) fn routes(&self, body: &Body) -> bool {
        match body {
            Body::Dkg(_) => self.dkg.is_some(),
            Body::Decryption(_) => self.decryption.is_some(),
        }
    }

    /// Whether this node takes `message` now; it can tell before it fetches any blob the message
    /// names.
    pub(crate) fn admits(&self, message: &PeerMessage) -> bool {
        let sender = message.sender;
        self.running()
            && match &message.body {
                Body::Dkg(body) => self
                    .dkg
                    .as_ref()
                    .is_some_and(|dkg| dkg.admits(sender, body)),
                Body::Decryption(body) => self
                    .decryption
                    .as_ref()
                    .is_some_and(|decryption| decryption.admits(sender, body)),
            }
    }

    pub(crate) fn receive(&mut self, now: UnixSecs, message: PeerMessage) -> Vec<Effect> {
        let effects = match message.body {
            Body::Dkg(body) => match self.dkg_mut() {
                Some(dkg) => dkg.receive(now, message.sender, body),
                None => Vec::new(),
            },
            Body::Decryption(body) => match self.decryption_mut() {
                Some(decryption) => decryption.receive(now, message.sender, body),
                None => Vec::new(),
            },
        };
        self.sent(now, effects)
    }

    pub(crate) fn job_done(&mut self, now: UnixSecs, result: WorkResult) -> Vec<Effect> {
        let effects = match result {
            WorkResult::Dkg(result) => match self.dkg_mut() {
                Some(dkg) => dkg.job_done(now, result),
                None => Vec::new(),
            },
            WorkResult::Decryption(result) => match self.decryption_mut() {
                Some(decryption) => decryption.job_done(now, result),
                None => Vec::new(),
            },
        };
        self.sent(now, effects)
    }

    pub(crate) fn signed(
        &mut self,
        now: UnixSecs,
        purpose: Purpose,
        signatures: Vec<Bytes>,
    ) -> Vec<Effect> {
        let effects = match purpose {
            Purpose::Dkg(purpose) => match self.dkg_mut() {
                Some(dkg) => dkg.signed(now, purpose, signatures),
                None => Vec::new(),
            },
            Purpose::Decryption(purpose) => match self.decryption_mut() {
                Some(decryption) => decryption.signed(now, purpose, signatures),
                None => Vec::new(),
            },
        };
        self.sent(now, effects)
    }

    pub(crate) fn expel(&mut self, now: UnixSecs, member: Address) -> Vec<Effect> {
        let mut effects = Vec::new();
        if let Some(dkg) = self.dkg_mut() {
            effects.extend(dkg.expel(now, member));
        }
        if let Some(decryption) = self.decryption_mut() {
            effects.extend(decryption.expel(now, member));
        }
        self.sent(now, effects)
    }

    pub(crate) fn pass_deadlines(&mut self, now: UnixSecs) -> Vec<Effect> {
        let mut effects = Vec::new();
        if self.finalizer_due().is_some_and(|due| now >= due) {
            if let Some(ticket) = &mut self.ticket {
                ticket.finalize_sent = true;
            }
            effects.push(self.submit(Transaction::FinalizeCommittee));
        }
        if self.failure_due().is_some_and(|due| now >= due) {
            self.marked = Some(self.stage);
            effects.push(self.submit(Transaction::MarkFailed));
        }
        if self.settlement_due().is_some_and(|due| now >= due) {
            if let Some(failure) = &mut self.failure {
                failure.settle_sent = true;
            }
            effects.push(self.submit(Transaction::SettleFailure));
        }
        if let Some(dkg) = self.dkg_mut() {
            effects.extend(dkg.pass_deadlines(now));
        }
        if let Some(decryption) = self.decryption_mut() {
            effects.extend(decryption.pass_deadlines(now));
        }
        let mut effects = self.sent(now, effects);
        let (dkg_runs, decryption_runs) = self.work_running();
        let again = self.resend.due(now, |body| match body {
            Body::Dkg(_) => dkg_runs,
            Body::Decryption(_) => decryption_runs,
        });
        effects.extend(again.into_iter().map(Effect::Gossip));
        effects
    }

    pub(crate) fn next_deadline(&self) -> Option<UnixSecs> {
        let (dkg_runs, decryption_runs) = self.work_running();
        let work = self.running().then(|| {
            let dkg = self.dkg.as_ref().and_then(Dkg::next_deadline);
            let decryption = self.decryption.as_ref().and_then(Decryption::next_deadline);
            let resend = self.resend.next_deadline(|body| match body {
                Body::Dkg(_) => dkg_runs,
                Body::Decryption(_) => decryption_runs,
            });
            dkg.into_iter()
                .chain(decryption)
                .chain(resend)
                .chain(self.finalizer_due())
                .chain(self.failure_due())
                .min()
        });
        [self.ends_at(), work.flatten(), self.settlement_due()]
            .into_iter()
            .flatten()
            .min()
    }

    /// This node's turn after the deadline of the stage it watches.
    fn failure_due(&self) -> Option<UnixSecs> {
        if self.marked == Some(self.stage) {
            return None;
        }
        turn(*self.deadlines.get(&self.stage)?, self.slot?)
    }

    fn settlement_due(&self) -> Option<UnixSecs> {
        let failure = self
            .failure
            .filter(|failure| !failure.settle_sent && !failure.settled)?;
        turn(failure.at, self.slot?)
    }

    /// After the committee deadline, in rank order, while the chain has not finalized the
    /// committee.
    fn finalizer_due(&self) -> Option<UnixSecs> {
        let ticket = self.ticket.filter(|ticket| !ticket.finalize_sent)?;
        if self.stage != Stage::Requested {
            return None;
        }
        turn(ticket.deadline, ticket.rank as u64)
    }

    fn submit(&self, transaction: Transaction) -> Effect {
        Effect::Submit(Submission {
            e3: self.id,
            transaction,
        })
    }

    /// Keep this node's messages for sending again while their work runs.
    fn sent(&mut self, now: UnixSecs, effects: Vec<Effect>) -> Vec<Effect> {
        for effect in &effects {
            if let Effect::Gossip(message) = effect {
                self.resend.record(now, message.clone());
            }
        }
        effects
    }

    /// Whether the DKG, and decryption, still run here.
    fn work_running(&self) -> (bool, bool) {
        let dkg = self.dkg.as_ref().is_some_and(Dkg::running);
        let decryption = self.decryption.as_ref().is_some_and(Decryption::running);
        (self.running() && dkg, self.running() && decryption)
    }

    /// The chain has not failed the E3; after a failure only accusation work remains.
    fn running(&self) -> bool {
        self.stage != Stage::Failed
    }

    fn dkg_mut(&mut self) -> Option<&mut Dkg> {
        let running = self.running();
        self.dkg.as_mut().filter(|_| running)
    }

    fn decryption_mut(&mut self) -> Option<&mut Decryption> {
        let running = self.running();
        self.decryption.as_mut().filter(|_| running)
    }
}
