// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! One E3 at this node: its stage, its DKG from the committee's finalization, and its decryption
//! from the key's publication.

use crate::{
    accusation::{Accusations, Fault, Slashing, Verdict},
    decryption::{Decryption, DecryptionWorkResult, Handover, PublishedKey},
    dkg::{AttestationContext, Dkg, DkgTiming, DkgWorkResult, KeyAnchor},
    node::{
        Body, CommitteeRequest, CommitteeSeed, CryptoParams, DataRef, Effect, Kind, PeerMessage,
        Purpose, Stage, Submission, Transaction, WorkResult,
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
    /// From the committee's finalization on, if the request snapshotted a slashing manager.
    accusations: Option<Accusations>,
    /// What the request snapshotted for slashing; unknown before the node saw the facts.
    slashing: Option<Slashing>,
    pub request: CommitteeRequest,
    /// The seed to rank with once the bonding registry says which operators may hold a seat,
    /// and the time to rank without knowing.
    selecting: Option<Selecting>,
    ticket: Option<Ticket>,
    resend: Resend,
    /// The deadline of each stage whose failure this node watches, as the contract counts it.
    deadlines: BTreeMap<Stage, UnixSecs>,
    /// This node's turn to mark the E3 failed and to settle it: its party ID in the committee,
    /// before that its place among the request's eligible operators.
    slot: Option<u64>,
    /// The stage, and its deadline, whose failure this node asked for; a stage whose deadline
    /// moves is watched again.
    marked: Option<(Stage, UnixSecs)>,
    failure: Option<Failure>,
    /// The message of each kind and sender whose blobs this node fetches. Another message of that
    /// kind from that sender waits until this one is taken, so a member makes the node download
    /// at most one message of each kind.
    fetching: BTreeMap<(Address, Kind), B256>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Selecting {
    seed: CommitteeSeed,
    by: UnixSecs,
}

/// The chain failed the E3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Failure {
    at: UnixSecs,
    /// Accusations can still need the E3's work until then.
    accusable_until: UnixSecs,
    settle_sent: bool,
    settled: bool,
    released: bool,
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
        slashing: Option<Slashing>,
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
            accusations: None,
            slashing,
            request,
            selecting: None,
            ticket: None,
            resend: Resend::default(),
            deadlines: BTreeMap::from([(Stage::Requested, committee_deadline)]),
            slot,
            marked: None,
            failure: None,
            fetching: BTreeMap::new(),
        }
    }

    /// The registry accepted the randomness, so tickets are due by `committee_deadline`. Ticket
    /// holders finalize the committee after it, and `finalizeCommittee` fails one short of its
    /// threshold. If no ticket holder acts, the contract fails a committee that met its threshold
    /// only after the DKG window too, so the watch waits that long.
    pub(crate) fn seeded(&mut self, committee_deadline: UnixSecs) {
        let deadline = committee_deadline + self.request.dkg_window;
        self.deadlines.insert(Stage::Requested, deadline);
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
            released: false,
        });
    }

    pub(crate) fn settled(&mut self) {
        if let Some(failure) = &mut self.failure {
            failure.settled = true;
        }
    }

    pub(crate) fn released(&mut self) {
        if let Some(failure) = &mut self.failure {
            failure.released = true;
        }
    }

    /// When the node lets a failed E3 go: once accusations cannot need its work, once the chain
    /// settled it if this node settles it, and, if this node holds a committee's work, once
    /// governance released the E3's slashing dependencies. Accusations that expel no member can
    /// come, and be appealed, even after settlement, until that release; they can need the
    /// committee's work and its blobs.
    pub(crate) fn ends_at(&self) -> Option<UnixSecs> {
        let accusations = self.accusations.as_ref().and_then(Accusations::closes_at);
        if self.stage == Stage::Complete {
            return Some(accusations.unwrap_or_default());
        }
        let failure = self.failure?;
        let settles = self
            .slot
            .is_some_and(|slot| turn(failure.at, slot).is_some());
        if (settles && !failure.settled) || (self.has_work() && !failure.released) {
            return None;
        }
        Some(failure.accusable_until.max(failure.at))
    }

    /// Whether the E3 still has DKG, decryption or accusation work, which the blobs of the E3
    /// serve.
    pub fn has_work(&self) -> bool {
        self.dkg.is_some() || self.decryption.is_some() || self.accuses()
    }

    /// Whether an accusation's window is still open.
    pub(crate) fn accuses(&self) -> bool {
        self.accusations.as_ref().is_some_and(Accusations::running)
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
        self.accusations = self.slashing.map(|slashing| {
            let members = members.clone();
            Accusations::new(self.id, self.me, self.params, members, slashing)
        });
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
        anchors: BTreeMap<Address, KeyAnchor>,
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
            anchors,
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

    /// Whether the node starts to wait for which operators may hold a seat: it ranks with `seed`
    /// once it knows, or at `by` without knowing. A wait under way goes on as it was.
    pub(crate) fn await_eligibility(&mut self, seed: CommitteeSeed, by: UnixSecs) -> bool {
        let waits = self.selecting.is_none();
        if waits {
            self.selecting = Some(Selecting { seed, by });
        }
        waits
    }

    /// The seed to rank with now that the answer came, unless the node ranked without it.
    pub(crate) fn answered(&mut self) -> Option<CommitteeSeed> {
        self.selecting.take().map(|selecting| selecting.seed)
    }

    /// The seed to rank with once the answer is late.
    pub(crate) fn unanswered(&mut self, now: UnixSecs) -> Option<CommitteeSeed> {
        let late = self.selecting.take_if(|selecting| selecting.by <= now);
        late.map(|selecting| selecting.seed)
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
            Body::Accusation(_) => self.accusations.is_some(),
        }
    }

    /// Whether this node takes `message` now; it can tell before it fetches any blob the message
    /// names.
    pub(crate) fn admits(&self, now: UnixSecs, message: &PeerMessage) -> bool {
        let sender = message.sender;
        match &message.body {
            Body::Dkg(body) => self
                .dkg
                .as_ref()
                .is_some_and(|dkg| self.running() && dkg.admits(sender, body)),
            Body::Decryption(body) => self
                .decryption
                .as_ref()
                .is_some_and(|decryption| self.running() && decryption.admits(sender, body)),
            Body::Accusation(body) => self
                .accusations
                .as_ref()
                .is_some_and(|accusations| accusations.admits(now, sender, body)),
        }
    }

    /// Whether to fetch the blobs of `message`: the E3 admits it, and it is the one message of its
    /// kind from its sender that this node fetches.
    pub(crate) fn fetches(&mut self, now: UnixSecs, message: &PeerMessage) -> bool {
        if !self.admits(now, message) {
            return false;
        }
        let id = message.id();
        let slot = (message.sender, message.body.kind());
        *self.fetching.entry(slot).or_insert(id) == id
    }

    pub(crate) fn receive(&mut self, now: UnixSecs, message: PeerMessage) -> Vec<Effect> {
        let slot = (message.sender, message.body.kind());
        if self.fetching.get(&slot) == Some(&message.id()) {
            self.fetching.remove(&slot);
        }
        let effects = match message.body {
            Body::Dkg(body) => match self.dkg_mut() {
                Some(dkg) => dkg.receive(now, message.sender, body),
                None => Vec::new(),
            },
            Body::Decryption(body) => match self.decryption_mut() {
                Some(decryption) => decryption.receive(now, message.sender, body),
                None => Vec::new(),
            },
            Body::Accusation(body) => match &mut self.accusations {
                Some(accusations) => accusations.receive(now, message.sender, body),
                None => Vec::new(),
            },
        };
        self.sent(now, effects)
    }

    pub(crate) fn job_done(&mut self, now: UnixSecs, result: WorkResult) -> Vec<Effect> {
        let fault = fault_of(&result);
        let mut effects = match result {
            WorkResult::Dkg(result) => match self.dkg_mut() {
                Some(dkg) => dkg.job_done(now, result),
                None => Vec::new(),
            },
            WorkResult::Decryption(result) => match self.decryption_mut() {
                Some(decryption) => decryption.job_done(now, result),
                None => Vec::new(),
            },
            WorkResult::Accusation(result) => match &mut self.accusations {
                Some(accusations) => accusations.verified(now, result),
                None => Vec::new(),
            },
        };
        if let Some((member, fault)) = fault {
            effects.extend(self.accuse(now, member, fault));
        }
        self.sent(now, effects)
    }

    /// Accuse `member` of the signed proof it sent that `fault` names.
    fn accuse(&mut self, now: UnixSecs, member: Address, fault: Fault) -> Vec<Effect> {
        let signed = self
            .dkg
            .as_ref()
            .and_then(|dkg| dkg.signed_proof(member, &fault.proof))
            .or_else(|| {
                let decryption = self.decryption.as_ref()?;
                decryption.signed_proof(member, &fault.proof)
            });
        match (signed, &mut self.accusations) {
            (Some(signed), Some(accusations)) => {
                accusations.accuse(now, member, fault.proof_type, signed, fault.data_hash)
            }
            _ => Vec::new(),
        }
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
            Purpose::Accusation(ballot) => match &mut self.accusations {
                Some(accusations) => accusations.signed(now, ballot, signatures),
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
        if let Some(accusations) = &mut self.accusations {
            accusations.expel(member);
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
            self.marked = self.watched();
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
        if let Some(accusations) = &mut self.accusations {
            effects.extend(accusations.pass_deadlines(now));
        }
        let mut effects = self.sent(now, effects);
        let (dkg_runs, decryption_runs) = self.work_running();
        let accusations = self.accusations.as_ref();
        let again = self.resend.due(now, |body| match body {
            Body::Dkg(_) => dkg_runs,
            Body::Decryption(_) => decryption_runs,
            Body::Accusation(message) => accusations.is_some_and(|open| open.open(message)),
        });
        effects.extend(again.into_iter().map(Effect::Gossip));
        effects
    }

    pub(crate) fn next_deadline(&self) -> Option<UnixSecs> {
        let (dkg_runs, decryption_runs) = self.work_running();
        let accusations = self.accusations.as_ref();
        let work = self.running().then(|| {
            let dkg = self.dkg.as_ref().and_then(Dkg::next_deadline);
            let decryption = self.decryption.as_ref().and_then(Decryption::next_deadline);
            dkg.into_iter()
                .chain(decryption)
                .chain(self.finalizer_due())
                .chain(self.failure_due())
                .chain(self.selecting.map(|selecting| selecting.by))
                .min()
        });
        let resend = self.resend.next_deadline(|body| match body {
            Body::Dkg(_) => dkg_runs,
            Body::Decryption(_) => decryption_runs,
            Body::Accusation(message) => accusations.is_some_and(|open| open.open(message)),
        });
        let accusation_due = self
            .accusations
            .as_ref()
            .and_then(Accusations::next_deadline);
        [
            self.ends_at(),
            work.flatten(),
            resend,
            accusation_due,
            self.settlement_due(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// The stage the E3 is in, and its deadline if this node watches it.
    fn watched(&self) -> Option<(Stage, UnixSecs)> {
        let deadline = self.deadlines.get(&self.stage)?;
        Some((self.stage, *deadline))
    }

    /// This node's turn after the deadline of the stage it watches.
    fn failure_due(&self) -> Option<UnixSecs> {
        let watched = self.watched()?;
        if self.marked == Some(watched) {
            return None;
        }
        turn(watched.1, self.slot?)
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

    /// The chain has neither failed nor completed the E3; after either, only accusation work
    /// remains.
    fn running(&self) -> bool {
        !matches!(self.stage, Stage::Failed | Stage::Complete)
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

/// The member and the failing proof that a check found, if any.
fn fault_of(result: &WorkResult) -> Option<(Address, Fault)> {
    let (member, verdict) = match result {
        WorkResult::Dkg(DkgWorkResult::EncryptionKeyChecked { sender, verdict }) => {
            (sender, verdict)
        }
        WorkResult::Dkg(DkgWorkResult::SharesChecked { dealer, verdict }) => (dealer, verdict),
        WorkResult::Dkg(DkgWorkResult::DecryptionKeyChecked { member, verdict })
        | WorkResult::Dkg(DkgWorkResult::KeyshareChecked { member, verdict })
        | WorkResult::Decryption(DecryptionWorkResult::SharesChecked { member, verdict }) => {
            (member, verdict)
        }
        _ => return None,
    };
    match verdict {
        Verdict::Fails(fault) => Some((*member, fault.clone())),
        Verdict::Valid | Verdict::Invalid => None,
    }
}
