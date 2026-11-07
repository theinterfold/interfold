// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! One E3's accusations. A member that finds a signed proof failing accuses its signer and votes;
//! the accusation carries the proof, and a member that finds the same bytes failing votes too. The
//! first H votes in one window go to the E3's slashing manager, which slashes the accused.

use super::{
    accusation_id, AccusationMessage, AccusationWork, AccusationWorkResult, Ballot, SignedVote,
    Slashing, Vote,
};
use crate::{
    node::{
        Body, CryptoParams, Effect, Job, PeerMessage, Purpose, Signing, Submission, Transaction,
        Work,
    },
    proof::{ProofType, SignedProof, ZkProof},
    E3Id, UnixSecs,
};
use alloy_primitives::{Address, Bytes, Signature, B256};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The first voters, in address order, submit the slash, this many seconds apart.
const SUBMITTERS: usize = 3;
const SUBMIT_TURN: UnixSecs = 30;
/// How far past the chain's time a vote's window may start: `SlashingEvidenceLib.CLOCK_SKEW`.
const CLOCK_SKEW: UnixSecs = 30;
/// The votes of one member that may wait for their accusations. A vote waits only until its
/// accusation arrives, and its voter sends it again while the window is open.
pub(super) const EARLY_VOTES_PER_MEMBER: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Accusations {
    e3: E3Id,
    me: Address,
    params: CryptoParams,
    members: Vec<Address>,
    /// H: the votes a slash needs, as the current node counts them; the contract needs T.
    quorum: usize,
    /// The slashing manager the E3's request snapshotted, whose domain votes sign under.
    manager: Address,
    /// The longest window a vote may sign; zero turns accusations off.
    validity: UnixSecs,
    cases: BTreeMap<Ballot, Case>,
    /// Votes that arrived before their accusation, which waits for its proof's blob.
    early: BTreeMap<Ballot, BTreeMap<Address, SignedVote>>,
    /// This node's check of each proof, by its type and bytes. A vote's evidence hash counts
    /// only when it is the hash of the proof this node checked.
    verdicts: BTreeMap<(ProofType, ZkProof), Checked>,
    /// The (accused, proof type) pairs this node accused.
    accused: BTreeSet<(Address, ProofType)>,
    expelled: BTreeSet<Address>,
    /// Members that H members found sending a failing proof, in some window.
    convicted: BTreeSet<Address>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Case {
    /// The member that opened the window.
    accuser: Address,
    accused: Address,
    proof_type: ProofType,
    proof: SignedProof,
    /// The evidence hash the accuser signed; votes for another hash do not count.
    data_hash: B256,
    votes: BTreeMap<Address, SignedVote>,
    /// This node asked to sign its vote.
    voting: bool,
    /// When this node submits the slash: once H members voted, if it is among the first voters.
    submit_at: Option<UnixSecs>,
    submitted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Checked {
    data_hash: B256,
    fails: bool,
}

impl Case {
    fn new(
        accuser: Address,
        accused: Address,
        proof_type: ProofType,
        proof: SignedProof,
        data_hash: B256,
    ) -> Self {
        Self {
            accuser,
            accused,
            proof_type,
            proof,
            data_hash,
            votes: BTreeMap::new(),
            voting: false,
            submit_at: None,
            submitted: false,
        }
    }
}

impl Accusations {
    pub(crate) fn new(
        e3: E3Id,
        me: Address,
        params: CryptoParams,
        members: Vec<Address>,
        slashing: Slashing,
    ) -> Self {
        Self {
            e3,
            me,
            params,
            members,
            quorum: params.committee_size.values().h,
            manager: slashing.manager,
            validity: slashing.validity,
            cases: BTreeMap::new(),
            early: BTreeMap::new(),
            verdicts: BTreeMap::new(),
            accused: BTreeSet::new(),
            expelled: BTreeSet::new(),
            convicted: BTreeSet::new(),
        }
    }

    /// This node's check found that `proof`, which `accused` signed, fails. The node accuses the
    /// signer of each proof type once, in a window that starts now.
    pub(crate) fn accuse(
        &mut self,
        now: UnixSecs,
        accused: Address,
        proof_type: ProofType,
        proof: SignedProof,
        data_hash: B256,
    ) -> Vec<Effect> {
        let checked = Checked {
            data_hash,
            fails: true,
        };
        self.verdicts
            .insert((proof_type, proof.proof.clone()), checked);
        if self.validity == 0
            || accused == self.me
            || !self.is_member(accused)
            || !self.accused.insert((accused, proof_type))
        {
            return Vec::new();
        }
        let ballot = Ballot {
            accusation_id: accusation_id(self.e3, accused, proof_type),
            issued_at: now,
            deadline: now.saturating_add(self.validity),
        };
        let case = Case::new(self.me, accused, proof_type, proof, data_hash);
        self.cases.insert(ballot, case);
        self.vote(ballot).into_iter().collect()
    }

    /// Whether to take `message` from `sender`: both it and the accused are live members, the
    /// accused signed the proof, the vote is the sender's and counts, and the sender has no other
    /// window open for the same accusation, so a member cannot open windows without end.
    pub(crate) fn admits(
        &self,
        now: UnixSecs,
        sender: Address,
        message: &AccusationMessage,
    ) -> bool {
        match message {
            AccusationMessage::Accuse {
                accused,
                proof_type,
                proof,
                vote,
            } => {
                let ballot = Ballot::of(&vote.vote);
                sender != *accused
                    && self.is_member(*accused)
                    && vote.vote.accusation_id == accusation_id(self.e3, *accused, *proof_type)
                    && proof.is_signed_by(*accused, self.e3, *proof_type)
                    && self.counts(now, sender, vote)
                    && !self.cases.iter().any(|(open, case)| {
                        *open == ballot
                            || (open.accusation_id == ballot.accusation_id
                                && case.accuser == sender)
                    })
            }
            AccusationMessage::Vote(vote) => {
                let accused = self
                    .cases
                    .get(&Ballot::of(&vote.vote))
                    .map(|case| case.accused);
                accused != Some(sender) && self.counts(now, sender, vote)
            }
        }
    }

    /// A vote counts from a live member that signed it, for this E3, in a window that is no longer
    /// than the vote validity and has not passed.
    fn counts(&self, now: UnixSecs, voter: Address, signed: &SignedVote) -> bool {
        let vote = &signed.vote;
        vote.e3 == self.e3
            && vote.voter == voter
            && self.is_member(voter)
            && vote.issued_at <= now.saturating_add(CLOCK_SKEW)
            && vote.issued_at <= vote.deadline
            && vote.deadline - vote.issued_at <= self.validity
            && now <= vote.deadline
            && Signature::try_from(signed.signature.as_ref())
                .ok()
                .and_then(|signature| {
                    let hash = vote.signing_hash(self.manager);
                    signature.recover_address_from_prehash(&hash).ok()
                })
                == Some(voter)
    }

    pub(crate) fn receive(
        &mut self,
        now: UnixSecs,
        sender: Address,
        message: AccusationMessage,
    ) -> Vec<Effect> {
        if !self.admits(now, sender, &message) {
            return Vec::new();
        }
        match message {
            AccusationMessage::Accuse {
                accused,
                proof_type,
                proof,
                vote,
            } => {
                let ballot = Ballot::of(&vote.vote);
                let mut case = Case::new(sender, accused, proof_type, proof, vote.vote.data_hash);
                let early = self.early.remove(&ballot).into_iter().flatten();
                let votes = early.filter(|(voter, early)| {
                    *voter != accused && early.vote.data_hash == case.data_hash
                });
                case.votes.extend(votes);
                case.votes.insert(sender, vote);
                let checked = self
                    .verdicts
                    .contains_key(&(case.proof_type, case.proof.proof.clone()));
                let check = (accused != self.me && !checked)
                    .then(|| self.verify(case.proof_type, case.proof.proof.clone()));
                self.cases.insert(ballot, case);
                let mut effects: Vec<Effect> = check.into_iter().collect();
                effects.extend(self.vote(ballot));
                effects.extend(self.reached(now, ballot));
                effects
            }
            AccusationMessage::Vote(vote) => {
                let ballot = Ballot::of(&vote.vote);
                match self.cases.get_mut(&ballot) {
                    Some(case) => {
                        if vote.vote.data_hash == case.data_hash {
                            case.votes.insert(sender, vote);
                        }
                        self.reached(now, ballot)
                    }
                    None => {
                        let waiting = self
                            .early
                            .values()
                            .filter(|votes| votes.contains_key(&sender));
                        if waiting.count() < EARLY_VOTES_PER_MEMBER {
                            self.early.entry(ballot).or_default().insert(sender, vote);
                        }
                        Vec::new()
                    }
                }
            }
        }
    }

    /// This node verified an accused proof: it votes in every window that accuses those bytes.
    pub(crate) fn verified(&mut self, now: UnixSecs, result: AccusationWorkResult) -> Vec<Effect> {
        let AccusationWorkResult::Verified {
            proof_type,
            proof,
            fails,
            data_hash,
        } = result;
        let ballots: Vec<Ballot> = self
            .cases
            .iter()
            .filter(|(_, case)| case.proof_type == proof_type && case.proof.proof == proof)
            .map(|(ballot, _)| *ballot)
            .collect();
        self.verdicts
            .insert((proof_type, proof), Checked { data_hash, fails });
        let mut effects = Vec::new();
        for ballot in ballots {
            effects.extend(self.vote(ballot));
            effects.extend(self.reached(now, ballot));
        }
        effects
    }

    /// This node's vote in `ballot`, once its own check found the accused proof failing, under
    /// the evidence hash the accuser signed, and the accused is not this node.
    fn vote(&mut self, ballot: Ballot) -> Option<Effect> {
        let (me, e3, manager) = (self.me, self.e3, self.manager);
        let case = self.cases.get(&ballot)?;
        let checked = self
            .verdicts
            .get(&(case.proof_type, case.proof.proof.clone()));
        let fails =
            checked.is_some_and(|checked| checked.fails && checked.data_hash == case.data_hash);
        if case.voting || case.accused == me || !fails {
            return None;
        }
        let vote = Vote {
            e3,
            accusation_id: ballot.accusation_id,
            voter: me,
            data_hash: case.data_hash,
            issued_at: ballot.issued_at,
            deadline: ballot.deadline,
        };
        self.cases.get_mut(&ballot)?.voting = true;
        Some(Effect::Sign(Signing {
            e3,
            purpose: Purpose::Accusation(ballot),
            hashes: vec![vote.signing_hash(manager)],
        }))
    }

    pub(crate) fn signed(
        &mut self,
        now: UnixSecs,
        ballot: Ballot,
        signatures: Vec<Bytes>,
    ) -> Vec<Effect> {
        let (me, e3) = (self.me, self.e3);
        let ([signature], Some(case)) = (signatures.as_slice(), self.cases.get_mut(&ballot)) else {
            return Vec::new();
        };
        let vote = SignedVote {
            vote: Vote {
                e3,
                accusation_id: ballot.accusation_id,
                voter: me,
                data_hash: case.data_hash,
                issued_at: ballot.issued_at,
                deadline: ballot.deadline,
            },
            signature: signature.clone(),
        };
        // The first vote in a window is the accusation, which carries the accused proof.
        let message = match case.votes.is_empty() {
            true => AccusationMessage::Accuse {
                accused: case.accused,
                proof_type: case.proof_type,
                proof: case.proof.clone(),
                vote: vote.clone(),
            },
            false => AccusationMessage::Vote(vote.clone()),
        };
        case.votes.insert(me, vote);
        let mut effects = vec![Effect::Gossip(PeerMessage {
            e3,
            sender: me,
            body: Body::Accusation(message),
        })];
        effects.extend(self.reached(now, ballot));
        effects
    }

    /// Once H members voted in `ballot`, this node takes its turn to submit if it is among the
    /// first voters in address order.
    fn reached(&mut self, now: UnixSecs, ballot: Ballot) -> Vec<Effect> {
        let (me, quorum) = (self.me, self.quorum);
        let Some(case) = self.cases.get_mut(&ballot) else {
            return Vec::new();
        };
        if case.votes.len() < quorum {
            return Vec::new();
        }
        self.convicted.insert(case.accused);
        if case.submit_at.is_some() {
            return Vec::new();
        }
        let Some(place) = case.votes.keys().position(|voter| *voter == me) else {
            return Vec::new();
        };
        if place < SUBMITTERS {
            case.submit_at = Some(now + SUBMIT_TURN * place as UnixSecs);
        }
        self.pass_deadlines(now)
    }

    pub(crate) fn pass_deadlines(&mut self, now: UnixSecs) -> Vec<Effect> {
        let (e3, manager) = (self.e3, self.manager);
        let mut effects = Vec::new();
        for (ballot, case) in &mut self.cases {
            let due = case.submit_at.is_some_and(|at| at <= now);
            if due && !case.submitted && now <= ballot.deadline {
                case.submitted = true;
                effects.push(Effect::Submit(Submission {
                    e3,
                    transaction: Transaction::ProposeSlash {
                        manager,
                        accused: case.accused,
                        proof_type: case.proof_type,
                        proof: case.proof.proof.clone(),
                        votes: case.votes.values().cloned().collect(),
                    },
                }));
            }
        }
        self.cases.retain(|ballot, _| now <= ballot.deadline);
        self.early.retain(|ballot, _| now <= ballot.deadline);
        effects
    }

    pub(crate) fn next_deadline(&self) -> Option<UnixSecs> {
        let submissions = self
            .cases
            .values()
            .filter(|case| !case.submitted)
            .filter_map(|case| case.submit_at);
        let windows = self
            .cases
            .keys()
            .chain(self.early.keys())
            .map(|ballot| ballot.deadline.saturating_add(1));
        submissions.chain(windows).min()
    }

    /// The chain expelled `member`: its accusations end, and its votes no longer count. The
    /// contract rejects a slash that names an expelled voter, so a window that lost the member's
    /// vote goes again with the votes left, once H members voted, even if this node sent it.
    pub(crate) fn expel(&mut self, now: UnixSecs, member: Address) -> Vec<Effect> {
        self.expelled.insert(member);
        self.cases.retain(|_, case| case.accused != member);
        let mut rearmed = Vec::new();
        for (ballot, case) in &mut self.cases {
            if case.votes.remove(&member).is_some() {
                case.submitted = false;
                case.submit_at = None;
                rearmed.push(*ballot);
            }
        }
        for votes in self.early.values_mut() {
            votes.remove(&member);
        }
        self.early.retain(|_, votes| !votes.is_empty());
        let mut effects = Vec::new();
        for ballot in rearmed {
            effects.extend(self.reached(now, ballot));
        }
        effects
    }

    /// Whether the window `message` belongs to is still open, so sending it again can help.
    pub(crate) fn open(&self, message: &AccusationMessage) -> bool {
        let vote = match message {
            AccusationMessage::Accuse { vote, .. } | AccusationMessage::Vote(vote) => vote,
        };
        self.cases.contains_key(&Ballot::of(&vote.vote))
    }

    /// The members that H members found sending a failing proof.
    pub(crate) fn convicted(&self) -> &BTreeSet<Address> {
        &self.convicted
    }

    /// Whether any accusation is open: its window has not passed.
    pub(crate) fn running(&self) -> bool {
        !self.cases.is_empty() || !self.early.is_empty()
    }

    /// When the last open window closes.
    pub(crate) fn closes_at(&self) -> Option<UnixSecs> {
        let ballots = self.cases.keys().chain(self.early.keys());
        ballots.map(|ballot| ballot.deadline + 1).max()
    }

    fn is_member(&self, member: Address) -> bool {
        self.members.contains(&member) && !self.expelled.contains(&member)
    }

    fn verify(&self, proof_type: ProofType, proof: ZkProof) -> Effect {
        Effect::Run(Job {
            e3: self.e3,
            params: self.params,
            work: Work::Accusation(AccusationWork::Verify { proof_type, proof }),
        })
    }
}
