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
    /// The windows each member has opened, by accusation. A member that follows the protocol
    /// accuses once; more windows, one after another, would keep an E3 and its blobs without end.
    opened: BTreeSet<(Address, B256)>,
    expelled: BTreeSet<Address>,
    /// Members that H members found sending a failing proof, in some window.
    convicted: BTreeSet<Address>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Case {
    accused: Address,
    proof_type: ProofType,
    /// The proofs brought for this ballot that this node has not checked yet. Anyone can bring
    /// one under a ballot it copied, and only a check tells which is the real evidence.
    candidates: BTreeMap<ZkProof, SignedProof>,
    votes: BTreeMap<Address, SignedVote>,
    evidence: Evidence,
}

/// What this node found for a ballot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Evidence {
    /// No check of this node's has found the proof that the ballot's votes sign.
    Unknown,
    /// This node found `proof` failing under the ballot's evidence hash, and a slash carries it.
    /// The node voted when it found it, unless it is the accused.
    Found { proof: SignedProof, slash: Slash },
}

/// This node's turn to submit a slash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Slash {
    /// Fewer than H members voted, or this node is not among the first voters. Each new vote,
    /// and each expulsion, looks again.
    NotDue,
    /// H members voted, and this node, among the first voters, submits at this time.
    Due(UnixSecs),
    /// This node submitted the slash.
    Sent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Checked {
    data_hash: B256,
    fails: bool,
}

impl Checked {
    /// Whether the proof checked is the evidence that votes for `data_hash` sign.
    fn shows(&self, data_hash: B256) -> bool {
        self.fails && self.data_hash == data_hash
    }
}

impl Case {
    fn new(accused: Address, proof_type: ProofType) -> Self {
        Self {
            accused,
            proof_type,
            candidates: BTreeMap::new(),
            votes: BTreeMap::new(),
            evidence: Evidence::Unknown,
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
            opened: BTreeSet::new(),
            expelled: BTreeSet::new(),
            convicted: BTreeSet::new(),
        }
    }

    /// This node's check found that `proof`, which `accused` signed, fails. The node accuses the
    /// signer of each proof type once, in a window that starts now. Another member that accused
    /// in the same second opened the same window, and this node joins it.
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
        let id = accusation_id(self.e3, accused, proof_type);
        if self.validity == 0
            || accused == self.me
            || !self.is_member(accused)
            || !self.opened.insert((self.me, id))
        {
            return Vec::new();
        }
        let ballot = Ballot {
            accusation_id: id,
            data_hash,
            issued_at: now,
            deadline: now.saturating_add(self.validity),
        };
        self.cases
            .entry(ballot)
            .or_insert_with(|| Case::new(accused, proof_type));
        self.found(ballot, proof).into_iter().collect()
    }

    /// Whether to take `message` from `sender`, which costs a journal entry: both it and the
    /// accused are live members, the accused signed the proof, and the vote is the sender's and
    /// counts. An accusation opens a window if the sender has not opened one for that accusation
    /// and this node's check did not rule the proof out; one for a window that is already open is
    /// one more vote in it, and one more proof to check.
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
                let opens_or_joins = match self.cases.get(&ballot) {
                    Some(case) => !case.votes.contains_key(&sender),
                    None => {
                        !self.opened.contains(&(sender, ballot.accusation_id))
                            && !self.ruled_out(*proof_type, &proof.proof, ballot.data_hash)
                    }
                };
                sender != *accused
                    && self.is_member(*accused)
                    && vote.vote.accusation_id == accusation_id(self.e3, *accused, *proof_type)
                    && proof.is_signed_by(*accused, self.e3, *proof_type)
                    && self.counts(now, sender, vote)
                    && opens_or_joins
            }
            AccusationMessage::Vote(vote) => {
                let ballot = Ballot::of(&vote.vote);
                let useful = match self.cases.get(&ballot) {
                    Some(case) => case.accused != sender && !case.votes.contains_key(&sender),
                    None => {
                        let waiting = self
                            .early
                            .values()
                            .filter(|votes| votes.contains_key(&sender))
                            .count();
                        waiting < EARLY_VOTES_PER_MEMBER
                            && !self
                                .early
                                .get(&ballot)
                                .is_some_and(|votes| votes.contains_key(&sender))
                    }
                };
                useful && self.counts(now, sender, vote)
            }
        }
    }

    /// Whether this node's own check shows that `proof` is not evidence under `data_hash`.
    fn ruled_out(&self, proof_type: ProofType, proof: &ZkProof, data_hash: B256) -> bool {
        self.verdicts
            .get(&(proof_type, proof.clone()))
            .is_some_and(|checked| !checked.shows(data_hash))
    }

    /// Takes `proof` as evidence for `ballot`, and votes, if this node already found it so, or as
    /// a candidate if no check has spoken. A proof no check is under way for gets one, unless this
    /// node is its accused.
    fn consider(&mut self, ballot: Ballot, proof: SignedProof) -> Option<Effect> {
        let case = self.cases.get(&ballot)?;
        if let Evidence::Found { .. } = case.evidence {
            return None;
        }
        let (proof_type, accused) = (case.proof_type, case.accused);
        if let Some(checked) = self.verdicts.get(&(proof_type, proof.proof.clone())) {
            return match checked.shows(ballot.data_hash) {
                true => self.found(ballot, proof),
                false => None,
            };
        }
        let asked = self.cases.values().any(|case| {
            case.accused != self.me
                && case.proof_type == proof_type
                && case.candidates.contains_key(&proof.proof)
        });
        let unchecked = proof.proof.clone();
        self.cases
            .get_mut(&ballot)?
            .candidates
            .insert(unchecked.clone(), proof);
        (accused != self.me && !asked).then(|| self.verify(proof_type, unchecked))
    }

    /// A vote counts from a live member that signed it, for this E3, in a window that is no longer
    /// than the vote validity and has not passed. Without a validity accusations are off.
    fn counts(&self, now: UnixSecs, voter: Address, signed: &SignedVote) -> bool {
        let vote = &signed.vote;
        self.validity != 0
            && vote.e3 == self.e3
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
                // Members that accuse in the same second share a window; the contract takes their
                // votes together.
                if !self.cases.contains_key(&ballot) {
                    self.opened.insert((sender, ballot.accusation_id));
                    let mut case = Case::new(accused, proof_type);
                    let early = self.early.remove(&ballot).into_iter().flatten();
                    case.votes
                        .extend(early.filter(|(voter, _)| *voter != accused));
                    self.cases.insert(ballot, case);
                }
                if let Some(case) = self.cases.get_mut(&ballot) {
                    case.votes.insert(sender, vote);
                }
                let mut effects: Vec<Effect> = self.consider(ballot, proof).into_iter().collect();
                effects.extend(self.reached(now, ballot));
                effects
            }
            AccusationMessage::Vote(vote) => {
                let ballot = Ballot::of(&vote.vote);
                match self.cases.get_mut(&ballot) {
                    Some(case) => {
                        case.votes.insert(sender, vote);
                        self.reached(now, ballot)
                    }
                    None => {
                        self.early.entry(ballot).or_default().insert(sender, vote);
                        Vec::new()
                    }
                }
            }
        }
    }

    /// This node checked a proof that ballots name as a candidate. If it is the evidence a ballot
    /// signs, the node votes there. If not, it is gone from that ballot, and a window with nothing
    /// left to check has no reason to stay open.
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
            .filter(|(_, case)| {
                case.proof_type == proof_type && case.candidates.contains_key(&proof)
            })
            .map(|(ballot, _)| *ballot)
            .collect();
        let checked = Checked { data_hash, fails };
        self.verdicts.insert((proof_type, proof.clone()), checked);
        let mut effects = Vec::new();
        for ballot in ballots {
            let Some(case) = self.cases.get_mut(&ballot) else {
                continue;
            };
            let candidate = case.candidates.remove(&proof);
            if checked.shows(ballot.data_hash) {
                case.candidates.clear();
                effects.extend(candidate.and_then(|proof| self.found(ballot, proof)));
                effects.extend(self.reached(now, ballot));
            } else if case.evidence == Evidence::Unknown && case.candidates.is_empty() {
                self.cases.remove(&ballot);
            }
        }
        effects
    }

    /// This node found `proof` to be the evidence that `ballot`'s votes sign. It votes there,
    /// unless it is the accused. A ballot whose evidence it found before stays as it was.
    fn found(&mut self, ballot: Ballot, proof: SignedProof) -> Option<Effect> {
        let vote = self.own_vote(ballot);
        let case = self.cases.get_mut(&ballot)?;
        if let Evidence::Found { .. } = case.evidence {
            return None;
        }
        let slash = Slash::NotDue;
        case.evidence = Evidence::Found { proof, slash };
        if case.accused == self.me {
            return None;
        }
        Some(Effect::Sign(Signing {
            e3: self.e3,
            purpose: Purpose::Accusation(ballot),
            hashes: vec![vote.signing_hash(self.manager)],
        }))
    }

    /// This node's vote in `ballot`.
    fn own_vote(&self, ballot: Ballot) -> Vote {
        Vote {
            e3: self.e3,
            accusation_id: ballot.accusation_id,
            voter: self.me,
            data_hash: ballot.data_hash,
            issued_at: ballot.issued_at,
            deadline: ballot.deadline,
        }
    }

    pub(crate) fn signed(
        &mut self,
        now: UnixSecs,
        ballot: Ballot,
        signatures: Vec<Bytes>,
    ) -> Vec<Effect> {
        let (me, e3) = (self.me, self.e3);
        let vote = self.own_vote(ballot);
        let ([signature], Some(case)) = (signatures.as_slice(), self.cases.get_mut(&ballot)) else {
            return Vec::new();
        };
        let Evidence::Found { proof, .. } = &case.evidence else {
            return Vec::new();
        };
        let vote = SignedVote {
            vote,
            signature: signature.clone(),
        };
        // The first vote in a window is the accusation, which carries the accused proof.
        let message = match case.votes.is_empty() {
            true => AccusationMessage::Accuse {
                accused: case.accused,
                proof_type: case.proof_type,
                proof: proof.clone(),
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
        let Evidence::Found { slash, .. } = &mut case.evidence else {
            return Vec::new();
        };
        if *slash != Slash::NotDue {
            return Vec::new();
        }
        let Some(place) = case.votes.keys().position(|voter| *voter == me) else {
            return Vec::new();
        };
        if place < SUBMITTERS {
            *slash = Slash::Due(now + SUBMIT_TURN * place as UnixSecs);
        }
        self.pass_deadlines(now)
    }

    pub(crate) fn pass_deadlines(&mut self, now: UnixSecs) -> Vec<Effect> {
        let (e3, manager) = (self.e3, self.manager);
        let mut effects = Vec::new();
        for (ballot, case) in &mut self.cases {
            let Evidence::Found { proof, slash } = &mut case.evidence else {
                continue;
            };
            let due = matches!(*slash, Slash::Due(at) if at <= now) && now <= ballot.deadline;
            if !due {
                continue;
            }
            *slash = Slash::Sent;
            effects.push(Effect::Submit(Submission {
                e3,
                transaction: Transaction::ProposeSlash {
                    manager,
                    accused: case.accused,
                    proof_type: case.proof_type,
                    proof: proof.proof.clone(),
                    votes: case.votes.values().cloned().collect(),
                },
            }));
        }
        self.cases.retain(|ballot, _| now <= ballot.deadline);
        self.early.retain(|ballot, _| now <= ballot.deadline);
        effects
    }

    pub(crate) fn next_deadline(&self) -> Option<UnixSecs> {
        let submissions = self.cases.values().filter_map(|case| match case.evidence {
            Evidence::Found {
                slash: Slash::Due(at),
                ..
            } => Some(at),
            _ => None,
        });
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
                if let Evidence::Found { slash, .. } = &mut case.evidence {
                    *slash = Slash::NotDue;
                }
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

    /// Whether any accusation is open: its window has not passed. A vote that waits for an
    /// accusation that may never come is not one, and keeps nothing.
    pub(crate) fn running(&self) -> bool {
        !self.cases.is_empty()
    }

    /// When the last open window closes.
    pub(crate) fn closes_at(&self) -> Option<UnixSecs> {
        self.cases.keys().map(|ballot| ballot.deadline + 1).max()
    }

    /// The longest window a vote may sign; zero turns accusations off.
    pub(crate) fn validity(&self) -> UnixSecs {
        self.validity
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
