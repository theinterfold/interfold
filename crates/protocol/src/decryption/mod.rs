// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Threshold decryption of an E3's ciphertext (C6, C7). Every member fetches the ciphertext's
//! bytes from where the chain says they are. Roster members decrypt with their sealed decryption
//! keys. Every member keeps the roster members' shares, so any member can take over as
//! the plaintext aggregator: once T+1 shares are here it checks them, combines exactly T+1 valid
//! ones into the plaintext (C7), and asks the chain writer to publish it. An aggregator that has
//! started combining finishes; the chain accepts one plaintext.

mod domain;
#[cfg(test)]
mod tests;

pub use domain::{committee_hash, decryption_domain};

use crate::{
    accusation::Verdict,
    dkg::KeyAnchor,
    failover::Failover,
    node::{
        Body, CryptoParams, DataRef, Effect, Fetch, Job, PeerMessage, Purpose, Signing, Submission,
        Transaction, Work,
    },
    proof::{ProofType, SignedProof, ZkProof},
    BlobRef, E3Id, UnixSecs,
};
use alloy_primitives::{Address, Bytes, B256};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The plaintext aggregator's budget, from when T+1 roster members' shares are here.
const PLAINTEXT_BUDGET: UnixSecs = 10 * 60;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecryptionMessage {
    /// A roster member's decryption share of each ciphertext, each with its C6 proof.
    Shares(SharesMessage),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharesMessage {
    pub shares: Vec<BlobRef>,
    pub c6: Vec<SignedProof>,
}

impl DecryptionMessage {
    pub(crate) fn blobs(&self) -> Vec<BlobRef> {
        let Self::Shares(message) = self;
        let proofs = message.c6.iter().map(|signed| signed.proof.data);
        message.shares.iter().copied().chain(proofs).collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecryptionWork {
    /// This node's decryption share of each ciphertext, made with its sealed decryption key, and
    /// a C6 proof of each that binds `domain`.
    MakeShares {
        key: BlobRef,
        ciphertext: BlobRef,
        domain: B256,
    },
    /// Check a roster member's shares against their C6 proofs, the ciphertext, `domain`, and the
    /// member's key commitments that the chain recorded.
    CheckShares {
        member: Address,
        committee: Vec<Address>,
        ciphertext: BlobRef,
        domain: B256,
        anchor: Option<KeyAnchor>,
        message: Box<SharesMessage>,
    },
    /// Combine exactly T+1 roster members' shares into the plaintext, with its C7 and final
    /// proofs.
    AggregatePlaintext {
        committee: Vec<Address>,
        ciphertext: BlobRef,
        domain: B256,
        shares: BTreeMap<Address, SharesMessage>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecryptionWorkResult {
    SharesMade(OwnShares),
    SharesChecked { member: Address, verdict: Verdict },
    PlaintextMade(PlaintextPublication),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnShares {
    pub shares: Vec<BlobRef>,
    pub c6: Vec<ZkProof>,
}

/// What `publishPlaintextOutput` needs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaintextPublication {
    pub plaintext: BlobRef,
    pub proof: ZkProof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecryptionSignature {
    /// One C6 proof per ciphertext, in order.
    ShareProofs,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecryptionFailure {
    /// Fewer than T+1 roster members can still give a valid share.
    TooFewShares,
    /// The decryption deadline passed.
    DeadlinePassed,
}

/// What decryption takes over from the DKG once the chain published the key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Handover {
    pub(crate) roster: Vec<Address>,
    /// A roster member's sealed decryption key; none outside the roster.
    pub(crate) key: Option<BlobRef>,
    pub(crate) expelled: BTreeSet<Address>,
    /// Members that H members found sending a failing proof, who aggregate no phase.
    pub(crate) convicted: BTreeSet<Address>,
}

/// The key the chain published, as the registry recorded it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PublishedKey {
    pub(crate) interfold: Address,
    /// The registry's committee, in its order.
    pub(crate) committee: Vec<Address>,
    pub(crate) commitment: B256,
    pub(crate) anchors: BTreeMap<Address, KeyAnchor>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Ciphertext {
    /// The bytes, once fetched.
    blob: Option<BlobRef>,
    domain: B256,
    deadline: UnixSecs,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Own {
    Waiting,
    Making,
    Signing(OwnShares),
    Sent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Aggregation {
    /// Not this node's work, or not yet.
    Idle,
    /// The members whose shares this node is checking or has checked, with each verdict so far.
    Checking {
        dispatched: BTreeSet<Address>,
        verdicts: BTreeMap<Address, bool>,
    },
    Combining,
    Submitted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decryption {
    e3: E3Id,
    me: Address,
    members: Vec<Address>,
    params: CryptoParams,
    roster: Vec<Address>,
    key: Option<BlobRef>,
    published: PublishedKey,
    expelled: BTreeSet<Address>,
    ciphertext: Option<Ciphertext>,
    own: Own,
    /// The first signed shares of each roster member, this node's included.
    shares: BTreeMap<Address, SharesMessage>,
    failover: Failover,
    aggregation: Aggregation,
    failure: Option<DecryptionFailure>,
}

impl Decryption {
    pub(crate) fn new(
        e3: E3Id,
        me: Address,
        members: Vec<Address>,
        params: CryptoParams,
        handover: Handover,
        published: PublishedKey,
    ) -> Self {
        let mut failover = Failover::new(PLAINTEXT_BUDGET);
        for member in handover.convicted {
            failover.convict(member);
        }
        Self {
            e3,
            me,
            members,
            params,
            roster: handover.roster,
            key: handover.key,
            published,
            expelled: handover.expelled,
            ciphertext: None,
            own: Own::Waiting,
            shares: BTreeMap::new(),
            failover,
            aggregation: Aggregation::Idle,
            failure: None,
        }
    }

    pub fn failure(&self) -> Option<DecryptionFailure> {
        self.failure
    }

    pub(crate) fn running(&self) -> bool {
        self.failure.is_none()
    }

    /// The proof that `member` signed and sent this node, for an accusation of it.
    pub(crate) fn signed_proof(&self, member: Address, proof: &ZkProof) -> Option<SignedProof> {
        let shares = self.shares_of(&member)?;
        shares
            .c6
            .iter()
            .find(|signed| signed.proof == *proof)
            .cloned()
    }

    pub fn shares_of(&self, member: &Address) -> Option<&SharesMessage> {
        self.shares.get(member)
    }

    pub(crate) fn ciphertext_ready(&mut self, data: DataRef, deadline: UnixSecs) -> Vec<Effect> {
        if self.ciphertext.is_some() || self.failure.is_some() {
            return Vec::new();
        }
        let domain = decryption_domain(
            self.e3,
            self.published.interfold,
            committee_hash(&self.published.committee),
            data.hash,
            self.published.commitment,
        );
        self.ciphertext = Some(Ciphertext {
            blob: None,
            domain,
            deadline,
        });
        vec![Effect::Fetch(Fetch { e3: self.e3, data })]
    }

    pub(crate) fn ciphertext_fetched(&mut self, now: UnixSecs, blob: BlobRef) -> Vec<Effect> {
        let Some(ciphertext) = self.ciphertext.as_mut() else {
            return Vec::new();
        };
        if ciphertext.blob.is_some() || self.failure.is_some() {
            return Vec::new();
        }
        ciphertext.blob = Some(blob);
        let domain = ciphertext.domain;
        let mut effects = Vec::new();
        if let (Some(key), true) = (self.key, self.roster.contains(&self.me)) {
            self.own = Own::Making;
            effects.push(self.run(DecryptionWork::MakeShares {
                key,
                ciphertext: blob,
                domain,
            }));
        }
        effects.extend(self.advance(now));
        effects
    }

    pub(crate) fn receive(
        &mut self,
        now: UnixSecs,
        sender: Address,
        message: DecryptionMessage,
    ) -> Vec<Effect> {
        if !self.admits(sender, &message) {
            return Vec::new();
        }
        let DecryptionMessage::Shares(shares) = message;
        self.shares.insert(sender, shares);
        self.advance(now)
    }

    /// Whether this node takes `message` from `sender` now; it can tell before it fetches any blob
    /// the message names.
    pub(crate) fn admits(&self, sender: Address, message: &DecryptionMessage) -> bool {
        let DecryptionMessage::Shares(shares) = message;
        self.failure.is_none()
            && sender != self.me
            && self.counts(&sender)
            && !self.shares.contains_key(&sender)
            && !shares.shares.is_empty()
            && shares.shares.len() == shares.c6.len()
            && shares.c6.iter().all(|proof| {
                proof.is_signed_by(sender, self.e3, ProofType::C6ThresholdShareDecryption)
            })
    }

    pub(crate) fn job_done(&mut self, now: UnixSecs, result: DecryptionWorkResult) -> Vec<Effect> {
        if self.failure.is_some() {
            return Vec::new();
        }
        let mut effects = match result {
            DecryptionWorkResult::SharesMade(made) => self.shares_made(made),
            DecryptionWorkResult::SharesChecked { member, verdict } => {
                if let Aggregation::Checking { verdicts, .. } = &mut self.aggregation {
                    verdicts.entry(member).or_insert(verdict.is_valid());
                }
                Vec::new()
            }
            DecryptionWorkResult::PlaintextMade(publication) => self.plaintext_made(publication),
        };
        effects.extend(self.advance(now));
        effects
    }

    pub(crate) fn signed(
        &mut self,
        now: UnixSecs,
        purpose: DecryptionSignature,
        signatures: Vec<Bytes>,
    ) -> Vec<Effect> {
        let DecryptionSignature::ShareProofs = purpose;
        let Own::Signing(made) = &self.own else {
            return Vec::new();
        };
        if self.failure.is_some() || signatures.len() != made.c6.len() {
            return Vec::new();
        }
        let message = SharesMessage {
            shares: made.shares.clone(),
            c6: made
                .c6
                .iter()
                .zip(signatures)
                .map(|(proof, signature)| SignedProof {
                    proof: proof.clone(),
                    signature,
                })
                .collect(),
        };
        self.own = Own::Sent;
        self.shares.insert(self.me, message.clone());
        let mut effects = vec![self.gossip(DecryptionMessage::Shares(message))];
        effects.extend(self.advance(now));
        effects
    }

    pub(crate) fn expel(&mut self, now: UnixSecs, member: Address) -> Vec<Effect> {
        if !self.expelled.insert(member) {
            return Vec::new();
        }
        self.pass_deadlines(now)
    }

    /// H members found `member` sending a failing proof: it aggregates the plaintext no more.
    pub(crate) fn convict(&mut self, now: UnixSecs, member: Address) -> Vec<Effect> {
        if !self.failover.convict(member) {
            return Vec::new();
        }
        self.pass_deadlines(now)
    }

    pub(crate) fn pass_deadlines(&mut self, now: UnixSecs) -> Vec<Effect> {
        let Some(ciphertext) = &self.ciphertext else {
            return Vec::new();
        };
        if self.failure.is_some() {
            return Vec::new();
        }
        if now >= ciphertext.deadline {
            self.failure = Some(DecryptionFailure::DeadlinePassed);
            return Vec::new();
        }
        if self.aggregation == Aggregation::Idle {
            self.failover
                .pass_deadlines(now, &self.members, &self.expelled);
        }
        self.advance(now)
    }

    pub(crate) fn next_deadline(&self) -> Option<UnixSecs> {
        let ciphertext = self
            .ciphertext
            .as_ref()
            .filter(|_| self.failure.is_none())?;
        let failover = match self.aggregation {
            Aggregation::Idle => self.failover.next_deadline(),
            _ => None,
        };
        [failover, Some(ciphertext.deadline)]
            .into_iter()
            .flatten()
            .min()
    }

    fn shares_made(&mut self, made: OwnShares) -> Vec<Effect> {
        // A repeated job's second shares are never used: this node decrypts once per E3.
        if self.own != Own::Making {
            return Vec::new();
        }
        let hashes = made
            .c6
            .iter()
            .map(|proof| proof.payload_signing_hash(self.e3, ProofType::C6ThresholdShareDecryption))
            .collect();
        self.own = Own::Signing(made);
        vec![Effect::Sign(Signing {
            e3: self.e3,
            purpose: Purpose::Decryption(DecryptionSignature::ShareProofs),
            hashes,
        })]
    }

    fn plaintext_made(&mut self, publication: PlaintextPublication) -> Vec<Effect> {
        if self.aggregation != Aggregation::Combining {
            return Vec::new();
        }
        self.aggregation = Aggregation::Submitted;
        vec![Effect::Submit(Submission {
            e3: self.e3,
            transaction: Transaction::PublishPlaintext(publication),
        })]
    }

    /// Start the aggregator's budget once T+1 roster members' shares are here; as the aggregator,
    /// check every share that is here, and combine the first T+1 valid ones in committee order.
    fn advance(&mut self, now: UnixSecs) -> Vec<Effect> {
        let Some((blob, domain)) = self
            .ciphertext
            .as_ref()
            .filter(|_| self.failure.is_none())
            .and_then(|ciphertext| Some((ciphertext.blob?, ciphertext.domain)))
        else {
            return Vec::new();
        };
        let here: Vec<Address> = self
            .roster
            .iter()
            .filter(|member| self.counts(member) && self.shares.contains_key(*member))
            .copied()
            .collect();
        if here.len() <= self.threshold() {
            return Vec::new();
        }
        self.failover
            .inputs_ready(now, &self.members, &self.expelled);
        if self.aggregation == Aggregation::Idle
            && self.failover.aggregator(&self.members, &self.expelled) == Some(self.me)
        {
            self.aggregation = Aggregation::Checking {
                dispatched: BTreeSet::new(),
                verdicts: BTreeMap::new(),
            };
        }
        let Aggregation::Checking {
            dispatched,
            verdicts,
        } = &self.aggregation
        else {
            return Vec::new();
        };
        let new: Vec<Address> = here
            .iter()
            .filter(|member| !dispatched.contains(*member))
            .copied()
            .collect();
        let valid: Vec<Address> = here
            .iter()
            .filter(|member| verdicts.get(*member) == Some(&true))
            .take(self.threshold() + 1)
            .copied()
            .collect();
        let possible = self
            .roster
            .iter()
            .filter(|member| self.counts(member) && verdicts.get(*member) != Some(&false))
            .count();
        if let Aggregation::Checking { dispatched, .. } = &mut self.aggregation {
            dispatched.extend(new.iter().copied());
        }
        let mut effects: Vec<Effect> = new
            .into_iter()
            .filter_map(|member| {
                let message = self.shares.get(&member)?.clone();
                Some(self.run(DecryptionWork::CheckShares {
                    member,
                    committee: self.members.clone(),
                    ciphertext: blob,
                    domain,
                    anchor: self.published.anchors.get(&member).copied(),
                    message: Box::new(message),
                }))
            })
            .collect();
        if valid.len() > self.threshold() {
            self.aggregation = Aggregation::Combining;
            let shares = valid
                .iter()
                .filter_map(|member| Some((*member, self.shares.get(member)?.clone())))
                .collect();
            effects.push(self.run(DecryptionWork::AggregatePlaintext {
                committee: self.members.clone(),
                ciphertext: blob,
                domain,
                shares,
            }));
        } else if possible <= self.threshold() {
            self.failure = Some(DecryptionFailure::TooFewShares);
        }
        effects
    }

    fn threshold(&self) -> usize {
        self.params.committee_size.values().threshold
    }

    /// A roster member the chain has not expelled.
    fn counts(&self, member: &Address) -> bool {
        self.roster.contains(member) && !self.expelled.contains(member)
    }

    fn run(&self, work: DecryptionWork) -> Effect {
        Effect::Run(Job {
            e3: self.e3,
            params: self.params,
            work: Work::Decryption(work),
        })
    }

    fn gossip(&self, message: DecryptionMessage) -> Effect {
        Effect::Gossip(PeerMessage {
            e3: self.e3,
            sender: self.me,
            body: Body::Decryption(message),
        })
    }
}
