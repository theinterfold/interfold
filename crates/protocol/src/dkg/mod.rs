// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! One committee member's DKG for one E3: its encryption key (C0), the threshold shares it deals
//! and receives (C1-C3), and its Ready report.

mod attestation;
mod keys;
mod shares;
mod timing;

pub use attestation::FoldAttestation;
pub use timing::DkgTiming;

use crate::{
    node::{Body, Effect, Job, PeerMessage, Purpose, Signing, Work},
    proof::{SignedProof, ZkProof},
    BlobRef, E3Id, UnixSecs,
};
use alloy_primitives::{keccak256, Address, Bytes, B256};
use keys::Keys;
use serde::{Deserialize, Serialize};
use shares::Shares;
use std::collections::{BTreeMap, BTreeSet};

/// What committee members send each other during the DKG.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DkgMessage {
    /// A member's BFV encryption key (C0).
    EncryptionKey(KeyMessage),
    /// A dealer's threshold shares for one recipient, with the proofs the recipient checks.
    Shares(Box<SharesMessage>),
    /// The dealers whose shares the sender verified, the sender included, ascending by member.
    /// A member's later report contains its earlier one.
    Ready(Vec<Dealer>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyMessage {
    pub key: BlobRef,
    pub proof: SignedProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharesMessage {
    pub recipient: Address,
    pub pk_share: BlobRef,
    /// The dealer's secret-key and smudging-noise shares for the recipient, encrypted to the
    /// recipient's C0 key.
    pub shares: BlobRef,
    pub c2a: SignedProof,
    pub c2b: SignedProof,
    /// One proof per threshold Shamir row.
    pub c3a: Vec<SignedProof>,
    pub c3b: Vec<SignedProof>,
}

/// A dealer's exact contribution, as Ready reports name it. It binds the public statements of the
/// dealer's C2 proofs, not their randomized proof bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Dealer {
    pub member: Address,
    pub contribution: B256,
}

impl Dealer {
    fn new(member: Address, pk_share: BlobRef, c2a: &ZkProof, c2b: &ZkProof) -> Self {
        let statement = |proof: &ZkProof| {
            keccak256(
                proof
                    .public_inputs
                    .iter()
                    .flat_map(|word| word.0)
                    .collect::<Vec<u8>>(),
            )
        };
        Self {
            member,
            contribution: keccak256([pk_share.hash, statement(c2a), statement(c2b)].concat()),
        }
    }
}

impl DkgMessage {
    pub(crate) fn size(&self) -> u64 {
        match self {
            Self::EncryptionKey(message) => message.key.len + message.proof.size(),
            Self::Shares(message) => {
                let proofs = [&message.c2a, &message.c2b]
                    .into_iter()
                    .chain(&message.c3a)
                    .chain(&message.c3b);
                message.pk_share.len
                    + message.shares.len
                    + proofs.map(SignedProof::size).sum::<u64>()
            }
            Self::Ready(dealers) => 52 * dealers.len() as u64,
        }
    }
}

/// Work the DKG asks the job runner for. Jobs that need party IDs get the committee: a member's
/// party ID is its index there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DkgWork {
    /// This node's BFV keypair and its C0 proof. The secret key stays sealed in the job runner's
    /// blob store; the DKG only holds its reference.
    MakeEncryptionKey,
    /// Check a member's key blob against the key commitment in its C0 proof, and the proof.
    CheckEncryptionKey {
        sender: Address,
        key: BlobRef,
        proof: ZkProof,
    },
    /// This node's threshold shares and their C1-C3 proofs. Every member in `keys` gets its
    /// encrypted shares; every other member's C3 slot gets a placeholder.
    MakeShares {
        dealer: Address,
        committee: Vec<Address>,
        secret: BlobRef,
        keys: BTreeMap<Address, BlobRef>,
    },
    /// Check what `dealer` sent this node: decrypt the shares with this node's secret key and
    /// check them against their C2 and C3 proofs.
    CheckShares {
        dealer: Address,
        committee: Vec<Address>,
        secret: BlobRef,
        message: Box<SharesMessage>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DkgWorkResult {
    EncryptionKeyMade(OwnKey),
    EncryptionKeyChecked { sender: Address, valid: bool },
    SharesMade(OwnShares),
    SharesChecked { dealer: Address, valid: bool },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DkgSignature {
    EncryptionKeyProof,
    /// C1, C2a, C2b, then each recipient's C3a and C3b proofs, recipients ascending.
    DealerProofs,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnKey {
    pub public: BlobRef,
    pub secret: BlobRef,
    pub proof: ZkProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnShares {
    pub pk_share: BlobRef,
    /// This node's own plaintext share rows, sealed in the job runner's blob store, for C4.
    pub own_share: BlobRef,
    pub c1: ZkProof,
    pub c2a: ZkProof,
    pub c2b: ZkProof,
    pub recipients: BTreeMap<Address, RecipientShares>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientShares {
    pub shares: BlobRef,
    pub c3a: Vec<ZkProof>,
    pub c3b: Vec<ZkProof>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DkgFailure {
    /// The committee was finalized after the key cutoff, so this node's key could not count.
    StartedAfterKeyCutoff,
    /// Fewer than H valid keys, this node's included, by the key cutoff.
    TooFewKeys,
    /// The chain expelled this node from the committee.
    Expelled,
    /// The canonical DKG deadline passed.
    DeadlinePassed,
}

/// This node's own progress. Peers' inputs are kept apart, because they arrive whatever this node
/// has reached.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Phase {
    MakingKey,
    SigningKey(OwnKey),
    CollectingKeys(OwnKey),
    MakingShares(OwnKey),
    SigningShares(OwnKey, Box<OwnShares>),
    /// Shares sent; the contribution is what Ready reports name for this node.
    Dealt(OwnKey, Dealer),
    Failed(DkgFailure),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dkg {
    e3: E3Id,
    me: Address,
    /// The finalized committee, ascending by address; a party's ID is its index.
    members: Vec<Address>,
    h: usize,
    timing: DkgTiming,
    expelled: BTreeSet<Address>,
    keys: Keys,
    shares: Shares,
    /// The latest Ready report of each member, this node's included.
    ready: BTreeMap<Address, Vec<Dealer>>,
    phase: Phase,
}

impl Dkg {
    pub(crate) fn start(
        e3: E3Id,
        me: Address,
        members: Vec<Address>,
        h: usize,
        timing: DkgTiming,
        now: UnixSecs,
    ) -> (Self, Vec<Effect>) {
        let mut dkg = Self {
            e3,
            me,
            members,
            h,
            timing,
            expelled: BTreeSet::new(),
            keys: Keys::default(),
            shares: Shares::default(),
            ready: BTreeMap::new(),
            phase: Phase::MakingKey,
        };
        if now >= timing.key_cutoff() {
            dkg.phase = Phase::Failed(DkgFailure::StartedAfterKeyCutoff);
            return (dkg, Vec::new());
        }
        let make = dkg.run(DkgWork::MakeEncryptionKey);
        (dkg, vec![make])
    }

    pub fn valid_keys(&self) -> &BTreeSet<Address> {
        &self.keys.valid
    }

    pub fn keys_collected(&self) -> bool {
        matches!(
            self.phase,
            Phase::MakingShares(_) | Phase::SigningShares(..) | Phase::Dealt(..)
        )
    }

    pub fn ready(&self, member: &Address) -> Option<&[Dealer]> {
        self.ready.get(member).map(Vec::as_slice)
    }

    pub fn failure(&self) -> Option<DkgFailure> {
        match self.phase {
            Phase::Failed(failure) => Some(failure),
            _ => None,
        }
    }

    pub(crate) fn receive(&mut self, sender: Address, message: DkgMessage) -> Vec<Effect> {
        match message {
            DkgMessage::EncryptionKey(message) => self.receive_key(sender, message),
            DkgMessage::Shares(message) => self.receive_shares(sender, *message),
            DkgMessage::Ready(dealers) => {
                self.receive_ready(sender, dealers);
                Vec::new()
            }
        }
    }

    pub(crate) fn job_done(&mut self, result: DkgWorkResult) -> Vec<Effect> {
        match result {
            DkgWorkResult::EncryptionKeyMade(own) => self.key_made(own),
            DkgWorkResult::EncryptionKeyChecked { sender, valid } => {
                self.key_checked(sender, valid)
            }
            DkgWorkResult::SharesMade(made) => self.shares_made(made),
            DkgWorkResult::SharesChecked { dealer, valid } => self.shares_checked(dealer, valid),
        }
    }

    pub(crate) fn signed(&mut self, purpose: DkgSignature, signatures: Vec<Bytes>) -> Vec<Effect> {
        match purpose {
            DkgSignature::EncryptionKeyProof => self.key_signed(signatures),
            DkgSignature::DealerProofs => self.shares_signed(signatures),
        }
    }

    pub(crate) fn expel(&mut self, member: Address) -> Vec<Effect> {
        if !self.is_member(member) || !self.expelled.insert(member) {
            return Vec::new();
        }
        if member == self.me {
            self.phase = Phase::Failed(DkgFailure::Expelled);
            return Vec::new();
        }
        let mut effects = self.close_keys_if_all_in();
        effects.extend(self.send_ready_if_due());
        effects
    }

    pub(crate) fn pass_deadlines(&mut self, now: UnixSecs) -> Vec<Effect> {
        let mut effects = Vec::new();
        if self.collecting_keys() && now >= self.timing.key_cutoff() {
            effects.extend(self.close_keys_at_cutoff());
        }
        if !self.shares.checkpoint_passed && now >= self.timing.share_checkpoint() {
            self.shares.checkpoint_passed = true;
            effects.extend(self.send_ready_if_due());
        }
        if self.running() && now >= self.timing.deadline {
            self.phase = Phase::Failed(DkgFailure::DeadlinePassed);
        }
        effects
    }

    pub(crate) fn next_deadline(&self) -> Option<UnixSecs> {
        if !self.running() {
            return None;
        }
        let key_cutoff = self.collecting_keys().then(|| self.timing.key_cutoff());
        let checkpoint = (!self.shares.checkpoint_passed).then(|| self.timing.share_checkpoint());
        [key_cutoff, checkpoint, Some(self.timing.deadline)]
            .into_iter()
            .flatten()
            .min()
    }

    fn running(&self) -> bool {
        !matches!(self.phase, Phase::Failed(_))
    }

    fn is_member(&self, address: Address) -> bool {
        self.members.binary_search(&address).is_ok()
    }

    fn is_live(&self, member: &Address) -> bool {
        !self.expelled.contains(member)
    }

    fn run(&self, work: DkgWork) -> Effect {
        Effect::Run(Job {
            e3: self.e3,
            work: Work::Dkg(work),
        })
    }

    fn sign(&self, purpose: DkgSignature, hashes: Vec<B256>) -> Effect {
        Effect::Sign(Signing {
            e3: self.e3,
            purpose: Purpose::Dkg(purpose),
            hashes,
        })
    }

    fn gossip(&self, message: DkgMessage) -> Effect {
        Effect::Gossip(PeerMessage {
            e3: self.e3,
            sender: self.me,
            body: Body::Dkg(message),
        })
    }
}

#[cfg(test)]
mod tests;
