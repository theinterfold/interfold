// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! One committee member's DKG for one E3: its encryption key (C0), the threshold shares it deals
//! and receives (C1-C3), the roster, its decryption key (C4), its keyshare and proof fold, and,
//! as the key aggregator, the committee key (C5) and its publication.

mod aggregation;
mod attestation;
mod decryption_key;
mod fold;
mod keys;
mod roster;
mod shares;
mod timing;

pub use attestation::{AttestationContext, FoldAttestation};
pub use timing::DkgTiming;

use crate::{
    accusation::Verdict,
    node::{Body, CryptoParams, Effect, Job, PeerMessage, Purpose, Signing, Work},
    proof::{SignedProof, ZkProof},
    BlobRef, E3Id, UnixSecs,
};
use aggregation::Aggregation;
use alloy_primitives::{keccak256, Address, Bytes, B256};
use decryption_key::DecryptionKeys;
use fold::OwnFold;
use keys::Keys;
use roster::Rosters;
use serde::{Deserialize, Serialize};
use shares::{Dealt, Shares};
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
    /// The H dealers whose shares every member sums into its decryption key, ascending by member.
    Roster(Vec<Dealer>),
    /// A roster member's proofs that its decryption key sums the roster's shares (C4).
    DecryptionKey(DecryptionKeyMessage),
    /// A roster member's public-key share and its C1 proof, for the public-key aggregator.
    Keyshare(KeyshareMessage),
    /// A roster member's recursive fold of its own DKG proofs, for the public-key aggregator.
    NodeFold(NodeFoldMessage),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeFoldMessage {
    pub fold: NodeFold,
    /// The member's EIP-712 signature over the fold's commitments for its committee slot, which
    /// the fold-attestation verifier checks.
    pub attestation: Bytes,
}

/// A roster member's aggregate commitments as the DKG proof that the chain verified carries them,
/// and the registry stores them: the key commitments that member's C6 proofs must name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyAnchor {
    pub sk_agg_commit: B256,
    pub esm_agg_commit: B256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeFold {
    pub proof: ZkProof,
    pub sk_agg_commit: B256,
    pub esm_agg_commit: B256,
}

/// What `publishCommittee` and the key chunks need.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPublication {
    pub commitment: B256,
    pub public_key: BlobRef,
    pub proof: ZkProof,
    /// One per roster member, ascending by party ID.
    pub attestations: Vec<SignedAttestation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAttestation {
    pub party_id: u64,
    /// The member in the party's committee slot, which the verifier binds to it.
    pub node: Address,
    pub sk_agg_commit: B256,
    pub esm_agg_commit: B256,
    pub signature: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptionKeyMessage {
    pub c4a: SignedProof,
    /// One proof per smudging-noise set.
    pub c4b: Vec<SignedProof>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyshareMessage {
    pub pk_share: BlobRef,
    pub c1: SignedProof,
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

/// A dealer's exact contribution, as Ready reports and rosters name it. It binds the public statements of the
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
    pub(crate) fn blobs(&self) -> Vec<BlobRef> {
        match self {
            Self::EncryptionKey(message) => vec![message.key, message.proof.proof.data],
            Self::Shares(message) => {
                let proofs = [&message.c2a, &message.c2b]
                    .into_iter()
                    .chain(&message.c3a)
                    .chain(&message.c3b)
                    .map(|signed| signed.proof.data);
                [message.pk_share, message.shares]
                    .into_iter()
                    .chain(proofs)
                    .collect()
            }
            Self::Ready(_) | Self::Roster(_) => Vec::new(),
            Self::DecryptionKey(message) => [&message.c4a]
                .into_iter()
                .chain(&message.c4b)
                .map(|signed| signed.proof.data)
                .collect(),
            Self::Keyshare(message) => vec![message.pk_share, message.c1.proof.data],
            Self::NodeFold(message) => vec![message.fold.proof.data],
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
    /// encrypted shares. Every other member's slot but the dealer's own is encrypted under
    /// `own_key` and proved, and that member never receives it.
    MakeShares {
        dealer: Address,
        committee: Vec<Address>,
        own_key: BlobRef,
        keys: BTreeMap<Address, BlobRef>,
    },
    /// Check what `dealer` sent this node: decrypt the shares with this node's secret key and
    /// check them against their C2 and C3 proofs. Each C3 must name this node's key, as this
    /// node's C0 proof `own_key` commits to it.
    CheckShares {
        dealer: Address,
        committee: Vec<Address>,
        secret: BlobRef,
        own_key: ZkProof,
        message: Box<SharesMessage>,
    },
    /// This node's decryption key, the sum of the roster dealers' shares for it, and its C4
    /// proofs. `shares` holds the encrypted shares of every roster dealer but this node, which
    /// uses `own_share`; `c2` holds every roster dealer's C2a and C2b proofs, which C4 binds.
    MakeDecryptionKey {
        member: Address,
        committee: Vec<Address>,
        secret: BlobRef,
        own_share: BlobRef,
        shares: BTreeMap<Address, BlobRef>,
        c2: BTreeMap<Address, (ZkProof, ZkProof)>,
    },
    /// Check a roster member's C4 proofs against the roster dealers' C2 proofs.
    CheckDecryptionKey {
        member: Address,
        committee: Vec<Address>,
        c2: BTreeMap<Address, (ZkProof, ZkProof)>,
        message: Box<DecryptionKeyMessage>,
    },
    /// Fold this node's DKG proofs into one recursive proof.
    FoldProofs {
        member: Address,
        committee: Vec<Address>,
        proofs: Box<DkgProofs>,
    },
    /// Check a roster member's C1 proof against its public-key share.
    CheckKeyshare {
        member: Address,
        committee: Vec<Address>,
        keyshare: Box<KeyshareMessage>,
    },
    /// Sum the roster's public-key shares into the committee key, prove C5, and combine the
    /// roster members' folds. Keyshares and folds come in roster order.
    AggregateKey {
        committee: Vec<Address>,
        roster: Vec<Address>,
        keyshares: Vec<KeyshareMessage>,
        folds: Vec<NodeFold>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DkgWorkResult {
    EncryptionKeyMade(OwnKey),
    EncryptionKeyChecked { sender: Address, verdict: Verdict },
    SharesMade(OwnShares),
    SharesChecked { dealer: Address, verdict: Verdict },
    DecryptionKeyMade(OwnDecryptionKey),
    DecryptionKeyChecked { member: Address, verdict: Verdict },
    ProofsFolded(NodeFold),
    KeyshareChecked { member: Address, verdict: Verdict },
    KeyAggregated(AggregatedKey),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatedKey {
    pub public_key: BlobRef,
    pub commitment: B256,
    pub proof: ZkProof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DkgSignature {
    EncryptionKeyProof,
    /// C1, C2a, C2b, then each delivered recipient's C3a and C3b proofs, recipients ascending.
    DealerProofs,
    /// C4a, then each C4b proof.
    DecryptionKeyProofs,
    FoldAttestation,
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
    /// Every other member's shares and their C3 proofs.
    pub recipients: BTreeMap<Address, RecipientShares>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnDecryptionKey {
    /// The summed secret-key and smudging-noise shares, sealed in the job runner's blob store,
    /// for decryption.
    pub key: BlobRef,
    pub c4a: ZkProof,
    pub c4b: Vec<ZkProof>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientShares {
    /// None for a member without a valid key: C3 still proves its slot, encrypted under the
    /// dealer's own key, and the member receives nothing.
    pub shares: Option<BlobRef>,
    /// One proof per share row.
    pub c3a: Vec<ZkProof>,
    pub c3b: Vec<ZkProof>,
}

/// A member's own DKG proofs, which its node fold combines.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgProofs {
    pub c0: ZkProof,
    pub c1: ZkProof,
    pub c2a: ZkProof,
    pub c2b: ZkProof,
    /// Every other member's C3a proofs, one per share row.
    pub c3a: BTreeMap<Address, Vec<ZkProof>>,
    /// Every other member's C3b proofs, one per share row.
    pub c3b: BTreeMap<Address, Vec<ZkProof>>,
    pub c4a: ZkProof,
    /// One proof per smudging-noise set.
    pub c4b: Vec<ZkProof>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DkgFailure {
    /// The committee was finalized after the key cutoff, so this node's key could not count.
    StartedAfterKeyCutoff,
    /// Fewer than H valid keys, this node's included, by the key cutoff.
    TooFewKeys,
    /// The chain expelled this node from the committee.
    Expelled,
    /// The chain expelled a roster member before the key was published. The key needs every
    /// roster dealer, so the DKG cannot finish.
    RosterMemberExpelled,
    /// T or fewer roster members have a valid decryption key, too few to ever decrypt.
    TooFewValidDecryptionKeys,
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
    /// Shares sent: collecting shares, Ready reports, and a roster.
    Dealt(OwnKey, Box<Dealt>),
    MakingDecryptionKey(Box<Dealt>),
    SigningDecryptionKey(Box<Dealt>, Box<OwnDecryptionKey>),
    /// C4 sent: the keyshare waits for every other roster member's C4 verdict.
    DecryptionKeySent(Box<Dealt>),
    KeyshareSent,
    /// Outside the roster: this node only checks the roster members' C4 proofs.
    Observing,
    Failed(DkgFailure),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dkg {
    e3: E3Id,
    me: Address,
    /// The finalized committee, ascending by address; a party's ID is its index.
    members: Vec<Address>,
    params: CryptoParams,
    timing: DkgTiming,
    attestation: AttestationContext,
    expelled: BTreeSet<Address>,
    keys: Keys,
    shares: Shares,
    /// The latest Ready report of each member, this node's included.
    ready: BTreeMap<Address, Vec<Dealer>>,
    rosters: Rosters,
    decryption_keys: DecryptionKeys,
    fold: OwnFold,
    aggregation: Aggregation,
    phase: Phase,
    /// This node's sealed decryption key, once made. The chain's key over the same roster needs it
    /// even when this node's DKG failed locally, as when the deadline passes before the node reads
    /// the key's publication.
    sealed_key: Option<BlobRef>,
    /// The chain published the committee key: the DKG is over.
    published: bool,
}

impl Dkg {
    pub(crate) fn start(
        e3: E3Id,
        me: Address,
        members: Vec<Address>,
        params: CryptoParams,
        timing: DkgTiming,
        attestation: AttestationContext,
        now: UnixSecs,
    ) -> (Self, Vec<Effect>) {
        let mut dkg = Self {
            e3,
            me,
            members,
            params,
            timing,
            attestation,
            expelled: BTreeSet::new(),
            keys: Keys::default(),
            shares: Shares::default(),
            ready: BTreeMap::new(),
            rosters: Rosters::default(),
            decryption_keys: DecryptionKeys::default(),
            fold: OwnFold::NotStarted,
            aggregation: Aggregation::default(),
            phase: Phase::MakingKey,
            sealed_key: None,
            published: false,
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
        self.running() && !self.collecting_keys()
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

    pub fn published(&self) -> bool {
        self.published
    }

    pub(crate) fn members(&self) -> &[Address] {
        &self.members
    }

    pub(crate) fn expelled(&self) -> &BTreeSet<Address> {
        &self.expelled
    }

    /// This node's sealed decryption key, once it sent its keyshare.
    pub(crate) fn decryption_key(&self) -> Option<BlobRef> {
        self.sealed_key
    }

    pub(crate) fn key_published(&mut self) {
        self.published = true;
    }

    pub(crate) fn receive(
        &mut self,
        now: UnixSecs,
        sender: Address,
        message: DkgMessage,
    ) -> Vec<Effect> {
        if !self.running() {
            return Vec::new();
        }
        let admitted = self.admits(sender, &message);
        let mut effects = match message {
            _ if !admitted => Vec::new(),
            DkgMessage::EncryptionKey(message) => self.receive_key(sender, message),
            DkgMessage::Shares(message) => self.receive_shares(sender, *message),
            DkgMessage::Ready(dealers) => {
                self.receive_ready(sender, dealers);
                Vec::new()
            }
            DkgMessage::Roster(dealers) => {
                self.receive_roster(sender, dealers);
                Vec::new()
            }
            DkgMessage::DecryptionKey(message) => self.receive_decryption_key(sender, message),
            DkgMessage::Keyshare(message) => {
                self.receive_keyshare(sender, message);
                Vec::new()
            }
            DkgMessage::NodeFold(message) => {
                self.receive_fold(sender, message);
                Vec::new()
            }
        };
        effects.extend(self.advance(now));
        effects
    }

    /// Whether this node takes `message` from `sender` now; it can tell before it fetches any blob
    /// the message names.
    pub(crate) fn admits(&self, sender: Address, message: &DkgMessage) -> bool {
        self.running()
            && match message {
                DkgMessage::EncryptionKey(message) => self.admits_key(sender, message),
                DkgMessage::Shares(message) => self.admits_shares(sender, message),
                DkgMessage::Ready(dealers) => self.admits_ready(sender, dealers),
                DkgMessage::Roster(dealers) => self.admits_roster(sender, dealers),
                DkgMessage::DecryptionKey(message) => self.admits_decryption_key(sender, message),
                DkgMessage::Keyshare(message) => self.admits_keyshare(sender, message),
                DkgMessage::NodeFold(message) => self.admits_fold(sender, message),
            }
    }

    pub(crate) fn job_done(&mut self, now: UnixSecs, result: DkgWorkResult) -> Vec<Effect> {
        if !self.running() {
            return Vec::new();
        }
        let mut effects = match result {
            DkgWorkResult::EncryptionKeyMade(own) => self.key_made(own),
            DkgWorkResult::EncryptionKeyChecked { sender, verdict } => {
                self.key_checked(sender, verdict.is_valid())
            }
            DkgWorkResult::SharesMade(made) => self.shares_made(made),
            DkgWorkResult::SharesChecked { dealer, verdict } => {
                self.shares_checked(dealer, verdict.is_valid())
            }
            DkgWorkResult::DecryptionKeyMade(made) => self.decryption_key_made(made),
            DkgWorkResult::DecryptionKeyChecked { member, verdict } => {
                self.decryption_key_checked(member, verdict.is_valid())
            }
            DkgWorkResult::ProofsFolded(fold) => self.proofs_folded(fold),
            DkgWorkResult::KeyshareChecked { member, verdict } => {
                self.keyshare_checked(member, verdict.is_valid());
                Vec::new()
            }
            DkgWorkResult::KeyAggregated(key) => self.key_aggregated(key),
        };
        effects.extend(self.advance(now));
        effects
    }

    pub(crate) fn signed(
        &mut self,
        now: UnixSecs,
        purpose: DkgSignature,
        signatures: Vec<Bytes>,
    ) -> Vec<Effect> {
        if !self.running() {
            return Vec::new();
        }
        let mut effects = match purpose {
            DkgSignature::EncryptionKeyProof => self.key_signed(signatures),
            DkgSignature::DealerProofs => self.shares_signed(signatures),
            DkgSignature::DecryptionKeyProofs => self.decryption_key_signed(signatures),
            DkgSignature::FoldAttestation => self.fold_signed(signatures),
        };
        effects.extend(self.advance(now));
        effects
    }

    pub(crate) fn expel(&mut self, now: UnixSecs, member: Address) -> Vec<Effect> {
        if !self.running() || !self.is_member(member) || !self.expelled.insert(member) {
            return Vec::new();
        }
        if member == self.me {
            self.phase = Phase::Failed(DkgFailure::Expelled);
            return Vec::new();
        }
        if self
            .roster()
            .is_some_and(|roster| roster.iter().any(|d| d.member == member))
        {
            self.phase = Phase::Failed(DkgFailure::RosterMemberExpelled);
            return Vec::new();
        }
        let mut effects = self.close_keys_if_all_in();
        effects.extend(self.send_ready_if_due());
        effects.extend(self.pass_roster_deadlines(now));
        effects.extend(self.pass_aggregation_deadlines(now));
        effects
    }

    pub(crate) fn pass_deadlines(&mut self, now: UnixSecs) -> Vec<Effect> {
        if !self.running() {
            return Vec::new();
        }
        let mut effects = Vec::new();
        if self.collecting_keys() && now >= self.timing.key_cutoff() {
            effects.extend(self.close_keys_at_cutoff());
        }
        if !self.shares.checkpoint_passed && now >= self.timing.share_checkpoint() {
            self.shares.checkpoint_passed = true;
            effects.extend(self.send_ready_if_due());
        }
        effects.extend(self.pass_roster_deadlines(now));
        effects.extend(self.pass_aggregation_deadlines(now));
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
        [
            key_cutoff,
            checkpoint,
            self.roster_deadline(),
            self.aggregation_deadline(),
            Some(self.timing.deadline),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Until the DKG fails or the chain publishes the key.
    pub(crate) fn running(&self) -> bool {
        !self.published && !matches!(self.phase, Phase::Failed(_))
    }

    /// Every input ends here, since any of them can complete a roster or an aggregation.
    fn advance(&mut self, now: UnixSecs) -> Vec<Effect> {
        let mut effects = self.advance_roster(now);
        effects.extend(self.advance_aggregation(now));
        effects
    }

    fn party_id(&self, member: Address) -> Option<u64> {
        let index = self.members.binary_search(&member).ok()?;
        Some(index as u64)
    }

    fn h(&self) -> usize {
        self.params.committee_size.values().h
    }

    fn t(&self) -> usize {
        self.params.committee_size.values().threshold
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
            params: self.params,
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

    /// The proof that `member` signed and sent this node, for an accusation of it.
    pub(crate) fn signed_proof(&self, member: Address, proof: &ZkProof) -> Option<SignedProof> {
        let key = self.keys.received.get(&member).map(|key| &key.proof);
        let shares = self
            .shares
            .received
            .get(&member)
            .into_iter()
            .flat_map(|shares| {
                [&shares.c2a, &shares.c2b]
                    .into_iter()
                    .chain(&shares.c3a)
                    .chain(&shares.c3b)
            });
        let decryption_key = self
            .decryption_keys
            .received
            .get(&member)
            .into_iter()
            .flat_map(|key| std::iter::once(&key.c4a).chain(&key.c4b));
        let keyshare = self
            .aggregation
            .keyshares
            .get(&member)
            .map(|keyshare| &keyshare.c1);
        key.into_iter()
            .chain(shares)
            .chain(decryption_key)
            .chain(keyshare)
            .find(|signed| signed.proof == *proof)
            .cloned()
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
