// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The whole node as one machine: admission of E3s from chain facts, routing of peer messages,
//! jobs and signatures, and the end of each E3's work.

pub use crate::e3::E3;

use crate::{
    accusation::{
        AccusationMessage, AccusationWork, AccusationWorkResult, Ballot, SignedVote, Slashing,
    },
    decryption::{
        DecryptionMessage, DecryptionSignature, DecryptionWork, DecryptionWorkResult,
        PlaintextPublication,
    },
    dkg::{
        AttestationContext, DkgFailure, DkgMessage, DkgSignature, DkgTiming, DkgWork,
        DkgWorkResult, KeyAnchor, KeyPublication,
    },
    proof::{ProofType, ZkProof},
    registry::Registry,
    selection::{candidate_owners, candidates, Eligible},
    BlobRef, E3Id, Machine, Tick, UnixSecs,
};
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use e3_committee::CiphernodesCommitteeSize;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// A failed E3 that may still see accusations keeps its work for this long after the failure,
/// plus the chain's maximum vote validity: longer than the DKG and decryption windows in which
/// peers can still accuse, plus five minutes for votes.
const SLASHABLE_FAILURE_GRACE: UnixSecs = 24 * 60 * 60 + 5 * 60;

/// How many ended E3s the node remembers, to drop late peer messages for them.
const ENDED_MEMORY: usize = 1_024;

/// Where a chain fact sits in its chain's confirmed log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LogPosition {
    pub chain_id: u64,
    pub block: u64,
    pub log_index: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Stage {
    Requested,
    CommitteeFinalized,
    KeyPublished,
    CiphertextReady,
    Complete,
    Failed,
}

/// The contract's `FailureReason`, in declaration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FailureReason {
    None,
    CommitteeFormationTimeout,
    InsufficientCommitteeMembers,
    DkgTimeout,
    DkgInvalidShares,
    NoInputsReceived,
    ComputeTimeout,
    ComputeProviderExpired,
    ComputeProviderFailed,
    RequesterCancelled,
    DecryptionTimeout,
    DecryptionInvalidShares,
    VerificationFailed,
}

impl FailureReason {
    /// A deadline passed or the request was withdrawn; no peer acted against the protocol, so no
    /// accusation can follow.
    fn ends_without_slashing(self) -> bool {
        matches!(
            self,
            Self::CommitteeFormationTimeout
                | Self::DkgTimeout
                | Self::ComputeTimeout
                | Self::DecryptionTimeout
                | Self::NoInputsReceived
                | Self::ComputeProviderExpired
                | Self::ComputeProviderFailed
                | Self::RequesterCancelled
        )
    }
}

/// What a request fixed for its E3's cryptography. Every job gets it: the job runner maps the
/// contract's parameter set to BFV parameters and derives the error size from them and the
/// committee size; the seed is the E3's shared randomness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoParams {
    pub param_set: u8,
    pub committee_size: CiphernodesCommitteeSize,
    pub seed: B256,
}

/// What a request froze for forming its committee: the registry's selection inputs (and
/// `CommitteeBondOwnerCapEnabled` when the same transaction emits it), and the DKG window the
/// Interfold contract gives the committee.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeRequest {
    /// T, the request's timestamp (the contracts call it `requestBlock`); selection reads the
    /// registry at T−1.
    pub time: UnixSecs,
    pub ticket_price: U256,
    /// The contract keeps one candidate per request-time bond owner.
    pub owner_cap: bool,
    pub dkg_window: UnixSecs,
}

/// The registry accepted a request's randomness: the committee seed, and the deadline by which
/// tickets must arrive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeSeed {
    pub seed: U256,
    pub deadline: UnixSecs,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainFact {
    /// `interfold` is the contract that emitted `E3Requested`. The chain adapter takes
    /// `attestation` and the owner cap from logs of the same transaction, and delivers no request
    /// whose crypto configuration this node does not support. `committee_deadline` is the
    /// registry's: the randomness deadline until it accepts randomness. `seed` is set when the
    /// registry already accepted it: a provider can fulfill inside the request's own transaction,
    /// before `E3Requested`.
    E3Requested {
        e3: E3Id,
        params: CryptoParams,
        interfold: Address,
        attestation: AttestationContext,
        request: CommitteeRequest,
        committee_deadline: UnixSecs,
        seed: Option<U256>,
    },
    /// The registry accepted the request's randomness.
    SeedReady {
        e3: E3Id,
        seed: CommitteeSeed,
    },
    CommitteeFinalized {
        e3: E3Id,
        members: Vec<Address>,
        dkg: DkgTiming,
    },
    /// `CommitteeProofPublished`: the registry's committee in its order, the roster (the selected
    /// party IDs that the proof's public inputs carry), and the key commitment.
    KeyPublished {
        e3: E3Id,
        committee: Vec<Address>,
        roster: Vec<Address>,
        commitment: B256,
        /// The deadline for the ciphertext.
        compute_deadline: UnixSecs,
        /// Each roster member's key commitments, from the proof's public inputs.
        anchors: BTreeMap<Address, KeyAnchor>,
    },
    /// `CiphertextOutputReferencePublished`: where the ciphertext's bytes are, and the decryption
    /// deadline.
    CiphertextReady {
        e3: E3Id,
        ciphertext: DataRef,
        deadline: UnixSecs,
    },
    StageChanged {
        e3: E3Id,
        stage: Stage,
    },
    /// `E3FailureProcessed`: the chain settled a failed E3's payment.
    FailureSettled {
        e3: E3Id,
    },
    /// `E3DependenciesReleased`: governance closed the E3 in its slashing manager, which then takes
    /// no more accusations or appeals about it.
    DependenciesReleased {
        e3: E3Id,
    },
    Failed {
        e3: E3Id,
        reason: FailureReason,
    },
    /// The chain slashed a committee member and removed it from the E3.
    MemberExpelled {
        e3: E3Id,
        member: Address,
    },
    /// The chain's maximum accusation vote validity, in seconds.
    VoteValidity {
        secs: u64,
    },
    /// A randomness provider the registry uses: a request is bound to one, and governance can set
    /// another.
    RandomnessProvider {
        provider: Address,
    },
    /// A slashing manager the Interfold contract uses: governance can set another, and an E3 keeps
    /// the one of its request.
    SlashingManager {
        manager: Address,
    },
    /// `OperatorActivationChanged`.
    OperatorActive {
        operator: Address,
        active: bool,
    },
    /// `TicketBalanceUpdated`.
    TicketBalance {
        operator: Address,
        balance: U256,
    },
    /// `BondOwnerSet`.
    BondOwner {
        operator: Address,
        owner: Address,
    },
    /// A new eligibility configuration: every operator is inactive until it refreshes.
    EligibilityReset,
    /// `CiphernodeAdded` or `CiphernodeRemoved`: whether the ciphernode registry lists the
    /// operator, without which it takes no ticket.
    OperatorEnabled {
        operator: Address,
        enabled: bool,
    },
}

/// Bytes the chain names by their Keccak-256 hash and an availability layer holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataRef {
    pub hash: B256,
    /// The availability layer's block and blob leaf that hold the bytes.
    pub block: u32,
    pub leaf: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainEvent {
    pub at: LogPosition,
    /// The block's timestamp.
    pub time: UnixSecs,
    pub fact: ChainFact,
}

/// A message between committee members. On receipt, the network edge has already recovered
/// `sender` from the envelope signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerMessage {
    pub e3: E3Id,
    pub sender: Address,
    pub body: Body,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Body {
    Dkg(DkgMessage),
    Decryption(DecryptionMessage),
    Accusation(AccusationMessage),
}

/// What a message is, whatever it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Kind {
    EncryptionKey,
    Shares,
    Ready,
    Roster,
    DecryptionKey,
    Keyshare,
    NodeFold,
    DecryptionShares,
    Accusation,
    Vote,
}

impl Body {
    pub fn kind(&self) -> Kind {
        match self {
            Body::Dkg(DkgMessage::EncryptionKey(_)) => Kind::EncryptionKey,
            Body::Dkg(DkgMessage::Shares(_)) => Kind::Shares,
            Body::Dkg(DkgMessage::Ready(_)) => Kind::Ready,
            Body::Dkg(DkgMessage::Roster(_)) => Kind::Roster,
            Body::Dkg(DkgMessage::DecryptionKey(_)) => Kind::DecryptionKey,
            Body::Dkg(DkgMessage::Keyshare(_)) => Kind::Keyshare,
            Body::Dkg(DkgMessage::NodeFold(_)) => Kind::NodeFold,
            Body::Decryption(DecryptionMessage::Shares(_)) => Kind::DecryptionShares,
            Body::Accusation(AccusationMessage::Accuse { .. }) => Kind::Accusation,
            Body::Accusation(AccusationMessage::Vote(_)) => Kind::Vote,
        }
    }
}

/// The blobs one message may name. A peer that names more only makes work: each entry costs a
/// signature check when the message is admitted, and a fetch and a verification after that.
pub const MAX_MESSAGE_BLOBS: usize = 128;

impl PeerMessage {
    /// Whether `node` uses this message: a share message only reaches its recipient's DKG.
    pub fn is_for(&self, node: Address) -> bool {
        match &self.body {
            Body::Dkg(DkgMessage::Shares(shares)) => shares.recipient == node,
            _ => true,
        }
    }

    /// The blobs a node that uses this message needs in its store.
    pub fn blobs(&self) -> Vec<BlobRef> {
        match &self.body {
            Body::Dkg(message) => message.blobs(),
            Body::Decryption(message) => message.blobs(),
            Body::Accusation(message) => message.blobs(),
        }
    }

    /// The same for every copy and re-send of the message.
    pub fn id(&self) -> B256 {
        keccak256(bincode::serialize(self).expect("a peer message encodes"))
    }

    /// Its encoded bytes and the bytes of the blobs it would bring.
    fn size(&self) -> u64 {
        let encoded = bincode::serialized_size(self).unwrap_or(u64::MAX);
        self.blobs()
            .iter()
            .fold(encoded, |size, blob| size.saturating_add(blob.len))
    }
}

/// Work for the job runner. Its result returns as [`Input::Job`] and is journaled before anything
/// uses it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    pub e3: E3Id,
    pub params: CryptoParams,
    pub work: Work,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Work {
    Dkg(DkgWork),
    Decryption(DecryptionWork),
    Accusation(AccusationWork),
}

impl Work {
    /// Whether the job makes proofs, which can hold the machine for hours. The checks that a
    /// deadline waits on must not queue behind them.
    pub fn proves(&self) -> bool {
        matches!(
            self,
            Work::Dkg(
                DkgWork::MakeEncryptionKey
                    | DkgWork::MakeShares { .. }
                    | DkgWork::MakeDecryptionKey { .. }
                    | DkgWork::FoldProofs { .. }
                    | DkgWork::FoldRoster { .. }
                    | DkgWork::AggregateKey { .. }
            ) | Work::Decryption(
                DecryptionWork::MakeShares { .. } | DecryptionWork::AggregatePlaintext { .. }
            )
        )
    }

    /// Whether the job checks a proof a member signed, which can end in an accusation.
    fn checks_a_member(&self) -> bool {
        matches!(
            self,
            Work::Dkg(
                DkgWork::CheckEncryptionKey { .. }
                    | DkgWork::CheckShares { .. }
                    | DkgWork::CheckDecryptionKey { .. }
                    | DkgWork::CheckKeyshare { .. }
            ) | Work::Decryption(DecryptionWork::CheckShares { .. })
                | Work::Accusation(_)
        )
    }

    /// The kind of work, for logs.
    pub fn name(&self) -> &'static str {
        match self {
            Work::Dkg(DkgWork::MakeEncryptionKey) => "dkg: make the encryption key",
            Work::Dkg(DkgWork::CheckEncryptionKey { .. }) => "dkg: check an encryption key",
            Work::Dkg(DkgWork::MakeShares { .. }) => "dkg: deal shares",
            Work::Dkg(DkgWork::CheckShares { .. }) => "dkg: check a dealer's shares",
            Work::Dkg(DkgWork::MakeDecryptionKey { .. }) => "dkg: make the decryption key",
            Work::Dkg(DkgWork::CheckDecryptionKey { .. }) => "dkg: check a decryption key",
            Work::Dkg(DkgWork::FoldProofs { .. }) => "dkg: fold this node's proofs",
            Work::Dkg(DkgWork::CheckKeyshare { .. }) => "dkg: check a keyshare",
            Work::Dkg(DkgWork::FoldRoster { .. }) => "dkg: fold a roster member's proof",
            Work::Dkg(DkgWork::AggregateKey { .. }) => "dkg: aggregate the committee key",
            Work::Decryption(_) => "decryption",
            Work::Accusation(_) => "accusation: verify a proof",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobDone {
    pub e3: E3Id,
    pub result: WorkResult,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkResult {
    Dkg(DkgWorkResult),
    Decryption(DecryptionWorkResult),
    Accusation(AccusationWorkResult),
}

impl WorkResult {
    /// Whether this answers a job for which [`Work::checks_a_member`] holds.
    pub(crate) fn answers_a_check(&self) -> bool {
        matches!(
            self,
            Self::Dkg(
                DkgWorkResult::EncryptionKeyChecked { .. }
                    | DkgWorkResult::SharesChecked { .. }
                    | DkgWorkResult::DecryptionKeyChecked { .. }
                    | DkgWorkResult::KeyshareChecked { .. }
            ) | Self::Decryption(DecryptionWorkResult::SharesChecked { .. })
                | Self::Accusation(_)
        )
    }
}

/// Hashes for the operator key to sign. The signatures return in the same order as
/// [`Input::Signed`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signing {
    pub e3: E3Id,
    pub purpose: Purpose,
    pub hashes: Vec<B256>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Purpose {
    Dkg(DkgSignature),
    Decryption(DecryptionSignature),
    /// This node's vote in an accusation's window.
    Accusation(Ballot),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    pub e3: E3Id,
    pub purpose: Purpose,
    pub signatures: Vec<Bytes>,
}

/// Bytes for the fetcher to copy from their availability layer into the blob store, checked
/// against their hash. The blob returns as [`Input::Fetched`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fetch {
    pub e3: E3Id,
    pub data: DataRef,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fetched {
    pub e3: E3Id,
    pub blob: BlobRef,
}

/// Which of `operators` the bonding registry finds eligible at `at`, which only it can say: an
/// owner's admission cooldown and pause apply, and under a required identity policy so does its
/// credential. The answer returns as [`Input::Eligibility`]; one after `by` comes too late to
/// rank with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EligibilityRead {
    pub e3: E3Id,
    pub operators: Vec<Address>,
    pub at: UnixSecs,
    pub by: UnixSecs,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Eligibility {
    pub e3: E3Id,
    /// None when the read failed.
    pub eligible: Option<BTreeSet<Address>>,
}

/// A fetch of a peer message's blobs came back with nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchFailed {
    pub e3: E3Id,
    pub sender: Address,
    pub kind: Kind,
    pub id: B256,
    pub attempt: u32,
}

/// The blobs of `message` to bring into the store, from the peers that sent it. `attempt` counts
/// this node's tries at this message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobFetch {
    pub message: PeerMessage,
    pub attempt: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Input {
    Chain(ChainEvent),
    /// A peer's message as gossip announced it; the blobs it names may not be in the store.
    Announced(PeerMessage),
    /// A peer's message whose blobs are in the store.
    Peer(PeerMessage),
    FetchFailed(FetchFailed),
    Job(JobDone),
    Signed(Signed),
    Fetched(Fetched),
    /// Wakes the machine at its next deadline. Every input first applies the deadlines that have
    /// passed, so a late wake-up changes nothing.
    Tick,
    Eligibility(Eligibility),
}

impl From<Tick> for Input {
    fn from(_: Tick) -> Self {
        Input::Tick
    }
}

/// A transaction for the chain writer, which checks chain state before it submits and retries
/// temporary failures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Submission {
    pub e3: E3Id,
    pub transaction: Transaction,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transaction {
    /// `publishCommittee`, then the key's chunks. Another aggregator's equal commitment completes
    /// it.
    PublishCommittee(KeyPublication),
    /// `publishPlaintextOutput`. Another aggregator's plaintext on chain completes it.
    PublishPlaintext(PlaintextPublication),
    /// This node's ticket for the committee.
    SubmitTicket { ticket: u64 },
    /// `finalizeCommittee`, after the committee deadline.
    FinalizeCommittee,
    /// `markE3Failed`, once the E3's stage stalled past its deadline.
    MarkFailed,
    /// `processE3Failure`: refunds a failed E3's requester and pays its honest members.
    SettleFailure,
    /// `proposeSlash` at `manager`, with the votes of H members that `proof`, which `accused`
    /// signed, fails. Another voter's proposal completes it.
    ProposeSlash {
        manager: Address,
        accused: Address,
        proof_type: ProofType,
        proof: ZkProof,
        votes: Vec<SignedVote>,
    },
}

/// What an operator would want to read about a step the node took. Only steps the node admitted
/// make notes, so a flood of refused messages writes nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    pub e3: E3Id,
    pub event: Noted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Noted {
    /// The DKG stopped at this node, with the members it still waited for.
    DkgFailed {
        failure: DkgFailure,
        missing: Vec<Address>,
    },
    /// A member named the dealers whose shares it verified: `reports` of the committee have.
    Ready {
        reporter: Address,
        dealers: usize,
        reports: usize,
        committee: usize,
    },
    RosterAccepted {
        proposer: Address,
        dealers: Vec<Address>,
    },
    /// A proof that `member` signed fails.
    ProofFailed {
        member: Address,
        proof_type: ProofType,
    },
}

impl Noted {
    /// Whether the operator should look at it.
    pub fn is_warning(&self) -> bool {
        matches!(self, Noted::DkgFailed { .. } | Noted::ProofFailed { .. })
    }
}

impl std::fmt::Display for Noted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Noted::DkgFailed { failure, missing } if missing.is_empty() => {
                write!(f, "the DKG failed here: {failure:?}")
            }
            Noted::DkgFailed { failure, missing } => {
                let missing: Vec<String> = missing.iter().map(ToString::to_string).collect();
                write!(
                    f,
                    "the DKG failed here: {failure:?}, waiting for {}",
                    missing.join(", ")
                )
            }
            Noted::Ready {
                reporter,
                dealers,
                reports,
                committee,
            } => write!(
                f,
                "{reporter} verified {dealers} dealers; {reports} of {committee} members reported"
            ),
            Noted::RosterAccepted { proposer, dealers } => {
                let dealers: Vec<String> = dealers.iter().map(ToString::to_string).collect();
                write!(f, "roster from {proposer}: {}", dealers.join(", "))
            }
            Noted::ProofFailed { member, proof_type } => {
                write!(f, "{member} signed a failing {proof_type:?} proof")
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    Run(Job),
    Sign(Signing),
    Gossip(PeerMessage),
    Submit(Submission),
    Fetch(Fetch),
    /// The message comes back as `Input::Peer` once its blobs are there, and as
    /// `Input::FetchFailed` if they did not come.
    FetchBlobs(BlobFetch),
    ReadEligibility(EligibilityRead),
    Note(Note),
}

impl Effect {
    pub fn e3(&self) -> E3Id {
        match self {
            Effect::Run(job) => job.e3,
            Effect::Sign(signing) => signing.e3,
            Effect::Gossip(message) => message.e3,
            Effect::FetchBlobs(fetch) => fetch.message.e3,
            Effect::Submit(submission) => submission.e3,
            Effect::Fetch(fetch) => fetch.e3,
            Effect::ReadEligibility(read) => read.e3,
            Effect::Note(note) => note.e3,
        }
    }

    /// What the effect's life depends on.
    pub fn scope(&self) -> Scope {
        match self {
            // A check of what a member signed is owed even after the DKG is over: a bad proof is
            // still an accusation.
            Effect::Run(job) if job.work.checks_a_member() => Scope::Held,
            Effect::Run(job) => match job.work {
                Work::Dkg(_) => Scope::Dkg,
                Work::Decryption(_) => Scope::Live,
                Work::Accusation(_) => Scope::Held,
            },
            Effect::Sign(signing) => match signing.purpose {
                Purpose::Dkg(_) => Scope::Dkg,
                Purpose::Decryption(_) => Scope::Live,
                Purpose::Accusation(_) => Scope::Held,
            },
            Effect::Gossip(PeerMessage { body, .. })
            | Effect::FetchBlobs(BlobFetch {
                message: PeerMessage { body, .. },
                ..
            }) => match body {
                Body::Dkg(_) => Scope::Dkg,
                Body::Decryption(_) => Scope::Live,
                Body::Accusation(_) => Scope::Held,
            },
            // A key's publication stays live after the chain logs it: the commitment lands first,
            // and the key's chunks follow it.
            Effect::Submit(submission) => match submission.transaction {
                Transaction::MarkFailed
                | Transaction::SettleFailure
                | Transaction::ProposeSlash { .. } => Scope::Held,
                _ => Scope::Live,
            },
            Effect::Fetch(_) | Effect::ReadEligibility(_) => Scope::Live,
            Effect::Note(_) => Scope::Held,
        }
    }
}

/// How long an effect is owed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// While the DKG runs: until the chain publishes the key, or the DKG fails here.
    Dkg,
    /// Until the chain fails or completes the E3.
    Live,
    /// While the node holds the E3: accusations and failure settlement go on after it fails.
    Held,
}

/// What the node does with a peer's message when the network announces it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Classified {
    /// It cannot use the message, which costs nothing more: it is not journaled.
    Drop,
    /// It could use the message later, and the hold has no room for it: a share is full. Not
    /// journaled; the sender's re-send brings it again.
    Full,
    /// It waits for the chain fact that lets the node judge it.
    Hold,
    /// The node uses it once its blobs are here.
    Fetch,
    /// The node uses it now.
    Deliver,
}

/// Who the network deals with, as the chain has told this node so far.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Admission {
    /// Every operator a chain's registry named: the senders whose messages the network takes.
    pub senders: BTreeSet<Address>,
    /// The members of each E3's committee, for the E3s this node is on: only they may read its
    /// blobs. A member the chain expelled reads no more.
    pub committees: BTreeMap<E3Id, BTreeSet<Address>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    me: Address,
    e3s: BTreeMap<E3Id, E3>,
    /// Each chain's operator registry over time.
    registries: BTreeMap<u64, Registry>,
    held: Hold,
    ended: VecDeque<E3Id>,
    applied: BTreeMap<u64, LogPosition>,
    vote_validity: BTreeMap<u64, u64>,
    /// Each chain's randomness providers and slashing managers, so the chain adapter reads their
    /// logs after a restart too.
    providers: BTreeMap<u64, BTreeSet<Address>>,
    managers: BTreeMap<u64, BTreeSet<Address>>,
    /// Each chain's current slashing manager, which a request now snapshots.
    slashing: BTreeMap<u64, Address>,
}

impl Node {
    pub fn new(me: Address) -> Self {
        Self {
            me,
            e3s: BTreeMap::new(),
            registries: BTreeMap::new(),
            held: Hold::default(),
            ended: VecDeque::new(),
            applied: BTreeMap::new(),
            vote_validity: BTreeMap::new(),
            providers: BTreeMap::new(),
            managers: BTreeMap::new(),
            slashing: BTreeMap::new(),
        }
    }

    pub fn randomness_providers(&self, chain_id: u64) -> impl Iterator<Item = &Address> {
        self.providers.get(&chain_id).into_iter().flatten()
    }

    pub fn slashing_managers(&self, chain_id: u64) -> impl Iterator<Item = &Address> {
        self.managers.get(&chain_id).into_iter().flatten()
    }

    /// Who the network deals with now.
    pub fn admission(&self) -> Admission {
        Admission {
            senders: self
                .registries
                .values()
                .flat_map(Registry::operators)
                .collect(),
            committees: self
                .e3s
                .iter()
                .filter(|(_, state)| !state.committee().is_empty())
                .map(|(e3, state)| (*e3, state.committee().clone()))
                .collect(),
        }
    }

    /// Every E3 the node holds, each until it ends, with the key share of an E3 it dealt in.
    pub fn held(&self) -> impl Iterator<Item = &E3Id> {
        self.e3s.keys()
    }

    /// The E3s whose DKG or decryption work still needs their blobs.
    pub fn working(&self) -> impl Iterator<Item = &E3Id> {
        let working = self.e3s.iter().filter(|(_, state)| state.has_work());
        working.map(|(e3, _)| e3)
    }

    pub fn e3(&self, e3: &E3Id) -> Option<&E3> {
        self.e3s.get(e3)
    }

    /// Whether this node's operator is active on `chain_id` now, and listed by its registry.
    pub fn standing(&self, chain_id: u64) -> (bool, bool) {
        self.registries
            .get(&chain_id)
            .map_or((false, false), |registry| registry.standing(self.me))
    }

    /// Whether the node still owes an effect of `e3` with this `scope`.
    pub fn owes(&self, e3: &E3Id, scope: Scope) -> bool {
        self.e3s.get(e3).is_some_and(|state| match scope {
            Scope::Held => true,
            Scope::Live => state.running(),
            Scope::Dkg => state.running() && state.dkg_running(),
        })
    }

    /// The position of the last fact this node applied from chain `chain_id`.
    pub fn applied(&self, chain_id: u64) -> Option<LogPosition> {
        self.applied.get(&chain_id).copied()
    }

    fn apply_chain(&mut self, now: UnixSecs, event: ChainEvent) -> Vec<Effect> {
        // The chain adapter delivers each chain's confirmed log in order; a position at or before
        // the last applied one is a re-read of the same history.
        if self
            .applied
            .get(&event.at.chain_id)
            .is_some_and(|last| event.at <= *last)
        {
            return Vec::new();
        }
        self.applied.insert(event.at.chain_id, event.at);
        let (chain_id, time) = (event.at.chain_id, event.time);
        let registry = self.registries.entry(chain_id).or_default();
        match event.fact {
            ChainFact::E3Requested {
                e3,
                params,
                interfold,
                attestation,
                request,
                committee_deadline,
                seed,
            } => {
                if !self.e3s.contains_key(&e3) && !self.ended.contains(&e3) {
                    let slot = request_slot(registry, self.me, &request);
                    // The request snapshots the Interfold's slashing manager and the registry's
                    // vote validity of now.
                    let slashing = self.slashing.get(&chain_id).map(|manager| Slashing {
                        manager: *manager,
                        validity: self
                            .vote_validity
                            .get(&chain_id)
                            .copied()
                            .unwrap_or_default(),
                    });
                    let state = E3::new(
                        e3,
                        self.me,
                        params,
                        interfold,
                        attestation,
                        request,
                        committee_deadline,
                        slot,
                        slashing,
                    );
                    self.e3s.insert(e3, state);
                }
                match seed {
                    Some(seed) => self.select(
                        now,
                        e3,
                        CommitteeSeed {
                            seed,
                            deadline: committee_deadline,
                        },
                    ),
                    None => Vec::new(),
                }
            }
            ChainFact::SeedReady { e3, seed } => self.select(now, e3, seed),
            ChainFact::OperatorActive { operator, active } => {
                registry.set_active(time, operator, active);
                self.select_again_if_me(now, operator)
            }
            ChainFact::TicketBalance { operator, balance } => {
                registry.set_balance(time, operator, balance);
                Vec::new()
            }
            ChainFact::BondOwner { operator, owner } => {
                registry.set_owner(time, operator, owner);
                Vec::new()
            }
            ChainFact::EligibilityReset => {
                registry.reset_activity(time);
                Vec::new()
            }
            ChainFact::OperatorEnabled { operator, enabled } => {
                registry.set_enabled(operator, enabled);
                self.select_again_if_me(now, operator)
            }
            ChainFact::CommitteeFinalized {
                e3,
                mut members,
                dkg,
            } => {
                members.sort();
                members.dedup();
                if members.binary_search(&self.me).is_err() {
                    self.end(e3);
                    return Vec::new();
                }
                let Some(state) = self.e3s.get_mut(&e3) else {
                    return Vec::new();
                };
                let mut effects = state.finalize(now, members, dkg);
                effects.extend(self.release_held(now, e3));
                effects
            }
            ChainFact::KeyPublished {
                e3,
                committee,
                roster,
                commitment,
                compute_deadline,
                anchors,
            } => {
                if let Some(state) = self.e3s.get_mut(&e3) {
                    state.key_published(committee, roster, commitment, compute_deadline, anchors);
                }
                self.release_held(now, e3)
            }
            ChainFact::CiphertextReady {
                e3,
                ciphertext,
                deadline,
            } => match self.e3s.get_mut(&e3) {
                Some(state) => state.ciphertext_ready(now, ciphertext, deadline),
                None => Vec::new(),
            },
            ChainFact::StageChanged { e3, stage } => {
                match (stage, self.e3s.get_mut(&e3)) {
                    (Stage::Complete, Some(state)) => match state.stays_after_completion(now) {
                        true => state.advance(stage),
                        false => self.end(e3),
                    },
                    (Stage::Complete, None) => {}
                    (stage, Some(state)) => state.advance(stage),
                    (_, None) => {}
                }
                Vec::new()
            }
            ChainFact::Failed { e3, reason } => {
                let vote_validity = self
                    .vote_validity
                    .get(&event.at.chain_id)
                    .copied()
                    .unwrap_or_default();
                let accusable = match reason.ends_without_slashing() {
                    true => 0,
                    false => SLASHABLE_FAILURE_GRACE + vote_validity,
                };
                if let Some(state) = self.e3s.get_mut(&e3) {
                    state.failed(event.time, event.time + accusable);
                }
                Vec::new()
            }
            ChainFact::FailureSettled { e3 } => {
                if let Some(state) = self.e3s.get_mut(&e3) {
                    state.settled();
                }
                Vec::new()
            }
            ChainFact::DependenciesReleased { e3 } => {
                if let Some(state) = self.e3s.get_mut(&e3) {
                    state.released();
                }
                Vec::new()
            }
            ChainFact::MemberExpelled { e3, member } => match self.e3s.get_mut(&e3) {
                Some(state) => state.expel(now, member),
                None => Vec::new(),
            },
            ChainFact::VoteValidity { secs } => {
                self.vote_validity.insert(event.at.chain_id, secs);
                Vec::new()
            }
            ChainFact::RandomnessProvider { provider } => {
                let providers = self.providers.entry(event.at.chain_id).or_default();
                providers.insert(provider);
                Vec::new()
            }
            ChainFact::SlashingManager { manager } => {
                let managers = self.managers.entry(event.at.chain_id).or_default();
                managers.insert(manager);
                self.slashing.insert(event.at.chain_id, manager);
                Vec::new()
            }
        }
    }

    /// The registry accepted the request's randomness. An owner-capped request first asks the
    /// bonding registry which operators may hold a seat, while there is time for the read and for
    /// a ticket after it.
    fn select(&mut self, now: UnixSecs, e3: E3Id, seed: CommitteeSeed) -> Vec<Effect> {
        let Some(state) = self.e3s.get_mut(&e3) else {
            return Vec::new();
        };
        state.seeded(seed);
        let request = state.request;
        let by = (now + ELIGIBILITY_READ).min(seed.deadline.saturating_sub(TICKET_RESERVE));
        if request.owner_cap && now < by && state.ticket().is_none() {
            if !state.await_eligibility(seed, by) {
                return Vec::new();
            }
            let registry = self.registries.entry(e3.chain_id).or_default();
            let operators = submitters(registry, &request)
                .into_iter()
                .map(|operator| operator.operator)
                .collect();
            let read = EligibilityRead {
                e3,
                operators,
                at: request.time.saturating_sub(1),
                by,
            };
            return vec![Effect::ReadEligibility(read)];
        }
        self.rank(now, e3, seed, None)
    }

    /// This node's registry standing changed: a request it could not take a ticket in can have
    /// room for it now, until its deadline. Others ranked it without this node, so it asks no
    /// shortlist and the contract decides.
    fn select_again_if_me(&mut self, now: UnixSecs, operator: Address) -> Vec<Effect> {
        if operator != self.me {
            return Vec::new();
        }
        let open: Vec<(E3Id, CommitteeSeed)> = self
            .e3s
            .iter()
            .filter(|(_, state)| state.ticket().is_none())
            .filter_map(|(e3, state)| Some((*e3, state.seed()?)))
            .collect();
        open.into_iter()
            .flat_map(|(e3, seed)| self.rank(now, e3, seed, None))
            .collect()
    }

    /// Rank the request's candidates from the registry at T−1 and submit this node's ticket if it
    /// is one of them, before the committee deadline. Only the operators in `confirmed` keep the
    /// owner shortlist; without that answer the node ranks every eligible operator, and the
    /// contract rejects the others. A node takes at most as many E3s at once as it has tickets.
    fn rank(
        &mut self,
        now: UnixSecs,
        e3: E3Id,
        seed: CommitteeSeed,
        confirmed: Option<&BTreeSet<Address>>,
    ) -> Vec<Effect> {
        let CommitteeSeed {
            seed,
            deadline: committee_deadline,
        } = seed;
        let active_jobs = self
            .e3s
            .values()
            .filter(|state| state.ticket().is_some() && state.running())
            .count() as u64;
        let Some(state) = self.e3s.get(&e3) else {
            return Vec::new();
        };
        if state.ticket().is_some() || now >= committee_deadline || state.stage != Stage::Requested
        {
            return Vec::new();
        }
        let request = state.request;
        let registry = self.registries.entry(e3.chain_id).or_default();
        let mut eligible = submitters(registry, &request);
        if let Some(confirmed) = confirmed {
            eligible.retain(|operator| confirmed.contains(&operator.operator));
        }
        let owner_cap = request.owner_cap && confirmed.is_some();
        let committee = state.params.committee_size.values();
        let owners = candidate_owners(committee.n, committee.threshold);
        let ranked = candidates(e3, seed, &eligible, owner_cap, owners);
        let tickets = eligible
            .iter()
            .find(|operator| operator.operator == self.me)
            .map_or(0, |operator| operator.tickets);
        let Some((rank, mine)) = ranked
            .iter()
            .enumerate()
            .find(|(_, candidate)| candidate.operator == self.me)
        else {
            return Vec::new();
        };
        if active_jobs >= tickets {
            return Vec::new();
        }
        let ticket = mine.ticket;
        match self.e3s.get_mut(&e3) {
            Some(state) => state.submit_ticket(ticket, rank, committee_deadline),
            None => Vec::new(),
        }
    }

    fn end(&mut self, e3: E3Id) {
        if self.e3s.remove(&e3).is_none() {
            return;
        }
        self.held.take(&e3);
        self.ended.push_back(e3);
        if self.ended.len() > ENDED_MEMORY {
            self.ended.pop_front();
        }
    }

    /// The one admission rule for what the network announces. It only reads, so the node can call
    /// it before the journal, and what it drops costs no durable record. A message waits in the
    /// bounded hold until the chain fact that lets the node judge it: the committee's finalization
    /// for the DKG, the key's publication for decryption. Blobs are fetched only once the E3 admits
    /// the message, so a sender outside the committee costs no download.
    pub fn classify(&self, now: UnixSecs, message: &PeerMessage) -> Classified {
        if self.ended.contains(&message.e3)
            || !message.is_for(self.me)
            || message.blobs().len() > MAX_MESSAGE_BLOBS
        {
            return Classified::Drop;
        }
        match self.e3s.get(&message.e3) {
            Some(state) if state.routes(&message.body) => state.classify(now, message),
            _ if self.held.holds(message) => Classified::Drop,
            _ if self.held.has_room(message) => Classified::Hold,
            _ => Classified::Full,
        }
    }

    fn apply_announced(&mut self, now: UnixSecs, message: PeerMessage) -> Vec<Effect> {
        match self.classify(now, &message) {
            Classified::Drop | Classified::Full => Vec::new(),
            Classified::Hold => {
                self.held.hold(now, message);
                Vec::new()
            }
            Classified::Deliver => self
                .e3s
                .get_mut(&message.e3)
                .map_or_else(Vec::new, |state| state.receive(now, message)),
            Classified::Fetch => self
                .e3s
                .get_mut(&message.e3)
                .map_or_else(Vec::new, |state| vec![state.start_fetch(message)]),
        }
    }

    fn apply_peer(&mut self, now: UnixSecs, message: PeerMessage) -> Vec<Effect> {
        if !message.is_for(self.me) {
            return Vec::new();
        }
        match self.e3s.get_mut(&message.e3) {
            Some(state) if state.routes(&message.body) => state.receive(now, message),
            _ => Vec::new(),
        }
    }

    fn release_held(&mut self, now: UnixSecs, e3: E3Id) -> Vec<Effect> {
        let held = self.held.take(&e3);
        held.into_iter()
            .flat_map(|message| self.apply_announced(now, message))
            .collect()
    }

    fn apply_job(&mut self, now: UnixSecs, done: JobDone) -> Vec<Effect> {
        match self.e3s.get_mut(&done.e3) {
            Some(state) => state.job_done(now, done.result),
            None => Vec::new(),
        }
    }

    fn apply_signed(&mut self, now: UnixSecs, signed: Signed) -> Vec<Effect> {
        match self.e3s.get_mut(&signed.e3) {
            Some(state) => state.signed(now, signed.purpose, signed.signatures),
            None => Vec::new(),
        }
    }

    /// A check of a member's proof that goes out is one its E3 waits for.
    fn count_checks(&mut self, effects: &[Effect]) {
        for effect in effects {
            if let Effect::Run(job) = effect {
                if job.work.checks_a_member() {
                    if let Some(state) = self.e3s.get_mut(&job.e3) {
                        state.check_started();
                    }
                }
            }
        }
    }

    fn pass_deadlines(&mut self, now: UnixSecs) -> Vec<Effect> {
        self.held.pass_deadlines(now);
        let mut effects: Vec<Effect> = self
            .e3s
            .values_mut()
            .flat_map(|state| state.pass_deadlines(now))
            .collect();
        let unanswered: Vec<(E3Id, CommitteeSeed)> = self
            .e3s
            .iter_mut()
            .filter_map(|(e3, state)| state.unanswered(now).map(|seed| (*e3, seed)))
            .collect();
        for (e3, seed) in unanswered {
            effects.extend(self.rank(now, e3, seed, None));
        }
        let due: Vec<E3Id> = self
            .e3s
            .iter()
            .filter(|(_, state)| state.ends_at().is_some_and(|at| at <= now))
            .map(|(e3, _)| *e3)
            .collect();
        for e3 in due {
            self.end(e3);
        }
        effects
    }
}

/// How long an eligibility read may take, and the time it leaves before the ticket deadline for
/// the ticket's transaction: about a block, plus clock skew.
const ELIGIBILITY_READ: UnixSecs = 20;
const TICKET_RESERVE: UnixSecs = 20;

/// This node's place among the operators eligible for `request`, in address order: the order in
/// which they mark it failed while no committee exists.
fn request_slot(registry: &Registry, me: Address, request: &CommitteeRequest) -> Option<u64> {
    let at = request.time.saturating_sub(1);
    registry
        .eligible_at(at, request.ticket_price)
        .iter()
        .position(|eligible| eligible.operator == me)
        .map(|slot| slot as u64)
}

/// The operators that can take a seat of `request`: eligible when it was made, and able to submit
/// a ticket now.
fn submitters(registry: &Registry, request: &CommitteeRequest) -> Vec<Eligible> {
    let mut eligible = registry.eligible_at(request.time.saturating_sub(1), request.ticket_price);
    eligible.retain(|operator| registry.can_submit(operator.operator));
    eligible
}

impl Machine for Node {
    type Input = Input;
    type Effect = Effect;

    fn step(&mut self, now: UnixSecs, input: Input) -> Vec<Effect> {
        // Counted now: the input may complete the E3, which must see these checks.
        let deadlines = self.pass_deadlines(now);
        self.count_checks(&deadlines);
        let mut effects = deadlines;
        let applied = match input {
            Input::Chain(event) => self.apply_chain(now, event),
            Input::Announced(message) => self.apply_announced(now, message),
            Input::Peer(message) => self.apply_peer(now, message),
            Input::FetchFailed(failed) => {
                if let Some(state) = self.e3s.get_mut(&failed.e3) {
                    state.fetch_failed(&failed);
                }
                Vec::new()
            }
            Input::Job(done) => self.apply_job(now, done),
            Input::Signed(signed) => self.apply_signed(now, signed),
            Input::Fetched(fetched) => match self.e3s.get_mut(&fetched.e3) {
                Some(state) => state.fetched(now, fetched.blob),
                None => Vec::new(),
            },
            Input::Tick => Vec::new(),
            Input::Eligibility(answer) => match self.e3s.get_mut(&answer.e3).and_then(E3::answered)
            {
                Some(seed) => self.rank(now, answer.e3, seed, answer.eligible.as_ref()),
                None => Vec::new(),
            },
        };
        self.count_checks(&applied);
        effects.extend(applied);
        effects
    }

    fn next_deadline(&self) -> Option<UnixSecs> {
        let e3s = self.e3s.values().filter_map(E3::next_deadline);
        e3s.chain(self.held.next_deadline()).min()
    }
}

/// Peer messages that wait for a chain fact, in arrival order. A message that would pass its
/// sender's, its E3's, or the node's share is refused, so no sender can push out another's: the
/// sender's re-send brings it again. A message that waits too long goes, so stale ones cannot
/// hold the room.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Hold {
    messages: VecDeque<Held>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Held {
    message: PeerMessage,
    expires: UnixSecs,
}

const HOLD_FOR: UnixSecs = 10 * 60;
const HOLD_PER_SENDER_MESSAGES: usize = 64;
const HOLD_PER_SENDER_BYTES: u64 = 128 * 1024 * 1024;
const HOLD_PER_E3_MESSAGES: usize = 512;
const HOLD_PER_E3_BYTES: u64 = 128 * 1024 * 1024;
const HOLD_TOTAL_MESSAGES: usize = 1_024;
const HOLD_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

impl Hold {
    /// Whether a copy of `message` waits here already: its re-sends cost nothing.
    fn holds(&self, message: &PeerMessage) -> bool {
        self.messages.iter().any(|held| held.message == *message)
    }

    /// Whether every share `message` would count against has room for it.
    fn has_room(&self, message: &PeerMessage) -> bool {
        let size = message.size();
        let sender = self.usage(|held| held.sender == message.sender);
        let e3 = self.usage(|held| held.e3 == message.e3);
        let total = self.usage(|_| true);
        sender.fits(HOLD_PER_SENDER_MESSAGES, HOLD_PER_SENDER_BYTES, size)
            && e3.fits(HOLD_PER_E3_MESSAGES, HOLD_PER_E3_BYTES, size)
            && total.fits(HOLD_TOTAL_MESSAGES, HOLD_TOTAL_BYTES, size)
    }

    fn hold(&mut self, now: UnixSecs, message: PeerMessage) {
        self.messages.push_back(Held {
            message,
            expires: now.saturating_add(HOLD_FOR),
        });
    }

    fn take(&mut self, e3: &E3Id) -> Vec<PeerMessage> {
        let (taken, kept): (VecDeque<_>, VecDeque<_>) = self
            .messages
            .drain(..)
            .partition(|held| &held.message.e3 == e3);
        self.messages = kept;
        taken.into_iter().map(|held| held.message).collect()
    }

    fn pass_deadlines(&mut self, now: UnixSecs) {
        self.messages.retain(|held| now < held.expires);
    }

    fn next_deadline(&self) -> Option<UnixSecs> {
        self.messages.iter().map(|held| held.expires).min()
    }

    fn usage(&self, counts: impl Fn(&PeerMessage) -> bool) -> Usage {
        self.messages
            .iter()
            .filter(|held| counts(&held.message))
            .fold(Usage::default(), |usage, held| Usage {
                messages: usage.messages + 1,
                bytes: usage.bytes + held.message.size(),
            })
    }
}

#[derive(Default)]
struct Usage {
    messages: usize,
    bytes: u64,
}

impl Usage {
    fn fits(&self, max_messages: usize, max_bytes: u64, incoming: u64) -> bool {
        self.messages < max_messages && self.bytes.saturating_add(incoming) <= max_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{dkg::DkgProofs, testing::*};

    fn node() -> Node {
        Node::new(address(ME))
    }

    fn members(operators: impl IntoIterator<Item = u64>) -> Vec<Address> {
        operators.into_iter().chain([ME]).map(address).collect()
    }

    /// Operators active from timestamp 0 with `balance` tokens (tickets at one token each), each
    /// its own bond owner.
    fn registered(node: &mut Node, operators: &[u64], balance: u64) {
        for (index, operator) in operators.iter().enumerate() {
            let facts = [
                ChainFact::OperatorActive {
                    operator: address(*operator),
                    active: true,
                },
                ChainFact::TicketBalance {
                    operator: address(*operator),
                    balance: U256::from(balance),
                },
                ChainFact::BondOwner {
                    operator: address(*operator),
                    owner: address(*operator),
                },
                ChainFact::OperatorEnabled {
                    operator: address(*operator),
                    enabled: true,
                },
            ];
            for (offset, fact) in facts.into_iter().enumerate() {
                let at = LogPosition {
                    chain_id: 1,
                    block: 0,
                    log_index: (4 * index + offset) as u64,
                };
                node.step(0, Input::Chain(ChainEvent { at, time: 0, fact }));
            }
        }
    }

    /// A request at timestamp `time`, so selection reads the registry at `time - 1`.
    fn requested_at(block: u64, e3: E3Id, time: UnixSecs) -> Input {
        chain(
            block,
            ChainFact::E3Requested {
                e3,
                params: params(e3_committee::CiphernodesCommitteeSize::Minimum),
                interfold: INTERFOLD,
                attestation: ATTESTATION,
                request: CommitteeRequest { time, ..REQUEST },
                committee_deadline: COMMITTEE_DEADLINE,
                seed: None,
            },
        )
    }

    /// An owner-capped request at timestamp `time`.
    fn capped_requested_at(block: u64, e3: E3Id, time: UnixSecs) -> Input {
        chain(
            block,
            ChainFact::E3Requested {
                e3,
                params: params(e3_committee::CiphernodesCommitteeSize::Minimum),
                interfold: INTERFOLD,
                attestation: ATTESTATION,
                request: CommitteeRequest {
                    time,
                    owner_cap: true,
                    ..REQUEST
                },
                committee_deadline: COMMITTEE_DEADLINE,
                seed: None,
            },
        )
    }

    fn committee_seed(seed: u64, deadline: UnixSecs) -> CommitteeSeed {
        CommitteeSeed {
            seed: U256::from(seed),
            deadline,
        }
    }

    fn seed_ready(block: u64, e3: E3Id, seed: u64, deadline: UnixSecs) -> Input {
        chain(
            block,
            ChainFact::SeedReady {
                e3,
                seed: committee_seed(seed, deadline),
            },
        )
    }

    fn failure(block: u64, e3: E3Id, reason: FailureReason) -> Input {
        chain(block, ChainFact::Failed { e3, reason })
    }

    /// This node's place among `operators` in address order, which is its party ID in a
    /// committee of them.
    fn place(operators: &[u64]) -> u64 {
        let mut addresses: Vec<Address> = operators.iter().copied().map(address).collect();
        addresses.sort();
        let place = addresses
            .iter()
            .position(|operator| *operator == address(ME));
        place.expect("this node is one of them") as u64
    }

    fn submissions(effects: &[Effect]) -> Vec<Transaction> {
        effects
            .iter()
            .filter_map(|effect| match effect {
                Effect::Submit(submission) => Some(submission.transaction.clone()),
                _ => None,
            })
            .collect()
    }

    /// This node's rank and best ticket among `operators` for `seed`, as every node ranks them.
    fn rank(operators: &[u64], seed: u64, owner_cap: bool) -> Option<(usize, u64)> {
        let eligible: Vec<Eligible> = operators
            .iter()
            .map(|operator| Eligible {
                operator: address(*operator),
                tickets: 10,
                owner: Some(address(*operator)),
            })
            .collect();
        let owners = candidate_owners(3, 1);
        let ranked = candidates(e3(1), U256::from(seed), &eligible, owner_cap, owners);
        ranked
            .iter()
            .enumerate()
            .find(|(_, candidate)| candidate.operator == address(ME))
            .map(|(rank, candidate)| (rank, candidate.ticket))
    }

    /// Blobs go to the committee of an E3 this node is on, from the step the chain names it.
    #[test]
    fn the_admission_names_the_committee_of_an_e3_this_node_is_on() {
        let mut node = node();
        registered(&mut node, &[1], 1);
        node.step(1, requested(1, e3(1)));
        node.step(1, requested(2, e3(2)));
        assert_eq!(node.admission().senders, [address(1)].into());
        assert!(node.admission().committees.is_empty());

        node.step(3, finalized(3, e3(1), members([1, 2])));
        node.step(4, finalized(4, e3(2), vec![address(1), address(2)]));
        let committee: BTreeSet<Address> = members([1, 2]).into_iter().collect();
        assert_eq!(
            node.admission().committees,
            [(e3(1), committee.clone())].into()
        );

        let expelled = ChainFact::MemberExpelled {
            e3: e3(1),
            member: address(2),
        };
        node.step(5, chain(5, expelled));
        let left = committee.into_iter().filter(|m| *m != address(2)).collect();
        assert_eq!(node.admission().committees, [(e3(1), left)].into());
    }

    #[test]
    fn a_selected_node_submits_its_best_ticket_before_the_committee_deadline() {
        let mut node = node();
        registered(&mut node, &[1, 2, ME], 10);
        node.step(1, requested(1, e3(1)));
        let effects = node.step(5, seed_ready(5, e3(1), 42, 100));
        let (_, ticket) = rank(&[1, 2, ME], 42, false).unwrap();
        assert_eq!(
            submissions(&effects),
            vec![Transaction::SubmitTicket { ticket }]
        );
    }

    #[test]
    fn a_request_whose_randomness_came_in_its_own_transaction_selects_at_once() {
        let mut node = node();
        registered(&mut node, &[1, 2, ME], 10);
        let Input::Chain(mut request) = requested(1, e3(1)) else {
            unreachable!("a request is a chain fact")
        };
        if let ChainFact::E3Requested { seed, .. } = &mut request.fact {
            *seed = Some(U256::from(42));
        }
        let effects = node.step(5, Input::Chain(request));
        let (_, ticket) = rank(&[1, 2, ME], 42, false).unwrap();
        assert_eq!(
            submissions(&effects),
            vec![Transaction::SubmitTicket { ticket }]
        );
        assert!(submissions(&node.step(6, seed_ready(6, e3(1), 42, 100))).is_empty());
    }

    #[test]
    fn a_node_inactive_at_the_request_submits_nothing() {
        let mut node = node();
        registered(&mut node, &[1, 2, ME], 10);
        node.step(1, chain(1, ChainFact::EligibilityReset));
        node.step(3, requested_at(3, e3(1), 3));
        assert!(submissions(&node.step(5, seed_ready(5, e3(1), 42, 100))).is_empty());
    }

    #[test]
    fn a_change_in_the_request_s_own_block_does_not_count() {
        let mut node = node();
        registered(&mut node, &[1, 2], 10);
        let activation = LogPosition {
            chain_id: 1,
            block: 3,
            log_index: 0,
        };
        let facts = [
            ChainFact::OperatorActive {
                operator: address(ME),
                active: true,
            },
            ChainFact::TicketBalance {
                operator: address(ME),
                balance: U256::from(10),
            },
            ChainFact::BondOwner {
                operator: address(ME),
                owner: address(ME),
            },
            ChainFact::OperatorEnabled {
                operator: address(ME),
                enabled: true,
            },
        ];
        for (log_index, fact) in (1..).zip(facts) {
            let at = LogPosition {
                log_index,
                ..activation
            };
            node.step(3, Input::Chain(ChainEvent { at, time: 3, fact }));
        }
        let request = LogPosition {
            log_index: 9,
            ..activation
        };
        let fact = match requested_at(3, e3(1), 3) {
            Input::Chain(event) => event.fact,
            _ => unreachable!(),
        };
        node.step(
            3,
            Input::Chain(ChainEvent {
                at: request,
                time: 3,
                fact,
            }),
        );
        assert!(submissions(&node.step(5, seed_ready(5, e3(1), 42, 100))).is_empty());
    }

    #[test]
    fn a_seed_after_the_committee_deadline_submits_nothing() {
        let mut node = node();
        registered(&mut node, &[1, 2, ME], 10);
        node.step(1, requested(1, e3(1)));
        assert!(submissions(&node.step(100, seed_ready(5, e3(1), 42, 100))).is_empty());
    }

    #[test]
    fn a_node_takes_at_most_as_many_e3s_at_once_as_it_has_tickets() {
        let mut node = node();
        registered(&mut node, &[1, 2, ME], 1);
        node.step(1, requested(1, e3(1)));
        node.step(1, requested(2, e3(2)));
        assert_eq!(
            submissions(&node.step(5, seed_ready(5, e3(1), 42, 100))).len(),
            1
        );
        assert!(submissions(&node.step(5, seed_ready(6, e3(2), 42, 100))).is_empty());
    }

    #[test]
    fn the_finalizer_calls_after_the_deadline_staggered_by_rank() {
        let seed = (0..1_000)
            .find(|seed| rank(&[1, 2, ME], *seed, false).is_some_and(|(rank, _)| rank > 0))
            .expect("a seed that ranks this node after another");
        let mut node = node();
        registered(&mut node, &[1, 2, ME], 10);
        node.step(1, requested(1, e3(1)));
        node.step(5, seed_ready(5, e3(1), seed, 100));
        let (rank, _) = rank(&[1, 2, ME], seed, false).unwrap();
        let due = 100 + 1 + 30 * rank as u64;
        assert_eq!(node.next_deadline(), Some(due));
        assert!(submissions(&node.step(due - 1, Input::Tick)).is_empty());
        let effects = node.step(due, Input::Tick);
        assert_eq!(submissions(&effects), vec![Transaction::FinalizeCommittee]);
        assert!(submissions(&node.step(due + 600, Input::Tick)).is_empty());
    }

    #[test]
    fn a_finalized_committee_stops_the_finalizer() {
        let mut node = node();
        registered(&mut node, &[1, 2, ME], 10);
        node.step(1, requested(1, e3(1)));
        node.step(5, seed_ready(5, e3(1), 42, 100));
        node.step(100, finalized(6, e3(1), members([1, 2])));
        assert!(submissions(&node.step(10_000, Input::Tick)).is_empty());
    }

    /// An owner-capped request whose seed leaves this node off the owner shortlist of all nine
    /// operators, and the effects of the seed.
    fn capped_request() -> (Node, Vec<Effect>) {
        let operators: Vec<u64> = (1..=8).chain([ME]).collect();
        let seed = (0..1_000)
            .find(|seed| rank(&operators, *seed, true).is_none())
            .expect("a seed that leaves this node off the owner shortlist");
        let mut node = node();
        registered(&mut node, &operators, 10);
        node.step(3, capped_requested_at(3, e3(1), 3));
        let effects = node.step(5, seed_ready(5, e3(1), seed, 100));
        (node, effects)
    }

    fn confirmed(operators: &[u64]) -> Input {
        Input::Eligibility(Eligibility {
            e3: e3(1),
            eligible: Some(operators.iter().copied().map(address).collect()),
        })
    }

    #[test]
    fn an_owner_capped_request_ranks_only_the_operators_the_bonding_registry_confirms() {
        let (mut node, effects) = capped_request();
        let reads: Vec<&EligibilityRead> = effects
            .iter()
            .filter_map(|effect| match effect {
                Effect::ReadEligibility(read) => Some(read),
                _ => None,
            })
            .collect();
        let [read] = reads.as_slice() else {
            panic!("one eligibility read: {effects:?}");
        };
        assert_eq!((read.at, read.by, read.operators.len()), (2, 25, 9));
        assert!(submissions(&effects).is_empty());
        assert_eq!(submissions(&node.step(6, confirmed(&[1, ME]))).len(), 1);

        let (mut node, _) = capped_request();
        assert!(submissions(&node.step(6, confirmed(&[1, 2]))).is_empty());
    }

    #[test]
    fn without_an_answer_in_time_the_node_ranks_every_eligible_operator() {
        let (mut node, _) = capped_request();
        assert!(submissions(&node.step(24, Input::Tick)).is_empty());
        assert_eq!(submissions(&node.step(25, Input::Tick)).len(), 1);
        assert!(submissions(&node.step(26, confirmed(&[]))).is_empty());
    }

    /// Every entry of a message costs a signature check, so the limit comes before them.
    #[test]
    fn a_message_that_names_too_many_blobs_is_dropped_unread() {
        let mut node = node();
        node.step(0, requested(10, e3(1)));
        let shares = DecryptionMessage::Shares(crate::decryption::SharesMessage {
            shares: vec![BlobRef::of(b"share"); MAX_MESSAGE_BLOBS + 1],
            c6: Vec::new(),
        });
        let message = PeerMessage {
            e3: e3(1),
            sender: address(1),
            body: Body::Decryption(shares),
        };
        assert_eq!(node.classify(1, &message), Classified::Drop);
    }

    /// A node that comes back while the eligibility read is out takes its turn: that read cannot
    /// name it, and no other event would bring it back.
    #[test]
    fn a_node_that_comes_back_during_the_eligibility_read_gets_its_ticket() {
        let mut node = node();
        registered(&mut node, &[1, 2, ME], 10);
        let standing = |active| ChainFact::OperatorActive {
            operator: address(ME),
            active,
        };
        node.step(2, chain(2, standing(false)));
        node.step(3, capped_requested_at(3, e3(1), 1));
        let effects = node.step(5, seed_ready(5, e3(1), 42, 100));
        assert!(submissions(&effects).is_empty());
        let effects = node.step(6, chain(6, standing(true)));
        assert!(matches!(
            submissions(&effects)[..],
            [Transaction::SubmitTicket { .. }]
        ));
        assert!(submissions(&node.step(7, confirmed(&[1, 2]))).is_empty());
    }

    /// An operator that is back before the deadline can still take its seat.
    #[test]
    fn a_node_that_comes_back_before_the_deadline_gets_its_ticket() {
        let mut node = node();
        registered(&mut node, &[1, 2, ME], 10);
        let away = ChainFact::OperatorActive {
            operator: address(ME),
            active: false,
        };
        node.step(2, chain(2, away));
        let inactive_later = ChainFact::OperatorActive {
            operator: address(ME),
            active: true,
        };
        node.step(3, requested_at(3, e3(1), 1));
        assert!(submissions(&node.step(5, seed_ready(5, e3(1), 42, 100))).is_empty());
        let effects = node.step(6, chain(6, inactive_later));
        assert!(matches!(
            submissions(&effects)[..],
            [Transaction::SubmitTicket { .. }]
        ));
    }

    /// A check of what a member signed outlives the DKG: a bad proof is still an accusation.
    #[test]
    fn a_check_of_a_member_s_proof_is_owed_after_the_key_is_published() {
        let check = Effect::Run(Job {
            e3: e3(1),
            params: params(e3_committee::CiphernodesCommitteeSize::Minimum),
            work: Work::Dkg(DkgWork::CheckEncryptionKey {
                sender: address(1),
                key: BlobRef::of(b"key"),
                proof: proof(1),
            }),
        });
        let mut node = node();
        node.step(0, requested(10, e3(1)));
        node.step(0, finalized(11, e3(1), members([1])));
        node.step(100, key_published(12, e3(1), members([1]), members([1])));
        assert!(owes(&node, &check));
    }

    /// The contract rejects the ticket of an operator governance removed, and of one no longer
    /// active, so neither takes a place among the candidates.
    #[test]
    fn an_operator_that_cannot_submit_is_no_candidate() {
        let mut node = node();
        registered(&mut node, &[1, 2, ME], 10);
        let removed = ChainFact::OperatorEnabled {
            operator: address(ME),
            enabled: false,
        };
        node.step(2, chain(2, removed));
        node.step(3, requested_at(3, e3(1), 3));
        assert!(submissions(&node.step(5, seed_ready(5, e3(1), 42, 100))).is_empty());
    }

    /// A node ranked past every turn still finalizes if the ones ahead of it stay silent: ranks
    /// count candidates, and they need not have submitted.
    #[test]
    fn a_rank_past_the_last_turn_shares_the_last_turn() {
        let operators: Vec<u64> = (1..=30).chain([ME]).collect();
        let seed = (0..1_000)
            .find(|seed| rank(&operators, *seed, false).is_some_and(|(rank, _)| rank >= 20))
            .expect("a seed that ranks this node past the twentieth");
        let mut node = node();
        registered(&mut node, &operators, 10);
        node.step(1, requested(1, e3(1)));
        node.step(5, seed_ready(5, e3(1), seed, 100));
        let last_turn = 100 + 1 + 30 * 19;
        assert!(submissions(&node.step(last_turn - 1, Input::Tick)).is_empty());
        let effects = node.step(last_turn, Input::Tick);
        assert_eq!(submissions(&effects), vec![Transaction::FinalizeCommittee]);
    }

    /// Nodes that restart together, long after a deadline, keep their spacing from when each
    /// found its turn past: the first still goes first and the others wait theirs.
    #[test]
    fn a_turn_found_long_past_counts_from_when_it_was_found() {
        let mut node = node();
        node.step(0, requested(10, e3(1)));
        node.step(0, finalized(11, e3(1), members([1, 2])));
        let place = place(&[1, 2, ME]);
        let restarted = TIMING.deadline + 1 + 30 * place + 3_600;
        let due = restarted + 1 + 30 * place;
        assert!(submissions(&node.step(restarted, Input::Tick)).is_empty());
        assert_eq!(node.next_deadline(), Some(due));
        assert!(submissions(&node.step(due - 1, Input::Tick)).is_empty());
        let effects = node.step(due, Input::Tick);
        assert_eq!(submissions(&effects), vec![Transaction::MarkFailed]);
        assert!(submissions(&node.step(due + 3_600, Input::Tick)).is_empty());
    }

    /// A second late restart, before the turn counted from the first came, spaces the turns again.
    #[test]
    fn a_turn_counted_from_a_late_restart_can_be_found_long_past_again() {
        let mut node = node();
        node.step(0, requested(10, e3(1)));
        node.step(0, finalized(11, e3(1), members([1, 2])));
        let place = place(&[1, 2, ME]);
        let first = TIMING.deadline + 1 + 30 * place + 3_600;
        node.step(first, Input::Tick);
        let second = first + 1 + 30 * place + 3_600;
        assert!(submissions(&node.step(second, Input::Tick)).is_empty());
        assert_eq!(node.next_deadline(), Some(second + 1 + 30 * place));
    }

    /// A node that wakes a little late for its turn takes it, rather than queueing again.
    #[test]
    fn a_turn_met_a_little_late_is_taken_at_once() {
        let mut node = node();
        node.step(0, requested(10, e3(1)));
        node.step(0, finalized(11, e3(1), members([1, 2])));
        let due = TIMING.deadline + 1 + 30 * place(&[1, 2, ME]);
        let effects = node.step(due + 10, Input::Tick);
        assert_eq!(submissions(&effects), vec![Transaction::MarkFailed]);
    }

    #[test]
    fn a_peer_message_never_creates_an_e3() {
        let mut node = node();
        node.step(0, key_from(e3(1), 1));
        assert!(node.e3(&e3(1)).is_none());
    }

    #[test]
    fn keys_announced_before_the_committee_is_known_are_fetched_once_it_is() {
        let mut node = node();
        node.step(0, announced(key_from(e3(1), 1)));
        node.step(0, requested(10, e3(1)));
        node.step(0, announced(key_from(e3(1), 2)));
        let effects = node.step(0, finalized(11, e3(1), members([1, 2])));
        assert_eq!(fetched_from(&effects), vec![address(1), address(2)]);
    }

    #[test]
    fn a_member_s_message_is_fetched_then_taken_once() {
        let mut node = node();
        node.step(0, requested(10, e3(1)));
        node.step(0, finalized(11, e3(1), members([1])));
        let key = key_from(e3(1), 1);
        let effects = node.step(0, announced(key.clone()));
        assert_eq!(fetched_from(&effects), vec![address(1)]);
        assert_eq!(key_checks(&node.step(0, key.clone())), vec![address(1)]);
        assert!(key_checks(&node.step(0, key.clone())).is_empty());
        assert!(node.step(0, announced(key)).is_empty());
    }

    /// A member that announces many messages makes the node fetch only its first of each kind.
    #[test]
    fn a_member_s_other_message_of_a_kind_waits_until_the_first_is_taken() {
        let mut node = node();
        node.step(0, requested(10, e3(1)));
        node.step(0, finalized(11, e3(1), members([1])));
        let first = key_from(e3(1), 1);
        let other = key(e3(1), 1, proof(2), 1);
        assert_eq!(
            fetched_from(&node.step(0, announced(first.clone()))),
            vec![address(1)]
        );
        assert!(node.step(0, announced(other.clone())).is_empty());
        assert!(node.step(60, announced(first.clone())).is_empty());
        assert_eq!(key_checks(&node.step(61, first)), vec![address(1)]);
        assert!(node.step(62, announced(other)).is_empty());
    }

    #[test]
    fn a_message_from_outside_the_committee_is_never_fetched() {
        let mut node = node();
        node.step(0, requested(10, e3(1)));
        node.step(0, finalized(11, e3(1), members([1])));
        assert!(node.step(0, announced(key_from(e3(1), 9))).is_empty());
    }

    #[test]
    fn a_full_e3_hold_keeps_what_it_has_and_refuses_the_newcomer() {
        let mut node = node();
        for n in 1..=513 {
            node.step(0, announced(key_from(e3(1), n)));
        }
        node.step(0, requested(10, e3(1)));
        let fetched = fetched_from(&node.step(0, finalized(11, e3(1), members(1..=513))));
        assert_eq!(fetched.len(), 512);
        assert!(!fetched.contains(&address(513)));
    }

    /// A full hold pushes out no other E3's messages.
    #[test]
    fn a_full_hold_refuses_a_newcomer_of_another_e3() {
        let mut node = node();
        for n in 1..=512 {
            node.step(0, announced(key_from(e3(1), n)));
            node.step(0, announced(key_from(e3(2), n)));
        }
        node.step(0, announced(key_from(e3(3), 1)));
        node.step(0, requested(10, e3(3)));
        assert!(fetched_from(&node.step(0, finalized(11, e3(3), members([1])))).is_empty());
        node.step(0, requested(12, e3(1)));
        let fetched = fetched_from(&node.step(0, finalized(13, e3(1), members(1..=512))));
        assert_eq!(fetched.len(), 512);
    }

    /// Copies of a held message are not journaled or held again.
    #[test]
    fn a_copy_of_a_held_message_is_dropped() {
        let mut node = node();
        let key = peer_message(key_from(e3(1), 1));
        assert_eq!(node.classify(0, &key), Classified::Hold);
        node.step(0, Input::Announced(key.clone()));
        assert_eq!(node.classify(0, &key), Classified::Drop);
    }

    /// One member cannot fill the hold: its share ends at its own messages.
    #[test]
    fn a_sender_over_its_share_of_the_hold_is_refused() {
        let mut node = node();
        for number in 1..=(HOLD_PER_SENDER_MESSAGES as u64 + 1) {
            node.step(0, announced(key_from(e3(number), 1)));
        }
        assert!(matches!(
            node.classify(0, &peer_message(key_from(e3(999), 1))),
            Classified::Full
        ));
        assert!(matches!(
            node.classify(0, &peer_message(key_from(e3(999), 2))),
            Classified::Hold
        ));
    }

    #[test]
    fn a_held_message_goes_when_it_waits_too_long() {
        let mut node = node();
        node.step(0, announced(key_from(e3(1), 1)));
        assert_eq!(node.next_deadline(), Some(HOLD_FOR));
        node.step(HOLD_FOR, Input::Tick);
        assert_eq!(node.next_deadline(), None);
        node.step(HOLD_FOR, requested(10, e3(1)));
        let effects = node.step(HOLD_FOR, finalized(11, e3(1), members([1])));
        assert!(fetched_from(&effects).is_empty());
    }

    fn peer_message(input: Input) -> PeerMessage {
        match input {
            Input::Peer(message) | Input::Announced(message) => message,
            other => panic!("not a peer message: {other:?}"),
        }
    }

    /// Copies of a message that is being fetched cost nothing: no effect, and no journal entry.
    #[test]
    fn a_copy_of_a_message_being_fetched_is_dropped_before_the_journal() {
        let mut node = node();
        node.step(0, requested(10, e3(1)));
        node.step(0, finalized(11, e3(1), members([1])));
        let key = key_from(e3(1), 1);
        assert_eq!(
            node.classify(0, &peer_message(key.clone())),
            Classified::Fetch
        );
        assert_eq!(fetched_from(&node.step(0, announced(key.clone()))).len(), 1);
        assert_eq!(
            node.classify(0, &peer_message(key.clone())),
            Classified::Drop
        );
        assert!(node.step(0, announced(key)).is_empty());
    }

    /// A failed fetch reopens exactly that attempt: the next copy tries again.
    #[test]
    fn a_failed_fetch_lets_the_next_copy_try_again() {
        let mut node = node();
        node.step(0, requested(10, e3(1)));
        node.step(0, finalized(11, e3(1), members([1])));
        let key = peer_message(key_from(e3(1), 1));
        let effects = node.step(0, Input::Announced(key.clone()));
        let [Effect::FetchBlobs(fetch)] = &effects[..] else {
            panic!("one fetch: {effects:?}");
        };
        assert_eq!(fetch.attempt, 0);
        let failed = |attempt| {
            Input::FetchFailed(FetchFailed {
                e3: e3(1),
                sender: key.sender,
                kind: key.body.kind(),
                id: key.id(),
                attempt,
            })
        };
        node.step(0, failed(7));
        assert_eq!(node.classify(0, &key), Classified::Drop, "another attempt");
        node.step(0, failed(0));
        assert_eq!(node.classify(0, &key), Classified::Fetch);
        let effects = node.step(0, Input::Announced(key.clone()));
        assert!(matches!(
            &effects[..],
            [Effect::FetchBlobs(BlobFetch { attempt: 1, .. })]
        ));
    }

    #[test]
    fn a_message_for_an_ended_e3_or_another_node_is_dropped() {
        let mut node = node();
        node.step(0, requested(10, e3(1)));
        node.step(
            0,
            chain(
                11,
                ChainFact::StageChanged {
                    e3: e3(1),
                    stage: Stage::Complete,
                },
            ),
        );
        assert_eq!(
            node.classify(0, &peer_message(key_from(e3(1), 1))),
            Classified::Drop
        );
        assert_eq!(
            node.classify(0, &peer_message(shares_from(e3(2), 1, 2))),
            Classified::Drop
        );
    }

    /// A sample of what the node journals and snapshots, through a DKG and a failure.
    #[test]
    fn the_persisted_encoding_is_the_one_its_version_names() {
        let mut node = node();
        let mut journal = Vec::new();
        let mut step = |input: Input| {
            journal.extend(bincode::serialize(&(30u64, &input)).unwrap());
            let effects = node.step(30, input);
            for effect in &effects {
                journal.extend(bincode::serialize(effect).unwrap());
            }
            effects
        };
        step(chain(
            2,
            ChainFact::SlashingManager {
                manager: address(9),
            },
        ));
        step(chain(3, ChainFact::VoteValidity { secs: 600 }));
        step(requested(10, e3(1)));
        step(finalized(11, e3(1), members([1, 2])));
        let effects = step(key_made(e3(1), own_key(0xee)));
        step(sign(ME, signing(&effects)));
        for n in [1, 2] {
            step(announced(key_from(e3(1), n)));
            step(key_from(e3(1), n));
            step(key_checked(e3(1), n, true));
        }
        // A dealer's shares for this node, and the check they start.
        step(shares_from(e3(1), 1, ME));
        let mut made = own_shares(&[1, 2]);
        made.recipients
            .get_mut(&address(2))
            .expect("a recipient")
            .shares = None;
        let effects = step(shares_made(e3(1), made));
        step(sign(ME, signing(&effects)));
        let effects = step(key_failed(e3(1), 1, B256::repeat_byte(0xd1)));
        step(sign(ME, signing(&effects)));
        step(Input::Job(JobDone {
            e3: e3(1),
            result: WorkResult::Accusation(AccusationWorkResult::Verified {
                proof_type: ProofType::C0PkBfv,
                proof: proof(2),
                fails: false,
                data_hash: B256::repeat_byte(0xd2),
            }),
        }));
        let anchor = |fill: u8| KeyAnchor {
            sk_agg_commit: B256::repeat_byte(fill),
            esm_agg_commit: B256::repeat_byte(!fill),
        };
        step(chain(
            12,
            ChainFact::KeyPublished {
                e3: e3(1),
                committee: members([1, 2]),
                roster: members([1, 2]),
                commitment: KEY_COMMITMENT,
                compute_deadline: COMPUTE_DEADLINE,
                anchors: [(address(1), anchor(0xa1)), (address(2), anchor(0xa2))].into(),
            },
        ));
        step(failure(20, e3(1), FailureReason::DkgInvalidShares));
        step(Input::Tick);
        journal.extend(bincode::serialize(&node).unwrap());
        // The fold's input, which this sample's DKG does not reach.
        let fold = DkgWork::FoldProofs {
            member: address(ME),
            committee: members([1, 2]),
            proofs: Box::new(DkgProofs {
                c0: proof(0xc0),
                c1: proof(0xc1),
                c2a: proof(0xca),
                c2b: proof(0xcb),
                c3a: [(address(1), vec![proof(0x3a)])].into(),
                c3b: [(address(1), vec![proof(0x3b)])].into(),
                c4a: proof(0x4a),
                c4b: vec![proof(0x4b)],
            }),
        };
        journal.extend(bincode::serialize(&fold).unwrap());
        // The eligibility read and its answer, which this sample's request does not need.
        let read = Effect::ReadEligibility(EligibilityRead {
            e3: e3(1),
            operators: vec![address(1)],
            at: 2,
            by: 25,
        });
        journal.extend(bincode::serialize(&read).unwrap());
        journal.extend(bincode::serialize(&confirmed(&[1])).unwrap());
        assert_eq!(
            (crate::ENCODING_VERSION, keccak256(&journal)),
            (
                14,
                alloy_primitives::b256!(
                    "a29eae0a7dc3eef8e59b9354512d8306c4bd2add4c15f16037b35b87bc64637c"
                )
            ),
            "the persisted encoding changed: bump ENCODING_VERSION, then this fingerprint"
        );
    }

    #[test]
    fn a_chain_fact_read_again_changes_nothing() {
        let mut node = node();
        node.step(0, requested(10, e3(1)));
        let finalization = finalized(11, e3(1), members([1]));
        node.step(0, finalization.clone());
        let before = node.clone();
        assert!(node.step(0, finalization).is_empty());
        assert_eq!(node, before);
    }

    #[test]
    fn a_node_that_does_not_settle_lets_a_failure_without_slashing_go_at_once() {
        let mut node = node();
        node.step(0, requested(10, e3(1)));
        node.step(11, failure(11, e3(1), FailureReason::DkgTimeout));
        node.step(11, Input::Tick);
        assert!(node.e3(&e3(1)).is_none());
    }

    #[test]
    fn a_member_settles_a_failed_e3_in_its_turn_and_keeps_it_until_the_chain_has() {
        let mut node = node();
        node.step(0, requested(10, e3(1)));
        node.step(0, finalized(11, e3(1), members([1])));
        node.step(20, failure(20, e3(1), FailureReason::DkgTimeout));
        let due = 20 + 1 + 30 * place(&[1, ME]);
        assert!(submissions(&node.step(due - 1, Input::Tick)).is_empty());
        let effects = node.step(due, Input::Tick);
        assert_eq!(submissions(&effects), vec![Transaction::SettleFailure]);
        assert!(submissions(&node.step(due + 3_600, Input::Tick)).is_empty());
        assert!(node.e3(&e3(1)).is_some());
        node.step(
            due + 3_600,
            chain(30, ChainFact::FailureSettled { e3: e3(1) }),
        );
        node.step(due + 3_600, chain(31, released(e3(1))));
        node.step(due + 3_600, Input::Tick);
        assert!(node.e3(&e3(1)).is_none());
    }

    fn released(e3: E3Id) -> ChainFact {
        ChainFact::DependenciesReleased { e3 }
    }

    #[test]
    fn a_stalled_stage_is_marked_failed_once_in_this_node_s_turn() {
        let mut node = node();
        node.step(0, requested(10, e3(1)));
        node.step(0, finalized(11, e3(1), members([1, 2])));
        let due = TIMING.deadline + 1 + 30 * place(&[1, 2, ME]);
        assert!(submissions(&node.step(due - 1, Input::Tick)).is_empty());
        let effects = node.step(due, Input::Tick);
        assert_eq!(submissions(&effects), vec![Transaction::MarkFailed]);
        assert!(submissions(&node.step(due + 3_600, Input::Tick)).is_empty());
    }

    #[test]
    fn a_published_key_moves_the_watch_from_the_dkg_to_the_ciphertext() {
        let mut node = node();
        node.step(0, requested(10, e3(1)));
        node.step(0, finalized(11, e3(1), members([1])));
        node.step(0, key_published(12, e3(1), members([1]), members([1])));
        let after_every_turn = TIMING.deadline + 30 * 20;
        assert!(submissions(&node.step(after_every_turn, Input::Tick)).is_empty());
        let due = COMPUTE_DEADLINE + 1 + 30 * place(&[1, ME]);
        let effects = node.step(due, Input::Tick);
        assert_eq!(submissions(&effects), vec![Transaction::MarkFailed]);
    }

    #[test]
    fn a_request_whose_randomness_never_comes_is_marked_failed() {
        let mut node = node();
        registered(&mut node, &[1, 2, ME], 10);
        node.step(1, requested(1, e3(1)));
        let due = COMMITTEE_DEADLINE + 1 + 30 * place(&[1, 2, ME]);
        assert!(submissions(&node.step(due - 1, Input::Tick)).is_empty());
        let effects = node.step(due, Input::Tick);
        assert_eq!(submissions(&effects), vec![Transaction::MarkFailed]);
    }

    /// The seed came after the ticket deadline, as it does for a node that replays history, so
    /// this node holds no ticket and no finalizer turn.
    #[test]
    fn a_seeded_request_nobody_finalizes_is_marked_failed_after_the_dkg_window() {
        let mut node = node();
        registered(&mut node, &[1, 2, ME], 10);
        node.step(1, requested(1, e3(1)));
        node.step(200, seed_ready(5, e3(1), 42, 100));
        let due = 100 + TIMING.window + 1 + 30 * place(&[1, 2, ME]);
        assert!(submissions(&node.step(due - 1, Input::Tick)).is_empty());
        let effects = node.step(due, Input::Tick);
        assert_eq!(submissions(&effects), vec![Transaction::MarkFailed]);
    }

    /// Settlement can stay closed for months after a failure, and accusations that expel no
    /// member can come and be appealed even after it, until governance closes the E3.
    #[test]
    fn a_failed_committee_keeps_its_work_until_governance_releases_the_e3() {
        let operators = vec![1, 2];
        let mut node = node();
        node.step(0, requested(10, e3(1)));
        node.step(0, finalized(11, e3(1), members(operators.clone())));
        node.step(20, failure(20, e3(1), FailureReason::DkgTimeout));
        let months = 20 + 200 * 24 * 60 * 60;
        node.step(months, Input::Tick);
        let state = node.e3(&e3(1)).expect("the E3 waits for its settlement");
        assert!(state.has_work());
        node.step(months, chain(30, ChainFact::FailureSettled { e3: e3(1) }));
        node.step(months, Input::Tick);
        assert!(node.e3(&e3(1)).is_some_and(|state| state.has_work()));
        node.step(months, chain(31, released(e3(1))));
        node.step(months, Input::Tick);
        assert!(node.e3(&e3(1)).is_none());
    }

    #[test]
    fn a_failed_e3_frees_its_ticket() {
        let mut node = node();
        registered(&mut node, &[1, 2, ME], 1);
        node.step(1, requested(1, e3(1)));
        node.step(1, requested(2, e3(2)));
        node.step(5, seed_ready(5, e3(1), 42, 100));
        node.step(
            6,
            failure(6, e3(1), FailureReason::CommitteeFormationTimeout),
        );
        let effects = node.step(7, seed_ready(7, e3(2), 42, 100));
        let ticket = |tx: &Transaction| matches!(tx, Transaction::SubmitTicket { .. });
        assert!(submissions(&effects).iter().any(ticket));
    }

    /// A completed E3 that the node keeps for its open accusations no longer takes a ticket's place.
    #[test]
    fn a_completed_e3_kept_for_accusations_frees_its_ticket() {
        let mut node = node();
        registered(&mut node, &[1, 2, ME], 1);
        let manager = Address::repeat_byte(0x5a);
        node.step(1, chain(1, ChainFact::SlashingManager { manager }));
        node.step(1, chain(2, ChainFact::VoteValidity { secs: 600 }));
        node.step(3, requested(3, e3(1)));
        node.step(4, requested(4, e3(2)));
        node.step(5, seed_ready(5, e3(1), 42, 100));
        node.step(6, finalized(6, e3(1), members([1, 2])));
        // An accusation this node opens keeps the E3 after its completion.
        node.step(6, key_from(e3(1), 1));
        node.step(6, key_failed(e3(1), 1, B256::repeat_byte(0xd1)));
        let completed = ChainFact::StageChanged {
            e3: e3(1),
            stage: Stage::Complete,
        };
        node.step(7, chain(7, completed));
        assert!(node.e3(&e3(1)).is_some());
        let effects = node.step(8, seed_ready(8, e3(2), 42, 100));
        let ticket = |tx: &Transaction| matches!(tx, Transaction::SubmitTicket { .. });
        assert!(submissions(&effects).iter().any(ticket));
    }

    #[test]
    fn a_slashable_failure_keeps_the_e3_until_the_grace_and_vote_validity_pass() {
        let mut node = node();
        node.step(0, chain(9, ChainFact::VoteValidity { secs: 600 }));
        node.step(0, requested(10, e3(1)));
        node.step(
            1_000,
            failure(1_000, e3(1), FailureReason::DkgInvalidShares),
        );
        let deadline = 1_000 + SLASHABLE_FAILURE_GRACE + 600;
        assert_eq!(node.next_deadline(), Some(deadline));
        node.step(deadline - 1, Input::Tick);
        assert!(node.e3(&e3(1)).is_some());
        node.step(deadline, Input::Tick);
        assert!(node.e3(&e3(1)).is_none());
        assert_eq!(node.next_deadline(), None);
    }

    #[test]
    fn after_a_slashable_failure_the_dkg_does_no_more_work() {
        let mut node = node();
        for (block, number) in [(10, 1), (12, 2)] {
            node.step(0, requested(block, e3(number)));
            node.step(0, finalized(block + 1, e3(number), members([1])));
        }
        let effects = node.step(0, key_made(e3(2), own_key(0xee)));
        node.step(100, failure(20, e3(1), FailureReason::DkgInvalidShares));
        node.step(100, failure(21, e3(2), FailureReason::DkgInvalidShares));
        node.step(100, Input::Tick);
        assert!(node.step(100, key_made(e3(1), own_key(0xee))).is_empty());
        assert!(node.step(100, sign(ME, signing(&effects))).is_empty());
        assert!(node.step(100, key_from(e3(2), 1)).is_empty());
    }

    fn owes(node: &Node, effect: &Effect) -> bool {
        node.owes(&effect.e3(), effect.scope())
    }

    /// The commitment lands first and the key's chunks follow, so the publication outlives the
    /// chain's log of it; the DKG jobs do not.
    #[test]
    fn a_key_s_publication_is_owed_after_the_chain_logs_it_and_dkg_jobs_are_not() {
        let mut node = node();
        node.step(0, requested(10, e3(1)));
        let effects = node.step(0, finalized(11, e3(1), members([1])));
        let make_key = effects
            .into_iter()
            .find(|effect| matches!(effect, Effect::Run(_)))
            .expect("a member makes its key");
        let publish = Effect::Submit(Submission {
            e3: e3(1),
            transaction: Transaction::PublishCommittee(crate::dkg::KeyPublication {
                commitment: B256::ZERO,
                public_key: BlobRef::of(b"key"),
                proof: proof(1),
                attestations: Vec::new(),
            }),
        });
        assert!(owes(&node, &make_key) && owes(&node, &publish));
        node.step(100, key_published(12, e3(1), members([1]), members([1])));
        assert!(!owes(&node, &make_key), "the key is out");
        assert!(owes(&node, &publish), "its chunks are not");
    }

    /// After the chain fails an E3, a restart or a running task still serves its accusations and
    /// settlement, but no longer its DKG.
    #[test]
    fn a_failed_e3_needs_its_accusation_and_settlement_effects_only() {
        let mut node = node();
        node.step(0, requested(10, e3(1)));
        let effects = node.step(0, finalized(11, e3(1), members([1])));
        let Some(Effect::Run(make_key)) = effects.into_iter().find(|e| matches!(e, Effect::Run(_)))
        else {
            panic!("a member makes its key");
        };
        let verify = Effect::Run(Job {
            work: Work::Accusation(crate::accusation::AccusationWork::Verify {
                proof_type: ProofType::C0PkBfv,
                proof: proof(0xc0),
            }),
            ..make_key.clone()
        });
        let submit = |transaction| {
            Effect::Submit(Submission {
                e3: e3(1),
                transaction,
            })
        };
        let (make_key, settle) = (Effect::Run(make_key), submit(Transaction::SettleFailure));
        assert!(owes(&node, &make_key) && owes(&node, &settle));

        node.step(100, failure(20, e3(1), FailureReason::DkgInvalidShares));
        assert!(!owes(&node, &make_key));
        assert!(!owes(&node, &submit(Transaction::FinalizeCommittee)));
        assert!(owes(&node, &settle) && owes(&node, &verify));
        let elsewhere = Effect::Submit(Submission {
            e3: e3(2),
            transaction: Transaction::SettleFailure,
        });
        assert!(!owes(&node, &elsewhere));
    }

    #[test]
    fn decryption_shares_wait_in_the_hold_until_the_key_is_published() {
        let mut node = node();
        node.step(0, requested(10, e3(1)));
        node.step(0, finalized(11, e3(1), members([1, 2])));
        node.step(0, announced(decryption_shares(e3(1), 1, 1)));
        let roster = vec![address(1), address(ME)];
        let effects = node.step(0, key_published(12, e3(1), members([1, 2]), roster));
        assert_eq!(fetched_from(&effects), vec![address(1)]);
    }

    #[test]
    fn a_node_outside_the_committee_has_no_work_in_the_e3() {
        let mut node = node();
        node.step(0, requested(10, e3(1)));
        node.step(0, finalized(11, e3(1), vec![address(1), address(2)]));
        assert!(node.e3(&e3(1)).is_none());
    }

    #[test]
    fn finalization_drops_what_non_members_sent() {
        let mut node = node();
        node.step(0, announced(key_from(e3(1), 1)));
        node.step(0, announced(key_from(e3(1), 9)));
        node.step(0, requested(10, e3(1)));
        let effects = node.step(0, finalized(11, e3(1), members([1])));
        assert_eq!(fetched_from(&effects), vec![address(1)]);
    }

    #[test]
    fn a_late_message_for_an_ended_e3_takes_no_hold_space() {
        let mut node = node();
        node.step(0, requested(10, e3(1)));
        node.step(
            0,
            chain(
                11,
                ChainFact::StageChanged {
                    e3: e3(1),
                    stage: Stage::Complete,
                },
            ),
        );
        for n in 1..=512 {
            node.step(0, announced(key_from(e3(2), n)));
            node.step(0, announced(key_from(e3(3), n)));
        }
        node.step(0, announced(key_from(e3(1), 1)));
        node.step(0, requested(12, e3(2)));
        let fetched = fetched_from(&node.step(0, finalized(13, e3(2), members(1..=512))));
        assert_eq!(fetched.len(), 512);
    }
}
