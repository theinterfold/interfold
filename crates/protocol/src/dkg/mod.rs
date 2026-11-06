// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! One committee member's DKG for one E3.

mod attestation;
mod timing;

pub use attestation::FoldAttestation;
pub use timing::DkgTiming;

use crate::{
    node::{Body, Effect, Job, PeerMessage, Purpose, Signing, Work},
    proof::{ProofType, ZkProof},
    BlobRef, E3Id, UnixSecs,
};
use alloy_primitives::{Address, Bytes, Signature};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// What committee members send each other during the DKG.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DkgMessage {
    /// A member's BFV encryption key (C0), with its proof signed by the member.
    EncryptionKey(KeyMessage),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyMessage {
    pub key: BlobRef,
    pub proof: ZkProof,
    pub signature: Bytes,
}

impl DkgMessage {
    pub(crate) fn size(&self) -> u64 {
        match self {
            DkgMessage::EncryptionKey(message) => {
                message.key.len
                    + (message.proof.data.len() + 32 * message.proof.public_inputs.len()) as u64
            }
        }
    }
}

/// Work the DKG asks the job runner for.
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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DkgWorkResult {
    EncryptionKeyMade(OwnKey),
    EncryptionKeyChecked { sender: Address, valid: bool },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DkgSignature {
    EncryptionKeyProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnKey {
    pub public: BlobRef,
    pub secret: BlobRef,
    pub proof: ZkProof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DkgFailure {
    /// The committee was finalized after the key cutoff, so this node's key could not count.
    StartedAfterKeyCutoff,
    /// Fewer than H valid keys, this node's included, by the key cutoff.
    TooFewKeys,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Phase {
    MakingKey,
    SigningKey(OwnKey),
    CollectingKeys(OwnKey),
    KeysCollected(OwnKey),
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
    /// The first key each member signed.
    keys: BTreeMap<Address, KeyMessage>,
    /// Members whose key passed its check, this node included once its key is signed.
    valid: BTreeSet<Address>,
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
            keys: BTreeMap::new(),
            valid: BTreeSet::new(),
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
        &self.valid
    }

    pub fn keys_collected(&self) -> bool {
        matches!(self.phase, Phase::KeysCollected(_))
    }

    pub fn failure(&self) -> Option<DkgFailure> {
        match self.phase {
            Phase::Failed(failure) => Some(failure),
            _ => None,
        }
    }

    pub(crate) fn receive(&mut self, sender: Address, message: DkgMessage) -> Vec<Effect> {
        let DkgMessage::EncryptionKey(key) = message;
        if !self.collecting()
            || sender == self.me
            || self.members.binary_search(&sender).is_err()
            || self.keys.contains_key(&sender)
            || !self.signed_by(sender, &key)
        {
            return Vec::new();
        }
        let check = self.run(DkgWork::CheckEncryptionKey {
            sender,
            key: key.key,
            proof: key.proof.clone(),
        });
        self.keys.insert(sender, key);
        vec![check]
    }

    pub(crate) fn job_done(&mut self, result: DkgWorkResult) -> Vec<Effect> {
        match result {
            DkgWorkResult::EncryptionKeyMade(own) => {
                // A repeated job's second key is never used: this node publishes one key per E3.
                if self.phase != Phase::MakingKey {
                    return Vec::new();
                }
                let hash = own.proof.payload_signing_hash(self.e3, ProofType::C0PkBfv);
                self.phase = Phase::SigningKey(own);
                vec![Effect::Sign(Signing {
                    e3: self.e3,
                    purpose: Purpose::Dkg(DkgSignature::EncryptionKeyProof),
                    hashes: vec![hash],
                })]
            }
            DkgWorkResult::EncryptionKeyChecked { sender, valid } => {
                if valid && self.collecting() {
                    self.valid.insert(sender);
                    self.complete_if_all_keys_are_in();
                }
                Vec::new()
            }
        }
    }

    pub(crate) fn signed(&mut self, purpose: DkgSignature, signatures: Vec<Bytes>) -> Vec<Effect> {
        let (DkgSignature::EncryptionKeyProof, Phase::SigningKey(own), [signature]) =
            (purpose, &self.phase, signatures.as_slice())
        else {
            return Vec::new();
        };
        let (own, signature) = (own.clone(), signature.clone());
        let message = KeyMessage {
            key: own.public,
            proof: own.proof.clone(),
            signature,
        };
        self.phase = Phase::CollectingKeys(own);
        self.valid.insert(self.me);
        self.complete_if_all_keys_are_in();
        vec![Effect::Gossip(PeerMessage {
            e3: self.e3,
            sender: self.me,
            body: Body::Dkg(DkgMessage::EncryptionKey(message)),
        })]
    }

    /// At the key cutoff, key collection ends with at least H valid keys, this node's included, or
    /// fails.
    pub(crate) fn pass_deadlines(&mut self, now: UnixSecs) {
        if !self.collecting() || now < self.timing.key_cutoff() {
            return;
        }
        self.phase = match &self.phase {
            // This node's key is among the valid ones from the moment it is sent.
            Phase::CollectingKeys(own) if self.valid.len() >= self.h => {
                Phase::KeysCollected(own.clone())
            }
            _ => Phase::Failed(DkgFailure::TooFewKeys),
        };
    }

    pub(crate) fn next_deadline(&self) -> Option<UnixSecs> {
        self.collecting().then(|| self.timing.key_cutoff())
    }

    fn collecting(&self) -> bool {
        matches!(
            self.phase,
            Phase::MakingKey | Phase::SigningKey(_) | Phase::CollectingKeys(_)
        )
    }

    fn complete_if_all_keys_are_in(&mut self) {
        if self.valid.len() < self.members.len() {
            return;
        }
        if let Phase::CollectingKeys(own) = &self.phase {
            self.phase = Phase::KeysCollected(own.clone());
        }
    }

    fn signed_by(&self, sender: Address, message: &KeyMessage) -> bool {
        let hash = message
            .proof
            .payload_signing_hash(self.e3, ProofType::C0PkBfv);
        Signature::try_from(message.signature.as_ref())
            .ok()
            .and_then(|signature| signature.recover_address_from_prehash(&hash).ok())
            == Some(sender)
    }

    fn run(&self, work: DkgWork) -> Effect {
        Effect::Run(Job {
            e3: self.e3,
            work: Work::Dkg(work),
        })
    }
}

#[cfg(test)]
mod tests;
