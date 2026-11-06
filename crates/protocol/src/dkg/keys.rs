// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C0: every member's BFV encryption key, which the other members encrypt their shares to.

use super::{Dkg, DkgFailure, DkgMessage, DkgSignature, DkgWork, KeyMessage, OwnKey, Phase};
use crate::{
    node::Effect,
    proof::{ProofType, SignedProof},
};
use alloy_primitives::{Address, Bytes};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Keys {
    /// The first key each member signed.
    pub(super) received: BTreeMap<Address, KeyMessage>,
    /// Members whose key passed its check, this node included once its key is sent. Fixed when
    /// key collection ends.
    pub(super) valid: BTreeSet<Address>,
}

impl Dkg {
    pub(super) fn admits_key(&self, sender: Address, message: &KeyMessage) -> bool {
        self.collecting_keys()
            && sender != self.me
            && self.is_member(sender)
            && !self.keys.received.contains_key(&sender)
            && message
                .proof
                .is_signed_by(sender, self.e3, ProofType::C0PkBfv)
    }

    pub(super) fn receive_key(&mut self, sender: Address, message: KeyMessage) -> Vec<Effect> {
        let check = self.run(DkgWork::CheckEncryptionKey {
            sender,
            key: message.key,
            proof: message.proof.proof.clone(),
        });
        self.keys.received.insert(sender, message);
        vec![check]
    }

    pub(super) fn key_made(&mut self, own: OwnKey) -> Vec<Effect> {
        // A repeated job's second key is never used: this node publishes one key per E3.
        if self.phase != Phase::MakingKey {
            return Vec::new();
        }
        let hash = own.proof.payload_signing_hash(self.e3, ProofType::C0PkBfv);
        self.phase = Phase::SigningKey(own);
        vec![self.sign(DkgSignature::EncryptionKeyProof, vec![hash])]
    }

    pub(super) fn key_signed(&mut self, signatures: Vec<Bytes>) -> Vec<Effect> {
        let (Phase::SigningKey(own), [signature]) = (&self.phase, signatures.as_slice()) else {
            return Vec::new();
        };
        let message = KeyMessage {
            key: own.public,
            proof: SignedProof {
                proof: own.proof.clone(),
                signature: signature.clone(),
            },
        };
        self.phase = Phase::CollectingKeys(own.clone());
        self.keys.valid.insert(self.me);
        let mut effects = vec![self.gossip(DkgMessage::EncryptionKey(message))];
        effects.extend(self.close_keys_if_all_in());
        effects
    }

    pub(super) fn key_checked(&mut self, sender: Address, valid: bool) -> Vec<Effect> {
        if !valid || !self.collecting_keys() {
            return Vec::new();
        }
        self.keys.valid.insert(sender);
        self.close_keys_if_all_in()
    }

    pub(super) fn close_keys_if_all_in(&mut self) -> Vec<Effect> {
        let all_in = self
            .members
            .iter()
            .filter(|member| self.is_live(member))
            .all(|member| self.keys.valid.contains(member));
        match all_in && matches!(self.phase, Phase::CollectingKeys(_)) {
            true => self.start_shares(),
            false => Vec::new(),
        }
    }

    /// At the key cutoff, key collection ends with at least H valid keys of members the chain has
    /// not expelled, this node's included, or fails.
    pub(super) fn close_keys_at_cutoff(&mut self) -> Vec<Effect> {
        let live_keys = self
            .keys
            .valid
            .iter()
            .filter(|member| self.is_live(member))
            .count();
        // This node's key is among the valid ones from the moment it is sent.
        if matches!(self.phase, Phase::CollectingKeys(_)) && live_keys >= self.h() {
            return self.start_shares();
        }
        self.phase = Phase::Failed(DkgFailure::TooFewKeys);
        Vec::new()
    }

    pub(super) fn collecting_keys(&self) -> bool {
        matches!(
            self.phase,
            Phase::MakingKey | Phase::SigningKey(_) | Phase::CollectingKeys(_)
        )
    }

    /// This node's key, from the moment it is sent until the roster is accepted, which ends share
    /// collection.
    pub(super) fn own_key(&self) -> Option<&OwnKey> {
        match &self.phase {
            Phase::CollectingKeys(own)
            | Phase::MakingShares(own)
            | Phase::SigningShares(own, _)
            | Phase::Dealt(own, _) => Some(own),
            Phase::MakingKey
            | Phase::SigningKey(_)
            | Phase::MakingDecryptionKey(_)
            | Phase::SigningDecryptionKey(..)
            | Phase::DecryptionKeySent(..)
            | Phase::KeyshareSent
            | Phase::Observing
            | Phase::Failed(_) => None,
        }
    }
}
