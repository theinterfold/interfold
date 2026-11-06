// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C4: each roster member's decryption key, the sum of the roster dealers' shares for it. Every
//! member checks the roster members' C4 proofs; a roster member sends its keyshare once every
//! other roster member's C4 is checked and more than T roster members hold a valid key.
//! Members outside the roster only check: decryption admits roster members alone, and the key
//! aggregates roster keyshares alone.

use super::{
    DecryptionKeyMessage, Dkg, DkgFailure, DkgMessage, DkgSignature, DkgWork, KeyshareMessage,
    OwnDecryptionKey, Phase,
};
use crate::{
    node::Effect,
    proof::{ProofType, SignedProof, ZkProof},
    E3Id,
};
use alloy_primitives::{Address, Bytes};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, iter};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct DecryptionKeys {
    /// The first signed C4 proofs of each member. Before the roster is known every member's are
    /// kept; afterwards only roster members' count.
    pub(super) received: BTreeMap<Address, DecryptionKeyMessage>,
    /// Each roster member's C4 verdict.
    checked: BTreeMap<Address, bool>,
    /// The roster dealers' C2 proofs, which every C4 binds; fixed with the roster.
    c2: BTreeMap<Address, (ZkProof, ZkProof)>,
}

impl DecryptionKeyMessage {
    fn is_signed_by(&self, member: Address, e3: E3Id) -> bool {
        self.c4a
            .is_signed_by(member, e3, ProofType::C4aSkShareDecryption)
            && self
                .c4b
                .iter()
                .all(|proof| proof.is_signed_by(member, e3, ProofType::C4bESmShareDecryption))
    }
}

impl OwnDecryptionKey {
    /// Every C4 proof, in [`DkgSignature::DecryptionKeyProofs`] order.
    fn proofs(&self) -> Vec<(ProofType, &ZkProof)> {
        iter::once((ProofType::C4aSkShareDecryption, &self.c4a))
            .chain(
                self.c4b
                    .iter()
                    .map(|proof| (ProofType::C4bESmShareDecryption, proof)),
            )
            .collect()
    }
}

impl Dkg {
    /// With the roster accepted, a roster member makes its decryption key, and every member checks
    /// the C4 proofs that roster members already sent.
    pub(super) fn start_decryption_key(&mut self) -> Vec<Effect> {
        let (Some(roster), Phase::Dealt(own, dealt)) = (self.roster_members(), &self.phase) else {
            return Vec::new();
        };
        let (secret, dealt) = (own.secret, dealt.clone());
        self.decryption_keys.c2 = roster
            .iter()
            .filter_map(|member| match *member == self.me {
                true => Some((*member, (dealt.c2a.clone(), dealt.c2b.clone()))),
                false => {
                    let shares = self.shares.received.get(member)?;
                    Some((
                        *member,
                        (shares.c2a.proof.clone(), shares.c2b.proof.clone()),
                    ))
                }
            })
            .collect();
        let mut effects = Vec::new();
        if roster.contains(&self.me) {
            let shares = roster
                .iter()
                .filter(|member| **member != self.me)
                .filter_map(|member| Some((*member, self.shares.received.get(member)?.shares)))
                .collect();
            effects.push(self.run(DkgWork::MakeDecryptionKey {
                member: self.me,
                committee: self.members.clone(),
                secret,
                own_share: dealt.own_share,
                shares,
                c2: self.decryption_keys.c2.clone(),
            }));
            self.phase = Phase::MakingDecryptionKey(dealt);
        } else {
            self.phase = Phase::Observing;
        }
        let me = self.me;
        self.decryption_keys
            .received
            .retain(|member, _| *member != me && roster.contains(member));
        effects.extend(
            self.decryption_keys
                .received
                .iter()
                .map(|(member, message)| self.check_decryption_key(*member, message)),
        );
        effects
    }

    pub(super) fn admits_decryption_key(
        &self,
        member: Address,
        message: &DecryptionKeyMessage,
    ) -> bool {
        let in_roster = self
            .roster_members()
            .is_none_or(|roster| roster.contains(&member));
        in_roster
            && member != self.me
            && self.is_member(member)
            && !self.decryption_keys.received.contains_key(&member)
            && message.is_signed_by(member, self.e3)
    }

    pub(super) fn receive_decryption_key(
        &mut self,
        member: Address,
        message: DecryptionKeyMessage,
    ) -> Vec<Effect> {
        let check = self
            .roster()
            .is_some()
            .then(|| self.check_decryption_key(member, &message));
        self.decryption_keys.received.insert(member, message);
        check.into_iter().collect()
    }

    pub(super) fn decryption_key_made(&mut self, made: OwnDecryptionKey) -> Vec<Effect> {
        // A repeated job's second key is never used: this node proves one decryption key.
        let Phase::MakingDecryptionKey(dealt) = &self.phase else {
            return Vec::new();
        };
        let hashes = made
            .proofs()
            .into_iter()
            .map(|(proof_type, proof)| proof.payload_signing_hash(self.e3, proof_type))
            .collect();
        self.phase = Phase::SigningDecryptionKey(dealt.clone(), Box::new(made));
        vec![self.sign(DkgSignature::DecryptionKeyProofs, hashes)]
    }

    pub(super) fn decryption_key_signed(&mut self, signatures: Vec<Bytes>) -> Vec<Effect> {
        let Phase::SigningDecryptionKey(dealt, made) = &self.phase else {
            return Vec::new();
        };
        let proofs = made.proofs();
        if signatures.len() != proofs.len() {
            return Vec::new();
        }
        let mut signed = proofs
            .into_iter()
            .zip(signatures)
            .map(|((_, proof), signature)| SignedProof {
                proof: proof.clone(),
                signature,
            });
        let Some(c4a) = signed.next() else {
            return Vec::new();
        };
        let message = DecryptionKeyMessage {
            c4a,
            c4b: signed.collect(),
        };
        let proofs = dealt.proofs(made);
        self.sealed_key = Some(made.key);
        self.phase = Phase::DecryptionKeySent(dealt.clone());
        let mut effects = vec![
            self.gossip(DkgMessage::DecryptionKey(message)),
            self.start_fold(proofs),
        ];
        effects.extend(self.send_keyshare_if_due());
        effects
    }

    pub(super) fn decryption_key_checked(&mut self, member: Address, valid: bool) -> Vec<Effect> {
        if !self.decryption_keys.received.contains_key(&member)
            || self.decryption_keys.checked.contains_key(&member)
        {
            return Vec::new();
        }
        self.decryption_keys.checked.insert(member, valid);
        self.send_keyshare_if_due()
    }

    fn send_keyshare_if_due(&mut self) -> Vec<Effect> {
        let (Some(roster), Phase::DecryptionKeySent(dealt)) = (self.roster_members(), &self.phase)
        else {
            return Vec::new();
        };
        let verdicts: Vec<Option<bool>> = roster
            .iter()
            .filter(|member| **member != self.me)
            .map(|member| self.decryption_keys.checked.get(member).copied())
            .collect();
        if verdicts.contains(&None) {
            return Vec::new();
        }
        let valid = 1 + verdicts
            .iter()
            .filter(|verdict| **verdict == Some(true))
            .count();
        if valid <= self.t() {
            self.phase = Phase::Failed(DkgFailure::TooFewValidDecryptionKeys);
            return Vec::new();
        }
        let message = KeyshareMessage {
            pk_share: dealt.pk_share,
            c1: dealt.c1.clone(),
        };
        self.phase = Phase::KeyshareSent;
        self.record_keyshare(self.me, message.clone());
        vec![self.gossip(DkgMessage::Keyshare(message))]
    }

    fn check_decryption_key(&self, member: Address, message: &DecryptionKeyMessage) -> Effect {
        self.run(DkgWork::CheckDecryptionKey {
            member,
            committee: self.members.clone(),
            c2: self.decryption_keys.c2.clone(),
            message: Box::new(message.clone()),
        })
    }
}
