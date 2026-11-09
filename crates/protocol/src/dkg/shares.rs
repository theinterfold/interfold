// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C1-C3: the threshold shares each member deals to the others, and the Ready report in which a
//! member names the dealers whose shares it verified.

use super::{
    Dealer, Dkg, DkgMessage, DkgProofs, DkgSignature, DkgWork, OwnDecryptionKey, OwnShares, Phase,
    RecipientShares, SharesMessage,
};
use crate::{
    node::{Effect, Noted},
    proof::{ProofType, SignedProof, ZkProof},
    BlobRef, E3Id, SealedRef,
};
use alloy_primitives::{Address, Bytes};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What this node dealt: its contribution, which Ready reports and rosters name, and what its C4,
/// its keyshare, and its fold need.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Dealt {
    pub(super) contribution: Dealer,
    pub(super) pk_share: BlobRef,
    pub(super) own_share: SealedRef,
    c0: ZkProof,
    pub(super) c1: SignedProof,
    pub(super) c2a: ZkProof,
    pub(super) c2b: ZkProof,
    c3a: BTreeMap<Address, Vec<ZkProof>>,
    c3b: BTreeMap<Address, Vec<ZkProof>>,
}

impl Dealt {
    /// Every proof the node fold combines, with the decryption key's.
    pub(super) fn proofs(&self, decryption_key: &OwnDecryptionKey) -> DkgProofs {
        DkgProofs {
            c0: self.c0.clone(),
            c1: self.c1.proof.clone(),
            c2a: self.c2a.clone(),
            c2b: self.c2b.clone(),
            c3a: self.c3a.clone(),
            c3b: self.c3b.clone(),
            c4a: decryption_key.c4a.clone(),
            c4b: decryption_key.c4b.clone(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Shares {
    /// The first signed shares each dealer sent this node.
    pub(super) received: BTreeMap<Address, SharesMessage>,
    /// Each received dealer's verdict: whether its shares match their proofs.
    checked: BTreeMap<Address, bool>,
    /// After the share checkpoint, Ready no longer waits for missing dealers.
    pub(super) checkpoint_passed: bool,
    /// The dealers this node still waited for were all without a valid key here. Their shares
    /// cannot join a roster with this node's, so Ready no longer waits for them, even if they
    /// come after all.
    waits_only_on_keyless: bool,
}

impl OwnShares {
    /// Every proof a dealer signs, in [`DkgSignature::DealerProofs`] order.
    fn proofs(&self) -> Vec<(ProofType, &ZkProof)> {
        let mut proofs = vec![
            (ProofType::C1PkGeneration, &self.c1),
            (ProofType::C2aSkShareComputation, &self.c2a),
            (ProofType::C2bESmShareComputation, &self.c2b),
        ];
        for recipient in self.delivered().map(|(_, recipient, _)| recipient) {
            proofs.extend(
                recipient
                    .c3a
                    .iter()
                    .map(|proof| (ProofType::C3aSkShareEncryption, proof)),
            );
            proofs.extend(
                recipient
                    .c3b
                    .iter()
                    .map(|proof| (ProofType::C3bESmShareEncryption, proof)),
            );
        }
        proofs
    }

    /// The recipients with a valid key, which receive their shares.
    fn delivered(&self) -> impl Iterator<Item = (Address, &RecipientShares, BlobRef)> {
        self.recipients
            .iter()
            .filter_map(|(member, recipient)| Some((*member, recipient, recipient.shares?)))
    }
}

impl SharesMessage {
    fn is_signed_by(&self, dealer: Address, e3: E3Id) -> bool {
        let proofs = [
            (ProofType::C2aSkShareComputation, &self.c2a),
            (ProofType::C2bESmShareComputation, &self.c2b),
        ]
        .into_iter()
        .chain(
            self.c3a
                .iter()
                .map(|proof| (ProofType::C3aSkShareEncryption, proof)),
        )
        .chain(
            self.c3b
                .iter()
                .map(|proof| (ProofType::C3bESmShareEncryption, proof)),
        );
        proofs
            .into_iter()
            .all(|(proof_type, proof)| proof.is_signed_by(dealer, e3, proof_type))
    }
}

impl Dkg {
    /// Deal shares to every live member whose key is valid; the others get placeholders.
    pub(super) fn start_shares(&mut self) -> Vec<Effect> {
        let Phase::CollectingKeys(own) = &self.phase else {
            return Vec::new();
        };
        let keys = self
            .keys
            .received
            .iter()
            .filter(|(member, _)| self.keys.valid.contains(*member) && self.is_live(member))
            .map(|(member, message)| (*member, message.key))
            .collect();
        let work = DkgWork::MakeShares {
            dealer: self.me,
            committee: self.members.clone(),
            own_key: own.public,
            keys,
        };
        self.phase = Phase::MakingShares(own.clone());
        vec![self.run(work)]
    }

    pub(super) fn shares_made(&mut self, made: OwnShares) -> Vec<Effect> {
        // A repeated job's second shares are never used: this node deals once per E3.
        let Phase::MakingShares(own) = &self.phase else {
            return Vec::new();
        };
        let hashes = made
            .proofs()
            .into_iter()
            .map(|(proof_type, proof)| proof.payload_signing_hash(self.e3, proof_type))
            .collect();
        self.phase = Phase::SigningShares(own.clone(), Box::new(made));
        vec![self.sign(DkgSignature::DealerProofs, hashes)]
    }

    pub(super) fn shares_signed(&mut self, signatures: Vec<Bytes>) -> Vec<Effect> {
        let Phase::SigningShares(own, made) = &self.phase else {
            return Vec::new();
        };
        let proofs = made.proofs();
        if signatures.len() != proofs.len() {
            return Vec::new();
        }
        let signed: Vec<SignedProof> = proofs
            .into_iter()
            .zip(signatures)
            .map(|((_, proof), signature)| SignedProof {
                proof: proof.clone(),
                signature,
            })
            .collect();
        let [c1, c2a, c2b, c3 @ ..] = signed.as_slice() else {
            return Vec::new();
        };
        let mut c3 = c3.iter().cloned();
        let mut messages = Vec::new();
        for (recipient, proofs, shares) in made.delivered() {
            messages.push(SharesMessage {
                recipient,
                pk_share: made.pk_share,
                shares,
                c2a: c2a.clone(),
                c2b: c2b.clone(),
                c3a: c3.by_ref().take(proofs.c3a.len()).collect(),
                c3b: c3.by_ref().take(proofs.c3b.len()).collect(),
            });
        }
        let c3 = |proofs: fn(&RecipientShares) -> &Vec<ZkProof>| {
            made.recipients
                .iter()
                .map(|(member, recipient)| (*member, proofs(recipient).clone()))
                .collect()
        };
        let dealt = Dealt {
            contribution: Dealer::new(self.me, made.pk_share, &made.c2a, &made.c2b),
            pk_share: made.pk_share,
            own_share: made.own_share,
            c0: own.proof.clone(),
            c1: c1.clone(),
            c2a: made.c2a.clone(),
            c2b: made.c2b.clone(),
            c3a: c3(|recipient| &recipient.c3a),
            c3b: c3(|recipient| &recipient.c3b),
        };
        self.phase = Phase::Dealt(own.clone(), Box::new(dealt));
        let mut effects: Vec<Effect> = messages
            .into_iter()
            .map(|message| self.gossip(DkgMessage::Shares(Box::new(message))))
            .collect();
        effects.extend(self.send_ready_if_due());
        effects
    }

    /// Shares can only be for a key this node has sent, so they count from then on.
    /// Shares need this node's key to open.
    pub(super) fn admits_shares(&self, dealer: Address, message: &SharesMessage) -> bool {
        self.own_key().is_some()
            && dealer != self.me
            && self.is_member(dealer)
            && !self.shares.received.contains_key(&dealer)
            && message.is_signed_by(dealer, self.e3)
    }

    pub(super) fn receive_shares(
        &mut self,
        dealer: Address,
        message: SharesMessage,
    ) -> Vec<Effect> {
        let Some(own) = self.own_key() else {
            return Vec::new();
        };
        let check = self.run(DkgWork::CheckShares {
            dealer,
            committee: self.members.clone(),
            secret: own.secret,
            own_key: own.proof.clone(),
            message: Box::new(message.clone()),
        });
        self.shares.received.insert(dealer, message);
        vec![check]
    }

    pub(super) fn shares_checked(&mut self, dealer: Address, valid: bool) -> Vec<Effect> {
        if !self.shares.received.contains_key(&dealer) || self.shares.checked.contains_key(&dealer)
        {
            return Vec::new();
        }
        self.shares.checked.insert(dealer, valid);
        self.send_ready_if_due()
    }

    pub(super) fn admits_ready(&self, reporter: Address, dealers: &[Dealer]) -> bool {
        reporter != self.me
            && self.is_member(reporter)
            && self.is_live(&reporter)
            && dealers.len() >= self.h()
            && dealers
                .windows(2)
                .all(|pair| pair[0].member < pair[1].member)
            && dealers.iter().all(|dealer| self.is_member(dealer.member))
            && dealers.iter().any(|dealer| dealer.member == reporter)
            && self
                .ready
                .get(&reporter)
                .is_none_or(|earlier| earlier.iter().all(|dealer| dealers.contains(dealer)))
    }

    pub(super) fn receive_ready(&mut self, reporter: Address, dealers: Vec<Dealer>) -> Effect {
        let noted = self.ready_noted(reporter, dealers.len());
        self.ready.insert(reporter, dealers);
        noted
    }

    fn ready_noted(&self, reporter: Address, dealers: usize) -> Effect {
        let reports = self.ready.len() + usize::from(!self.ready.contains_key(&reporter));
        self.note(Noted::Ready {
            reporter,
            dealers,
            reports,
            committee: self.members.len(),
        })
    }

    /// Send a Ready report, or a larger one, once it names at least H dealers and every live
    /// dealer's shares are checked, the share checkpoint has passed, or this node once waited
    /// only for dealers without a valid key here.
    pub(super) fn send_ready_if_due(&mut self) -> Vec<Effect> {
        let Phase::Dealt(_, dealt) = &self.phase else {
            return Vec::new();
        };
        let outstanding: Vec<&Address> = self
            .members
            .iter()
            .filter(|member| {
                **member != self.me
                    && self.is_live(member)
                    && !self.shares.checked.contains_key(*member)
            })
            .collect();
        let keyless = !outstanding.is_empty()
            && outstanding
                .iter()
                .all(|member| !self.keys.valid.contains(*member));
        if !(outstanding.is_empty()
            || self.shares.checkpoint_passed
            || self.shares.waits_only_on_keyless
            || keyless)
        {
            return Vec::new();
        }
        let contribution = dealt.contribution;
        self.shares.waits_only_on_keyless |= keyless;
        let mut dealers = vec![contribution];
        dealers.extend(
            self.shares
                .checked
                .iter()
                .filter(|(_, valid)| **valid)
                .filter_map(|(dealer, _)| {
                    let message = self.shares.received.get(dealer)?;
                    Some(Dealer::new(
                        *dealer,
                        message.pk_share,
                        &message.c2a.proof,
                        &message.c2b.proof,
                    ))
                }),
        );
        dealers.sort_by_key(|dealer| dealer.member);
        if dealers.len() < self.h() || self.ready.get(&self.me) == Some(&dealers) {
            return Vec::new();
        }
        let noted = self.ready_noted(self.me, dealers.len());
        self.ready.insert(self.me, dealers.clone());
        vec![self.gossip(DkgMessage::Ready(dealers)), noted]
    }
}
