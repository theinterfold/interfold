// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! A roster member's node fold: one recursive proof of all its own DKG proofs, which the key
//! aggregator combines with the other roster members' folds. The member attests the fold's
//! commitments for its committee slot.

use super::{
    Dkg, DkgMessage, DkgProofs, DkgSignature, DkgWork, FoldAttestation, NodeFold, NodeFoldMessage,
};
use crate::node::Effect;
use alloy_primitives::{Address, Bytes, Signature};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum OwnFold {
    NotStarted,
    Folding,
    Signing(NodeFold),
    Sent,
}

impl Dkg {
    pub(super) fn start_fold(&mut self, proofs: DkgProofs) -> Effect {
        self.fold = OwnFold::Folding;
        self.run(DkgWork::FoldProofs {
            member: self.me,
            committee: self.members.clone(),
            proofs: Box::new(proofs),
        })
    }

    pub(super) fn proofs_folded(&mut self, fold: NodeFold) -> Vec<Effect> {
        // A repeated job's second fold is never used: this node attests one fold.
        let (OwnFold::Folding, Some(attestation)) =
            (&self.fold, self.attestation_of(self.me, &fold))
        else {
            return Vec::new();
        };
        self.fold = OwnFold::Signing(fold);
        vec![self.sign(
            DkgSignature::FoldAttestation,
            vec![attestation.signing_hash()],
        )]
    }

    pub(super) fn fold_signed(&mut self, signatures: Vec<Bytes>) -> Vec<Effect> {
        let (OwnFold::Signing(fold), [signature]) = (&self.fold, signatures.as_slice()) else {
            return Vec::new();
        };
        let message = NodeFoldMessage {
            fold: fold.clone(),
            attestation: signature.clone(),
        };
        self.fold = OwnFold::Sent;
        self.record_fold(self.me, message.clone());
        vec![self.gossip(DkgMessage::NodeFold(message))]
    }

    /// Whether `member` signed the attestation of `message`'s fold for its own committee slot.
    pub(super) fn attests(&self, member: Address, message: &NodeFoldMessage) -> bool {
        let Some(attestation) = self.attestation_of(member, &message.fold) else {
            return false;
        };
        Signature::try_from(message.attestation.as_ref())
            .ok()
            .and_then(|signature| {
                signature
                    .recover_address_from_prehash(&attestation.signing_hash())
                    .ok()
            })
            == Some(member)
    }

    fn attestation_of(&self, member: Address, fold: &NodeFold) -> Option<FoldAttestation> {
        Some(FoldAttestation {
            e3: self.e3,
            verifier: self.attestation.verifier,
            registry: self.attestation.registry,
            party_id: self.party_id(member)?,
            sk_agg_commit: fold.sk_agg_commit,
            esm_agg_commit: fold.esm_agg_commit,
        })
    }
}
