// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! What the network carries under an operator's signature. A peer message is signed over all of
//! it, so a relay can change no field, and a receiver knows the sender without trusting the peer
//! that forwarded it. A peer proof ties a network identity to an operator.

use crate::{node::PeerMessage, UnixSecs};
use alloy_primitives::{keccak256, Address, Bytes, Signature, B256};
use bincode::Options;
use serde::{Deserialize, Serialize};

/// Keeps an envelope signature from passing as any other signature of the operator key.
const DOMAIN: &[u8] = b"interfold v2 peer message";
/// The same for a peer proof.
const PEER_DOMAIN: &[u8] = b"interfold v2 peer identity";

/// An operator's word that a network identity is theirs. Peer IDs are free and the chain names
/// none, so nothing else ties a peer to an operator. It names the peer, so a peer that is shown
/// one cannot pass it off as its own.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerProof {
    pub operator: Address,
    pub signature: Bytes,
}

impl PeerProof {
    /// The hash the operator key signs for the network identity `peer`.
    pub fn signing_hash(peer: &[u8]) -> B256 {
        keccak256([PEER_DOMAIN, peer].concat())
    }

    /// Whether `operator` signed that `peer` is theirs.
    pub fn holds_for(&self, peer: &[u8]) -> bool {
        Signature::try_from(self.signature.as_ref())
            .ok()
            .and_then(|signature| {
                signature
                    .recover_address_from_prehash(&Self::signing_hash(peer))
                    .ok()
            })
            .is_some_and(|signer| signer == self.operator)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub message: PeerMessage,
    /// When the sender sent this copy. Gossip drops repeats of the same bytes for a while, so
    /// each re-send is a new copy, and only the sender can make one.
    pub sent_at: UnixSecs,
    pub signature: Bytes,
}

impl Envelope {
    /// The hash the sender's operator key signs.
    pub fn signing_hash(message: &PeerMessage, sent_at: UnixSecs) -> B256 {
        let encoded = bincode::serialize(&(message, sent_at)).expect("a peer message encodes");
        keccak256([DOMAIN, &encoded].concat())
    }

    /// The message, if its sender's key signed all of it and every blob it names has bytes: no
    /// honest message names an empty one.
    pub fn open(self) -> Option<PeerMessage> {
        if self.message.blobs().iter().any(|blob| blob.len == 0) {
            return None;
        }
        let signature = Signature::try_from(self.signature.as_ref()).ok()?;
        let signer = signature
            .recover_address_from_prehash(&Self::signing_hash(&self.message, self.sent_at))
            .ok()?;
        (signer == self.message.sender).then_some(self.message)
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("an envelope encodes")
    }

    /// An envelope from bytes a peer sent; their length bounds what decoding may allocate.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(bytes.len() as u64)
            .deserialize(bytes)
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dkg::DkgMessage,
        node::Body,
        testing::{address, e3, operator},
    };
    use alloy_signer::SignerSync;

    fn signed(message: PeerMessage, by: u64) -> Envelope {
        let signature = operator(by)
            .sign_hash_sync(&Envelope::signing_hash(&message, 100))
            .unwrap();
        Envelope {
            message,
            sent_at: 100,
            signature: signature.as_bytes().into(),
        }
    }

    fn ready(sender: u64) -> PeerMessage {
        PeerMessage {
            e3: e3(1),
            sender: address(sender),
            body: Body::Dkg(DkgMessage::Ready(Vec::new())),
        }
    }

    #[test]
    fn an_envelope_opens_only_for_the_sender_that_signed_all_of_it() {
        let envelope = signed(ready(1), 1);
        assert_eq!(envelope.clone().open(), Some(ready(1)));
        assert_eq!(Envelope::decode(&envelope.encode()), Some(envelope.clone()));

        let mut relabeled = envelope.clone();
        relabeled.message.sender = address(2);
        assert_eq!(relabeled.open(), None);

        let mut moved = envelope.clone();
        moved.message.e3 = e3(2);
        assert_eq!(moved.open(), None);

        let mut copied = envelope;
        copied.sent_at = 101;
        assert_eq!(copied.open(), None, "only the sender makes a new copy");

        assert_eq!(signed(ready(1), 2).open(), None);
    }

    #[test]
    fn a_peer_proof_holds_only_for_the_peer_it_names_and_the_operator_that_signed() {
        let proof = PeerProof {
            operator: address(1),
            signature: operator(1)
                .sign_hash_sync(&PeerProof::signing_hash(b"peer one"))
                .unwrap()
                .as_bytes()
                .into(),
        };
        assert!(proof.holds_for(b"peer one"));
        assert!(!proof.holds_for(b"peer two"), "another peer cannot use it");

        let mut claimed = proof.clone();
        claimed.operator = address(2);
        assert!(!claimed.holds_for(b"peer one"));

        assert!(!PeerProof::default().holds_for(b"peer one"));
    }
}
