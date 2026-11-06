// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Peer messages as the network carries them: each signed by its sender's operator key over all
//! of it, so a relay can change no field, and a receiver knows the sender without trusting the
//! peer that forwarded it.

use crate::node::PeerMessage;
use alloy_primitives::{keccak256, Bytes, Signature, B256};
use bincode::Options;
use serde::{Deserialize, Serialize};

/// Keeps an envelope signature from passing as any other signature of the operator key.
const DOMAIN: &[u8] = b"interfold v2 peer message";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub message: PeerMessage,
    pub signature: Bytes,
}

impl Envelope {
    /// The hash the sender's operator key signs.
    pub fn signing_hash(message: &PeerMessage) -> B256 {
        let encoded = bincode::serialize(message).expect("a peer message encodes");
        keccak256([DOMAIN, &encoded].concat())
    }

    /// The message, if its sender's key signed all of it.
    pub fn open(self) -> Option<PeerMessage> {
        let signature = Signature::try_from(self.signature.as_ref()).ok()?;
        let signer = signature
            .recover_address_from_prehash(&Self::signing_hash(&self.message))
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
            .sign_hash_sync(&Envelope::signing_hash(&message))
            .unwrap();
        Envelope {
            message,
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

        let mut moved = envelope;
        moved.message.e3 = e3(2);
        assert_eq!(moved.open(), None);

        assert_eq!(signed(ready(1), 2).open(), None);
    }
}
