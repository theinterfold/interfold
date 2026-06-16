// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{Context, Result};
use e3_events::{
    DecryptionKeyShared, DocumentKind, DocumentMeta, EncryptionKeyCreated, EncryptionKeyReceived,
    Filter, PublishDocumentRequested, ThresholdShareCreated,
};
use e3_utils::ArcBytes;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

/// Wire representation of a document that is published to / received from the network.
///
/// This is the serialized payload stored in the DHT. Disambiguation between the document
/// variants happens here on deserialization.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReceivableDocument {
    ThresholdShareCreated(ThresholdShareCreated),
    EncryptionKeyCreated(EncryptionKeyCreated),
    DecryptionKeyShared(DecryptionKeyShared),
}

impl ReceivableDocument {
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// A document received from the network, decoded into the internal event it should be
/// republished as on the local bus.
#[derive(Clone, Debug)]
pub enum IncomingDocument {
    ThresholdShare(ThresholdShareCreated),
    EncryptionKey(EncryptionKeyReceived),
    DecryptionKey(DecryptionKeyShared),
}

/// Pure converter between internal events and network document payloads.
///
/// - Outgoing: local events → party-filtered [`PublishDocumentRequested`] (or `None` for events
///   that originated remotely and must not be re-published).
/// - Incoming: received document bytes → the internal event to publish locally.
///
/// No actix/bus state — the owning actor performs the publishing.
pub struct EventConversionService;

impl EventConversionService {
    /// Local node created a threshold share (already split per-party by ThresholdKeyshare).
    /// Produces the single-party document with the appropriate filter, or `None` for
    /// externally-sourced events.
    pub fn threshold_share_to_request(
        msg: ThresholdShareCreated,
    ) -> Result<Option<PublishDocumentRequested>> {
        if msg.external {
            return Ok(None);
        }
        let target_party_id = msg.target_party_id;
        info!(
            "Publishing ThresholdShare from party {} for target party {} (E3 {})",
            msg.share.party_id, target_party_id, msg.e3_id
        );
        let e3_id = msg.e3_id.clone();
        let meta = DocumentMeta::new(
            e3_id,
            DocumentKind::TrBFV,
            vec![Filter::Item(target_party_id)],
            None,
        );
        let value = encode(&ReceivableDocument::ThresholdShareCreated(msg))?;
        Ok(Some(PublishDocumentRequested::new(meta, value)))
    }

    /// Convert a locally-created encryption key into an unfiltered publish request, or `None`
    /// for externally-sourced events.
    pub fn encryption_key_to_request(
        msg: EncryptionKeyCreated,
    ) -> Result<Option<PublishDocumentRequested>> {
        if msg.external {
            return Ok(None);
        }
        let meta = DocumentMeta::new(msg.e3_id.clone(), DocumentKind::TrBFV, vec![], None);
        let value = encode(&ReceivableDocument::EncryptionKeyCreated(msg))?;
        Ok(Some(PublishDocumentRequested::new(meta, value)))
    }

    /// Convert a locally-created decryption key share into an unfiltered publish request, or
    /// `None` for externally-sourced events.
    pub fn decryption_key_to_request(
        msg: DecryptionKeyShared,
    ) -> Result<Option<PublishDocumentRequested>> {
        if msg.external {
            return Ok(None);
        }
        let meta = DocumentMeta::new(msg.e3_id.clone(), DocumentKind::TrBFV, vec![], None);
        let value = encode(&ReceivableDocument::DecryptionKeyShared(msg))?;
        Ok(Some(PublishDocumentRequested::new(meta, value)))
    }

    /// Decode a received document payload into the internal event that should be published.
    ///
    /// Note: party filtering already happened in `DocumentPublisher` before the DHT fetch.
    pub fn decode_received(bytes: &[u8]) -> Result<IncomingDocument> {
        let receivable = ReceivableDocument::from_bytes(bytes)
            .context("Could not deserialize document bytes")?;
        Ok(match receivable {
            ReceivableDocument::ThresholdShareCreated(evt) => {
                debug!(
                    "Received ThresholdShareCreated from party {} for target party {}",
                    evt.share.party_id, evt.target_party_id
                );
                IncomingDocument::ThresholdShare(ThresholdShareCreated {
                    external: true,
                    e3_id: evt.e3_id,
                    share: evt.share,
                    target_party_id: evt.target_party_id,
                    signed_c2a_proof: evt.signed_c2a_proof,
                    signed_c2b_proof: evt.signed_c2b_proof,
                    signed_c3a_proofs: evt.signed_c3a_proofs,
                    signed_c3b_proofs: evt.signed_c3b_proofs,
                })
            }
            ReceivableDocument::EncryptionKeyCreated(evt) => {
                debug!(
                    "Received EncryptionKeyCreated from party {}",
                    evt.key.party_id
                );
                IncomingDocument::EncryptionKey(EncryptionKeyReceived {
                    e3_id: evt.e3_id,
                    key: evt.key,
                })
            }
            ReceivableDocument::DecryptionKeyShared(evt) => {
                debug!("Received DecryptionKeyShared from party {}", evt.party_id);
                IncomingDocument::DecryptionKey(DecryptionKeyShared {
                    external: true,
                    ..evt
                })
            }
        })
    }
}

fn encode(doc: &ReceivableDocument) -> Result<ArcBytes> {
    Ok(ArcBytes::from_bytes(&doc.to_bytes()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_received_rejects_garbage() {
        assert!(EventConversionService::decode_received(b"not a document").is_err());
    }
}
