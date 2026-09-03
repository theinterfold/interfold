// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{ensure, Context, Result};
use e3_events::{
    DecryptionKeyShared, DocumentKind, DocumentMeta, EncryptionKeyCreated, EncryptionKeyReceived,
    Filter, PublishDocumentRequested, RelinCeremonyShare, ThresholdShareCreated,
};
use e3_utils::ArcBytes;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use super::wire::{decode, MAX_DHT_DOCUMENT_BYTES};

/// Wire representation of a document that is published to / received from the network.
///
/// This is the serialized payload stored in the DHT. Disambiguation between the document
/// variants happens here on deserialization.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReceivableDocument {
    ThresholdShareCreated(ThresholdShareCreated),
    EncryptionKeyCreated(EncryptionKeyCreated),
    DecryptionKeyShared(DecryptionKeyShared),
    RelinCeremonyShare(RelinCeremonyShare),
}

impl ReceivableDocument {
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        decode(bytes, MAX_DHT_DOCUMENT_BYTES)
    }

    fn e3_id(&self) -> &e3_events::E3id {
        match self {
            Self::ThresholdShareCreated(event) => &event.e3_id,
            Self::EncryptionKeyCreated(event) => &event.e3_id,
            Self::DecryptionKeyShared(event) => &event.e3_id,
            Self::RelinCeremonyShare(event) => &event.e3_id,
        }
    }

    fn validate_meta(&self, meta: &DocumentMeta) -> Result<()> {
        ensure!(
            self.e3_id() == &meta.e3_id,
            "DHT document metadata E3 {} does not match payload E3 {}",
            meta.e3_id,
            self.e3_id()
        );
        ensure!(
            matches!(&meta.kind, DocumentKind::TrBFV),
            "DHT document metadata has an unsupported document kind"
        );

        match self {
            Self::ThresholdShareCreated(event) => ensure!(
                matches!(
                    meta.filter.as_slice(),
                    [Filter::Item(target)] if *target == event.target_party_id
                ),
                "threshold-share metadata must target payload party {}",
                event.target_party_id
            ),
            Self::EncryptionKeyCreated(_) | Self::DecryptionKeyShared(_) => ensure!(
                meta.filter.is_empty(),
                "broadcast key document metadata must not contain party filters"
            ),
            Self::RelinCeremonyShare(event) => {
                ensure!(
                    meta.filter.is_empty(),
                    "relin ceremony document metadata must not contain party filters"
                );
                // Wire-level envelope sanity before the keyshare machine
                // sees the chunk: round, index/count, and non-empty body.
                ensure!(
                    event.round == 1 || event.round == 2,
                    "relin ceremony document names round {}; only 1 and 2 exist",
                    event.round
                );
                ensure!(
                    event.chunk_count > 0 && event.chunk_index < event.chunk_count,
                    "relin ceremony document chunk {}/{} is malformed",
                    event.chunk_index,
                    event.chunk_count
                );
                ensure!(
                    event.party_id > 0,
                    "relin ceremony document party id 0 is not a Shamir coordinate"
                );
                ensure!(
                    event.chunk.size() > 0,
                    "relin ceremony document carries an empty chunk"
                );
            }
        }

        Ok(())
    }
}

/// A document received from the network, decoded into the internal event it should be
/// republished as on the local bus.
#[derive(Clone, Debug)]
pub enum IncomingDocument {
    ThresholdShare(ThresholdShareCreated),
    EncryptionKey(EncryptionKeyReceived),
    DecryptionKey(DecryptionKeyShared),
    RelinShare(RelinCeremonyShare),
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

    /// Convert a local relin-ceremony broadcast to a DHT publication
    /// (unfiltered broadcast: every committee member aggregates all
    /// parties' shares).
    pub fn relin_share_to_request(
        msg: RelinCeremonyShare,
    ) -> Result<Option<PublishDocumentRequested>> {
        if msg.external {
            return Ok(None);
        }
        let meta = DocumentMeta::new(msg.e3_id.clone(), DocumentKind::TrBFV, vec![], None);
        let value = encode(&ReceivableDocument::RelinCeremonyShare(msg))?;
        Ok(Some(PublishDocumentRequested::new(meta, value)))
    }

    /// Validate that independently-gossiped metadata describes the content-addressed DHT payload.
    pub fn validate_received(meta: &DocumentMeta, bytes: &[u8]) -> Result<()> {
        let receivable = Self::decode_and_validate(meta, bytes)?;
        drop(receivable);
        Ok(())
    }

    /// Decode a received document payload into the internal event that should be published.
    ///
    /// Note: party filtering already happened in `DocumentPublisher` before the DHT fetch.
    pub fn decode_received(meta: &DocumentMeta, bytes: &[u8]) -> Result<IncomingDocument> {
        let receivable = Self::decode_and_validate(meta, bytes)?;
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
            ReceivableDocument::RelinCeremonyShare(evt) => {
                debug!(
                    "Received RelinCeremonyShare round {} from party {}",
                    evt.round, evt.party_id
                );
                IncomingDocument::RelinShare(RelinCeremonyShare {
                    external: true,
                    ..evt
                })
            }
        })
    }

    fn decode_and_validate(meta: &DocumentMeta, bytes: &[u8]) -> Result<ReceivableDocument> {
        let receivable = ReceivableDocument::from_bytes(bytes)
            .context("Could not deserialize document bytes")?;
        receivable.validate_meta(meta)?;
        Ok(receivable)
    }
}

fn encode(doc: &ReceivableDocument) -> Result<ArcBytes> {
    Ok(ArcBytes::from_bytes(&doc.to_bytes()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::{E3id, EncryptionKey};
    use std::sync::Arc;

    fn encryption_key_document(e3_id: E3id) -> ReceivableDocument {
        ReceivableDocument::EncryptionKeyCreated(EncryptionKeyCreated {
            e3_id,
            key: Arc::new(EncryptionKey::new(1, ArcBytes::from_bytes(b"pk"))),
            external: false,
        })
    }

    fn meta(e3_id: E3id) -> DocumentMeta {
        DocumentMeta::new(e3_id, DocumentKind::TrBFV, vec![], None)
    }

    #[test]
    fn decode_received_rejects_garbage() {
        assert!(EventConversionService::decode_received(
            &meta(E3id::new("1", 1)),
            b"not a document"
        )
        .is_err());
    }

    #[test]
    fn received_document_must_match_metadata_e3_and_chain() {
        let payload_id = E3id::new("9", 1);
        let bytes = encryption_key_document(payload_id.clone())
            .to_bytes()
            .unwrap();

        EventConversionService::validate_received(&meta(payload_id), &bytes).unwrap();

        let wrong_e3 = EventConversionService::validate_received(&meta(E3id::new("10", 1)), &bytes)
            .unwrap_err();
        assert!(wrong_e3.to_string().contains("1:10"));
        assert!(wrong_e3.to_string().contains("1:9"));

        let wrong_chain =
            EventConversionService::validate_received(&meta(E3id::new("9", 2)), &bytes)
                .unwrap_err();
        assert!(wrong_chain.to_string().contains("2:9"));
        assert!(wrong_chain.to_string().contains("1:9"));
    }

    #[test]
    fn broadcast_key_document_rejects_party_filter_relabeling() {
        let e3_id = E3id::new("9", 1);
        let bytes = encryption_key_document(e3_id.clone()).to_bytes().unwrap();
        let filtered = DocumentMeta::new(e3_id, DocumentKind::TrBFV, vec![Filter::Item(3)], None);

        let error = EventConversionService::validate_received(&filtered, &bytes).unwrap_err();
        assert!(error.to_string().contains("must not contain party filters"));
    }

    fn relin_document(e3_id: E3id) -> RelinCeremonyShare {
        RelinCeremonyShare {
            e3_id,
            party_id: 2,
            node: "n".into(),
            round: 1,
            level: 0,
            chunk_index: 0,
            chunk_count: 1,
            payload_keccak: [7u8; 32],
            chunk: ArcBytes::from_bytes(b"chunk"),
            external: false,
        }
    }

    #[test]
    fn relin_ceremony_document_envelope_is_validated_at_the_wire() {
        let e3_id = E3id::new("9", 1);
        let ok = ReceivableDocument::RelinCeremonyShare(relin_document(e3_id.clone()))
            .to_bytes()
            .unwrap();
        EventConversionService::validate_received(&meta(e3_id.clone()), &ok).unwrap();

        let cases: Vec<(&str, Box<dyn Fn(&mut RelinCeremonyShare)>)> = vec![
            ("only 1 and 2 exist", Box::new(|d| d.round = 3)),
            ("is malformed", Box::new(|d| d.chunk_count = 0)),
            ("is malformed", Box::new(|d| d.chunk_index = d.chunk_count)),
            ("not a Shamir coordinate", Box::new(|d| d.party_id = 0)),
            (
                "empty chunk",
                Box::new(|d| d.chunk = ArcBytes::from_bytes(b"")),
            ),
        ];
        for (needle, mutate) in cases {
            let mut doc = relin_document(e3_id.clone());
            mutate(&mut doc);
            let bytes = ReceivableDocument::RelinCeremonyShare(doc)
                .to_bytes()
                .unwrap();
            let error = EventConversionService::validate_received(&meta(e3_id.clone()), &bytes)
                .unwrap_err();
            assert!(error.to_string().contains(needle), "{needle}: {error}");
        }
    }
}
