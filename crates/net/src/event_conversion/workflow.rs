// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{ensure, Context, Result};
use e3_events::{
    DecryptionKeyShared, DocumentKind, DocumentMeta, EncryptionKeyCreated, EncryptionKeyReceived,
    Filter, LbfvKeyShareDocument, LbfvKeyShareDocumentCreated, LbfvKeyShareDocumentFetchRequested,
    LbfvKeyShareDocumentReceived, PublishDocumentRequested, ThresholdShareCreated,
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

    /// Convert one local l-BFV key-share document into an unfiltered DHT request.
    pub fn lbfv_key_share_to_request(
        msg: LbfvKeyShareDocumentCreated,
    ) -> Result<PublishDocumentRequested> {
        msg.document.validate()?;
        let meta = DocumentMeta::new(
            msg.document.e3_id().clone(),
            DocumentKind::LbfvKeyShare,
            vec![],
            None,
        );
        let value = encode_lbfv(&msg.document)?;
        Ok(PublishDocumentRequested::new(meta, value))
    }

    /// Validate that independently-gossiped metadata describes the content-addressed DHT payload.
    pub fn validate_received(meta: &DocumentMeta, bytes: &[u8]) -> Result<()> {
        let incoming = Self::decode_received(meta, bytes)?;
        drop(incoming);
        Ok(())
    }

    /// Decode a received document payload into the internal event that should be published.
    ///
    /// Note: party filtering already happened in `DocumentPublisher` before the DHT fetch.
    pub fn decode_received(meta: &DocumentMeta, bytes: &[u8]) -> Result<IncomingDocument> {
        ensure!(
            !matches!(meta.kind, DocumentKind::LbfvKeyShare),
            "l-BFV key-share documents require a targeted fetch request"
        );
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
        })
    }

    /// Decode and validate a document against one targeted l-BFV fetch identity.
    pub fn decode_lbfv_fetch(
        request: &LbfvKeyShareDocumentFetchRequested,
        bytes: &[u8],
    ) -> Result<LbfvKeyShareDocumentReceived> {
        let request = request.request();
        let actual_hash = e3_events::lbfv_document_hash(bytes);
        ensure!(
            actual_hash == request.content_hash,
            "l-BFV DHT document SHA-256 does not match the requested content hash"
        );

        let document: LbfvKeyShareDocument = decode(bytes, MAX_DHT_DOCUMENT_BYTES)
            .context("could not deserialize the targeted l-BFV key-share document")?;
        ensure!(
            document.e3_id() == &request.e3_id,
            "l-BFV DHT document E3 does not match the targeted fetch"
        );
        ensure!(
            document.context().proof_session_id == request.proof_session_id,
            "l-BFV DHT document proof session does not match the targeted fetch"
        );
        ensure!(
            document.context().party_id == request.party_id,
            "l-BFV DHT document party does not match the targeted fetch"
        );
        ensure!(
            document.role() == request.role,
            "l-BFV DHT document role does not match the targeted fetch"
        );
        document.validate()?;

        Ok(LbfvKeyShareDocumentReceived {
            document,
            content_hash: actual_hash,
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
    encode_bounded(&doc.to_bytes()?)
}

fn encode_lbfv(doc: &LbfvKeyShareDocument) -> Result<ArcBytes> {
    encode_bounded(&doc.to_bytes()?)
}

fn encode_bounded(bytes: &[u8]) -> Result<ArcBytes> {
    ensure!(
        bytes.len() <= MAX_DHT_DOCUMENT_BYTES,
        "DHT document size {} exceeds the {} byte limit",
        bytes.len(),
        MAX_DHT_DOCUMENT_BYTES
    );
    Ok(ArcBytes::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        primitives::{Address, B256, U256},
        signers::local::PrivateKeySigner,
    };
    use e3_committee_hash::{hash_lbfv_proof_session, LbfvProofDomainContext};
    use e3_events::{
        E3id, EncryptionKey, LbfvKeyShareDocumentContextV1, LbfvKeyShareDocumentFetchRequestedV1,
        LbfvKeyShareDocumentRole, LbfvPublicKeyShareDocumentV1,
        LbfvRelinearizationKeyShareDocumentV1, Proof, ProofPayload, ProofType, SignedProofPayload,
    };
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

    fn lbfv_context() -> LbfvKeyShareDocumentContextV1 {
        let e3_id = E3id::new("9", 1);
        let proof_domain = LbfvProofDomainContext {
            protocol_version: 4,
            chain_id: 1,
            interfold_address: Address::repeat_byte(0x11),
            e3_id: U256::from(9),
            crypto_config_id: B256::repeat_byte(0x22),
            finalized_committee_hash: B256::repeat_byte(0x33),
            lbfv_constants_version: 1,
            ciphertext_level: 0,
            key_level: 0,
        };
        LbfvKeyShareDocumentContextV1 {
            e3_id,
            proof_domain,
            proof_session_id: hash_lbfv_proof_session(proof_domain),
            party_id: 1,
        }
    }

    fn signed_proof(
        context: &LbfvKeyShareDocumentContextV1,
        proof_type: ProofType,
        row: u32,
        signer: &PrivateKeySigner,
    ) -> SignedProofPayload {
        let circuit = proof_type.circuit_names()[0];
        let public_signals = if proof_type.is_multirow() {
            let layout = circuit.input_layout();
            let session = e3_committee_hash::split_hash_to_field_limbs(context.proof_session_id);
            let field_count =
                layout.field_count().unwrap() + circuit.output_layout().field_count().unwrap();
            let mut signals = vec![0u8; field_count * 32];
            let session_hi = layout.field_index("session_id_hi").unwrap();
            signals[session_hi * 32 + 16..session_hi * 32 + 32]
                .copy_from_slice(&session.hi.to_be_bytes());
            let session_lo = layout.field_index("session_id_lo").unwrap();
            signals[session_lo * 32 + 16..session_lo * 32 + 32]
                .copy_from_slice(&session.lo.to_be_bytes());
            let party_id = layout.field_index("party_id").unwrap();
            signals[party_id * 32 + 28..party_id * 32 + 32]
                .copy_from_slice(&context.party_id.to_be_bytes());
            let row_index = layout.field_index("row_index").unwrap();
            signals[row_index * 32 + 28..row_index * 32 + 32].copy_from_slice(&row.to_be_bytes());
            signals
        } else {
            vec![0; circuit.output_layout().field_count().unwrap() * 32]
        };
        SignedProofPayload::sign(
            ProofPayload {
                e3_id: context.e3_id.clone(),
                proof_type,
                proof: Proof::new(
                    circuit,
                    ArcBytes::from_bytes(&[1]),
                    ArcBytes::from_bytes(&public_signals),
                ),
            },
            signer,
        )
        .unwrap()
    }

    fn lbfv_public_key_document(share_len: usize) -> LbfvKeyShareDocument {
        let signer: PrivateKeySigner =
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                .parse()
                .unwrap();
        let context = lbfv_context();
        LbfvKeyShareDocument::PublicKeyV1(LbfvPublicKeyShareDocumentV1 {
            context: context.clone(),
            share: ArcBytes::from_bytes(&vec![7; share_len]),
            signed_c1_proof: signed_proof(&context, ProofType::C1PkGeneration, 0, &signer),
            signed_row_proofs: std::array::from_fn(|row| {
                signed_proof(&context, ProofType::LbfvPkGeneration, row as u32, &signer)
            }),
        })
    }

    fn lbfv_relinearization_key_document(share_len: usize) -> LbfvKeyShareDocument {
        let signer: PrivateKeySigner =
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                .parse()
                .unwrap();
        let context = lbfv_context();
        LbfvKeyShareDocument::RelinearizationKeyV1(LbfvRelinearizationKeyShareDocumentV1 {
            context: context.clone(),
            share: ArcBytes::from_bytes(&vec![7; share_len]),
            signed_row_proofs: std::array::from_fn(|row| {
                signed_proof(&context, ProofType::RlkGeneration, row as u32, &signer)
            }),
        })
    }

    fn lbfv_fetch_request(document: &LbfvKeyShareDocument) -> LbfvKeyShareDocumentFetchRequested {
        LbfvKeyShareDocumentFetchRequested::V1(LbfvKeyShareDocumentFetchRequestedV1 {
            e3_id: document.e3_id().clone(),
            proof_session_id: document.context().proof_session_id,
            party_id: document.context().party_id,
            role: document.role(),
            content_hash: document.content_hash().unwrap(),
            attempt: 1,
        })
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

    #[test]
    fn targeted_lbfv_document_roundtrip_binds_identity_and_content_hash() {
        for document in [
            lbfv_public_key_document(64),
            lbfv_relinearization_key_document(64),
        ] {
            let request =
                EventConversionService::lbfv_key_share_to_request(LbfvKeyShareDocumentCreated {
                    document: document.clone(),
                })
                .unwrap();

            assert_eq!(request.meta.e3_id, *document.e3_id());
            assert_eq!(request.meta.kind, DocumentKind::LbfvKeyShare);
            assert!(request.meta.filter.is_empty());
            let received = EventConversionService::decode_lbfv_fetch(
                &lbfv_fetch_request(&document),
                &request.value,
            )
            .unwrap();
            assert_eq!(received.document, document);
            assert_eq!(
                received.content_hash,
                e3_events::lbfv_document_hash(&request.value)
            );
        }
    }

    #[test]
    fn generic_lbfv_conversion_is_suppressed() {
        let document = lbfv_public_key_document(64);
        let bytes = document.to_bytes().unwrap();
        let meta = DocumentMeta::new(
            document.e3_id().clone(),
            DocumentKind::LbfvKeyShare,
            vec![],
            None,
        );
        assert!(EventConversionService::validate_received(&meta, &bytes)
            .unwrap_err()
            .to_string()
            .contains("require a targeted fetch"));
    }

    #[test]
    fn targeted_lbfv_document_rejects_wrong_identity() {
        let document = lbfv_public_key_document(64);
        let bytes = document.to_bytes().unwrap();
        let mut wrong_e3 = lbfv_fetch_request(&document);
        let LbfvKeyShareDocumentFetchRequested::V1(identity) = &mut wrong_e3;
        identity.e3_id = E3id::new("10", 1);
        assert!(EventConversionService::decode_lbfv_fetch(&wrong_e3, &bytes)
            .unwrap_err()
            .to_string()
            .contains("E3 does not match"));

        let mut wrong_session = lbfv_fetch_request(&document);
        let LbfvKeyShareDocumentFetchRequested::V1(identity) = &mut wrong_session;
        identity.proof_session_id = B256::repeat_byte(0x99);
        assert!(
            EventConversionService::decode_lbfv_fetch(&wrong_session, &bytes)
                .unwrap_err()
                .to_string()
                .contains("proof session does not match")
        );

        let mut wrong_party = lbfv_fetch_request(&document);
        let LbfvKeyShareDocumentFetchRequested::V1(identity) = &mut wrong_party;
        identity.party_id += 1;
        assert!(
            EventConversionService::decode_lbfv_fetch(&wrong_party, &bytes)
                .unwrap_err()
                .to_string()
                .contains("party does not match")
        );

        let mut wrong_role = lbfv_fetch_request(&document);
        let LbfvKeyShareDocumentFetchRequested::V1(identity) = &mut wrong_role;
        identity.role = LbfvKeyShareDocumentRole::RelinearizationKey;
        assert!(
            EventConversionService::decode_lbfv_fetch(&wrong_role, &bytes)
                .unwrap_err()
                .to_string()
                .contains("role does not match")
        );

        let mut wrong_hash = lbfv_fetch_request(&document);
        let LbfvKeyShareDocumentFetchRequested::V1(identity) = &mut wrong_hash;
        identity.content_hash = B256::repeat_byte(0x88);
        assert!(
            EventConversionService::decode_lbfv_fetch(&wrong_hash, &bytes)
                .unwrap_err()
                .to_string()
                .contains("SHA-256 does not match")
        );
    }

    #[test]
    fn secure_lbfv_share_fits_one_dht_document() {
        for document in [
            lbfv_public_key_document(5_222_596),
            lbfv_relinearization_key_document(5_222_618),
        ] {
            let request =
                EventConversionService::lbfv_key_share_to_request(LbfvKeyShareDocumentCreated {
                    document,
                })
                .unwrap();
            assert!(request.value.len() <= MAX_DHT_DOCUMENT_BYTES);
        }
    }

    #[test]
    fn oversized_lbfv_document_is_rejected_before_publication() {
        let document = lbfv_public_key_document(MAX_DHT_DOCUMENT_BYTES);
        let error =
            EventConversionService::lbfv_key_share_to_request(LbfvKeyShareDocumentCreated {
                document,
            })
            .unwrap_err();
        assert!(error.to_string().contains("exceeds the"));
    }
}
