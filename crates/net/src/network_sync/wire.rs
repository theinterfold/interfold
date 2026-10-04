// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{ensure, Context, Result};
use bincode::Error;
use chrono::{DateTime, Utc};
use e3_events::{Event, EventContextAccessors, Filter, InterfoldEvent, Unsequenced};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    domain::EventTranslationService,
    events::{DocumentPublishedNotification, GossipData},
    network::{GOSSIP_WIRE_MAJOR, SYNC_WIRE_MAJOR},
    NetworkPolicy,
};

pub(crate) const MAX_GOSSIP_BYTES: usize = 10 * 1024 * 1024;
pub(crate) const MAX_DIRECT_MESSAGE_BYTES: usize = 10 * 1024 * 1024;
pub(crate) const MAX_DHT_DOCUMENT_BYTES: usize = 25 * 1024 * 1024;

const GOSSIP_MAGIC: [u8; 4] = *b"IFG3";
const SYNC_MAGIC: [u8; 4] = *b"IFS3";
const GOSSIP_SCHEMA_VERSION: u16 = GOSSIP_WIRE_MAJOR;
const SYNC_SCHEMA_VERSION: u16 = SYNC_WIRE_MAJOR;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum GossipMessageKind {
    Event,
    DocumentNotification,
}

#[derive(Debug, Serialize, Deserialize)]
struct GossipWireEnvelope {
    magic: [u8; 4],
    schema_version: u16,
    network_id: [u8; 32],
    kind: GossipMessageKind,
    chain_id: u64,
    deployment: [u8; 20],
    aggregate_id: u64,
    message_id: [u8; 32],
    delivery_id: Option<[u8; 16]>,
    payload_hash: [u8; 32],
    payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum SyncMessageKind {
    FetchEvents,
    EventBatch,
    SyncResponse,
}

#[derive(Debug, Serialize, Deserialize)]
struct SyncWireEnvelope {
    magic: [u8; 4],
    schema_version: u16,
    kind: SyncMessageKind,
    payload_hash: [u8; 32],
    payload: Vec<u8>,
}

/// Check the notification before forwarding, and again after a wait in the local buffer.
pub(crate) fn notification_is_valid(
    notification: &DocumentPublishedNotification,
    now: DateTime<Utc>,
) -> bool {
    notification_has_valid_shape(notification) && notification.meta.expires_at > now
}

fn notification_has_valid_shape(notification: &DocumentPublishedNotification) -> bool {
    notification.key.0.len() == 32
        && matches!(notification.meta.filter.as_slice(), [] | [Filter::Item(_)])
        && notification.meta.e3_id.e3_id().len() <= 78
}

#[derive(Debug)]
pub(crate) struct ExpiredDocumentNotification;

impl std::fmt::Display for ExpiredDocumentNotification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("expired document notification")
    }
}

impl std::error::Error for ExpiredDocumentNotification {}

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8], max_bytes: usize) -> Result<T, Error> {
    let max_bytes =
        u64::try_from(max_bytes).map_err(|_| Box::new(bincode::ErrorKind::SizeLimit))?;
    e3_utils::deserialize_bounded(bytes, max_bytes)
}

pub(crate) fn encode_gossip(
    data: &GossipData,
    policy: &NetworkPolicy,
    delivery_id: Option<[u8; 16]>,
) -> Result<Vec<u8>> {
    let payload = data.to_bytes()?;
    let (kind, chain_id, deployment, aggregate_id, message_id) = gossip_metadata(data, policy)?;
    let envelope = GossipWireEnvelope {
        magic: GOSSIP_MAGIC,
        schema_version: GOSSIP_SCHEMA_VERSION,
        network_id: policy.profile().id().into_bytes(),
        kind,
        chain_id,
        deployment,
        aggregate_id,
        message_id,
        delivery_id,
        payload_hash: sha256(&payload),
        payload,
    };
    let encoded = bincode::serialize(&envelope).context("failed to serialize gossip envelope")?;
    ensure!(
        encoded.len() <= MAX_GOSSIP_BYTES,
        "gossip envelope exceeds the {} byte limit",
        MAX_GOSSIP_BYTES
    );
    Ok(encoded)
}

pub(crate) fn decode_gossip(
    bytes: &[u8],
    policy: &NetworkPolicy,
    now: DateTime<Utc>,
) -> Result<GossipData> {
    let envelope: GossipWireEnvelope =
        decode(bytes, MAX_GOSSIP_BYTES).context("failed to deserialize gossip envelope")?;
    ensure!(
        envelope.magic == GOSSIP_MAGIC,
        "invalid gossip envelope magic"
    );
    ensure!(
        envelope.schema_version == GOSSIP_SCHEMA_VERSION,
        "unsupported gossip schema version {}",
        envelope.schema_version
    );
    ensure!(
        envelope.network_id == policy.profile().id().into_bytes(),
        "gossip envelope belongs to a different network"
    );
    ensure!(
        sha256(&envelope.payload) == envelope.payload_hash,
        "gossip payload hash does not match the envelope"
    );
    let data = GossipData::from_bytes(&envelope.payload)?;
    if let GossipData::DocumentPublishedNotification(notification) = &data {
        ensure!(
            notification_has_valid_shape(notification),
            "invalid document notification"
        );
    }
    let metadata = gossip_metadata(&data, policy)?;
    ensure!(
        metadata
            == (
                envelope.kind,
                envelope.chain_id,
                envelope.deployment,
                envelope.aggregate_id,
                envelope.message_id,
            ),
        "gossip envelope metadata does not match its payload"
    );
    if let GossipData::DocumentPublishedNotification(notification) = &data {
        ensure!(
            notification.meta.expires_at > now,
            ExpiredDocumentNotification
        );
    }
    Ok(data)
}

pub(crate) fn encode_sync<T: Serialize>(kind: SyncMessageKind, value: &T) -> Result<Vec<u8>> {
    let payload = bincode::serialize(value).context("failed to serialize sync payload")?;
    let envelope = SyncWireEnvelope {
        magic: SYNC_MAGIC,
        schema_version: SYNC_SCHEMA_VERSION,
        kind,
        payload_hash: sha256(&payload),
        payload,
    };
    let encoded = bincode::serialize(&envelope).context("failed to serialize sync envelope")?;
    ensure!(
        encoded.len() <= MAX_DIRECT_MESSAGE_BYTES,
        "sync envelope exceeds the {} byte limit",
        MAX_DIRECT_MESSAGE_BYTES
    );
    Ok(encoded)
}

pub(crate) fn decode_sync<T: DeserializeOwned>(
    bytes: &[u8],
    expected_kind: SyncMessageKind,
) -> Result<T> {
    let envelope: SyncWireEnvelope =
        decode(bytes, MAX_DIRECT_MESSAGE_BYTES).context("failed to deserialize sync envelope")?;
    ensure!(envelope.magic == SYNC_MAGIC, "invalid sync envelope magic");
    ensure!(
        envelope.schema_version == SYNC_SCHEMA_VERSION,
        "unsupported sync schema version {}",
        envelope.schema_version
    );
    ensure!(
        envelope.kind == expected_kind,
        "sync message kind {:?} does not match {:?}",
        envelope.kind,
        expected_kind
    );
    ensure!(
        sha256(&envelope.payload) == envelope.payload_hash,
        "sync payload hash does not match the envelope"
    );
    decode(&envelope.payload, MAX_DIRECT_MESSAGE_BYTES)
        .context("failed to deserialize sync payload")
}

type GossipMetadata = (GossipMessageKind, u64, [u8; 20], u64, [u8; 32]);

fn gossip_metadata(data: &GossipData, policy: &NetworkPolicy) -> Result<GossipMetadata> {
    match data {
        GossipData::GossipBytes(bytes) => {
            let event = InterfoldEvent::<Unsequenced>::from_bytes(bytes)
                .context("failed to deserialize gossip event")?;
            ensure!(
                EventTranslationService::is_forwardable_event(&event),
                "event type {} is not allowed on the protocol gossip topic",
                event.event_type()
            );
            policy.validate_event(&event)?;
            let chain_id = event
                .aggregate_id()
                .to_chain_id()
                .context("gossip event does not have a chain aggregate")?;
            let aggregate_id = chain_id;
            Ok((
                GossipMessageKind::Event,
                chain_id,
                policy.deployment_binding(chain_id)?,
                aggregate_id,
                event.id().0,
            ))
        }
        GossipData::DocumentPublishedNotification(notification) => {
            policy.validate_e3_id(&notification.meta.e3_id)?;
            let chain_id = notification.meta.e3_id.chain_id();
            Ok((
                GossipMessageKind::DocumentNotification,
                chain_id,
                policy.deployment_binding(chain_id)?,
                chain_id,
                sha256(&data.to_bytes()?),
            ))
        }
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Shared by the wire tests here and the sync actor tests.
#[cfg(test)]
pub(crate) mod fixtures {
    use e3_events::{
        E3id, EventConstructorWithTimestamp, EventSource, InterfoldEvent, KeyshareCreated,
        Unsequenced,
    };
    use e3_utils::ArcBytes;

    pub(crate) fn unsequenced_event() -> InterfoldEvent<Unsequenced> {
        InterfoldEvent::<Unsequenced>::new_with_timestamp(
            KeyshareCreated {
                pubkey: ArcBytes::from_bytes(b"public-key"),
                e3_id: E3id::new("1", 1),
                node: "node-1".to_string(),
                party_id: 1,
                signed_pk_generation_proof: None,
            }
            .into(),
            None,
            1,
            None,
            EventSource::Local,
        )
    }

    /// Asserts the length and SHA-256 digest of one wire message. A peer on another release decodes
    /// these bytes, so they change only with a gossip or sync wire version change, or a protocol
    /// version change. Update the expected values in that change. On failure the message prints the
    /// new bytes.
    pub(crate) fn assert_locked_bytes(name: &str, bytes: &[u8], len: usize, digest: &str) {
        assert_eq!(
            (bytes.len(), hex::encode(super::sha256(bytes)).as_str()),
            (len, digest),
            "the {name} wire bytes changed: {}",
            hex::encode(bytes)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{assert_locked_bytes, unsequenced_event};
    use super::*;
    use crate::domain::net_event_batch::{BatchCursor, EventBatch, FetchEventsSince};
    use e3_config::NetworkProfile;
    use e3_events::AggregateId;

    // The locked wire bytes for gossip wire 4 and sync wire 3.
    const GOSSIP_LEN: usize = 390;
    const GOSSIP_DIGEST: &str = "42f1309c42285bfa14ff3515f0396295ceb9c5d95847bf9cd55b2fcd59ab79bb";
    const FETCH_LEN: usize = 82;
    const FETCH_DIGEST: &str = "c7843e62df85a7e18fb8acca5285635f5b0936cca70709542995b4f7fd8b1496";
    const BATCH_LEN: usize = 297;
    const BATCH_DIGEST: &str = "440eaa7cfba38ed9ca359a681fda3710686207c18b4045e354fc5aba145ff046";
    const REQUEST_FRAME: (usize, &str) = (
        119,
        "80d4b2528825a099b2052ec2063a2ede1bebf06956021ec95fcfbc53e8997966",
    );
    const OK_FRAME: (usize, &str) = (
        123,
        "7c760f45c6c9e30ea8c645bda4beffea990c737ec9341fabd1cf1dcf8e10b19a",
    );
    const BAD_REQUEST_FRAME: (usize, &str) = (
        24,
        "642a7adb11e0f910ea6f6edbf0c27437872752d524997b6763da9a3f8e295b57",
    );
    const ERROR_FRAME: (usize, &str) = (
        13,
        "d9d63a05a856c947769f3755271cd8d7c9b6c91f4e249e95578d68b4338b339b",
    );

    fn forwardable_gossip() -> GossipData {
        unsequenced_event().into_sequenced(1).try_into().unwrap()
    }

    #[test]
    fn notification_shapes_are_checked_before_gossip() -> Result<()> {
        use crate::ContentHash;
        use e3_events::{DocumentKind, DocumentMeta, E3id};
        let policy = NetworkPolicy::local_unrestricted();
        let now = Utc::now();
        let valid = DocumentPublishedNotification {
            key: ContentHash::from_content(b"document"),
            ts: 1,
            meta: DocumentMeta::new(
                E3id::new("1", 1),
                DocumentKind::TrBFV,
                vec![],
                Some(now + chrono::Duration::hours(1)),
            ),
        };
        for (key, filter, e3, expiry, accepted) in [
            (
                valid.key.clone(),
                vec![],
                "1".into(),
                valid.meta.expires_at,
                true,
            ),
            (
                valid.key.clone(),
                vec![Filter::Item(7)],
                "9".repeat(78),
                valid.meta.expires_at,
                true,
            ),
            (
                ContentHash(vec![7; 33]),
                vec![],
                "1".into(),
                valid.meta.expires_at,
                false,
            ),
            (
                valid.key.clone(),
                vec![Filter::Item(1), Filter::Item(2)],
                "1".into(),
                valid.meta.expires_at,
                false,
            ),
            (
                valid.key.clone(),
                vec![Filter::Range(None, None)],
                "1".into(),
                valid.meta.expires_at,
                false,
            ),
            (
                valid.key.clone(),
                vec![],
                "9".repeat(79),
                valid.meta.expires_at,
                false,
            ),
            (valid.key.clone(), vec![], "1".into(), now, false),
        ] {
            let data = GossipData::DocumentPublishedNotification(DocumentPublishedNotification {
                key,
                meta: DocumentMeta::new(
                    E3id::new(&e3, 1),
                    DocumentKind::TrBFV,
                    filter,
                    Some(expiry),
                ),
                ..valid.clone()
            });
            let bytes = encode_gossip(&data, &policy, None)?;
            assert_eq!(
                decode_gossip(&bytes, &policy, now).is_ok(),
                accepted,
                "{data:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn gossip_envelope_round_trips_on_the_same_network() {
        let policy = NetworkPolicy::local_unrestricted();
        let expected = forwardable_gossip();
        let bytes = encode_gossip(&expected, &policy, None).unwrap();
        assert_eq!(
            decode_gossip(&bytes, &policy, Utc::now()).unwrap(),
            expected
        );
    }

    #[test]
    fn gossip_redelivery_changes_transport_bytes_but_not_protocol_data() {
        let policy = NetworkPolicy::local_unrestricted();
        let expected = forwardable_gossip();
        let first = encode_gossip(&expected, &policy, Some([1; 16])).unwrap();
        let second = encode_gossip(&expected, &policy, Some([2; 16])).unwrap();

        assert_ne!(first, second);
        assert_eq!(
            decode_gossip(&first, &policy, Utc::now()).unwrap(),
            expected
        );
        assert_eq!(
            decode_gossip(&second, &policy, Utc::now()).unwrap(),
            expected
        );
    }

    #[test]
    fn gossip_envelope_rejects_a_different_network() {
        let local = NetworkPolicy::local_unrestricted();
        let mainnet = NetworkPolicy::new(NetworkProfile::mainnet(), [(1, [1; 20])]).unwrap();
        let bytes = encode_gossip(&forwardable_gossip(), &local, None).unwrap();
        let error = decode_gossip(&bytes, &mainnet, Utc::now()).unwrap_err();
        assert!(error.to_string().contains("different network"));
    }

    #[test]
    fn gossip_envelope_rejects_a_different_contract_deployment() {
        let first = NetworkPolicy::new(NetworkProfile::mainnet(), [(1, [1; 20])]).unwrap();
        let second = NetworkPolicy::new(NetworkProfile::mainnet(), [(1, [2; 20])]).unwrap();
        let bytes = encode_gossip(&forwardable_gossip(), &first, None).unwrap();
        let error = decode_gossip(&bytes, &second, Utc::now()).unwrap_err();
        assert!(error.to_string().contains("metadata"));
    }

    #[test]
    fn sync_envelope_rejects_a_different_message_kind() {
        let bytes = encode_sync(SyncMessageKind::FetchEvents, &7u64).unwrap();
        let error = decode_sync::<u64>(&bytes, SyncMessageKind::EventBatch).unwrap_err();
        assert!(error.to_string().contains("message kind"));
    }

    /// `SyncResponseValue` has no lock here: the node passes it only inside the process, and a peer
    /// receives the `EventBatch` below.
    #[test]
    fn wire_message_bytes_are_locked() {
        let policy = NetworkPolicy::local_unrestricted();
        let gossip = encode_gossip(&forwardable_gossip(), &policy, Some([7; 16])).unwrap();
        assert_locked_bytes("gossip event envelope", &gossip, GOSSIP_LEN, GOSSIP_DIGEST);

        let fetch: Vec<u8> = FetchEventsSince::new(AggregateId::new(3), 5, 7)
            .try_into()
            .unwrap();
        assert_locked_bytes("FetchEvents", &fetch, FETCH_LEN, FETCH_DIGEST);

        let batch: Vec<u8> = EventBatch {
            events: vec![unsequenced_event()],
            next: BatchCursor::Next(9),
            aggregate_id: AggregateId::new(3),
        }
        .try_into()
        .unwrap();
        assert_locked_bytes("EventBatch", &batch, BATCH_LEN, BATCH_DIGEST);
    }

    /// Sync envelopes travel in CBOR frames that libp2p's request-response codec writes. CBOR
    /// writes variant names, so renaming a `ProtocolResponse` variant breaks a peer on another
    /// release.
    #[test]
    fn request_response_frame_bytes_are_locked() {
        use crate::events::ProtocolResponse;
        use futures::executor::block_on;
        use futures::io::Cursor;
        use libp2p::request_response::{cbor::codec::Codec, Codec as _};
        use libp2p::StreamProtocol;

        // The codec does not write the protocol name.
        let protocol = StreamProtocol::new("/unused");
        let mut codec = Codec::<Vec<u8>, ProtocolResponse>::default();
        let envelope: Vec<u8> = FetchEventsSince::new(AggregateId::new(3), 5, 7)
            .try_into()
            .unwrap();

        let mut frame = Cursor::new(Vec::new());
        block_on(codec.write_request(&protocol, &mut frame, envelope.clone())).unwrap();
        assert_locked_bytes(
            "request frame",
            frame.get_ref(),
            REQUEST_FRAME.0,
            REQUEST_FRAME.1,
        );

        for (name, response, (len, digest)) in [
            ("Ok frame", ProtocolResponse::Ok(envelope), OK_FRAME),
            (
                "BadRequest frame",
                ProtocolResponse::BadRequest("bad request".to_string()),
                BAD_REQUEST_FRAME,
            ),
            (
                "Error frame",
                ProtocolResponse::Error("error".to_string()),
                ERROR_FRAME,
            ),
        ] {
            let mut frame = Cursor::new(Vec::new());
            block_on(codec.write_response(&protocol, &mut frame, response)).unwrap();
            assert_locked_bytes(name, frame.get_ref(), len, digest);
        }
    }
}
