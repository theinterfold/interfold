// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{ensure, Context, Result};
use bincode::Error;
use e3_events::{Event, EventContextAccessors, InterfoldEvent, Unsequenced};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    domain::EventTranslationService,
    events::GossipData,
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

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8], max_bytes: usize) -> Result<T, Error> {
    let max_bytes =
        u64::try_from(max_bytes).map_err(|_| Box::new(bincode::ErrorKind::SizeLimit))?;
    e3_utils::deserialize_bounded(bytes, max_bytes)
}

pub(crate) fn encode_gossip(data: &GossipData, policy: &NetworkPolicy) -> Result<Vec<u8>> {
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

pub(crate) fn decode_gossip(bytes: &[u8], policy: &NetworkPolicy) -> Result<GossipData> {
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

fn gossip_metadata(
    data: &GossipData,
    policy: &NetworkPolicy,
) -> Result<(GossipMessageKind, u64, [u8; 20], u64, [u8; 32])> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use e3_config::NetworkProfile;
    use e3_events::{E3id, EventConstructorWithTimestamp, EventSource, KeyshareCreated};
    use e3_utils::ArcBytes;

    fn forwardable_gossip() -> GossipData {
        let event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
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
        );
        event.into_sequenced(1).try_into().unwrap()
    }

    #[test]
    fn gossip_envelope_round_trips_on_the_same_network() {
        let policy = NetworkPolicy::local_unrestricted();
        let expected = forwardable_gossip();
        let bytes = encode_gossip(&expected, &policy).unwrap();
        assert_eq!(decode_gossip(&bytes, &policy).unwrap(), expected);
    }

    #[test]
    fn gossip_envelope_rejects_a_different_network() {
        let local = NetworkPolicy::local_unrestricted();
        let mainnet = NetworkPolicy::new(NetworkProfile::mainnet(), [(1, [1; 20])]).unwrap();
        let bytes = encode_gossip(&forwardable_gossip(), &local).unwrap();
        let error = decode_gossip(&bytes, &mainnet).unwrap_err();
        assert!(error.to_string().contains("different network"));
    }

    #[test]
    fn gossip_envelope_rejects_a_different_contract_deployment() {
        let first = NetworkPolicy::new(NetworkProfile::mainnet(), [(1, [1; 20])]).unwrap();
        let second = NetworkPolicy::new(NetworkProfile::mainnet(), [(1, [2; 20])]).unwrap();
        let bytes = encode_gossip(&forwardable_gossip(), &first).unwrap();
        let error = decode_gossip(&bytes, &second).unwrap_err();
        assert!(error.to_string().contains("metadata"));
    }

    #[test]
    fn sync_envelope_rejects_a_different_message_kind() {
        let bytes = encode_sync(SyncMessageKind::FetchEvents, &7u64).unwrap();
        let error = decode_sync::<u64>(&bytes, SyncMessageKind::EventBatch).unwrap_err();
        assert!(error.to_string().contains("message kind"));
    }

    #[test]
    fn sync_envelope_v3_fixture_is_stable() {
        let bytes = encode_sync(SyncMessageKind::FetchEvents, &7u64).unwrap();
        assert_eq!(
            hex::encode(bytes),
            "49465333030000000000aae89fc0f03e2959ae4d701a80cc3915918c950b159f6abb6c92c1433b1a853408000000000000000700000000000000"
        );
    }
}
