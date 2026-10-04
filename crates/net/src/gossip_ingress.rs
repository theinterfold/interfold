// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::time::Instant;

use anyhow::Result;
use chrono::{DateTime, Utc};
use libp2p::{gossipsub::MessageId, PeerId};

use crate::{
    domain::wire::decode_gossip,
    events::GossipData,
    seen_messages::{Admission, SeenIds},
    NetworkPolicy,
};

pub(crate) struct GossipIngress {
    seen: SeenIds<MessageId>,
}

impl GossipIngress {
    pub(crate) fn new() -> Self {
        Self {
            seen: SeenIds::new("gossip"),
        }
    }

    /// Check an admitted propagation peer before libp2p forwards its message.
    pub(crate) fn validate(
        &mut self,
        peer: PeerId,
        id: &MessageId,
        bytes: &[u8],
        network: &NetworkPolicy,
        now: Instant,
        wall_time: DateTime<Utc>,
    ) -> Result<Option<GossipData>> {
        if self.seen.contains(id, now) {
            return Ok(None);
        }
        let data = decode_gossip(bytes, network, wall_time)?;
        Ok((self.seen.admit(Some(peer), id, now) == Admission::New).then_some(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::wire::encode_gossip, events::DocumentPublishedNotification,
        seen_messages::SEEN_TTL, ContentHash,
    };
    use e3_events::{DocumentKind, DocumentMeta, E3id};
    use sha2::{Digest, Sha256};
    use std::time::Duration;

    #[test]
    fn sustained_peer_churn_preserves_another_peers_retained_id() -> Result<()> {
        let policy = NetworkPolicy::local_unrestricted();
        let peers = [PeerId::random(), PeerId::random(), PeerId::random()];
        let start = Instant::now();
        let wall = Utc::now();
        let mut ingress = GossipIngress::new();
        let data = |index: u64| {
            GossipData::DocumentPublishedNotification(DocumentPublishedNotification {
                key: ContentHash::from_content(&index.to_le_bytes()),
                ts: 1,
                meta: DocumentMeta::new(
                    E3id::new("1", 1),
                    DocumentKind::TrBFV,
                    vec![],
                    Some(wall + chrono::Duration::hours(12)),
                ),
            })
        };
        let bytes = encode_gossip(&data(0), &policy, None)?;
        let original = MessageId::from(Sha256::digest(&bytes).to_vec());
        assert!(ingress
            .validate(peers[2], &original, &bytes, &policy, start, wall)?
            .is_some());
        let mut index = 1;
        // Two sources each send eight distinct deliveries per second; a third sends one.
        for second in 0..SEEN_TTL.as_secs() {
            let now = start + Duration::from_secs(second);
            for (peer, count) in [(peers[0], 8), (peers[1], 8), (peers[2], 1)] {
                for _ in 0..count {
                    let encoded = encode_gossip(&data(index), &policy, None)?;
                    let id = MessageId::from(Sha256::digest(&encoded).to_vec());
                    assert!(
                        ingress
                            .validate(peer, &id, &encoded, &policy, now, wall)?
                            .is_some(),
                        "new protocol input must remain admissible at second {second}"
                    );
                    index += 1;
                }
            }
        }
        assert!(ingress
            .validate(
                peers[0],
                &original,
                &bytes,
                &policy,
                start + SEEN_TTL - Duration::from_secs(1),
                wall
            )?
            .is_none());
        assert!(ingress
            .validate(peers[2], &original, &bytes, &policy, start + SEEN_TTL, wall)?
            .is_some());
        Ok(())
    }

    #[test]
    fn valid_large_events_do_not_exhaust_a_relay_byte_budget() -> Result<()> {
        use e3_events::{
            EventConstructorWithTimestamp, EventSource, InterfoldEvent, KeyshareCreated,
            Unsequenced,
        };
        use e3_utils::ArcBytes;
        let policy = NetworkPolicy::local_unrestricted();
        let peer = PeerId::random();
        let mut ingress = GossipIngress::new();
        let now = Instant::now();
        for party_id in 0..4 {
            let event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
                KeyshareCreated {
                    e3_id: E3id::new("1", 1),
                    party_id,
                    node: "node".into(),
                    pubkey: ArcBytes::from_bytes(&vec![1; 9 * 1024 * 1024]),
                    signed_pk_generation_proof: None,
                }
                .into(),
                None,
                1,
                None,
                EventSource::Local,
            );
            let bytes = encode_gossip(&GossipData::GossipBytes(event.to_bytes()?), &policy, None)?;
            let id = MessageId::from(Sha256::digest(&bytes).to_vec());
            assert!(ingress
                .validate(peer, &id, &bytes, &policy, now, Utc::now())?
                .is_some());
        }
        Ok(())
    }
}
