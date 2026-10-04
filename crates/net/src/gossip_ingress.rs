// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use anyhow::Result;
use chrono::{DateTime, Utc};
use libp2p::{gossipsub::MessageId, PeerId};

use crate::{
    domain::wire::decode_gossip,
    events::GossipData,
    seen_messages::{Admission, RateBudget, SeenIds},
    NetworkPolicy,
};

const PEER_RATE: u64 = 8;
const PEER_BURST: u64 = 32;
const PEER_BYTES_PER_SECOND: u64 = 1024 * 1024;
const PEER_BYTE_BURST: u64 = 20 * 1024 * 1024;
const MAX_TRACKED_PEERS: usize = 1024;
const PEER_IDLE_TTL: Duration = Duration::from_secs(60);

struct PeerBudget {
    messages: RateBudget,
    bytes: RateBudget,
    last_seen: Instant,
}

pub(crate) struct GossipIngress {
    seen: SeenIds<MessageId>,
    peers: HashMap<PeerId, PeerBudget>,
}

impl GossipIngress {
    pub(crate) fn new() -> Self {
        Self {
            seen: SeenIds::new(),
            peers: HashMap::new(),
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
        if !self.peers.contains_key(&peer) && self.peers.len() >= MAX_TRACKED_PEERS {
            self.peers.retain(|_, budget| {
                now.saturating_duration_since(budget.last_seen) < PEER_IDLE_TTL
            });
            if self.peers.len() >= MAX_TRACKED_PEERS {
                return Ok(None);
            }
        }
        let budget = self.peers.entry(peer).or_insert_with(|| PeerBudget {
            messages: RateBudget::new(PEER_RATE, PEER_BURST),
            bytes: RateBudget::new(PEER_BYTES_PER_SECOND, PEER_BYTE_BURST),
            last_seen: now,
        });
        budget.last_seen = now;
        if !budget.messages.take(1, now) || !budget.bytes.take(bytes.len() as u64, now) {
            return Ok(None);
        }
        let data = decode_gossip(bytes, network, wall_time)?;
        Ok((self.seen.admit(id, now) == Admission::New).then_some(data))
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

    #[test]
    fn a_peer_byte_budget_leaves_other_peers_admissible() -> Result<()> {
        use e3_events::{
            EventConstructorWithTimestamp, EventSource, InterfoldEvent, KeyshareCreated,
            Unsequenced,
        };
        use e3_utils::ArcBytes;
        let policy = NetworkPolicy::local_unrestricted();
        let peer = PeerId::random();
        let other = PeerId::random();
        let start = Instant::now();
        let wall = Utc::now();
        let mut ingress = GossipIngress::new();
        for index in 0..3 {
            let event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
                KeyshareCreated {
                    e3_id: E3id::new("1", 1),
                    party_id: index,
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
            assert_eq!(
                ingress
                    .validate(peer, &id, &bytes, &policy, start, wall)?
                    .is_some(),
                index < 2
            );
            if index == 2 {
                assert!(ingress
                    .validate(other, &id, &bytes, &policy, start, wall)?
                    .is_some());
            }
        }
        Ok(())
    }

    #[test]
    fn churn_is_throttled_before_a_handled_gossip_id_can_return() -> Result<()> {
        let policy = NetworkPolicy::local_unrestricted();
        let peer = PeerId::random();
        let start = Instant::now();
        let wall = Utc::now();
        let mut ingress = GossipIngress::new();
        let mut first = None;
        let mut accepted = 0;
        for index in 0u64..100_002 {
            let data = GossipData::DocumentPublishedNotification(DocumentPublishedNotification {
                key: ContentHash::from_content(&index.to_le_bytes()),
                ts: 1,
                meta: DocumentMeta::new(
                    E3id::new("1", 1),
                    DocumentKind::TrBFV,
                    vec![],
                    Some(wall + chrono::Duration::hours(12)),
                ),
            });
            let bytes = encode_gossip(&data, &policy, None)?;
            let id = MessageId::from(Sha256::digest(&bytes).to_vec());
            if index == 0 {
                first = Some((id.clone(), bytes.clone()));
            }
            accepted += usize::from(
                ingress
                    .validate(peer, &id, &bytes, &policy, start, wall)?
                    .is_some(),
            );
        }
        let (id, bytes) = first.unwrap();
        assert!(ingress
            .validate(
                peer,
                &id,
                &bytes,
                &policy,
                start + SEEN_TTL - Duration::from_secs(1),
                wall + chrono::Duration::hours(5)
            )?
            .is_none());
        assert_eq!(
            accepted, PEER_BURST as usize,
            "churn must stop before seen-ID admission"
        );
        assert!(ingress
            .validate(
                peer,
                &id,
                &bytes,
                &policy,
                start + SEEN_TTL,
                wall + chrono::Duration::hours(6)
            )?
            .is_some());
        Ok(())
    }
}
