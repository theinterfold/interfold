// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Tests that feed the events of a real swarm to `process_swarm_event` and dial through the real
//! `NodeBehaviour`.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use libp2p::kad::{Record, RecordKey};
use libp2p::swarm::ConnectionId;
use libp2p::{Multiaddr, PeerId};

/// The state that `start` keeps for one node, so a test can feed swarm events to
/// `process_swarm_event` without the timers of the event loop.
struct TestNode {
    interface: super::Libp2pNetInterface,
    correlator: super::Correlator,
    peer_failures: super::PeerConnectionFailures,
    admission: super::PeerAdmission,
    dht_records: HashMap<PeerId, HashSet<Vec<u8>>>,
    seen_gossip: super::SeenIds<libp2p::gossipsub::MessageId>,
    dht_puts: super::DhtPutSummary,
}

impl TestNode {
    fn new() -> anyhow::Result<Self> {
        let mut interface = super::Libp2pNetInterface::new(
            super::Libp2pKeypair::generate(),
            vec![],
            None,
            super::NetworkPolicy::local_unrestricted(),
        )?;
        let topic = interface.topic.clone();
        interface
            .swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&topic)?;
        Ok(Self {
            interface,
            correlator: super::Correlator::new(),
            peer_failures: super::PeerConnectionFailures::new(),
            admission: super::PeerAdmission::default(),
            dht_records: Default::default(),
            seen_gossip: super::SeenIds::new(super::SEEN_GOSSIP_TTL, 16),
            dht_puts: super::DhtPutSummary::default(),
        })
    }

    fn peer_id(&self) -> PeerId {
        *self.interface.swarm.local_peer_id()
    }

    fn health(&mut self) -> &mut super::GossipSubscriptionHealth {
        &mut self.interface.swarm.behaviour_mut().gossip_health
    }

    async fn next_event(&mut self) -> anyhow::Result<super::SwarmEvent<super::NodeBehaviourEvent>> {
        use libp2p::futures::StreamExt;
        tokio::time::timeout(
            Duration::from_secs(20),
            self.interface.swarm.select_next_some(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("the swarm emitted no event in time"))
    }

    async fn process(
        &mut self,
        event: super::SwarmEvent<super::NodeBehaviourEvent>,
    ) -> anyhow::Result<()> {
        super::process_swarm_event(
            &mut self.interface.swarm,
            &self.interface.event_tx,
            &self.interface.cmd_tx,
            &mut self.correlator,
            &mut self.peer_failures,
            &mut self.admission,
            &mut [],
            &mut self.dht_records,
            &mut self.seen_gossip,
            &mut self.dht_puts,
            &self.interface.network,
            &self.interface.status,
            event,
        )
        .await
    }

    fn dial(&mut self, peer: PeerId) -> Result<(), libp2p::swarm::DialError> {
        let address: Multiaddr = "/ip4/127.0.0.1/udp/9/quic-v1".parse().expect("address");
        self.interface.swarm.dial(
            libp2p::swarm::dial_opts::DialOpts::peer_id(peer)
                .addresses(vec![address])
                .build(),
        )
    }
}

fn is_redial_backoff(error: &libp2p::swarm::DialError) -> bool {
    matches!(
        error,
        libp2p::swarm::DialError::Denied { cause }
            if cause.downcast_ref::<crate::gossip_subscription_health::RedialBackoff>().is_some()
    )
}

#[tokio::test]
async fn redial_backoff_refuses_outbound_dials_until_a_subscription() -> anyhow::Result<()> {
    let mut node = TestNode::new()?;
    let peer = PeerId::random();
    node.health()
        .disconnected_unsubscribed(peer, Instant::now());

    let refused = node.dial(peer).expect_err("a dial during the backoff");
    assert!(is_redial_backoff(&refused), "{refused}");

    node.health().subscribed(&peer);
    node.dial(peer)?;
    Ok(())
}

/// A Kademlia query keeps the candidates that it chose before the disconnect, and dials them
/// with addresses from its routing table or the Identify cache. The backoff holds back these
/// dials too.
#[tokio::test]
async fn dht_query_does_not_dial_a_peer_in_redial_backoff() -> anyhow::Result<()> {
    let mut node = TestNode::new()?;
    let peer = PeerId::random();
    let address: Multiaddr = "/ip4/127.0.0.2/udp/9/quic-v1".parse()?;
    let kademlia = &mut node.interface.swarm.behaviour_mut().kademlia;
    kademlia.add_address(&peer, address);
    let query = kademlia.get_closest_peers(PeerId::random());
    node.health()
        .disconnected_unsubscribed(peer, Instant::now());

    loop {
        match node.next_event().await? {
            super::SwarmEvent::Dialing {
                peer_id: Some(dialed),
                ..
            } if dialed == peer => anyhow::bail!("the query dialed a peer in its backoff"),
            super::SwarmEvent::Behaviour(super::NodeBehaviourEvent::Kademlia(
                libp2p::kad::Event::OutboundQueryProgressed { id, .. },
            )) if id == query => return Ok(()),
            _ => {}
        }
    }
}

/// A peer that subscribes after its admission ends its backoff at the subscribe event, so a
/// disconnect before the next health check leaves it free to be dialed at once.
#[tokio::test]
async fn subscribe_event_after_admission_ends_the_redial_backoff() -> anyhow::Result<()> {
    let mut node = TestNode::new()?;
    let peer = PeerId::random();
    let address: Multiaddr = "/ip4/127.0.0.1/udp/9/quic-v1".parse()?;
    node.admission
        .stage(
            peer,
            super::PeerAdmission::pending(ConnectionId::new_unchecked(1), address, "inbound", 1),
        )
        .map_err(|kind| anyhow::anyhow!("staging failed: {kind:?}"))?;
    node.admission.admit(peer);
    node.health()
        .disconnected_unsubscribed(peer, Instant::now());

    let topic = node.interface.topic.hash();
    node.process(super::SwarmEvent::Behaviour(
        super::NodeBehaviourEvent::Gossipsub(libp2p::gossipsub::Event::Subscribed {
            peer_id: peer,
            topic,
        }),
    ))
    .await?;

    node.dial(peer)?;
    Ok(())
}

/// A peer that subscribes before its admission: the node ignores the subscribe event and sees
/// the subscription when Identify admits the peer. That also ends the backoff at once.
#[tokio::test]
async fn subscription_before_admission_ends_the_redial_backoff() -> anyhow::Result<()> {
    let mut node = TestNode::new()?;
    node.interface
        .swarm
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse()?)?;
    let address = loop {
        if let super::SwarmEvent::NewListenAddr { address, .. } = node.next_event().await? {
            break address;
        }
    };
    let mut remote = TestNode::new()?;
    let remote_id = remote.peer_id();
    // Read the backoff at its start, so the check below cannot pass because the backoff ran out.
    let backoff_start = Instant::now();
    node.health()
        .disconnected_unsubscribed(remote_id, backoff_start);
    remote.interface.swarm.dial(address)?;
    let remote_task = tokio::spawn(async move {
        use libp2p::futures::StreamExt;
        loop {
            remote.interface.swarm.select_next_some().await;
        }
    });

    // Hold the Identify result back until the subscribe event of the remote was processed.
    let mut identify = None;
    let mut subscribed = false;
    while identify.is_none() || !subscribed {
        match node.next_event().await? {
            event @ super::SwarmEvent::Behaviour(super::NodeBehaviourEvent::Identify(
                libp2p::identify::Event::Received { peer_id, .. },
            )) if peer_id == remote_id && identify.is_none() => identify = Some(event),
            event @ super::SwarmEvent::Behaviour(super::NodeBehaviourEvent::Gossipsub(
                libp2p::gossipsub::Event::Subscribed { peer_id, .. },
            )) if peer_id == remote_id && !subscribed => {
                node.process(event).await?;
                assert!(!node.admission.is_admitted(&remote_id));
                subscribed = true;
            }
            event => {
                let _ = node.process(event).await;
            }
        }
    }
    node.process(identify.expect("held above")).await?;
    remote_task.abort();

    assert!(node.admission.is_admitted(&remote_id));
    assert!(node
        .interface
        .swarm
        .behaviour()
        .gossip_health
        .may_redial(&remote_id, backoff_start));
    Ok(())
}

/// Every finished DHT upload reaches the summary, also one that the network interface cannot
/// match to a command.
#[tokio::test]
async fn finished_dht_upload_is_counted_for_the_summary() -> anyhow::Result<()> {
    let mut node = TestNode::new()?;
    let record = Record::new(RecordKey::new(&b"document"), b"value".to_vec());
    let query = node
        .interface
        .swarm
        .behaviour_mut()
        .kademlia
        .put_record(record, libp2p::kad::Quorum::One)?;

    loop {
        let event = node.next_event().await?;
        let finished = matches!(
            &event,
            super::SwarmEvent::Behaviour(super::NodeBehaviourEvent::Kademlia(
                libp2p::kad::Event::OutboundQueryProgressed { id, .. },
            )) if *id == query
        );
        let _ = node.process(event).await;
        if finished {
            break;
        }
    }
    assert_eq!(node.dht_puts.take(), Some((0, 1)));
    Ok(())
}
