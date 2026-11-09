// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The names that keep one network apart from every other, and what a peer's Identify shows.

use libp2p::{gossipsub::IdentTopic, identify, StreamProtocol};

/// The protocol names of one deployment on one network, at one protocol version.
pub(crate) struct Protocols {
    pub(crate) topic: IdentTopic,
    pub(crate) identify: String,
    pub(crate) kademlia: StreamProtocol,
    pub(crate) blobs: StreamProtocol,
}

/// What a peer's Identify says about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Standing {
    /// Of another network or release, or missing a protocol the network needs.
    Refused,
    /// It serves lookups and takes no part in the network's messages.
    Bootstrap,
    Member,
}

impl Protocols {
    pub(crate) fn new(network: &str, deployment: &str, protocol_version: u32) -> Self {
        let prefix = format!("interfold/{network}/{deployment}/protocol/{protocol_version}");
        let stream = |name: &str| {
            StreamProtocol::try_from_owned(format!("/{prefix}/{name}"))
                .expect("a protocol name starts with a slash")
        };
        Self {
            topic: IdentTopic::new(format!("{prefix}/messages/2")),
            identify: format!("/{prefix}/identify/2"),
            kademlia: stream("kad/1.0.0"),
            blobs: stream("blobs/1"),
        }
    }

    /// Where a peer that identified as `info` stands on this network.
    pub(crate) fn standing(&self, info: &identify::Info) -> Standing {
        if info.protocol_version != self.identify || !info.protocols.contains(&self.kademlia) {
            return Standing::Refused;
        }
        match info.protocols.contains(&self.blobs) {
            true => Standing::Member,
            false => Standing::Bootstrap,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    fn info(version: String, offered: Vec<StreamProtocol>) -> identify::Info {
        identify::Info {
            public_key: Keypair::generate_ed25519().public(),
            protocol_version: version,
            agent_version: "test".into(),
            listen_addrs: Vec::new(),
            protocols: offered,
            observed_addr: "/ip4/127.0.0.1/udp/1/quic-v1".parse().unwrap(),
            signed_peer_record: None,
        }
    }

    #[test]
    fn a_peer_of_another_deployment_never_shares_a_name() {
        let ours = Protocols::new("mainnet", "aaaa", 8);
        let theirs = Protocols::new("mainnet", "bbbb", 8);
        assert_ne!(ours.identify, theirs.identify);
        assert_ne!(ours.topic.hash(), theirs.topic.hash());
        assert_ne!(ours.blobs, theirs.blobs);
    }

    #[test]
    fn identify_says_whether_a_peer_is_a_member_a_bootstrap_node_or_refused() {
        let ours = Protocols::new("mainnet", "aaaa", 8);
        let member = info(
            ours.identify.clone(),
            vec![ours.kademlia.clone(), ours.blobs.clone()],
        );
        assert_eq!(ours.standing(&member), Standing::Member);
        let bootstrap = info(ours.identify.clone(), vec![ours.kademlia.clone()]);
        assert_eq!(ours.standing(&bootstrap), Standing::Bootstrap);
        let no_lookups = info(ours.identify.clone(), vec![ours.blobs.clone()]);
        assert_eq!(ours.standing(&no_lookups), Standing::Refused);
        let other = info(
            "/interfold/other".into(),
            vec![ours.kademlia.clone(), ours.blobs.clone()],
        );
        assert_eq!(ours.standing(&other), Standing::Refused);
    }
}
