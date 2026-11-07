// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Three nodes in one process, each with its own blob store, connected over loopback QUIC.

use super::*;
use alloy_primitives::Bytes;
use alloy_signer::SignerSync;
use e3_blobs::{BlobError, BlobStore, Blobs, E3Blobs, FileBlobs};
use e3_protocol::{
    dkg::{DkgMessage, KeyMessage, SharesMessage},
    node::Body,
    proof::{SignedProof, ZkProof},
    testing::{address, e3, operator},
    BlobRef,
};
use tempfile::TempDir;

const WAIT: Duration = Duration::from_secs(30);

struct Node {
    p2p: P2p,
    inbound: mpsc::Receiver<PeerMessage>,
    store: FileBlobs,
    /// The blobs of E3 1, which most tests use.
    blobs: E3Blobs<FileBlobs>,
    _dir: TempDir,
}

async fn node(n: u64, peers: Vec<Multiaddr>) -> Node {
    started(n, peers, |blobs| blobs).await
}

/// A node whose store serves other bytes than it holds.
async fn forger(n: u64, peers: Vec<Multiaddr>) -> Node {
    started(n, peers, Forging).await
}

async fn started<S: BlobStore>(
    n: u64,
    peers: Vec<Multiaddr>,
    serve: impl FnOnce(FileBlobs) -> S,
) -> Node {
    let dir = tempfile::tempdir().unwrap();
    let blobs = FileBlobs::open(dir.path()).unwrap();
    let (p2p, inbound) = P2p::start(config(n, peers), address(n), serve(blobs.clone()))
        .await
        .unwrap();
    p2p.admit((1..=3).map(address).collect());
    Node {
        p2p,
        inbound,
        blobs: blobs.of(e3(1)),
        store: blobs,
        _dir: dir,
    }
}

fn config(n: u64, peers: Vec<Multiaddr>) -> P2pConfig {
    P2pConfig {
        identity: [n as u8; 32],
        network: "test".into(),
        protocol_version: 1,
        listen: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        peers,
    }
}

#[derive(Clone)]
struct Forging(FileBlobs);

impl BlobStore for Forging {
    fn put(&self, e3: E3Id, bytes: &[u8]) -> Result<BlobRef, BlobError> {
        self.0.put(e3, bytes)
    }

    fn get(&self, _: E3Id, _: &BlobRef) -> Result<Vec<u8>, BlobError> {
        Ok(b"forged".to_vec())
    }

    fn has(&self, e3: E3Id, blob: &BlobRef) -> bool {
        self.0.has(e3, blob)
    }

    fn close(&self, e3: E3Id) -> Result<(), BlobError> {
        self.0.close(e3)
    }

    fn retain(&self, keep: impl Fn(&E3Id) -> bool) -> Result<(), BlobError> {
        self.0.retain(keep)
    }
}

/// Operators 1, 2 and 3, each connected to the others.
async fn network() -> [Node; 3] {
    let first = node(1, Vec::new()).await;
    let second = node(2, first.p2p.listening().to_vec()).await;
    let peers = [first.p2p.listening(), second.p2p.listening()].concat();
    let third = node(3, peers).await;
    [first, second, third]
}

/// Copy `copy` of `message`, signed now; copies with different numbers are different bytes.
fn signed(message: PeerMessage, signer: u64, copy: u64) -> Envelope {
    signed_at(message, signer, unix_now() - 300 + copy)
}

fn signed_at(message: PeerMessage, signer: u64, sent_at: u64) -> Envelope {
    let hash = Envelope::signing_hash(&message, sent_at);
    let signature = operator(signer).sign_hash_sync(&hash).unwrap();
    Envelope {
        message,
        sent_at,
        signature: signature.as_bytes().into(),
    }
}

fn proof(blobs: &E3Blobs<FileBlobs>, bytes: &[u8]) -> SignedProof {
    SignedProof {
        proof: ZkProof {
            data: blobs.put(bytes).unwrap(),
            public_inputs: Vec::new(),
        },
        signature: Bytes::new(),
    }
}

/// Operator `sender`'s encryption key, which every member needs.
fn key(node: &Node, sender: u64) -> PeerMessage {
    key_in(node, e3(1), sender)
}

fn key_in(node: &Node, e3: E3Id, sender: u64) -> PeerMessage {
    let blobs = node.store.of(e3);
    let message = KeyMessage {
        key: blobs.put(format!("key of {sender}").as_bytes()).unwrap(),
        proof: proof(&blobs, b"key proof"),
    };
    PeerMessage {
        e3,
        sender: address(sender),
        body: Body::Dkg(DkgMessage::EncryptionKey(message)),
    }
}

/// Operator `sender`'s shares for `recipient`, which only the recipient needs.
fn shares(node: &Node, sender: u64, recipient: u64) -> PeerMessage {
    let message = SharesMessage {
        recipient: address(recipient),
        pk_share: node.blobs.put(b"pk share").unwrap(),
        shares: node
            .blobs
            .put(format!("shares for {recipient}").as_bytes())
            .unwrap(),
        c2a: proof(&node.blobs, b"c2a"),
        c2b: proof(&node.blobs, b"c2b"),
        c3a: vec![proof(&node.blobs, b"c3a")],
        c3b: vec![proof(&node.blobs, b"c3b")],
    };
    PeerMessage {
        e3: e3(1),
        sender: address(sender),
        body: Body::Dkg(DkgMessage::Shares(Box::new(message))),
    }
}

async fn publish(node: &Node, envelope: Envelope) {
    node.p2p.publish(envelope).await.unwrap();
}

async fn received(node: &mut Node) -> PeerMessage {
    tokio::time::timeout(WAIT, node.inbound.recv())
        .await
        .expect("a message in time")
        .expect("the network runs")
}

async fn fetch(node: &Node, message: PeerMessage) -> Result<(), NetworkError> {
    tokio::time::timeout(WAIT, node.p2p.fetch(message))
        .await
        .expect("a fetch ends in time")
}

async fn nothing(node: &mut Node, within: Duration) {
    if let Ok(message) = tokio::time::timeout(within, node.inbound.recv()).await {
        panic!("expected no message, got {message:?}");
    }
}

/// A message arrives before its blobs; a fetch brings them from its publisher.
#[tokio::test(flavor = "multi_thread")]
async fn a_broadcast_reaches_every_peer_and_its_blobs_come_on_request() {
    let [first, mut second, mut third] = network().await;
    let message = key(&first, 1);
    publish(&first, signed(message.clone(), 1, 10)).await;
    for node in [&mut second, &mut third] {
        assert_eq!(received(node).await, message);
        assert!(message.blobs().iter().all(|blob| !node.blobs.has(blob)));
        fetch(node, message.clone()).await.unwrap();
        assert!(message.blobs().iter().all(|blob| node.blobs.has(blob)));
    }
}

/// A launcher may know a peer's address but not its identity.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_given_by_its_address_alone_is_reached() {
    let first = node(1, Vec::new()).await;
    let bare = first
        .p2p
        .listening()
        .iter()
        .map(|address| {
            address
                .iter()
                .filter(|protocol| !matches!(protocol, Protocol::P2p(_)))
                .collect()
        })
        .collect();
    let mut second = node(2, bare).await;
    let message = key(&first, 1);
    publish(&first, signed(message.clone(), 1, 10)).await;
    assert_eq!(received(&mut second).await, message);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_share_reaches_only_its_recipient() {
    let [first, mut second, mut third] = network().await;
    let message = shares(&first, 1, 3);
    publish(&first, signed(message.clone(), 1, 10)).await;
    assert_eq!(received(&mut third).await, message);
    fetch(&third, message.clone()).await.unwrap();
    nothing(&mut second, Duration::from_secs(3)).await;
    let Body::Dkg(DkgMessage::Shares(sent)) = &message.body else {
        unreachable!("a share message")
    };
    assert!(!second.blobs.has(&sent.shares));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_envelope_its_sender_did_not_sign_is_dropped() {
    let [first, mut second, _third] = network().await;
    publish(&first, signed(key(&first, 1), 2, 10)).await;
    let genuine = key(&first, 1);
    publish(&first, signed(genuine.clone(), 1, 11)).await;
    assert_eq!(received(&mut second).await, genuine);
    nothing(&mut second, Duration::from_secs(2)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_copy_sent_again_arrives_again() {
    let [first, mut second, _third] = network().await;
    let message = key(&first, 1);
    publish(&first, signed(message.clone(), 1, 10)).await;
    assert_eq!(received(&mut second).await, message);
    publish(&first, signed(message.clone(), 1, 70)).await;
    assert_eq!(received(&mut second).await, message);
}

/// After gossip forgot a copy, a relay can send it again; an old copy is not delivered, and
/// neither is one from far ahead of this node's clock.
#[tokio::test(flavor = "multi_thread")]
async fn an_old_or_future_copy_is_not_delivered() {
    let [first, mut second, _third] = network().await;
    let message = key(&first, 1);
    let old = unix_now() - MAX_COPY_AGE - 60;
    publish(&first, signed_at(message.clone(), 1, old)).await;
    let ahead = unix_now() + MAX_CLOCK_AHEAD + 60;
    publish(&first, signed_at(message.clone(), 1, ahead)).await;
    nothing(&mut second, Duration::from_secs(3)).await;
    publish(&first, signed(message.clone(), 1, 10)).await;
    assert_eq!(received(&mut second).await, message);
}

/// The dealer and the recipient each know only the first node; the recipient finds the dealer
/// through it and fetches the share's blobs from the dealer.
#[tokio::test(flavor = "multi_thread")]
async fn a_recipient_finds_a_dealer_it_was_not_told_about() {
    let first = node(1, Vec::new()).await;
    let second = node(2, first.p2p.listening().to_vec()).await;
    let mut third = node(3, first.p2p.listening().to_vec()).await;
    let message = shares(&second, 2, 3);
    // A copy can arrive before the two have found each other; a re-send then reaches it.
    for sent_at in 10.. {
        assert!(sent_at < 20, "the recipient never fetched from the dealer");
        publish(&second, signed(message.clone(), 2, sent_at)).await;
        let arrived = tokio::time::timeout(Duration::from_secs(5), third.inbound.recv()).await;
        let Ok(Some(arrived)) = arrived else {
            continue;
        };
        assert_eq!(arrived, message);
        if fetch(&third, message.clone()).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert!(message.blobs().iter().all(|blob| third.blobs.has(blob)));
}

/// Nodes that know only a bootstrap node find each other through it. It does not carry their
/// messages, so one that arrives shows the two connected.
#[tokio::test(flavor = "multi_thread")]
async fn nodes_that_know_only_a_bootstrap_node_find_each_other() {
    let bootstrap = P2p::bootstrap(config(9, Vec::new())).await.unwrap();
    let first = node(1, bootstrap.listening().to_vec()).await;
    let mut second = node(2, bootstrap.listening().to_vec()).await;
    let message = key(&first, 1);
    publish(&first, signed(message.clone(), 1, 10)).await;
    assert_eq!(received(&mut second).await, message);
}

/// A node takes a message only from an operator its chain reader has named; until then it
/// neither delivers the message nor passes it on.
#[tokio::test(flavor = "multi_thread")]
async fn a_message_from_an_operator_the_node_does_not_know_is_not_taken() {
    let [first, mut second, _third] = network().await;
    second.p2p.admit([2, 3].map(address).into());
    let message = key(&first, 1);
    publish(&first, signed(message.clone(), 1, 10)).await;
    nothing(&mut second, Duration::from_secs(3)).await;
    second.p2p.admit((1..=3).map(address).collect());
    publish(&first, signed(message.clone(), 1, 70)).await;
    assert_eq!(received(&mut second).await, message);
}

#[test]
fn a_node_that_other_hosts_reach_shares_no_loopback_address() {
    let address = |text: &str| -> Multiaddr { text.parse().unwrap() };
    let loopback = address("/ip4/127.0.0.1/udp/9000/quic-v1");
    let mapped = address("/ip6/::ffff:127.0.0.1/udp/9000/quic-v1");
    let lan = address("/ip4/192.168.1.5/udp/9000/quic-v1");
    let given = vec![loopback.clone(), mapped, lan.clone()];
    let one_host: Vec<_> = routable(&[loopback], given.clone()).collect();
    assert_eq!(one_host, given);
    let reached: Vec<_> = routable(std::slice::from_ref(&lan), given).collect();
    assert_eq!(reached, vec![lan]);
}

/// After a restart the node has not heard the message, so it knows no peer to ask.
#[tokio::test(flavor = "multi_thread")]
async fn a_message_the_node_never_heard_cannot_be_fetched() {
    let [first, second, _third] = network().await;
    let result = fetch(&second, key(&first, 1)).await;
    assert!(
        matches!(result, Err(NetworkError::Unavailable)),
        "{result:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_message_that_names_too_many_bytes_is_not_fetched() {
    let [first, mut second, _third] = network().await;
    let mut message = shares(&first, 1, 2);
    let Body::Dkg(DkgMessage::Shares(sent)) = &mut message.body else {
        unreachable!("a share message")
    };
    let huge = |n: u8| BlobRef {
        hash: B256::repeat_byte(n),
        len: 30 * 1024 * 1024,
    };
    sent.c3a = (1..=40)
        .map(|n| SignedProof {
            proof: ZkProof {
                data: huge(n),
                public_inputs: Vec::new(),
            },
            signature: Bytes::new(),
        })
        .collect();
    publish(&first, signed(message.clone(), 1, 10)).await;
    assert_eq!(received(&mut second).await, message);
    let result = fetch(&second, message).await;
    assert!(matches!(result, Err(NetworkError::Busy)), "{result:?}");
}

/// Placeholder proofs of one kind have the same bytes in every E3. The publisher deleted the
/// copy of the E3 that sent them last.
#[tokio::test(flavor = "multi_thread")]
async fn a_blob_two_e3s_share_comes_from_the_copy_of_the_e3_asked_for() {
    let [first, mut second, _third] = network().await;
    let one = key_in(&first, e3(1), 1);
    let two = key_in(&first, e3(2), 1);
    publish(&first, signed(one.clone(), 1, 10)).await;
    assert_eq!(received(&mut second).await, one);
    publish(&first, signed(two.clone(), 1, 11)).await;
    assert_eq!(received(&mut second).await, two);
    first.store.retain(|kept| *kept == e3(1)).unwrap();
    fetch(&second, one).await.unwrap();
}

/// The publisher's store holds other bytes under the blob's name; a receiver keeps nothing from it.
#[tokio::test(flavor = "multi_thread")]
async fn a_blob_with_other_bytes_is_never_stored() {
    let first = forger(1, Vec::new()).await;
    let mut second = node(2, first.p2p.listening().to_vec()).await;
    let message = key(&first, 1);
    let Body::Dkg(DkgMessage::EncryptionKey(sent)) = &message.body else {
        unreachable!("a key message")
    };
    let forged = sent.key;
    publish(&first, signed(message.clone(), 1, 10)).await;
    assert_eq!(received(&mut second).await, message);
    let result = fetch(&second, message).await;
    assert!(
        matches!(result, Err(NetworkError::Unavailable)),
        "{result:?}"
    );
    assert!(!second.blobs.has(&forged));
}
