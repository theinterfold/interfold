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
    let config = P2pConfig {
        identity: [n as u8; 32],
        network: "test".into(),
        protocol_version: 1,
        listen: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        peers,
    };
    let (p2p, inbound) = P2p::start(config, address(n), serve(blobs.clone()))
        .await
        .unwrap();
    Node {
        p2p,
        inbound,
        blobs: blobs.of(e3(1)),
        _dir: dir,
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

fn signed(message: PeerMessage, signer: u64, sent_at: u64) -> Envelope {
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
    let message = KeyMessage {
        key: node
            .blobs
            .put(format!("key of {sender}").as_bytes())
            .unwrap(),
        proof: proof(&node.blobs, b"key proof"),
    };
    PeerMessage {
        e3: e3(1),
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
