// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Nodes in one process, each with its own blob store, connected over loopback QUIC.

use super::*;
use crate::Network;
use alloy_primitives::Bytes;
use alloy_signer::SignerSync;
use e3_blobs::{BlobError, BlobStore, Blobs, E3Blobs, FileBlobs};
use e3_protocol::{
    dkg::{DkgMessage, KeyMessage, SharesMessage},
    node::Body,
    proof::{SignedProof, ZkProof},
    testing::{address, e3, operator},
    BlobRef, SealedRef,
};
use libp2p::multiaddr::Protocol;
use tempfile::TempDir;

const WAIT: Duration = Duration::from_secs(30);

struct Node {
    p2p: P2p,
    inbound: Inbox,
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
    started(n, peers, |blobs| {
        Answering(blobs, |_: &FileBlobs, _: E3Id, _: &B256| {
            Some(b"forged".to_vec())
        })
    })
    .await
}

/// A node that takes a moment over every read, so that requests overlap.
async fn slow(n: u64, peers: Vec<Multiaddr>) -> Node {
    started(n, peers, |blobs| {
        Answering(blobs, |store: &FileBlobs, e3: E3Id, hash: &B256| {
            std::thread::sleep(Duration::from_millis(300));
            store.serve(e3, hash)
        })
    })
    .await
}

async fn started<S: BlobStore>(
    n: u64,
    peers: Vec<Multiaddr>,
    serve: impl FnOnce(FileBlobs) -> S,
) -> Node {
    let dir = tempfile::tempdir().unwrap();
    let blobs = FileBlobs::open(dir.path()).unwrap();
    let config = config(n, peers);
    let proof = proof_of(n, &config);
    let (p2p, inbound) = P2p::start(config, proof, serve(blobs.clone()))
        .await
        .unwrap();
    p2p.admit(team(1..=3));
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
        deployment: "local".into(),
        protocol_version: 1,
        listen: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        peers,
    }
}

/// Operator `n`'s word that the network identity of `config` is theirs.
fn proof_of(n: u64, config: &P2pConfig) -> PeerProof {
    let signature = operator(n)
        .sign_hash_sync(&config.proof_hash().unwrap())
        .unwrap();
    PeerProof {
        operator: address(n),
        signature: signature.as_bytes().into(),
    }
}

/// `operators` send messages and are the committee of E3s 1 and 2.
fn team(operators: impl IntoIterator<Item = u64>) -> Admission {
    let members: BTreeSet<_> = operators.into_iter().map(address).collect();
    Admission {
        committees: [e3(1), e3(2)].map(|e3| (e3, members.clone())).into(),
        senders: members,
    }
}

/// A store that answers peers' requests with `.1`.
#[derive(Clone)]
struct Answering<F>(FileBlobs, F);

impl<F> BlobStore for Answering<F>
where
    F: Fn(&FileBlobs, E3Id, &B256) -> Option<Vec<u8>> + Clone + Send + Sync + 'static,
{
    fn put(&self, e3: E3Id, bytes: &[u8]) -> Result<BlobRef, BlobError> {
        self.0.put(e3, bytes)
    }

    fn get(&self, e3: E3Id, blob: &BlobRef) -> Result<Vec<u8>, BlobError> {
        self.0.get(e3, blob)
    }

    fn has(&self, e3: E3Id, blob: &BlobRef) -> bool {
        self.0.has(e3, blob)
    }

    fn serve(&self, e3: E3Id, hash: &B256) -> Option<Vec<u8>> {
        (self.1)(&self.0, e3, hash)
    }

    fn put_sealed(&self, e3: E3Id, bytes: &[u8]) -> Result<SealedRef, BlobError> {
        self.0.put_sealed(e3, bytes)
    }

    fn get_sealed(&self, e3: E3Id, secret: &SealedRef) -> Result<Vec<u8>, BlobError> {
        self.0.get_sealed(e3, secret)
    }

    fn keep(&self, e3: E3Id, key: &B256, value: &[u8]) -> Result<(), BlobError> {
        self.0.keep(e3, key, value)
    }

    fn kept(&self, e3: E3Id, key: &B256) -> Result<Option<Vec<u8>>, BlobError> {
        self.0.kept(e3, key)
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

/// Operator `signer` sends copies of `message` until all of `nodes` have heard it: a node that
/// just connected is not on the topic yet.
async fn heard_by(publisher: &Node, signer: u64, nodes: &mut [Node], message: &PeerMessage) {
    let mut waiting: Vec<usize> = (0..nodes.len()).collect();
    for copy in 10..120 {
        publish(publisher, signed(message.clone(), signer, copy)).await;
        for index in std::mem::take(&mut waiting) {
            let wait = Duration::from_millis(250);
            let heard = tokio::time::timeout(wait, nodes[index].inbound.next()).await;
            if !matches!(heard, Ok(Some(_))) {
                waiting.push(index);
            }
        }
        if waiting.is_empty() {
            return;
        }
    }
    panic!("a node never heard the message");
}

async fn received(node: &mut Node) -> PeerMessage {
    tokio::time::timeout(WAIT, node.inbound.next())
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
    if let Ok(message) = tokio::time::timeout(within, node.inbound.next()).await {
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
    let third = node(3, first.p2p.listening().to_vec()).await;
    let message = shares(&second, 2, 3);
    // A copy can arrive before the two have found each other; a re-send then reaches it.
    for sent_at in 10.. {
        assert!(sent_at < 20, "the recipient never fetched from the dealer");
        publish(&second, signed(message.clone(), 2, sent_at)).await;
        let arrived = tokio::time::timeout(Duration::from_secs(5), third.inbound.next()).await;
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
    let (bootstrap, _stopped) = P2p::bootstrap(config(9, Vec::new())).await.unwrap();
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
    second.p2p.admit(team([2, 3]));
    let message = key(&first, 1);
    publish(&first, signed(message.clone(), 1, 10)).await;
    nothing(&mut second, Duration::from_secs(3)).await;
    second.p2p.admit(team(1..=3));
    publish(&first, signed(message.clone(), 1, 70)).await;
    assert_eq!(received(&mut second).await, message);
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
async fn a_message_that_names_too_many_blobs_is_not_fetched() {
    let [first, mut second, _third] = network().await;
    let mut message = shares(&first, 1, 2);
    let Body::Dkg(DkgMessage::Shares(sent)) = &mut message.body else {
        unreachable!("a share message")
    };
    let huge = |n: u8| BlobRef {
        hash: B256::repeat_byte(n),
        len: 1024,
    };
    sent.c3a = (1..=200)
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

/// A restarted node still serves what it holds: it asks the store, not a list made since it
/// started.
#[tokio::test(flavor = "multi_thread")]
async fn a_restarted_node_serves_what_it_holds() {
    let first = node(1, Vec::new()).await;
    let mut second = node(2, first.p2p.listening().to_vec()).await;
    let message = key(&first, 1);
    publish(&first, signed(message.clone(), 1, 10)).await;
    assert_eq!(received(&mut second).await, message);
    let Node {
        p2p, store, _dir, ..
    } = first;
    p2p.close().await;
    drop(p2p);
    let config = config(1, second.p2p.listening().to_vec());
    let proof = proof_of(1, &config);
    let (restarted, _inbox) = P2p::start(config, proof, store).await.unwrap();
    restarted.admit(team(1..=3));
    for _ in 0..30 {
        if fetch(&second, message.clone()).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    panic!("the restarted node never served its blob");
}

/// A peer with a good proof of an operator off the committee gets nothing; a member gets the blob.
#[tokio::test(flavor = "multi_thread")]
async fn a_blob_goes_only_to_a_member_of_its_committee() {
    let first = node(1, Vec::new()).await;
    let peers = first.p2p.listening().to_vec();
    let mut nodes = [node(2, peers.clone()).await, node(4, peers).await];
    let message = key(&first, 1);
    heard_by(&first, 1, &mut nodes, &message).await;
    let [member, stranger] = &nodes;

    let result = fetch(stranger, message.clone()).await;
    assert!(
        matches!(result, Err(NetworkError::Unavailable)),
        "{result:?}"
    );
    assert!(message.blobs().iter().all(|blob| !stranger.blobs.has(blob)));
    fetch(member, message.clone()).await.unwrap();
    assert!(message.blobs().iter().all(|blob| member.blobs.has(blob)));
}

/// Operator 2's real proof, shown by a peer it does not name.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_shows_the_proof_of_another_peer_gets_nothing_and_is_dropped() {
    let first = node(1, Vec::new()).await;
    let dir = tempfile::tempdir().unwrap();
    let store = FileBlobs::open(dir.path()).unwrap();
    let copied = proof_of(2, &config(2, Vec::new()));
    let identity = config(4, first.p2p.listening().to_vec());
    let (p2p, inbound) = P2p::join(identity, true, copied, store.clone())
        .await
        .unwrap();
    p2p.admit(team(1..=3));
    let mut impostor = [Node {
        p2p,
        inbound,
        blobs: store.of(e3(1)),
        store,
        _dir: dir,
    }];
    let message = key(&first, 1);
    heard_by(&first, 1, &mut impostor, &message).await;

    let result = fetch(&impostor[0], message.clone()).await;
    assert!(
        matches!(result, Err(NetworkError::Unavailable)),
        "{result:?}"
    );
    assert!(message
        .blobs()
        .iter()
        .all(|blob| !impostor[0].blobs.has(blob)));
    for _ in 0..60 {
        if first.p2p.connected() == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("the impostor stayed connected");
}

/// A node must not run under a proof that fails at every peer.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_does_not_start_on_a_proof_of_another_identity() {
    let dir = tempfile::tempdir().unwrap();
    let blobs = FileBlobs::open(dir.path()).unwrap();
    let copied = proof_of(2, &config(2, Vec::new()));
    let started = P2p::start(config(1, Vec::new()), copied, blobs).await;
    assert!(matches!(started, Err(P2pError::Identity(_))));
}

/// Nine members ask one publisher for two blobs each at the same moment, more than it serves at
/// once. Every one of them is served on its first try.
#[tokio::test(flavor = "multi_thread")]
async fn a_committee_that_asks_at_once_is_served_on_the_first_try() {
    let publisher = slow(1, Vec::new()).await;
    let committee = team(1..=10);
    publisher.p2p.admit(committee.clone());
    let mut members = Vec::new();
    for n in 2..=10 {
        let member = node(n, publisher.p2p.listening().to_vec()).await;
        member.p2p.admit(committee.clone());
        members.push(member);
    }
    let message = key(&publisher, 1);
    heard_by(&publisher, 1, &mut members, &message).await;

    let fetches = members.iter().map(|member| fetch(member, message.clone()));
    for result in futures::future::join_all(fetches).await {
        result.unwrap();
    }
    for member in &members {
        assert!(message.blobs().iter().all(|blob| member.blobs.has(blob)));
    }
}

/// A blob of no bytes names nothing: an envelope that names one does not open.
#[test]
fn an_envelope_that_names_an_empty_blob_does_not_open() {
    let message = PeerMessage {
        e3: e3(1),
        sender: address(1),
        body: Body::Dkg(DkgMessage::EncryptionKey(KeyMessage {
            key: BlobRef {
                hash: B256::repeat_byte(1),
                len: 0,
            },
            proof: SignedProof {
                proof: ZkProof {
                    data: BlobRef::of(b"proof"),
                    public_inputs: Vec::new(),
                },
                signature: Bytes::new(),
            },
        })),
    };
    assert!(signed(message, 1, 10).open().is_none());
}

/// Peers of another deployment on the same network never mix.
#[tokio::test(flavor = "multi_thread")]
async fn nodes_of_another_deployment_do_not_share_messages() {
    let first = node(1, Vec::new()).await;
    let dir = tempfile::tempdir().unwrap();
    let blobs = FileBlobs::open(dir.path()).unwrap();
    let mut other = config(2, first.p2p.listening().to_vec());
    other.deployment = "elsewhere".into();
    let proof = proof_of(2, &other);
    let (second, inbox) = P2p::start(other, proof, blobs).await.unwrap();
    second.admit(team(1..=3));
    let message = key(&first, 1);
    let _ = first.p2p.publish(signed(message, 1, 10)).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(5), inbox.next())
            .await
            .is_err(),
        "a message crossed deployments"
    );
}

/// A stop says goodbye and ends the network: the inbox closes.
#[tokio::test(flavor = "multi_thread")]
async fn closing_ends_the_network() {
    let first = node(1, Vec::new()).await;
    first.p2p.close().await;
    tokio::time::timeout(WAIT, first.inbound.closed())
        .await
        .unwrap();
}
