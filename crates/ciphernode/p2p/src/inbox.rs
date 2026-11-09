// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Where peer messages wait for the node. It is bounded in bytes and per sender, so one peer's
//! flood costs that peer's share and no one else's. Nothing is pushed out: a sender over its share
//! is refused, and its re-send brings the message again. The node reads from it only when it is
//! ready, one message at a time and sender by sender.

use alloy_primitives::Address;
use e3_protocol::node::PeerMessage;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex, PoisonError},
};
use tokio::sync::Notify;

const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SENDER_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SENDER_MESSAGES: usize = 128;

#[derive(Default)]
struct Queues {
    senders: BTreeMap<Address, Sender>,
    /// The senders with messages, the next to read from first.
    order: VecDeque<Address>,
    bytes: u64,
    closed: bool,
}

#[derive(Default)]
struct Sender {
    messages: VecDeque<(PeerMessage, u64)>,
    bytes: u64,
}

#[derive(Default)]
struct Shared {
    queues: Mutex<Queues>,
    ready: Notify,
}

impl Shared {
    fn queues(&self) -> std::sync::MutexGuard<'_, Queues> {
        self.queues.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The network's side of the inbox. Dropping it closes the inbox.
pub struct InboxWriter {
    shared: Arc<Shared>,
}

/// The node's side of the inbox.
pub struct Inbox {
    shared: Arc<Shared>,
}

/// An empty inbox with its two sides.
pub fn inbox() -> (InboxWriter, Inbox) {
    let shared = Arc::new(Shared::default());
    let writer = InboxWriter {
        shared: shared.clone(),
    };
    (writer, Inbox { shared })
}

impl InboxWriter {
    /// Queues `message`, which took `size` bytes on the wire; false if it is refused.
    pub fn push(&self, message: PeerMessage, size: u64) -> bool {
        let mut queues = self.shared.queues();
        let sender = message.sender;
        let queue = queues.senders.entry(sender).or_default();
        let (bytes, count) = (queue.bytes, queue.messages.len());
        if count >= MAX_SENDER_MESSAGES
            || bytes.saturating_add(size) > MAX_SENDER_BYTES
            || queues.bytes.saturating_add(size) > MAX_TOTAL_BYTES
        {
            return false;
        }
        let queue = queues.senders.get_mut(&sender).expect("just made");
        queue.messages.push_back((message, size));
        queue.bytes += size;
        if count == 0 {
            queues.order.push_back(sender);
        }
        queues.bytes += size;
        drop(queues);
        self.shared.ready.notify_one();
        true
    }
}

impl Drop for InboxWriter {
    fn drop(&mut self) {
        self.shared.queues().closed = true;
        self.shared.ready.notify_one();
    }
}

impl Inbox {
    /// The next message, from the sender whose turn it is; none once the network stopped and
    /// nothing is left.
    pub async fn next(&self) -> Option<PeerMessage> {
        loop {
            let ready = self.shared.ready.notified();
            {
                let mut queues = self.shared.queues();
                if let Some(message) = queues.pop() {
                    return Some(message);
                }
                if queues.closed {
                    return None;
                }
            }
            ready.await;
        }
    }

    /// Waits until the network stopped.
    pub async fn closed(&self) {
        loop {
            let ready = self.shared.ready.notified();
            if self.shared.queues().closed {
                return;
            }
            ready.await;
        }
    }
}

impl Queues {
    fn pop(&mut self) -> Option<PeerMessage> {
        let sender = self.order.pop_front()?;
        let queue = self.senders.get_mut(&sender)?;
        let (message, size) = queue.messages.pop_front()?;
        queue.bytes -= size;
        self.bytes -= size;
        match queue.messages.is_empty() {
            true => {
                self.senders.remove(&sender);
            }
            false => self.order.push_back(sender),
        }
        Some(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_protocol::{
        dkg::DkgMessage,
        node::Body,
        testing::{address, e3},
    };
    use std::time::Duration;

    fn message(sender: u64) -> PeerMessage {
        PeerMessage {
            e3: e3(1),
            sender: address(sender),
            body: Body::Dkg(DkgMessage::Ready(Vec::new())),
        }
    }

    async fn drained(inbox: &Inbox, count: usize) -> Vec<Address> {
        let mut senders = Vec::new();
        for _ in 0..count {
            senders.push(inbox.next().await.unwrap().sender);
        }
        senders
    }

    #[tokio::test]
    async fn the_node_reads_sender_by_sender() {
        let (writer, inbox) = inbox();
        for sender in [1, 1, 1, 2] {
            assert!(writer.push(message(sender), 10));
        }
        let read = drained(&inbox, 4).await;
        assert_eq!(read[..3], [address(1), address(2), address(1)]);
    }

    /// A flood costs the sender its own share; another sender still gets through.
    #[tokio::test]
    async fn a_sender_over_its_share_is_refused_and_others_are_not() {
        let (writer, inbox) = inbox();
        let mut taken = 0;
        while writer.push(message(1), 1) {
            taken += 1;
        }
        assert_eq!(taken, MAX_SENDER_MESSAGES);
        assert!(writer.push(message(2), 1));
        assert!(!writer.push(message(3), MAX_SENDER_BYTES + 1));
        drained(&inbox, 1).await;
        assert!(writer.push(message(1), 1), "room came back");
    }

    #[tokio::test]
    async fn the_bytes_of_every_sender_together_are_bounded() {
        let (writer, _inbox) = inbox();
        let mut sender = 1;
        while writer.push(message(sender), MAX_SENDER_BYTES) {
            sender += 1;
        }
        assert_eq!(sender - 1, MAX_TOTAL_BYTES / MAX_SENDER_BYTES);
    }

    #[tokio::test]
    async fn a_closed_inbox_gives_what_it_holds_then_ends() {
        let (writer, inbox) = inbox();
        assert!(writer.push(message(1), 1));
        drop(writer);
        assert!(inbox.next().await.is_some());
        assert!(inbox.next().await.is_none());
        tokio::time::timeout(Duration::from_secs(1), inbox.closed())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_waiting_reader_gets_the_next_message() {
        let (writer, inbox) = inbox();
        let reader = tokio::spawn(async move { inbox.next().await.map(|m| m.sender) });
        tokio::task::yield_now().await;
        assert!(writer.push(message(4), 1));
        let read = tokio::time::timeout(Duration::from_secs(1), reader).await;
        assert_eq!(read.unwrap().unwrap(), Some(address(4)));
    }
}
