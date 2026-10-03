// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use anyhow::{anyhow, Result};
use e3_events::CorrelationId;
use tokio::{
    sync::{broadcast, mpsc},
    time::sleep,
};

use crate::{
    command_responses::{PendingResponse, PendingResponses},
    events::{NetCommand, NetEvent},
    NetworkStatus,
};

/// A broadcast channel of network events that also gives each command result to the caller that
/// registered for it.
///
/// The network interface sends its events into `NetEventChannel`s, so a caller that registers for
/// a result reads it from its own oneshot channel and broadcast lag cannot drop it. A relay of these
/// events, such as the startup buffer, is a plain broadcast: see [`NetEventSubscriber::relayed_by`].
#[derive(Debug, Clone)]
pub struct NetEventChannel {
    events: broadcast::Sender<NetEvent>,
    responses: Arc<PendingResponses>,
}

impl NetEventChannel {
    pub fn new(capacity: usize) -> Self {
        let (events, _) = broadcast::channel(capacity);
        Self {
            events,
            responses: Arc::default(),
        }
    }

    /// Gives the event to the caller that waits for its correlation id, then broadcasts it.
    /// Returns the number of receivers reached, and fails only when nobody received the event.
    // The error returns the event, as `broadcast::Sender::send` does.
    #[allow(clippy::result_large_err)]
    pub fn send(&self, event: NetEvent) -> Result<usize, broadcast::error::SendError<NetEvent>> {
        let delivered = usize::from(self.responses.deliver(&event));
        match self.events.send(event) {
            Ok(receivers) => Ok(receivers + delivered),
            Err(error) if delivered == 0 => Err(error),
            Err(_) => Ok(delivered),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<NetEvent> {
        self.events.subscribe()
    }

    pub(crate) fn len(&self) -> usize {
        self.events.len()
    }
}

/// Sends each network event to the raw channel and, when required, to the application channel.
///
/// The application channel excludes sync and connection-control traffic at the producer.
#[derive(Debug, Clone)]
pub struct NetEventSender {
    raw: NetEventChannel,
    application: NetEventChannel,
}

impl NetEventSender {
    pub(crate) fn new(raw_capacity: usize, application_capacity: usize) -> Self {
        Self {
            raw: NetEventChannel::new(raw_capacity),
            application: NetEventChannel::new(application_capacity),
        }
    }

    /// Sends one event to its required channels and returns the number of receivers reached.
    ///
    /// A broadcast send only fails when no receiver is alive. Consumers subscribe lazily, so that
    /// is not an error for the producer: the event has nobody to go to and is dropped, exactly as
    /// it would be for a receiver that subscribes a moment later.
    pub fn send(&self, event: NetEvent) -> Result<usize, broadcast::error::SendError<NetEvent>> {
        if !event.requires_application_delivery() {
            return Ok(self.raw.send(event).unwrap_or(0));
        }

        let raw = self.raw.send(event.clone()).unwrap_or(0);
        let application = self.application.send(event).unwrap_or(0);
        Ok(raw + application)
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<NetEvent> {
        self.raw.subscribe()
    }

    pub(crate) fn len(&self) -> usize {
        self.raw.len()
    }

    pub(crate) fn subscriber(&self) -> NetEventSubscriber {
        NetEventSubscriber::from(&self.raw)
    }

    pub(crate) fn application_subscriber(&self) -> NetEventSubscriber {
        NetEventSubscriber::from(&self.application)
    }
}

/// Cheap, cloneable factory for live `NetEvent` receivers.
///
/// Holds a `WeakSender` rather than a template `Receiver` or a strong `Sender`, so a stored
/// subscriber neither pins the channel queue (a never-polled receiver would keep every event
/// queued and make `NetEventSender::len()` report permanent backpressure) nor keeps the channel
/// open after the producer drops it: receivers still observe `RecvError::Closed` on shutdown.
#[derive(Debug, Clone)]
pub struct NetEventSubscriber {
    tx: broadcast::WeakSender<NetEvent>,
    responses: Weak<PendingResponses>,
}

impl NetEventSubscriber {
    /// Returns a receiver that sees every event sent after this call. If the producer has
    /// already gone away the receiver reports `RecvError::Closed` immediately.
    pub fn subscribe(&self) -> broadcast::Receiver<NetEvent> {
        match self.tx.upgrade() {
            Some(tx) => tx.subscribe(),
            None => {
                let (tx, rx) = broadcast::channel(1);
                drop(tx);
                rx
            }
        }
    }

    /// Registers for the result of the command with this correlation id. Register before the
    /// command is sent, so the result cannot arrive first.
    pub(crate) fn expect_response(&self, id: CorrelationId) -> Result<PendingResponse> {
        self.responses
            .upgrade()
            .ok_or_else(|| anyhow!("network event channel is closed"))?
            .register(id)
    }

    /// Returns a subscriber that reads the events of `relay`, a channel that passes on the events
    /// of this one. Its callers still register their command results here, so a result goes from
    /// the network interface to its caller and never waits in, or is dropped by, the relay.
    pub(crate) fn relayed_by(&self, relay: &broadcast::Sender<NetEvent>) -> Self {
        Self {
            tx: relay.downgrade(),
            responses: self.responses.clone(),
        }
    }
}

impl From<&NetEventChannel> for NetEventSubscriber {
    fn from(channel: &NetEventChannel) -> Self {
        Self {
            tx: channel.events.downgrade(),
            responses: Arc::downgrade(&channel.responses),
        }
    }
}

#[derive(Debug)]
pub struct NetInterfaceHandle {
    tx: mpsc::Sender<NetCommand>,
    /// Weak subscribers: the handle neither pins the broadcast queue nor keeps the channels open
    /// once the interface that owns the `NetEventSender` shuts down.
    events: NetEventSubscriber,
    application_events: NetEventSubscriber,
    status: NetworkStatus,
}
impl NetInterfaceHandle {
    pub(crate) fn new(
        tx: mpsc::Sender<NetCommand>,
        event_tx: &NetEventSender,
        status: NetworkStatus,
    ) -> Self {
        Self {
            tx,
            events: event_tx.subscriber(),
            application_events: event_tx.application_subscriber(),
            status,
        }
    }

    pub fn status(&self) -> NetworkStatus {
        self.status.clone()
    }
}

pub trait NetInterface: Sized {
    fn tx(&self) -> mpsc::Sender<NetCommand>;
    /// Returns a subscriber for the raw event channel.
    fn events(&self) -> NetEventSubscriber;
    /// Returns a subscriber for the application-delivery event channel.
    fn application_events(&self) -> NetEventSubscriber;
    fn status(&self) -> NetworkStatus;
    /// Returns a live receiver on the raw event channel.
    fn rx(&self) -> broadcast::Receiver<NetEvent> {
        self.events().subscribe()
    }
    /// Returns a live receiver that contains only application-delivery events.
    fn application_rx(&self) -> broadcast::Receiver<NetEvent> {
        self.application_events().subscribe()
    }
}

#[derive(Debug, Clone)]
/// Allow Net events and commands to be bridged between nodes. This is used for testing purposes to
/// simulate libp2p without running libp2p.
pub struct NetChannelBridge {
    cmd_tx: broadcast::Sender<NetCommand>,
    /// A command receiver made with the bridge, for the first `cmd_rx` call. A node can send
    /// commands before the test network attaches it, for example a restarted node that restores
    /// its DHT records during startup; this receiver keeps them for the network.
    first_cmd_rx: Arc<Mutex<Option<broadcast::Receiver<NetCommand>>>>,
    tx: mpsc::Sender<NetCommand>,
    event_tx: NetEventSender,
}

impl NetInterface for NetInterfaceHandle {
    fn tx(&self) -> mpsc::Sender<NetCommand> {
        self.tx.clone()
    }

    fn events(&self) -> NetEventSubscriber {
        self.events.clone()
    }

    fn application_events(&self) -> NetEventSubscriber {
        self.application_events.clone()
    }

    fn status(&self) -> NetworkStatus {
        self.status.clone()
    }
}

/// This creates a channel bridge which allows for network events to be connected between test nodes
pub fn create_channel_bridge() -> (NetInterfaceHandle, NetChannelBridge) {
    create_channel_bridge_with_application_event_capacity(crate::DEFAULT_MAX_BUFFERED_NET_EVENTS)
}

/// Creates a test channel bridge whose application channel uses the specified capacity.
pub fn create_channel_bridge_with_application_event_capacity(
    application_event_capacity: usize,
) -> (NetInterfaceHandle, NetChannelBridge) {
    assert!(
        application_event_capacity > 0,
        "application event channel capacity must be greater than zero"
    );
    let (m_cmd_tx, mut m_cmd_rx) = mpsc::channel::<NetCommand>(1000);
    let event_tx = NetEventSender::new(1000, application_event_capacity);
    let (b_cmd_tx, _) = broadcast::channel(1000);

    let tx = b_cmd_tx.clone();
    let startup_event_tx = event_tx.clone();
    let keep_alive = b_cmd_tx.subscribe();

    // Bridge from mpsc channel to broadcast channel simulating AllPeersDialed for each node
    tokio::spawn(async move {
        let _rx_guard = keep_alive;
        sleep(Duration::from_millis(100)).await;
        let _ = startup_event_tx.send(NetEvent::AllPeersDialed {
            connected: 0,
            total: 0,
        });
        while let Some(cmd) = m_cmd_rx.recv().await {
            let _ = tx.send(cmd);
        }
    });

    let handle = NetInterfaceHandle::new(m_cmd_tx.clone(), &event_tx, NetworkStatus::new(0));

    let inverted = NetChannelBridge {
        tx: m_cmd_tx,
        first_cmd_rx: Arc::new(Mutex::new(Some(b_cmd_tx.subscribe()))),
        cmd_tx: b_cmd_tx,
        event_tx,
    };

    (handle, inverted)
}

pub trait NetInterfaceInverted: Sized {
    fn tx(&self) -> mpsc::Sender<NetCommand>;
    fn event_tx(&self) -> NetEventSender; //U
    fn event_rx(&self) -> broadcast::Receiver<NetEvent>;
    fn cmd_tx(&self) -> broadcast::Sender<NetCommand>;
    fn cmd_rx(&self) -> broadcast::Receiver<NetCommand>; //U

    fn into_handle_inverted(self) -> NetChannelBridge {
        NetChannelBridge {
            tx: self.tx(),
            event_tx: self.event_tx(),
            first_cmd_rx: Arc::new(Mutex::new(None)),
            cmd_tx: self.cmd_tx(),
        }
    }
}

impl NetInterfaceInverted for NetChannelBridge {
    fn tx(&self) -> mpsc::Sender<NetCommand> {
        self.tx.clone()
    }

    /// The first call returns every command since the bridge was made; later calls return the
    /// commands from then on.
    fn cmd_rx(&self) -> broadcast::Receiver<NetCommand> {
        self.first_cmd_rx
            .lock()
            .expect("the command receiver lock is not poisoned")
            .take()
            .unwrap_or_else(|| self.cmd_tx.subscribe())
    }
    fn event_tx(&self) -> NetEventSender {
        self.event_tx.clone()
    }
    fn cmd_tx(&self) -> broadcast::Sender<NetCommand> {
        self.cmd_tx.clone()
    }
    fn event_rx(&self) -> broadcast::Receiver<NetEvent> {
        self.event_tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use crate::events::GossipData;

    use super::*;

    /// A restarted node can send commands during startup, before the test network attaches it.
    /// The first command receiver still gets them; a later receiver gets only later commands.
    #[tokio::test(start_paused = true)]
    async fn commands_sent_before_the_network_attaches_reach_it() {
        let (handle, bridge) = create_channel_bridge();
        let command = || NetCommand::DhtRemoveRecords { keys: Vec::new() };
        handle.tx().send(command()).await.unwrap();
        // Let the bridge forward the command before anything receives commands.
        sleep(Duration::from_secs(1)).await;

        let mut first = bridge.cmd_rx();
        let mut later = bridge.cmd_rx();

        assert!(matches!(
            first.try_recv(),
            Ok(NetCommand::DhtRemoveRecords { .. })
        ));
        assert!(later.try_recv().is_err());
    }

    #[test]
    fn subscriber_closes_when_the_producer_drops() {
        let event_tx = NetEventSender::new(4, 4);
        let (cmd_tx, _cmd_rx) = mpsc::channel(1);
        let handle = NetInterfaceHandle::new(cmd_tx, &event_tx, NetworkStatus::new(0));
        let mut live_rx = handle.application_rx();

        drop(event_tx);

        assert!(matches!(
            live_rx.try_recv(),
            Err(broadcast::error::TryRecvError::Closed)
        ));
        assert!(matches!(
            handle.rx().try_recv(),
            Err(broadcast::error::TryRecvError::Closed)
        ));
    }

    #[test]
    fn send_without_subscribers_is_not_an_error() {
        let event_tx = NetEventSender::new(1, 1);
        assert_eq!(
            event_tx
                .send(NetEvent::GossipData(GossipData::GossipBytes(vec![1])))
                .expect("no subscriber is not a producer error"),
            0
        );
    }

    #[test]
    fn handle_does_not_pin_the_event_queue() {
        let event_tx = NetEventSender::new(4, 4);
        let (cmd_tx, _cmd_rx) = mpsc::channel(1);
        let handle = NetInterfaceHandle::new(cmd_tx, &event_tx, NetworkStatus::new(0));
        let mut rx = handle.rx();

        for i in 0..3u8 {
            event_tx
                .send(NetEvent::GossipData(GossipData::GossipBytes(vec![i])))
                .expect("live subscriber must receive");
        }
        assert_eq!(event_tx.len(), 3);

        while rx.try_recv().is_ok() {}
        assert_eq!(
            event_tx.len(),
            0,
            "queue must drain once the only live receiver has consumed it"
        );
    }

    #[test]
    fn application_event_send_succeeds_with_either_channel_subscribed() {
        let raw_only = NetEventSender::new(1, 1);
        let mut raw_rx = raw_only.subscribe();
        raw_only
            .send(NetEvent::GossipData(GossipData::GossipBytes(vec![1])))
            .expect("raw delivery must succeed without an application subscriber");
        assert!(matches!(raw_rx.try_recv(), Ok(NetEvent::GossipData(_))));

        let application_only = NetEventSender::new(1, 1);
        let mut application_rx = application_only.application_subscriber().subscribe();
        application_only
            .send(NetEvent::GossipData(GossipData::GossipBytes(vec![2])))
            .expect("application delivery must succeed without a raw subscriber");
        assert!(matches!(
            application_rx.try_recv(),
            Ok(NetEvent::GossipData(_))
        ));
    }
}
