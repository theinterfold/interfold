// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::time::Duration;

use tokio::{
    sync::{broadcast, mpsc},
    time::sleep,
};

use crate::{
    events::{NetCommand, NetEvent},
    NetworkStatus,
};

#[derive(Debug)]
pub struct NetInterfaceHandle {
    tx: mpsc::Sender<NetCommand>,
    rx: broadcast::Receiver<NetEvent>,
    status: NetworkStatus,
}
impl NetInterfaceHandle {
    pub fn new(
        tx: mpsc::Sender<NetCommand>,
        rx: broadcast::Receiver<NetEvent>,
        status: NetworkStatus,
    ) -> Self {
        Self { tx, rx, status }
    }

    pub fn status(&self) -> NetworkStatus {
        self.status.clone()
    }
}

pub trait NetInterface: Sized {
    fn tx(&self) -> mpsc::Sender<NetCommand>;
    fn rx(&self) -> broadcast::Receiver<NetEvent>;
    fn status(&self) -> NetworkStatus;
    fn handle(&self) -> NetInterfaceHandle {
        NetInterfaceHandle::from(self)
    }
}

#[derive(Debug, Clone)]
/// Allow Net events and commands to be bridged between nodes. This is used for testing purposes to
/// simulate libp2p without running libp2p.
pub struct NetChannelBridge {
    cmd_tx: broadcast::Sender<NetCommand>,
    tx: mpsc::Sender<NetCommand>,
    event_tx: broadcast::Sender<NetEvent>,
}

impl NetInterfaceHandle {
    pub fn from(interface: &impl NetInterface) -> Self {
        Self {
            tx: interface.tx(),
            rx: interface.rx(),
            status: interface.status(),
        }
    }
}
impl NetInterface for NetInterfaceHandle {
    fn rx(&self) -> broadcast::Receiver<NetEvent> {
        self.rx.resubscribe()
    }

    fn tx(&self) -> mpsc::Sender<NetCommand> {
        self.tx.clone()
    }

    fn status(&self) -> NetworkStatus {
        self.status.clone()
    }
}

/// This creates a channel bridge which allows for network events to be connected between test nodes
pub fn create_channel_bridge() -> (NetInterfaceHandle, NetChannelBridge) {
    let (m_cmd_tx, mut m_cmd_rx) = mpsc::channel::<NetCommand>(1000);
    let (b_evt_tx, _) = broadcast::channel(1000);
    let (b_cmd_tx, _) = broadcast::channel(1000);

    let tx = b_cmd_tx.clone();
    let startup_event_tx = b_evt_tx.clone();
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

    let handle = NetInterfaceHandle {
        tx: m_cmd_tx.clone(),
        rx: b_evt_tx.subscribe(),
        status: NetworkStatus::new(0),
    };

    let inverted = NetChannelBridge {
        tx: m_cmd_tx,
        cmd_tx: b_cmd_tx,
        event_tx: b_evt_tx,
    };

    (handle, inverted)
}

pub trait NetInterfaceInverted: Sized {
    fn tx(&self) -> mpsc::Sender<NetCommand>;
    fn event_tx(&self) -> broadcast::Sender<NetEvent>; //U
    fn event_rx(&self) -> broadcast::Receiver<NetEvent>;
    fn cmd_tx(&self) -> broadcast::Sender<NetCommand>;
    fn cmd_rx(&self) -> broadcast::Receiver<NetCommand>; //U

    fn into_handle_inverted(self) -> NetChannelBridge {
        NetChannelBridge {
            tx: self.tx(),
            event_tx: self.event_tx(),
            cmd_tx: self.cmd_tx(),
        }
    }
}

impl NetInterfaceInverted for NetChannelBridge {
    fn tx(&self) -> mpsc::Sender<NetCommand> {
        self.tx.clone()
    }

    fn cmd_rx(&self) -> broadcast::Receiver<NetCommand> {
        self.cmd_tx.subscribe()
    }
    fn event_tx(&self) -> broadcast::Sender<NetEvent> {
        self.event_tx.clone()
    }
    fn cmd_tx(&self) -> broadcast::Sender<NetCommand> {
        self.cmd_tx.clone()
    }
    fn event_rx(&self) -> broadcast::Receiver<NetEvent> {
        self.event_tx.subscribe()
    }
}
