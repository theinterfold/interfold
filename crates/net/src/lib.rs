// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod actors;
mod cid;
mod dialer;
pub mod direct_requester;
pub mod direct_responder;
mod domain;
mod event_subscription;
pub mod events;
mod keypair;
mod net_interface;
mod net_interface_handle;
mod net_supervisor;
mod protocol_auth;
mod repo;

use std::sync::Arc;

use actix::Recipient;
use anyhow::bail;
use anyhow::Result;
use e3_crypto::Cipher;
use e3_data::Repository;
use e3_events::{run_once, BusHandle, EffectsEnabled, EventStoreQueryBy, EventSubscriber, TsAgg};
use tracing::{info, instrument};

use actors::{NetEventBuffer, NetSyncManager};

pub use actors::*;
pub use cid::ContentHash;
pub use domain::{AuthenticatedPeer, ConnectedPeer, NetworkSnapshot, NetworkStatus};
pub use keypair::*;
pub use net_interface::*;
pub use net_interface_handle::*;
pub use net_supervisor::*;
pub use protocol_auth::*;
pub use repo::*;

pub async fn setup_libp2p_keypair(
    repository: Repository<Vec<u8>>,
    cipher: &Arc<Cipher>,
) -> Result<Libp2pKeypair> {
    // Get existing keypair or generate a new one
    let mut bytes = match repository.read().await? {
            Some(bytes) => {
                info!("Found keypair in repository");
                cipher.decrypt_data(&bytes)?
            }
            None => bail!("No network keypair found in repository, please generate a new one using `interfold net generate-key`"),
        };
    Libp2pKeypair::try_from_bytes(&mut bytes)
}

#[derive(Clone)]
pub struct ProtocolGossipIdentity {
    pub signer: ProtocolSigner,
    pub authorization: NetworkAuthorizationState,
}

impl ProtocolGossipIdentity {
    pub fn new(signer: ProtocolSigner, authorization: NetworkAuthorizationState) -> Self {
        Self {
            signer,
            authorization,
        }
    }
}

pub fn setup_net_interface(
    topic: &str,
    keypair: Libp2pKeypair,
    peers: Vec<String>,
    quic_port: u16,
) -> Result<(NetInterfaceHandle, NetworkTaskSupervisor)> {
    let mut interface = Libp2pNetInterface::new(keypair, peers, Some(quic_port), topic)?;

    let handle = interface.handle();
    let supervisor = supervise_network_task(handle.tx(), handle.status(), async move {
        interface.start().await
    });

    Ok((handle, supervisor))
}

/// Spawn a Libp2p interface and hook it up to this actor
#[instrument(name = "libp2p", skip_all)]
pub fn setup_net(
    topic: &str,
    bus: BusHandle,
    eventstore: impl Into<Recipient<EventStoreQueryBy<TsAgg>>>,
    interface: impl NetInterface,
    protocol_identity: ProtocolGossipIdentity,
) -> Result<()> {
    setup_net_with_limits(
        topic,
        bus,
        eventstore,
        interface,
        protocol_identity,
        DEFAULT_MAX_BUFFERED_NET_EVENTS,
        DEFAULT_MAX_BUFFERED_NET_BYTES,
    )?;
    Ok(())
}

/// Set up networking with an explicit fail-closed startup buffer bound and return the readiness
/// handle used by production startup.
pub fn setup_net_with_limits(
    topic: &str,
    bus: BusHandle,
    eventstore: impl Into<Recipient<EventStoreQueryBy<TsAgg>>>,
    interface: impl NetInterface,
    protocol_identity: ProtocolGossipIdentity,
    max_buffered_events: usize,
    max_buffered_bytes: usize,
) -> Result<NetEventBufferHandle> {
    if max_buffered_events == 0 || max_buffered_bytes == 0 {
        bail!("network startup buffer limits must both be greater than zero");
    }
    let ProtocolGossipIdentity {
        signer,
        authorization,
    } = protocol_identity;
    let network_status = interface.status();
    // NOTE: Pass the unbuffered rx to SyncManager as it must operate before live events are
    // processed
    let _net_sync = NetSyncManager::setup(
        &bus,
        &interface.tx(),
        &Arc::new(interface.rx()),
        eventstore.into(),
        topic,
        signer.clone(),
        authorization.clone(),
    );

    // Buffer all incoming events until SyncEnded
    let (rx, buffer_handle) = NetEventBuffer::setup_with_limits(
        &bus,
        &interface.rx(),
        interface.tx(),
        authorization.clone(),
        network_status,
        max_buffered_events,
        max_buffered_bytes,
    );
    let rx = Arc::new(rx);
    let tx = interface.tx();

    // Start the membership observer before replay. Ingress remains behind NetEventBuffer until
    // SyncEnded, and outbound publication remains gated until EffectsEnabled.
    NetEventTranslator::setup(&bus, &tx, &rx, topic, signer, authorization);

    let runner = run_once::<EffectsEnabled>({
        let bus = bus.clone();
        let rx = rx.clone();
        let topic = topic.to_owned();
        let tx = tx.clone();
        move |_| {
            DocumentPublisher::setup(&bus, &tx, &rx, &topic);
            Ok(())
        }
    });

    bus.subscribe(e3_events::EventType::EffectsEnabled, runner.recipient());

    Ok(buffer_handle)
}
