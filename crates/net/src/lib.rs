// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod actors;
mod bootstrap;
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
mod network;
mod peer_admission;
mod repo;

use std::{collections::HashMap, sync::Arc};

use actix::Recipient;
use anyhow::bail;
use anyhow::Result;
use e3_crypto::Cipher;
use e3_data::Repository;
use e3_events::{
    run_once, BusHandle, E3id, EffectsEnabled, EventStoreQueryBy, EventSubscriber, PartyId, TsAgg,
};
use tracing::error;
use tracing::{info, instrument};

use actors::{NetEventBuffer, NetSyncManager};

pub use actors::*;
pub use cid::ContentHash;
pub use domain::{ConnectedPeer, NetworkSnapshot, NetworkStatus};
pub use keypair::*;
pub use net_interface::*;
pub use net_interface_handle::*;
pub use network::*;
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

pub fn setup_net_interface(
    network: NetworkPolicy,
    keypair: Libp2pKeypair,
    peers: Vec<String>,
    quic_port: u16,
    max_buffered_events: usize,
) -> Result<NetInterfaceHandle> {
    let mut interface = Libp2pNetInterface::new_with_application_event_capacity(
        keypair,
        peers,
        Some(quic_port),
        network,
        max_buffered_events,
    )?;

    let handle = interface.handle();

    actix::spawn(async move {
        if let Err(e) = interface.start().await {
            error!("{e}");
        }
    });

    Ok(handle)
}

/// Spawn a Libp2p interface and hook it up to this actor
#[instrument(name = "libp2p", skip_all)]
pub fn setup_net(
    network: &NetworkPolicy,
    bus: BusHandle,
    eventstore: impl Into<Recipient<EventStoreQueryBy<TsAgg>>>,
    interface: impl NetInterface,
) -> Result<()> {
    setup_net_with_limits(
        network,
        bus,
        eventstore,
        interface,
        DEFAULT_MAX_BUFFERED_NET_EVENTS,
        DEFAULT_MAX_BUFFERED_NET_BYTES,
    )?;
    Ok(())
}

/// Set up networking with an explicit fail-closed startup buffer bound and return the readiness
/// handle used by production startup.
pub fn setup_net_with_limits(
    network: &NetworkPolicy,
    bus: BusHandle,
    eventstore: impl Into<Recipient<EventStoreQueryBy<TsAgg>>>,
    interface: impl NetInterface,
    max_buffered_events: usize,
    max_buffered_bytes: usize,
) -> Result<NetEventBufferHandle> {
    setup_net_with_limits_and_interests(
        network,
        bus,
        eventstore,
        interface,
        max_buffered_events,
        max_buffered_bytes,
        HashMap::new(),
        RecoveredDocumentState::default(),
    )
}

/// Set up bounded networking and restore active DHT interests without publishing new protocol
/// events during process startup.
pub fn setup_net_with_limits_and_interests(
    network: &NetworkPolicy,
    bus: BusHandle,
    eventstore: impl Into<Recipient<EventStoreQueryBy<TsAgg>>>,
    interface: impl NetInterface,
    max_buffered_events: usize,
    max_buffered_bytes: usize,
    initial_interests: HashMap<E3id, PartyId>,
    recovered_documents: RecoveredDocumentState,
) -> Result<NetEventBufferHandle> {
    if max_buffered_events == 0 || max_buffered_bytes == 0 {
        bail!("network startup buffer limits must both be greater than zero");
    }
    let topic = network.protocols().gossip_topic();
    // NOTE: Pass the unbuffered rx to SyncManager as it must operate before live events are
    // processed
    let _net_sync = NetSyncManager::setup(
        &bus,
        &interface.tx(),
        &interface.events(),
        eventstore.into(),
        topic,
        network.clone(),
    );

    // Buffer application events until SyncEnded. The producer keeps control events on the raw
    // channel that the sync manager consumes.
    let (rx, buffer_handle) = NetEventBuffer::setup_with_limits(
        &bus,
        &interface.application_events(),
        max_buffered_events,
        max_buffered_bytes,
    );
    let tx = interface.tx();
    let network = network.clone();

    DocumentPublisher::setup_before_effects(
        &bus,
        &tx,
        &rx,
        topic,
        initial_interests,
        recovered_documents,
    );

    let runner = run_once::<EffectsEnabled>({
        let bus = bus.clone();
        let rx = rx.clone();
        let topic = topic.to_owned();
        let tx = tx.clone();
        move |_| {
            NetEventTranslator::setup(&bus, &tx, &rx, &topic, network.clone());
            EventConverter::setup(&bus);
            Ok(())
        }
    });

    bus.subscribe(e3_events::EventType::EffectsEnabled, runner.recipient());

    Ok(buffer_handle)
}
