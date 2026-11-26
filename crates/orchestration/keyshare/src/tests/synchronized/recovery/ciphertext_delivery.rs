// SPDX-License-Identifier: LGPL-3.0-only

//! The object service is a fixture; log decoding, retrieval, digest verification and fanout
//! to the designated keyshares use the node's normal implementations.
use super::*;
use e3_evm::{DataAvailabilityCoordinator, DataAvailabilityRepositoryFactory};
use e3_evm_config::{DataAvailabilityConfig, DataAvailabilityMode};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
};

async fn serve_object(listener: TcpListener, ciphertext: &[u8]) -> Result<()> {
    let (mut socket, _) = listener.accept().await?;
    let mut request = BufReader::new(&mut socket).lines();
    let expected = format!("GET /objects/{} HTTP/1.1", keccak256(ciphertext));
    ensure!(
        request.next_line().await? == Some(expected),
        "DA reader requested a different object"
    );
    while request
        .next_line()
        .await?
        .is_some_and(|line| !line.is_empty())
    {}
    socket
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                ciphertext.len()
            )
            .as_bytes(),
        )
        .await?;
    socket.write_all(ciphertext).await?;
    Ok(())
}

pub(super) async fn retrieve(
    chain: &Chain,
    receipt: &TransactionReceipt,
    ct: &[u8],
    node: &DiskJournal,
    id: &E3id,
    keys: &CanonicalPublicKeys,
) -> Result<InterfoldEvent> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let config = DataAvailabilityConfig {
        mode: DataAvailabilityMode::MockHttp,
        rpc_url: format!("http://{}", listener.local_addr()?),
    };
    DataAvailabilityCoordinator::attach(
        &node.bus,
        id.chain_id(),
        Some(&config),
        node.db
            .repositories()
            .data_availability_recovery(id.chain_id()),
        &HashSet::new(),
    )
    .await?;
    let mut references = listen(&node.bus, EventType::CiphertextOutputReferencePublished);
    let mut openings = listen(&node.bus, EventType::CiphertextOutputPublished);
    node.bus.publish_without_context(EffectsEnabled::new())?;
    for event in chain.decode(receipt, chain.controller).await? {
        node.bus.naked_dispatch(event)?;
    }
    node.bus.flush_event_pipeline().await?;
    let reference = received(&mut references).await?;
    ensure!(reference.source() == EventSource::Evm && reference.block() == receipt.block_number);
    ensure!(
        keys.first_live_opening(id).is_none(),
        "a DA reference alone authorized allocation"
    );
    actix::clock::timeout(Duration::from_secs(10), serve_object(listener, ct)).await??;
    let opening = received(&mut openings).await?;
    node.bus.flush_event_pipeline().await?;
    ensure!(
        opening.source() == EventSource::Local
            && opening.causation_id() == reference.id()
            && keys.first_live_opening(id).as_ref() == Some(opening.get_ctx()),
        "keyshare opening did not come from the mined DA reference"
    );
    Ok(opening)
}
