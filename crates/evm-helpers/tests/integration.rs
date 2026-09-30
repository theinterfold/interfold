// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod helpers;
use alloy::consensus::BlockHeader;
use alloy::primitives::{Address, U256};
use alloy::providers::ext::AnvilApi;
use alloy::signers::local::PrivateKeySigner;
use alloy::{
    node_bindings::Anvil,
    providers::{Provider, ProviderBuilder},
    sol,
};
use e3_evm_helpers::nonce::send_with_next_nonce;
use e3_evm_helpers::{block_listener::BlockListener, event_listener::EventListener};
use eyre::Result;
use helpers::setup_logs_contract;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use tokio::time::sleep;

sol!(
    #[sol(rpc)]
    EmitLogs,
    "tests/fixtures/emit_logs.json"
);

/// A send that the node refuses gives its nonce back. Otherwise the next send of the account takes
/// a later nonce and waits in the queue behind a gap that no transaction fills.
#[tokio::test]
async fn a_refused_send_gives_its_nonce_back() -> Result<()> {
    let anvil = Anvil::new().try_spawn()?;
    // Not an Anvil development account, so it holds no funds.
    let signer: PrivateKeySigner =
        "0x2222222222222222222222222222222222222222222222222222222222222222".parse()?;
    let from = signer.address();
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect(&anvil.endpoint())
        .await?;
    // A call to an address without code succeeds, so the test needs no deployed contract.
    let target = EmitLogs::new(Address::repeat_byte(0x42), &provider);

    assert!(
        send_with_next_nonce(target.setValue("unfunded".to_string()), from)
            .await
            .is_err()
    );
    provider
        .anvil_set_balance(from, U256::from(10).pow(U256::from(18)))
        .await?;
    let receipt = tokio::time::timeout(Duration::from_secs(10), async {
        send_with_next_nonce(target.setValue("funded".to_string()), from)
            .await?
            .get_receipt()
            .await
            .map_err(eyre::Report::from)
    })
    .await??;
    assert!(receipt.status());
    Ok(())
}

/// A JSON-RPC proxy in front of `upstream` that acts as a lagging node behind a load balancer: it
/// reports the mined transaction count as the pending one, and it loses its first answer to a
/// `lost` request after `upstream` handled it.
async fn lossy_proxy(upstream: String, lost: &'static str) -> Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    tokio::spawn(async move {
        let client = alloy::transports::http::reqwest::Client::new();
        let mut answer_lost = false;
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut request = Vec::new();
            let mut buffer = [0; 8192];
            let body = loop {
                let read = socket.read(&mut buffer).await.unwrap();
                request.extend_from_slice(&buffer[..read]);
                let text = String::from_utf8_lossy(&request).into_owned();
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let length = head
                        .lines()
                        .find_map(|line| {
                            line.to_lowercase()
                                .strip_prefix("content-length:")?
                                .trim()
                                .parse()
                                .ok()
                        })
                        .unwrap_or(0);
                    if body.len() >= length {
                        break body.replace("\"pending\"", "\"latest\"");
                    }
                }
            };
            let answer = client
                .post(&upstream)
                .header("content-type", "application/json")
                .body(body.clone())
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            if body.contains(lost) && !answer_lost {
                answer_lost = true;
                continue;
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{answer}",
                answer.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        }
    });
    Ok(url)
}

/// A send keeps its nonce only while the node can hold its transaction. The answer to a broadcast
/// that the node took can be lost, and a lagging node then still reports the old pending count, so
/// the next send must not take the same nonce. A failure before the broadcast sends nothing, and
/// the next send must take the nonce, or its transaction waits behind a gap.
#[tokio::test]
async fn a_send_keeps_its_nonce_only_while_the_node_can_hold_its_transaction() -> Result<()> {
    // The request whose answer is lost, and the transactions that then wait with their own nonces.
    for (lost, waiting) in [("eth_sendRawTransaction", 2), ("eth_estimateGas", 1)] {
        // No mining, so the transactions stay pending and the mined count stays behind.
        let anvil = Anvil::new().arg("--no-mining").try_spawn()?;
        let signer = PrivateKeySigner::random();
        let from = signer.address();
        let upstream = ProviderBuilder::new().connect(&anvil.endpoint()).await?;
        upstream
            .anvil_set_balance(from, U256::from(10).pow(U256::from(18)))
            .await?;
        let provider = ProviderBuilder::new()
            .wallet(signer)
            .connect(&lossy_proxy(anvil.endpoint(), lost).await?)
            .await?;
        // A call to an address without code succeeds, so the test needs no deployed contract.
        let target = EmitLogs::new(Address::repeat_byte(0x42), &provider);

        assert!(
            send_with_next_nonce(target.setValue("lost".to_string()), from)
                .await
                .is_err()
        );
        let _next = send_with_next_nonce(target.setValue("next".to_string()), from).await?;

        assert_eq!(
            upstream.get_transaction_count(from).pending().await?,
            waiting,
            "{lost}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_event_listener() -> Result<()> {
    let (contract, _, _, anvil) = setup_logs_contract().await?;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(10);
    let (tx_addr, mut rx_addr) = tokio::sync::mpsc::channel::<String>(10);

    let event_listener = Arc::new(
        EventListener::create_contract_listener(
            &anvil.ws_endpoint(),
            &[&contract.address().to_string()],
        )
        .await?,
    );

    event_listener
        .add_event_handler(move |event: EmitLogs::ValueChanged| {
            let tx = tx.clone();
            async move {
                let _ = tx.try_send(event.value.clone());
                Ok(())
            }
        })
        .await;

    event_listener
        .add_event_handler(move |event: EmitLogs::ValueChanged| {
            let tx_addr = tx_addr.clone();
            async move {
                let _ = tx_addr.try_send(event.author.to_string());
                Ok(())
            }
        })
        .await;

    let spawn_event_listener = event_listener.clone();
    tokio::spawn(async move { spawn_event_listener.listen().await });

    contract
        .setValue("hello".to_string())
        .send()
        .await?
        .watch()
        .await?;

    contract
        .setValue("world!".to_string())
        .send()
        .await?
        .watch()
        .await?;

    assert_eq!(rx.recv().await.unwrap(), "hello");
    assert_eq!(rx.recv().await.unwrap(), "world!");

    assert_eq!(
        rx_addr.recv().await.unwrap(),
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    );
    assert_eq!(
        rx_addr.recv().await.unwrap(),
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    );
    Ok(())
}

fn time_diff(past_timestamp: u128) -> Result<String> {
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let time_diff = current_time.saturating_sub(past_timestamp);
    Ok(format!("{}ms", time_diff))
}

fn process_message_with_timestamp(input: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = input.splitn(2, ':').collect();
    let message = parts[0].to_string();
    let timestamp_str = parts[1].trim();
    let past_timestamp: u128 = timestamp_str.parse()?;
    let time_diff_string = time_diff(past_timestamp)?;
    Ok((message, time_diff_string))
}

#[tokio::test]
async fn test_overlapping_listener_handlers() -> Result<()> {
    // Test that listeners can have overlapping async handlers.
    // Long running handlers should run async while other handlers respond to
    // events without disruption.
    let (contract, _, _, anvil) = setup_logs_contract().await?;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(10);

    let event_listener = Arc::new(
        EventListener::create_contract_listener(
            &anvil.ws_endpoint(),
            &[&contract.address().to_string()],
        )
        .await?,
    );

    let tx1 = tx.clone();
    event_listener
        .add_event_handler(move |event: EmitLogs::PublishMessage| {
            let tx = tx1.clone();
            async move {
                let (msg, time_diff) = process_message_with_timestamp(&event.value)?;
                println!("PublishMessage '{}' ({} since sent)", msg, time_diff);

                let _ = tx.try_send("waiting".to_string());
                // Wait long enough to simulate a long-running handler. Must be large
                // enough that "two" (sent 100ms later) arrives before this completes,
                // even on slow CI runners with ~50ms event delivery latency.
                sleep(Duration::from_millis(1000)).await;
                println!("Sending message: '{msg}'");
                let _ = tx.try_send(msg);
                Ok(())
            }
        })
        .await;

    event_listener
        .add_event_handler(move |event: EmitLogs::ValueChanged| {
            let tx = tx.clone();
            async move {
                let (msg, time_diff) = process_message_with_timestamp(&event.value)?;
                println!("ValueChanged '{}' ({} since sent)", msg, time_diff);
                let _ = tx.try_send(msg);
                Ok(())
            }
        })
        .await;

    let spawn_event_listener = event_listener.clone();
    tokio::spawn(async move { spawn_event_listener.listen().await });

    // Events should be returned roughly in this order:
    // 0ms    : one
    // 0ms    : waiting
    // 100ms  : two
    // 1000ms : three  (after long-running handler completes)
    // 1300ms : four

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    contract
        .setValue(format!("one:{now}"))
        .send()
        .await?
        .watch()
        .await?;

    // Will delay 200ms
    contract
        .emitPublishMessage(format!("three:{now}"))
        .send()
        .await?
        .watch()
        .await?;

    sleep(Duration::from_millis(100)).await;

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    contract
        .setValue(format!("two:{now}"))
        .send()
        .await?
        .watch()
        .await?;

    // Wait for the long-running PublishMessage handler (1000ms) to complete
    // before sending "four", so "three" arrives before "four".
    sleep(Duration::from_millis(1200)).await;

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    contract
        .setValue(format!("four:{now}"))
        .send()
        .await?
        .watch()
        .await?;

    assert_eq!(rx.recv().await.unwrap(), "one");
    assert_eq!(rx.recv().await.unwrap(), "waiting");
    assert_eq!(rx.recv().await.unwrap(), "two");
    assert_eq!(rx.recv().await.unwrap(), "three");
    assert_eq!(rx.recv().await.unwrap(), "four");

    Ok(())
}

#[tokio::test]
async fn test_block_listener() -> Result<()> {
    let anvil = Anvil::new().try_spawn()?;
    let provider = Arc::new(ProviderBuilder::new().connect(&anvil.ws_endpoint()).await?);
    let block_listener = Arc::new(BlockListener::new(provider.clone()));
    let events: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(vec![]));
    let events_handler = events.clone();

    // Save each block number to a vector.
    block_listener
        .add_block_handler(move |block| {
            let events = events_handler.clone();
            let blockheight = block.number();
            async move {
                let mut events = events.lock().await;
                events.push(blockheight);
                Ok(())
            }
        })
        .await;

    // Start up a listener
    let listen_handle = tokio::spawn(async move {
        let _ = block_listener.listen().await;
    });

    // Give the listener time to start
    sleep(Duration::from_millis(100)).await;

    // Mine a few blocks
    provider.anvil_mine(Some(5), None).await?;

    // Wait for the block to be processed
    sleep(Duration::from_secs(1)).await;

    // Cancel the listener
    listen_handle.abort();

    let guard = events.lock().await;
    assert_eq!(*guard, vec![1, 2, 3, 4, 5]);

    Ok(())
}
