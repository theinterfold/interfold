// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod helpers;
use alloy::consensus::BlockHeader;
use alloy::providers::ext::AnvilApi;
use alloy::{node_bindings::Anvil, providers::ProviderBuilder, sol};
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
