// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The account against a real chain node: anvil, which mines only when a test says so.

use super::*;
use alloy::{
    network::EthereumWallet,
    node_bindings::Anvil,
    providers::{ext::AnvilApi, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use alloy_primitives::Address;
use std::sync::Arc;

const GWEI: u128 = 1_000_000_000;

fn call(byte: u8) -> Call {
    Call {
        label: "test",
        to: Address::repeat_byte(0x77),
        data: Bytes::from(vec![byte]),
        gas_multiplier: 1,
    }
}

/// A transaction whose call no one sends any more must not hold up the account's later ones.
#[tokio::test]
async fn an_abandoned_transaction_does_not_hold_up_later_ones() {
    let anvil = Anvil::new().arg("--no-mining").spawn();
    let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
    let account = signer.address();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(anvil.endpoint_url());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("unmined.json");
    let wallet = Arc::new(Wallet::new(provider.clone(), anvil.chain_id(), 0, path).unwrap());

    // A goes out, and then its sender stops.
    let sending = tokio::spawn({
        let wallet = wallet.clone();
        async move { wallet.send(&call(1), 100_000).await }
    });
    while provider
        .get_transaction_count(account)
        .pending()
        .await
        .unwrap()
        == 0
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    sending.abort();
    // Fees rise past what A offered. The chain node does not mine A; anvil drops it from its pool,
    // and a node that keeps it waits for fees to fall. Either way A's nonce stays unused.
    provider
        .anvil_set_next_block_base_fee_per_gas(1_000 * GWEI)
        .await
        .unwrap();
    provider.evm_mine(None).await.unwrap();

    // B goes out at the next nonce, behind A's.
    let landed = tokio::spawn({
        let wallet = wallet.clone();
        async move { wallet.send(&call(2), 100_000).await }
    });
    while !wallet.nonces.lock().await.unmined.sends.contains_key(&1) {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for _ in 0..2 {
        wallet.free_abandoned().await.unwrap();
    }
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        provider.evm_mine(None).await.unwrap();
    }
    let landed = tokio::time::timeout(Duration::from_secs(10), landed).await;
    assert!(
        matches!(landed, Ok(Ok(Ok(true)))),
        "B did not land: {landed:?}"
    );
}

/// A call whose sender still waits for it keeps its transaction, however long it waits.
#[tokio::test]
async fn a_transaction_whose_call_is_still_sent_is_kept() {
    let anvil = Anvil::new().arg("--no-mining").spawn();
    let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
    let account = signer.address();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(anvil.endpoint_url());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("unmined.json");
    let wallet = Arc::new(Wallet::new(provider.clone(), anvil.chain_id(), 0, path).unwrap());

    let _sending = tokio::spawn({
        let wallet = wallet.clone();
        async move { wallet.send(&call(1), 100_000).await }
    });
    while provider
        .get_transaction_count(account)
        .pending()
        .await
        .unwrap()
        == 0
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for _ in 0..3 {
        wallet.free_abandoned().await.unwrap();
    }
    let nonces = wallet.nonces.lock().await;
    let kept = nonces.unmined.sends.get(&0).and_then(|sent| sent.call);
    assert_eq!(kept, Some(call_hash(&call(1))));
}

/// After a restart the chain node's pending count can miss a transaction the account still keeps.
/// A new call takes the next nonce, so the kept one is not overwritten and can still be freed.
#[tokio::test]
async fn a_new_call_after_a_restart_does_not_take_a_kept_nonce() {
    let anvil = Anvil::new().arg("--no-mining").spawn();
    let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
    let account = signer.address();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(anvil.endpoint_url());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("unmined.json");
    let before =
        Arc::new(Wallet::new(provider.clone(), anvil.chain_id(), 0, path.clone()).unwrap());
    let sending = tokio::spawn({
        let wallet = before.clone();
        async move { wallet.send(&call(1), 100_000).await }
    });
    while provider
        .get_transaction_count(account)
        .pending()
        .await
        .unwrap()
        == 0
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    sending.abort();
    let _ = sending.await;
    // The chain node drops A, so its pending count no longer shows it.
    provider
        .anvil_set_next_block_base_fee_per_gas(1_000 * GWEI)
        .await
        .unwrap();
    provider.evm_mine(None).await.unwrap();
    drop(before);

    let after = Arc::new(Wallet::new(provider.clone(), anvil.chain_id(), 0, path).unwrap());
    let _sending = tokio::spawn({
        let wallet = after.clone();
        async move { wallet.send(&call(2), 100_000).await }
    });
    let b = call_hash(&call(2));
    let kept = loop {
        let nonces = after.nonces.lock().await;
        if let Some((nonce, _)) = nonces.unmined.of(&b) {
            break (nonce, nonces.unmined.of(&call_hash(&call(1))));
        }
        drop(nonces);
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(kept.0, 1);
    assert_eq!(kept.1.map(|(nonce, _)| nonce), Some(0));
}
