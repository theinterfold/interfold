// SPDX-License-Identifier: LGPL-3.0-only

use alloy::{
    node_bindings::Anvil,
    primitives::{Address, Bytes, U256},
    providers::{ext::AnvilApi, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolValue,
};
use e3_evm_client::{
    contracts::{
        CommitteeSize, E3Stage, FailureReason, InterfoldContract, InterfoldRead, InterfoldWrite,
    },
    events::E3Requested,
};
use eyre::Result;
use std::time::Duration;

sol!(
    #[sol(rpc)]
    ClientContract,
    "tests/fixtures/client_contract.json"
);

#[tokio::test]
async fn request_uses_the_canonical_event_and_failed_receipts_remain_errors() -> Result<()> {
    let anvil = Anvil::new().chain_id(92322).try_spawn()?;
    let signer = PrivateKeySigner::from_slice(&anvil.keys()[0].to_bytes())?;
    let account = signer.address();
    let key = alloy::hex::encode(signer.to_bytes());
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect(&anvil.endpoint())
        .await?;
    let deployed = ClientContract::deploy(&provider).await?;
    let address = *deployed.address();
    let client = InterfoldContract::new(&anvil.endpoint(), &key, &address.to_string()).await?;

    let (receipt, id) = client
        .request_e3(
            CommitteeSize::Micro,
            [U256::from(10), U256::from(20)],
            Address::repeat_byte(7),
            0,
            Bytes::new(),
            Bytes::from_static(b"custom"),
        )
        .await?;
    assert_eq!(id, U256::from(41));
    let event = receipt.logs()[0].log_decode::<E3Requested>()?.inner.data;
    assert_eq!(event.e3Id, id);
    assert_eq!(event.e3.committeeSize, u8::from(CommitteeSize::Micro));
    assert_eq!(event.e3.customParams.as_ref(), b"custom");
    assert_eq!(event.e3.requester, account);
    let read: e3_evm_client::events::E3 = client.get_e3(id).await?;
    assert_eq!(read.abi_encode(), event.e3.abi_encode());
    assert_eq!(client.get_e3_stage(id).await?, E3Stage::__Invalid);
    assert_eq!(
        client.get_failure_reason(id).await?,
        FailureReason::__Invalid
    );

    // Let estimation and broadcast succeed, then make execution revert before mining. A submitted
    // transaction is not a successful receipt, even through the high-level client API.
    provider.anvil_set_auto_mine(false).await?;
    let nonce = provider.get_transaction_count(account).await?;
    let write = tokio::spawn(async move { client.register_e3_program(Address::ZERO).await });
    tokio::time::timeout(Duration::from_secs(10), async {
        while provider.get_transaction_count(account).pending().await? == nonce {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok::<_, eyre::Report>(())
    })
    .await??;
    provider
        .anvil_set_code(address, Bytes::from_static(&[0x60, 0, 0x60, 0, 0xfd]))
        .await?;
    provider.anvil_mine(Some(1), None).await?;
    let error = tokio::time::timeout(Duration::from_secs(20), write)
        .await??
        .unwrap_err();
    assert!(
        error.to_string().contains("register E3 program"),
        "{error:?}"
    );
    Ok(())
}
