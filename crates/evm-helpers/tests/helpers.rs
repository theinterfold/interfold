// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// helpers.rs
use alloy::{
    node_bindings::{Anvil, AnvilInstance},
    providers::{Provider, ProviderBuilder, WsConnect},
    signers::local::PrivateKeySigner,
    sol,
};
use eyre::Result;
use EmitLogs::EmitLogsInstance;

sol!(
    #[sol(rpc)]
    Interfold,
    "tests/fixtures/fake_interfold.json"
);

sol!(
    #[sol(rpc)]
    EmitLogs,
    "tests/fixtures/emit_logs.json"
);

// Much cleaner return type using impl Provider
pub async fn setup_logs_contract() -> Result<(
    EmitLogsInstance<impl Provider>,
    String,
    String,
    AnvilInstance,
)> {
    let (provider, endpoint, anvil) = setup_provider().await?;
    let contract = EmitLogs::deploy(provider).await?;
    let address = contract.address().to_string();
    Ok((contract, address, endpoint, anvil))
}

pub async fn setup_provider() -> Result<(impl Provider, String, AnvilInstance)> {
    // Set anvil with fast blocktimes for testing
    let anvil = Anvil::new().block_time_f64(0.01).try_spawn()?;

    let provider = ProviderBuilder::new()
        .wallet(PrivateKeySigner::from_slice(&anvil.keys()[0].to_bytes())?)
        .connect_ws(WsConnect::new(anvil.ws_endpoint()))
        .await?;

    let endpoint = anvil.ws_endpoint();
    Ok((provider, endpoint, anvil))
}
