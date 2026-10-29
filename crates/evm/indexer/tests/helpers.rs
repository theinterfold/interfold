// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::sync::Arc;

// helpers.rs
use alloy::{
    node_bindings::{Anvil, AnvilInstance},
    providers::{Provider, ProviderBuilder, WsConnect},
    signers::local::PrivateKeySigner,
    sol,
};
use eyre::Result;
use EmitLogs::EmitLogsInstance;
use Interfold::InterfoldInstance;

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

pub async fn setup_two_contracts() -> Result<(
    InterfoldInstance<impl Provider>,
    String,
    EmitLogsInstance<impl Provider>,
    String,
    String,
    AnvilInstance,
)> {
    let (provider, endpoint, anvil) = setup_provider().await?;
    let provider = Arc::new(provider);
    let contract1 = Interfold::deploy(provider.clone()).await?;
    let contract2 = EmitLogsInstance::deploy(provider.clone()).await?;
    let address1 = contract1.address().to_string();
    let address2 = contract2.address().to_string();
    Ok((contract1, address1, contract2, address2, endpoint, anvil))
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
