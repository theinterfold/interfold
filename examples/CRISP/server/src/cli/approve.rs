// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, U256};
use alloy::providers::ProviderBuilder;
use alloy::rpc::client::RpcClient;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::transports::http::Http;
use crisp::config::CONFIG;
use crisp::server::rpc;
use eyre::Result;
use log::info;

sol! {
    #[sol(rpc)]
    contract ERC20 {
        function approve(address spender, uint256 amount) external returns (bool);
        function allowance(address owner, address spender) external view returns (uint256);
    }
}

/// Let the Interfold contract spend `amount` of the fee token, unless it already may.
pub async fn approve_fee_token(amount: U256) -> Result<()> {
    let token_address: Address = CONFIG.fee_token_address.parse()?;
    let spender: Address = CONFIG.interfold_address.parse()?;
    let signer: PrivateKeySigner = CONFIG.private_key.parse()?;
    let owner = signer.address();

    let url: reqwest::Url = CONFIG.http_rpc_url.parse()?;
    let transport = Http::with_client(rpc::HTTP.clone(), url);
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_client(RpcClient::new(transport, false));

    let contract = ERC20::new(token_address, &provider);
    let current_allowance = contract.allowance(owner, spender).call().await?;
    info!("Current allowance: {current_allowance}");

    if current_allowance < amount {
        info!("Approving {amount} tokens for spender {spender}");
        let receipt = contract
            .approve(spender, amount)
            .send()
            .await?
            .get_receipt()
            .await?;
        info!(
            "Approval successful. TxHash: {:?}",
            receipt.transaction_hash
        );
    } else {
        info!("Sufficient allowance already exists");
    }

    Ok(())
}
