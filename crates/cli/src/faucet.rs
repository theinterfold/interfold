// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::str::FromStr;

use alloy::{
    primitives::{Address, U256},
    providers::WalletProvider,
    sol,
};
use anyhow::{anyhow, bail, Context, Result};
use e3_config::{chain_config::ChainConfig, AppConfig};
use e3_console::{log, Console};
use e3_crypto::Cipher;
use e3_entrypoint::helpers::datastore::get_repositories;
use e3_evm::{
    error_decoder::format_evm_error,
    helpers::{load_signer_from_repository, ProviderConfig},
    EthPrivateKeyRepositoryFactory,
};

mod faucet_contract {
    use super::sol;

    sol!(
        #[sol(rpc)]
        FaucetContract,
        "../../packages/interfold-contracts/artifacts/contracts/test/Faucet.sol/Faucet.json"
    );
}

mod erc20 {
    use super::sol;

    sol!(
        #[sol(rpc)]
        interface IERC20 {
            function balanceOf(address account) external view returns (uint256);
        }
    );
}

use erc20::IERC20;
use faucet_contract::FaucetContract;

/// Calls `faucet()` on the configured Faucet contract, sending FOLD + fee
/// tokens to the operator's signing address. Testnet only.
pub async fn execute(out: Console, config: &AppConfig, selection: Option<&str>) -> Result<()> {
    let chain = select_chain(config, selection)?;
    let faucet_contract = chain
        .contracts
        .faucet
        .as_ref()
        .ok_or_else(|| anyhow!("No `faucet` contract configured for chain '{}'", chain.name))?;
    let faucet_address =
        Address::from_str(faucet_contract.address_str()).context("Invalid faucet address")?;

    let rpc = chain.rpc_url()?;
    let cipher = Cipher::from_file(config.key_file()).await?;
    let repositories = get_repositories(config)?;
    let signer = load_signer_from_repository(repositories.eth_private_key(), &cipher).await?;
    let provider = ProviderConfig::new(rpc, chain.rpc_auth.clone())
        .create_signer_provider(&signer)
        .await?;
    let recipient = provider.provider().default_signer_address();

    let faucet = FaucetContract::new(faucet_address, provider.provider().clone());

    // Replicate the contract's gating client-side so we can print a clear
    // message instead of a bare "execution reverted" (many RPCs omit the
    // revert reason). The faucet tops up each token independently, only when
    // the caller's balance is below the per-token amount.
    let fold_addr = faucet.fold().call().await?;
    let fee_token_addr = faucet.feeToken().call().await?;
    let amount_fold = faucet.AMOUNT_FOLD().call().await?;
    let amount_fee_token = faucet.AMOUNT_FEE_TOKEN().call().await?;

    let fold = IERC20::new(fold_addr, provider.provider().clone());
    let fee_token = IERC20::new(fee_token_addr, provider.provider().clone());

    let caller_fold = fold.balanceOf(recipient).call().await?;
    let caller_fee_token = fee_token.balanceOf(recipient).call().await?;

    let needs_fold = caller_fold < amount_fold;
    let needs_fee_token = caller_fee_token < amount_fee_token;

    if !needs_fold && !needs_fee_token {
        log!(
            out,
            "Nothing to claim: {:#x} already holds at least {} FOLD and {} fee tokens.",
            recipient,
            format_units(amount_fold, 18),
            format_units(amount_fee_token, 6)
        );
        return Ok(());
    }

    // Check the faucet itself is funded for whatever the caller needs.
    if needs_fold {
        let faucet_fold = fold.balanceOf(faucet_address).call().await?;
        if faucet_fold < amount_fold {
            bail!(
                "Faucet is out of FOLD (has {}, needs {}). Ask an admin to refund it.",
                format_units(faucet_fold, 18),
                format_units(amount_fold, 18)
            );
        }
    }
    if needs_fee_token {
        let faucet_fee_token = fee_token.balanceOf(faucet_address).call().await?;
        if faucet_fee_token < amount_fee_token {
            bail!(
                "Faucet is out of fee tokens (has {}, needs {}). Ask an admin to refund it.",
                format_units(faucet_fee_token, 6),
                format_units(amount_fee_token, 6)
            );
        }
    }

    let receipt = faucet
        .faucet()
        .send()
        .await
        .map_err(|err| {
            anyhow!(
                "Faucet transaction failed: {}",
                format_evm_error(&anyhow::Error::new(err))
            )
        })?
        .get_receipt()
        .await?;

    log!(
        out,
        "Faucet sent {}{}{} to {:#x} (tx: {:#x})",
        if needs_fold {
            format!("{} FOLD", format_units(amount_fold, 18))
        } else {
            String::new()
        },
        if needs_fold && needs_fee_token {
            " + "
        } else {
            ""
        },
        if needs_fee_token {
            format!("{} fee tokens", format_units(amount_fee_token, 6))
        } else {
            String::new()
        },
        recipient,
        receipt.transaction_hash
    );

    Ok(())
}

/// Format a token amount for display, falling back to the raw integer if the
/// decimals can't be applied.
fn format_units(value: U256, decimals: u8) -> String {
    alloy::primitives::utils::format_units(value, decimals).unwrap_or_else(|_| value.to_string())
}

fn select_chain<'a>(config: &'a AppConfig, name: Option<&str>) -> Result<&'a ChainConfig> {
    match name {
        Some(desired) => config
            .chains()
            .iter()
            .find(|c| c.name == desired)
            .ok_or_else(|| anyhow!("Chain '{}' not found in configuration", desired)),
        None => config.chains().first().ok_or_else(|| {
            anyhow!("No chains configured. Run `interfold ciphernode setup` first.")
        }),
    }
}
