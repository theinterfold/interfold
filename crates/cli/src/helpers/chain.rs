// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::{
    contract::{CallBuilder, CallDecoder},
    primitives::TxHash,
    providers::Provider,
};
use anyhow::{anyhow, Result};
use e3_config::{chain_config::ChainConfig, AppConfig};
use e3_evm::error_decoder::format_evm_error;
use e3_utils::require_successful_receipt;

pub fn select_chain<'a>(config: &'a AppConfig, name: Option<&str>) -> Result<&'a ChainConfig> {
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

pub async fn send_and_confirm<P: Provider, D: CallDecoder>(
    label: &str,
    call: CallBuilder<P, D>,
) -> Result<TxHash> {
    let pending = call.send().await.map_err(|err| {
        anyhow!(
            "{label} failed: {}",
            format_evm_error(&anyhow::Error::new(err))
        )
    })?;

    let receipt = pending.get_receipt().await?;
    require_successful_receipt(label, &receipt)?;

    Ok(receipt.transaction_hash)
}
