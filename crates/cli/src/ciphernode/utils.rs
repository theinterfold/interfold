// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::str::FromStr;

use alloy::primitives::{Address, U256};
use anyhow::{bail, Context, Result};

use crate::helpers::chain::send_and_confirm;

use super::context::ChainContext;

pub(crate) fn format_amount(amount: U256, decimals: u8) -> String {
    let scale = U256::from(10u64).pow(U256::from(decimals as u64));
    let int_part = amount / scale;
    let frac_part = amount % scale;

    if frac_part == U256::from(0) {
        int_part.to_string()
    } else {
        let frac_str = frac_part.to_string();
        let frac_padded = format!("{:0>width$}", frac_str, width = decimals as usize);
        let frac_trimmed = frac_padded.trim_end_matches('0');
        if frac_trimmed.is_empty() {
            int_part.to_string()
        } else {
            format!("{}.{}", int_part, frac_trimmed)
        }
    }
}

pub(crate) fn parse_amount(value: &str, decimals: u8) -> Result<U256> {
    let normalized = value.trim().replace('_', "");
    if normalized.is_empty() {
        bail!("Amount cannot be empty");
    }

    let parts: Vec<&str> = normalized.split('.').collect();
    if parts.len() > 2 {
        bail!("Invalid decimal amount '{}'", value);
    }

    let int_part = parts[0];
    let int_value = U256::from_str(int_part).context("Invalid integer component")?;
    let scale = U256::from(10u64).pow(U256::from(decimals as u64));
    let mut result = int_value * scale;

    if parts.len() == 2 {
        let frac = parts[1];
        if frac.is_empty() {
            return Ok(result);
        }
        let frac_len = frac.len();
        if frac_len > decimals as usize {
            bail!(
                "Fractional precision exceeds token decimals ({} > {})",
                frac_len,
                decimals
            );
        }
        let frac_value = U256::from_str(frac).context("Invalid fractional component")?;
        let power = decimals as usize - frac_len;
        let multiplier = U256::from(10u64).pow(U256::from(power as u64));
        result += frac_value * multiplier;
    }

    Ok(result)
}

pub(crate) async fn ensure_allowance(
    ctx: &ChainContext,
    token: Address,
    spender: Address,
    amount: U256,
) -> Result<()> {
    let erc20 = ctx.erc20(token);
    let current = erc20.allowance(ctx.operator(), spender).call().await?;
    if current >= amount {
        return Ok(());
    }

    send_and_confirm("approve token allowance", erc20.approve(spender, amount)).await?;

    Ok(())
}
