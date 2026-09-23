// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::primitives::{Address, U256};
use anyhow::Result;
use e3_console::{log, Console};

use crate::helpers::chain::send_and_confirm;

use super::context::ChainContext;
use super::utils::{ensure_allowance, parse_amount};
use super::BondCommands;

pub(crate) async fn execute(
    out: Console,
    ctx: &ChainContext,
    operator: Address,
    command: BondCommands,
) -> Result<()> {
    match command {
        BondCommands::Bond { amount } => {
            bond_ciphernode(out, ctx, operator, &amount).await?;
        }
        BondCommands::Unbond { amount } => unbond(out, ctx, operator, &amount).await?,
        BondCommands::Claim {
            max_ticket,
            max_bond,
        } => {
            let ticket_decimals = ctx
                .erc20(ctx.ticket_token_address().await?)
                .decimals()
                .call()
                .await?;
            let ciphernode_bond_decimals = ctx
                .erc20(ctx.ciphernode_bond_token_address().await?)
                .decimals()
                .call()
                .await?;

            let ticket = if let Some(value) = max_ticket {
                parse_amount(&value, ticket_decimals)?
            } else {
                U256::MAX
            };
            let ciphernode_bond = if let Some(value) = max_bond {
                parse_amount(&value, ciphernode_bond_decimals)?
            } else {
                U256::MAX
            };

            let tx = send_and_confirm(
                "claim exits",
                ctx.bonding()
                    .claimExitsFor(operator, ticket, ciphernode_bond),
            )
            .await?;
            log!(
                out,
                "Claimed exits for operator {:#x} (tx: {:#x})",
                operator,
                tx
            );
        }
    }

    Ok(())
}

async fn bond_ciphernode(
    out: Console,
    ctx: &ChainContext,
    operator: Address,
    amount: &str,
) -> Result<()> {
    let ciphernode_bond = ctx.ciphernode_bond_token_address().await?;
    let erc20 = ctx.erc20(ciphernode_bond);
    let decimals = erc20.decimals().call().await?;
    let parsed = parse_amount(amount, decimals)?;
    ensure_allowance(ctx, ciphernode_bond, ctx.bonding_registry(), parsed).await?;

    let tx = send_and_confirm(
        "bond FOLD",
        ctx.bonding().bondCiphernodeFor(operator, parsed),
    )
    .await?;

    log!(
        out,
        "Bonded {} FOLD for operator {:#x} (tx: {:#x})",
        amount,
        operator,
        tx
    );
    Ok(())
}

/// Queues `amount` of the ciphernode bond of `operator` for exit.
pub(crate) async fn unbond(
    out: Console,
    ctx: &ChainContext,
    operator: Address,
    amount: &str,
) -> Result<()> {
    let ciphernode_bond = ctx.ciphernode_bond_token_address().await?;
    let decimals = ctx.erc20(ciphernode_bond).decimals().call().await?;
    let parsed = parse_amount(amount, decimals)?;

    let tx = send_and_confirm(
        "unbond FOLD",
        ctx.bonding().unbondCiphernodeFor(operator, parsed),
    )
    .await?;

    log!(
        out,
        "Queued {} FOLD for operator {:#x} (tx: {:#x})",
        amount,
        operator,
        tx
    );
    Ok(())
}
