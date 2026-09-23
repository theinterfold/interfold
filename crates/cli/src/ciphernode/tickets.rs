// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::primitives::{Address, TxHash};
use anyhow::Result;
use e3_console::{log, Console};

use crate::helpers::chain::send_and_confirm;

use super::context::ChainContext;
use super::utils::{ensure_allowance, parse_amount};
use super::TicketCommands;

pub(crate) async fn execute(
    out: Console,
    ctx: &ChainContext,
    operator: Address,
    command: TicketCommands,
) -> Result<()> {
    match command {
        TicketCommands::Buy { amount } => {
            let ticket_contract = ctx.ticket_token_address().await?;
            let underlying = ctx.ticket_underlying_address().await?;
            let metadata = ctx.erc20(underlying);
            let decimals = metadata.decimals().call().await?;
            let symbol = metadata.symbol().call().await?;
            let parsed = parse_amount(&amount, decimals)?;
            ensure_allowance(ctx, underlying, ticket_contract, parsed).await?;

            let tx = send_and_confirm(
                "add ticket balance",
                ctx.bonding().addTicketBalanceFor(operator, parsed),
            )
            .await?;
            // `--amount` is collateral, not a ticket count: the contract holds a
            // collateral balance and derives tickets as floor(balance / ticketPrice).
            // Read the count back so a remainder (105 USDC at 10 USDC/ticket) is not
            // reported as a ticket the operator does not have.
            let action = format!("Deposited {amount} {symbol} for operator {operator:#x}");
            report_ticket_balance(out, ctx, operator, &action, tx).await;
        }
        TicketCommands::Burn { amount } => burn(out, ctx, operator, &amount).await?,
    }

    Ok(())
}

/// Removes `amount` of ticket collateral from `operator` and reports the new ticket balance.
pub(crate) async fn burn(
    out: Console,
    ctx: &ChainContext,
    operator: Address,
    amount: &str,
) -> Result<()> {
    let ticket_metadata = ctx.erc20(ctx.ticket_token_address().await?);
    let decimals = ticket_metadata.decimals().call().await?;
    let symbol = ticket_metadata.symbol().call().await?;
    let parsed = parse_amount(amount, decimals)?;

    let tx = send_and_confirm(
        "remove ticket balance",
        ctx.bonding().removeTicketBalanceFor(operator, parsed),
    )
    .await?;

    let action = format!("Burned {amount} {symbol} from operator {operator:#x}");
    report_ticket_balance(out, ctx, operator, &action, tx).await;
    Ok(())
}

/// Logs `action` with the ticket count read back after a confirmed transaction.
///
/// The transaction already succeeded, so a failed read is reported and does not fail the command.
async fn report_ticket_balance(
    out: Console,
    ctx: &ChainContext,
    operator: Address,
    action: &str,
    tx: TxHash,
) {
    match ctx.bonding().availableTickets(operator).call().await {
        Ok(tickets) => log!(
            out,
            "{action}. Ticket balance is now {tickets} tickets (tx: {tx:#x})"
        ),
        Err(err) => log!(
            out,
            "{action} (tx: {tx:#x}). Could not read the ticket balance: {err}"
        ),
    }
}
