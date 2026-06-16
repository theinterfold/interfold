// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::primitives::U256;
use anyhow::{bail, Result};
use e3_console::{log, Console};

use super::context::ChainContext;
use super::utils::{format_amount, parse_amount};

pub(crate) async fn register(out: Console, ctx: &ChainContext) -> Result<()> {
    let receipt = ctx
        .bonding()
        .registerOperator()
        .send()
        .await?
        .get_receipt()
        .await?;
    log!(
        out,
        "Registered ciphernode on {} (tx: {:#x})",
        ctx.chain_label(),
        receipt.transaction_hash
    );
    Ok(())
}

pub(crate) async fn deregister(out: Console, ctx: &ChainContext) -> Result<()> {
    let receipt = ctx
        .bonding()
        .deregisterOperator()
        .send()
        .await?
        .get_receipt()
        .await?;
    log!(
        out,
        "Deregistration requested (tx: {:#x})",
        receipt.transaction_hash
    );
    Ok(())
}

pub(crate) async fn activate(out: Console, ctx: &ChainContext) -> Result<()> {
    register(out, ctx).await
}

pub(crate) async fn deactivate(
    out: Console,
    ctx: &ChainContext,
    ticket_amount: Option<String>,
    license_amount: Option<String>,
) -> Result<()> {
    if ticket_amount.is_none() && license_amount.is_none() {
        bail!(
            "Provide --tickets and/or --license to specify what should be withdrawn for deactivation"
        );
    }

    if let Some(amount) = ticket_amount {
        let ticket_contract = ctx.ticket_token_address().await?;
        let decimals = ctx.erc20(ticket_contract).decimals().call().await?;
        let parsed = parse_amount(&amount, decimals)?;
        let receipt = ctx
            .bonding()
            .removeTicketBalance(parsed)
            .send()
            .await?
            .get_receipt()
            .await?;
        log!(
            out,
            "Removed {} tickets (tx: {:#x})",
            amount,
            receipt.transaction_hash
        );
    }

    if let Some(amount) = license_amount {
        let license = ctx.license_token_address().await?;
        let decimals = ctx.erc20(license).decimals().call().await?;
        let parsed = parse_amount(&amount, decimals)?;
        let receipt = ctx
            .bonding()
            .unbondLicense(parsed)
            .send()
            .await?
            .get_receipt()
            .await?;
        log!(
            out,
            "Queued {} FOLD for exit (tx: {:#x})",
            amount,
            receipt.transaction_hash
        );
    }

    log!(
        out,
        "Submitted deactivation transactions; monitor exit delays before claiming."
    );
    Ok(())
}

pub(crate) async fn status(out: Console, ctx: &ChainContext) -> Result<()> {
    let contract = ctx.bonding();
    let operator = ctx.operator();
    let ticket_balance: U256 = contract.getTicketBalance(operator).call().await?;
    let license_bond: U256 = contract.getLicenseBond(operator).call().await?;
    let available_tickets: U256 = contract.availableTickets(operator).call().await?;
    let is_registered: bool = contract.isRegistered(operator).call().await?;
    let is_active: bool = contract.isActive(operator).call().await?;
    let has_exit: bool = contract.hasExitInProgress(operator).call().await?;
    let pending = contract.pendingExits(operator).call().await?;
    let pending_tickets = pending.ticket;
    let pending_license = pending.license;
    let ticket_price: U256 = contract.ticketPrice().call().await?;
    let min_ticket_balance: U256 = contract.minTicketBalance().call().await?;
    let license_required: U256 = contract.licenseRequiredBond().call().await?;

    let ticket_token = ctx.ticket_token_address().await?;
    let license_token = ctx.license_token_address().await?;
    let ticket_decimals = ctx.erc20(ticket_token).decimals().call().await?;
    let license_decimals = ctx.erc20(license_token).decimals().call().await?;

    log!(out, "Ciphernode status on {}:", ctx.chain_label());
    log!(out, "  Address: {:#x}", operator);
    log!(out, "  Registered: {}", is_registered);
    log!(out, "  Active: {}", is_active);
    log!(out, "  Exit pending: {}", has_exit);
    log!(
        out,
        "  Ticket balance: {} ({} available)",
        format_amount(ticket_balance, ticket_decimals),
        format_amount(available_tickets, ticket_decimals)
    );
    log!(
        out,
        "  License bond: {}",
        format_amount(license_bond, license_decimals)
    );
    log!(
        out,
        "  Pending exits: tickets={}, license={}",
        format_amount(pending_tickets, ticket_decimals),
        format_amount(pending_license, license_decimals)
    );
    log!(
        out,
        "  Requirements: minTickets={}, ticketPrice={} EKT, licenseBond={} FOLD",
        format_amount(min_ticket_balance, ticket_decimals),
        format_amount(ticket_price, ticket_decimals),
        format_amount(license_required, license_decimals)
    );
    Ok(())
}
