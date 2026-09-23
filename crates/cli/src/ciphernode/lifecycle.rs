// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::primitives::{Address, U256};
use anyhow::{bail, Result};
use e3_console::{log, Console};

use crate::helpers::chain::send_and_confirm;

use super::context::{parse_address, ChainContext};
use super::utils::format_amount;
use super::{bond, tickets};

pub(crate) async fn set_bond_owner(out: Console, ctx: &ChainContext, owner: &str) -> Result<()> {
    let owner = parse_address(owner)?;

    let tx = send_and_confirm("set bond owner", ctx.bonding().setBondOwner(owner)).await?;

    log!(
        out,
        "Authorized bond owner {:#x} for operator {:#x} (tx: {:#x})",
        owner,
        ctx.operator(),
        tx
    );
    Ok(())
}

pub(crate) async fn propose_bond_owner(
    out: Console,
    ctx: &ChainContext,
    operator: &str,
    new_owner: &str,
) -> Result<()> {
    let operator = parse_address(operator)?;
    let new_owner = parse_address(new_owner)?;

    let tx = send_and_confirm(
        "propose bond owner",
        ctx.bonding().proposeBondOwner(operator, new_owner),
    )
    .await?;

    log!(
        out,
        "Proposed {:#x} as owner of operator {:#x} (tx: {:#x})",
        new_owner,
        operator,
        tx
    );
    Ok(())
}

pub(crate) async fn accept_bond_owner(
    out: Console,
    ctx: &ChainContext,
    operator: &str,
) -> Result<()> {
    let operator = parse_address(operator)?;

    let tx = send_and_confirm("accept bond owner", ctx.bonding().acceptBondOwner(operator)).await?;

    log!(
        out,
        "Accepted ownership of operator {:#x} (tx: {:#x})",
        operator,
        tx
    );
    Ok(())
}

pub(crate) async fn register(out: Console, ctx: &ChainContext, operator: Address) -> Result<()> {
    let tx = send_and_confirm(
        "register ciphernode",
        ctx.bonding().registerOperatorFor(operator),
    )
    .await?;

    log!(
        out,
        "Registered operator {:#x} on {} (tx: {:#x})",
        operator,
        ctx.chain_label(),
        tx
    );
    Ok(())
}

pub(crate) async fn deregister(out: Console, ctx: &ChainContext, operator: Address) -> Result<()> {
    let tx = send_and_confirm(
        "deregister operator",
        ctx.bonding().deregisterOperatorFor(operator),
    )
    .await?;

    log!(
        out,
        "Deregistration requested for {:#x} (tx: {:#x})",
        operator,
        tx
    );
    Ok(())
}

pub(crate) async fn activate(out: Console, ctx: &ChainContext, operator: Address) -> Result<()> {
    register(out, ctx, operator).await
}

pub(crate) async fn deactivate(
    out: Console,
    ctx: &ChainContext,
    operator: Address,
    ticket_amount: Option<String>,
    ciphernode_bond_amount: Option<String>,
) -> Result<()> {
    if ticket_amount.is_none() && ciphernode_bond_amount.is_none() {
        bail!(
            "Provide --tickets and/or --bond to specify what should be withdrawn for deactivation"
        );
    }

    if let Some(amount) = ticket_amount {
        tickets::burn(out.clone(), ctx, operator, &amount).await?;
    }

    if let Some(amount) = ciphernode_bond_amount {
        bond::unbond(out, ctx, operator, &amount).await?;
    }

    Ok(())
}

pub(crate) async fn status(out: Console, ctx: &ChainContext, operator: Address) -> Result<()> {
    let contract = ctx.bonding();
    let bond_owner = contract.bondOwnerOf(operator).call().await?;
    let pending_owner = contract.pendingBondOwnerOf(operator).call().await?;
    let ticket_balance: U256 = contract.getTicketBalance(operator).call().await?;
    let ciphernode_bond: U256 = contract.getCiphernodeBond(operator).call().await?;
    let available_tickets: U256 = contract.availableTickets(operator).call().await?;
    let is_registered: bool = contract.isRegistered(operator).call().await?;
    let is_active: bool = contract.isActive(operator).call().await?;
    let has_exit: bool = contract.hasExitInProgress(operator).call().await?;
    let pending = contract.pendingExits(operator).call().await?;
    let pending_tickets = pending.ticket;
    let pending_ciphernode_bond = pending.ciphernodeBond;
    let ticket_price: U256 = contract.ticketPrice().call().await?;
    let min_ticket_balance: U256 = contract.minTicketBalance().call().await?;
    let required_ciphernode_bond: U256 = contract.requiredCiphernodeBond().call().await?;

    let ticket_token = ctx.ticket_token_address().await?;
    let ciphernode_bond_token = ctx.ciphernode_bond_token_address().await?;
    let ticket_decimals = ctx.erc20(ticket_token).decimals().call().await?;
    let ciphernode_bond_decimals = ctx.erc20(ciphernode_bond_token).decimals().call().await?;

    log!(out, "Ciphernode status on {}:", ctx.chain_label());
    log!(out, "  Operator key: {:#x}", operator);
    if bond_owner.is_zero() {
        log!(out, "  Bond owner: not configured");
    } else {
        log!(out, "  Bond owner: {:#x}", bond_owner);
    }
    if !pending_owner.is_zero() {
        log!(out, "  Pending bond owner: {:#x}", pending_owner);
    }
    log!(out, "  Registered: {}", is_registered);
    log!(out, "  Active: {}", is_active);
    log!(out, "  Exit pending: {}", has_exit);
    log!(
        out,
        "  Ticket balance: {} ({} available)",
        format_amount(ticket_balance, ticket_decimals),
        available_tickets
    );
    log!(
        out,
        "  Ciphernode bond: {}",
        format_amount(ciphernode_bond, ciphernode_bond_decimals)
    );
    log!(
        out,
        "  Pending exits: tickets={}, bond={}",
        format_amount(pending_tickets, ticket_decimals),
        format_amount(pending_ciphernode_bond, ciphernode_bond_decimals)
    );
    log!(
        out,
        "  Requirements: minTickets={}, ticketPrice={} tFOLD, ciphernodeBond={} FOLD",
        min_ticket_balance,
        format_amount(ticket_price, ticket_decimals),
        format_amount(required_ciphernode_bond, ciphernode_bond_decimals)
    );
    Ok(())
}
