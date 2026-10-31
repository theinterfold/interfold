// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Refreshes this node's operator once in each owner capacity window.
//!
//! Under a required identity policy, BondingRegistry counts bond owners for request admission in
//! fixed windows. When a window ends, the count reads zero until operator refreshes rebuild it, and
//! no view shows which owners the new count holds. So each full node refreshes its own operator
//! once in each window. The node keeps the window in memory, so it refreshes once more after a
//! restart. A sent refresh settles before the node sends another: a check waits while it is pending,
//! takes its window from its block once mined, and sends again only if it reverted or left the
//! mempool.

use crate::{
    contracts::IBondingRegistry,
    helpers::{get_current_timestamp_from_provider, send_with_next_nonce, EthProvider},
};
use actix::prelude::*;
use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, TxHash},
    providers::{Provider, WalletProvider},
};
use anyhow::{Context as _, Result};
use e3_events::{
    prelude::*, BusHandle, EffectsEnabled, EventType, InterfoldEvent, InterfoldEventData, Shutdown,
};
use e3_sortition::IdentityPolicyRequiredAt;
use e3_utils::NotifySync;
use std::time::Duration;
use tracing::{info, warn};

/// `BondOwnerCapacityLib.IDENTITY_CAPACITY_WINDOW`. Windows start at multiples of it from Unix
/// time zero.
const CAPACITY_WINDOW_SECS: u64 = 30 * 24 * 60 * 60;

/// The wait before the first check after effects start, and between checks. The first wait keeps
/// a node that restarts in a loop from sending a refresh at each start.
const CHECK_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// The refresh writes the registry's activity and capacity checkpoints at `block.timestamp`, so it
/// needs the same margin as the release acknowledgment.
const REFRESH_GAS_MULTIPLIER: u64 = 2;

/// Whether the node must refresh its operator at `timestamp`, given the window of its last refresh.
fn refresh_due(required: bool, timestamp: u64, refreshed_window: Option<u64>) -> bool {
    required && refreshed_window != Some(timestamp / CAPACITY_WINDOW_SECS)
}

/// The refresh state of one chain between checks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Progress {
    /// The window of the last refresh that this process saw mined.
    refreshed_window: Option<u64>,
    /// A refresh that this process sent and has not seen settle.
    pending: Option<TxHash>,
}

/// Where a sent refresh stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sent {
    Pending,
    /// Mined successfully, in a block with this timestamp.
    Mined(u64),
    /// Reverted, or no longer known to the node's RPC.
    Lost,
}

impl Progress {
    /// Apply the state of the pending refresh. Returns whether the node may send another.
    fn settle(&mut self, sent: Sent) -> bool {
        match sent {
            Sent::Pending => return false,
            Sent::Mined(timestamp) => {
                self.refreshed_window = Some(timestamp / CAPACITY_WINDOW_SECS);
            }
            Sent::Lost => {}
        }
        self.pending = None;
        true
    }
}

/// Refreshes the operator of this node in each owner capacity window of one chain.
pub struct CapacityRefresher<P> {
    provider: EthProvider<P>,
    bonding_registry: Address,
    identity_policy: Recipient<IdentityPolicyRequiredAt>,
    progress: Progress,
    checking: bool,
}

impl<P: Provider + WalletProvider + Clone + 'static> CapacityRefresher<P> {
    pub fn attach(
        bus: &BusHandle,
        provider: EthProvider<P>,
        bonding_registry: Address,
        identity_policy: Recipient<IdentityPolicyRequiredAt>,
    ) {
        let addr = Self {
            provider,
            bonding_registry,
            identity_policy,
            progress: Progress::default(),
            checking: false,
        }
        .start();
        bus.subscribe_all(
            &[EventType::EffectsEnabled, EventType::Shutdown],
            addr.into(),
        );
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Actor for CapacityRefresher<P> {
    type Context = Context<Self>;
}

#[derive(Message)]
#[rtype(result = "()")]
struct Check;

impl<P: Provider + WalletProvider + Clone + 'static> Handler<InterfoldEvent>
    for CapacityRefresher<P>
{
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        match msg.into_data() {
            InterfoldEventData::EffectsEnabled(data) => self.notify_sync(ctx, data),
            InterfoldEventData::Shutdown(data) => self.notify_sync(ctx, data),
            _ => (),
        }
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<EffectsEnabled>
    for CapacityRefresher<P>
{
    type Result = ();

    fn handle(&mut self, _: EffectsEnabled, ctx: &mut Self::Context) -> Self::Result {
        if !self.checking {
            self.checking = true;
            ctx.notify_later(Check, CHECK_INTERVAL);
        }
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<Shutdown> for CapacityRefresher<P> {
    type Result = ();

    fn handle(&mut self, _: Shutdown, ctx: &mut Self::Context) -> Self::Result {
        ctx.stop();
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<Check> for CapacityRefresher<P> {
    type Result = ResponseActFuture<Self, ()>;

    fn handle(&mut self, _: Check, _: &mut Self::Context) -> Self::Result {
        let provider = self.provider.clone();
        let bonding_registry = self.bonding_registry;
        let identity_policy = self.identity_policy.clone();
        let mut progress = self.progress;
        Box::pin(
            async move {
                let result =
                    check(&provider, bonding_registry, identity_policy, &mut progress).await;
                (progress, result)
            }
            .into_actor(self)
            .map(|(progress, result), actor, ctx| {
                // Keep what the check learned even when a later step failed.
                actor.progress = progress;
                if let Err(error) = result {
                    warn!(
                        chain_id = actor.provider.chain_id(),
                        "Could not refresh the operator for the owner capacity window: {error:#}"
                    );
                }
                ctx.notify_later(Check, CHECK_INTERVAL);
            }),
        )
    }
}

/// Settle a sent refresh, then refresh the operator when its window is due.
async fn check<P>(
    provider: &EthProvider<P>,
    bonding_registry: Address,
    identity_policy: Recipient<IdentityPolicyRequiredAt>,
    progress: &mut Progress,
) -> Result<()>
where
    P: Provider + WalletProvider + Clone + 'static,
{
    if let Some(hash) = progress.pending {
        if !progress.settle(sent_state(provider, hash).await?) {
            return Ok(());
        }
    }
    let timestamp = get_current_timestamp_from_provider(provider.clone()).await?;
    let required = identity_policy
        .send(IdentityPolicyRequiredAt {
            chain_id: provider.chain_id(),
            timepoint: timestamp,
        })
        .await??;
    if !refresh_due(required, timestamp, progress.refreshed_window) {
        return Ok(());
    }
    // An unregistered operator sends nothing and keeps the window open, so a registration later in
    // the window gets its refresh at the next check.
    if let Some(hash) = send_refresh(provider, bonding_registry).await? {
        progress.pending = Some(hash);
    }
    Ok(())
}

/// Read where a sent refresh stands.
async fn sent_state<P>(provider: &EthProvider<P>, hash: TxHash) -> Result<Sent>
where
    P: Provider + WalletProvider + Clone + 'static,
{
    let client = provider.provider();
    if let Some(receipt) = client.get_transaction_receipt(hash).await? {
        if !receipt.status() {
            warn!(tx = %hash, "The operator refresh reverted; the next check sends it again");
            return Ok(Sent::Lost);
        }
        let block = receipt
            .block_number
            .context("mined refresh receipt has no block number")?;
        let timestamp = client
            .get_block_by_number(BlockNumberOrTag::Number(block))
            .await?
            .context("block of the mined refresh not found")?
            .header
            .timestamp;
        info!(tx = %hash, "Refreshed the operator for the owner capacity window");
        return Ok(Sent::Mined(timestamp));
    }
    if client.get_transaction_by_hash(hash).await?.is_some() {
        return Ok(Sent::Pending);
    }
    warn!(tx = %hash, "The operator refresh left the mempool; the next check sends it again");
    Ok(Sent::Lost)
}

/// Send `refreshOperatorStatus` for this node's operator. Returns `None` for an unregistered
/// operator, whose call would revert.
async fn send_refresh<P>(
    provider: &EthProvider<P>,
    bonding_registry: Address,
) -> Result<Option<TxHash>>
where
    P: Provider + WalletProvider + Clone + 'static,
{
    let operator = provider.provider().default_signer_address();
    let bonding = IBondingRegistry::new(bonding_registry, provider.provider());
    if !bonding.isRegistered(operator).call().await? {
        return Ok(None);
    }
    let call = bonding.refreshOperatorStatus(operator);
    let gas = call.estimate_gas().await?;
    let pending = send_with_next_nonce(
        provider,
        call.gas(gas.saturating_mul(REFRESH_GAS_MULTIPLIER)),
    )
    .await?;
    let hash = *pending.tx_hash();
    info!(tx = %hash, "Sent the operator refresh for the owner capacity window");
    Ok(Some(hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refreshes_once_in_each_window_under_a_required_policy() {
        let last_of_four = CAPACITY_WINDOW_SECS * 5 - 1;
        let first_of_five = CAPACITY_WINDOW_SECS * 5;

        assert!(!refresh_due(false, first_of_five, None));
        assert!(refresh_due(true, last_of_four, None));
        assert!(!refresh_due(true, last_of_four, Some(4)));
        assert!(refresh_due(true, first_of_five, Some(4)));
        assert!(!refresh_due(true, first_of_five, Some(5)));
    }

    #[test]
    fn a_sent_refresh_settles_before_another_is_sent() {
        let hash = TxHash::repeat_byte(1);
        let sent = Progress {
            refreshed_window: Some(3),
            pending: Some(hash),
        };

        let mut waiting = sent;
        assert!(!waiting.settle(Sent::Pending));
        assert_eq!(waiting, sent);

        // The window comes from the block that mined the refresh, not from the check that sent it.
        let mut mined = sent;
        assert!(mined.settle(Sent::Mined(CAPACITY_WINDOW_SECS * 5)));
        assert_eq!(
            mined,
            Progress {
                refreshed_window: Some(5),
                pending: None,
            }
        );
        assert!(!refresh_due(
            true,
            CAPACITY_WINDOW_SECS * 5 + 1,
            mined.refreshed_window
        ));

        let mut lost = sent;
        assert!(lost.settle(Sent::Lost));
        assert_eq!(lost.pending, None);
        assert!(refresh_due(
            true,
            CAPACITY_WINDOW_SECS * 5,
            lost.refreshed_window
        ));
    }
}
