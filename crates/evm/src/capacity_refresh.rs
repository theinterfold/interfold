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
//! restart.

use crate::{
    contracts::IBondingRegistry,
    helpers::{get_current_timestamp_from_provider, transaction_nonce_guard, EthProvider},
};
use actix::prelude::*;
use alloy::{
    primitives::Address,
    providers::{Provider, WalletProvider},
};
use anyhow::Result;
use e3_events::{
    prelude::*, BusHandle, EffectsEnabled, EventType, InterfoldEvent, InterfoldEventData, Shutdown,
};
use e3_sortition::IdentityPolicyRequiredAt;
use e3_utils::{require_successful_receipt, NotifySync};
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

/// Refreshes the operator of this node in each owner capacity window of one chain.
pub struct CapacityRefresher<P> {
    provider: EthProvider<P>,
    bonding_registry: Address,
    identity_policy: Recipient<IdentityPolicyRequiredAt>,
    /// The window of the last refresh in this process.
    refreshed_window: Option<u64>,
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
            refreshed_window: None,
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
        let refreshed_window = self.refreshed_window;
        Box::pin(
            async move {
                check(
                    provider,
                    bonding_registry,
                    identity_policy,
                    refreshed_window,
                )
                .await
            }
            .into_actor(self)
            .map(|result, actor, ctx| {
                match result {
                    Ok(Some(window)) => actor.refreshed_window = Some(window),
                    Ok(None) => {}
                    Err(error) => warn!(
                        chain_id = actor.provider.chain_id(),
                        "Could not refresh the operator for the owner capacity window: {error:#}"
                    ),
                }
                ctx.notify_later(Check, CHECK_INTERVAL);
            }),
        )
    }
}

/// Refresh the operator when its window is due. Returns the window that needs no other refresh.
async fn check<P>(
    provider: EthProvider<P>,
    bonding_registry: Address,
    identity_policy: Recipient<IdentityPolicyRequiredAt>,
    refreshed_window: Option<u64>,
) -> Result<Option<u64>>
where
    P: Provider + WalletProvider + Clone + 'static,
{
    let timestamp = get_current_timestamp_from_provider(provider.clone()).await?;
    let required = identity_policy
        .send(IdentityPolicyRequiredAt {
            chain_id: provider.chain_id(),
            timepoint: timestamp,
        })
        .await??;
    if !refresh_due(required, timestamp, refreshed_window) {
        return Ok(None);
    }
    refresh_operator(&provider, bonding_registry).await?;
    Ok(Some(timestamp / CAPACITY_WINDOW_SECS))
}

async fn refresh_operator<P>(provider: &EthProvider<P>, bonding_registry: Address) -> Result<()>
where
    P: Provider + WalletProvider + Clone + 'static,
{
    let operator = provider.provider().default_signer_address();
    let bonding = IBondingRegistry::new(bonding_registry, provider.provider());
    // The registry has nothing to count for an unregistered operator, and the call would revert.
    if !bonding.isRegistered(operator).call().await? {
        return Ok(());
    }
    let _nonce_guard = transaction_nonce_guard(provider).await;
    let nonce = provider
        .provider()
        .get_transaction_count(operator)
        .pending()
        .await?;
    let call = bonding.refreshOperatorStatus(operator).nonce(nonce);
    let gas = call.estimate_gas().await?;
    let pending = call
        .gas(gas.saturating_mul(REFRESH_GAS_MULTIPLIER))
        .send()
        .await?;
    drop(_nonce_guard);
    let receipt = pending.get_receipt().await?;
    require_successful_receipt("refresh operator status", &receipt)?;
    info!(
        tx = %receipt.transaction_hash,
        "Refreshed the operator for the owner capacity window"
    );
    Ok(())
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
}
