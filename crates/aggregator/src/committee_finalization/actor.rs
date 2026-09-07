// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::prelude::*;
use anyhow::{ensure, Result};
use e3_data::{AutoPersist, Persistable, Repository};
use e3_events::{
    prelude::*, BusHandle, CommitteeFinalizeRequested, CommitteeFinalized, CommitteeRequested,
    E3Failed, E3RequestComplete, E3Stage, E3StageChanged, EType, EffectsEnabled, EventType,
    InterfoldEvent, InterfoldEventData, Shutdown, TicketGenerated, TypedEvent,
};
use e3_events::{E3id, EventContext, Sequenced};
use e3_evm::helpers::{ConcreteReadProvider, EthProvider, ProviderFactory};
use e3_utils::{NotifySync, MAILBOX_LIMIT};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{error, info, warn};

#[path = "handlers.rs"]
mod handlers;

const FINALIZATION_BUFFER_SECONDS: u64 = 1;
/// Delay between one committee member's finalization attempt and the next.
///
/// A member cancels its own attempt when it observes `CommitteeFinalized`. That
/// observation needs the leader's transaction to be mined and its log to be
/// read. The interval must therefore exceed several block times, or every
/// member sends a transaction that reverts with `CommitteeAlreadyFinalized`.
/// The delay applies only while earlier members stay silent, so a larger value
/// costs nothing when the first member finalizes.
const FINALIZE_INTERVAL_SECONDS: u64 = 30;
const FINALIZATION_RPC_RETRY_SECONDS: u64 = 30;
pub const COMMITTEE_FINALIZER_RECOVERY_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveredCommitteeRequest {
    pub request: CommitteeRequested,
    pub context: EventContext<Sequenced>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitteeFinalizerRecoveryState {
    pub schema_version: u32,
    pub pending_requests: HashMap<E3id, RecoveredCommitteeRequest>,
    pub tickets: HashMap<E3id, TicketGenerated>,
}

impl Default for CommitteeFinalizerRecoveryState {
    fn default() -> Self {
        Self {
            schema_version: COMMITTEE_FINALIZER_RECOVERY_SCHEMA_VERSION,
            pending_requests: HashMap::new(),
            tickets: HashMap::new(),
        }
    }
}

impl CommitteeFinalizerRecoveryState {
    pub fn remove(&mut self, e3_id: &E3id) {
        self.pending_requests.remove(e3_id);
        self.tickets.remove(e3_id);
    }
}

/// Seconds a committee member waits after the submission window closes before it
/// attempts finalization.
///
/// Members attempt in `party_index` order. Each step must be long enough for the
/// previous member's transaction to be mined and for its `CommitteeFinalized`
/// log to be read, or every member sends a transaction that reverts.
fn finalization_delay_seconds(committee_deadline: u64, now: u64, party_index: u64) -> u64 {
    committee_deadline
        .saturating_sub(now)
        .saturating_add(FINALIZATION_BUFFER_SECONDS)
        .saturating_add(party_index.saturating_mul(FINALIZE_INTERVAL_SECONDS))
}

/// A read provider for one chain together with the means to rebuild it.
///
/// The provider is a WebSocket clone taken at startup. When the RPC endpoint is away for
/// longer than alloy's own reconnect budget the clone dies for good and every timestamp read
/// fails with "backend connection task has stopped". The factory lets the finalizer replace
/// it instead of retrying the dead one every 30 s until the committee deadline passes.
#[derive(Clone)]
pub struct FinalizerChainProvider {
    pub provider: EthProvider<ConcreteReadProvider>,
    pub factory: Option<ProviderFactory<ConcreteReadProvider>>,
}

impl FinalizerChainProvider {
    pub fn new(provider: EthProvider<ConcreteReadProvider>) -> Self {
        Self {
            provider,
            factory: None,
        }
    }

    pub fn with_factory(mut self, factory: ProviderFactory<ConcreteReadProvider>) -> Self {
        self.factory = Some(factory);
        self
    }
}

/// Read the chain's latest timestamp, rebuilding the provider once if the read fails.
///
/// Returns the timestamp result and, when a reconnect produced a new provider, that provider
/// so the actor can adopt it for later reads.
async fn read_timestamp_with_reconnect(
    chain_provider: FinalizerChainProvider,
    chain_id: u64,
    e3_id: &E3id,
) -> (Result<u64>, Option<EthProvider<ConcreteReadProvider>>) {
    read_timestamp_reconnecting(
        chain_provider.provider,
        chain_provider.factory,
        chain_id,
        e3_id,
    )
    .await
}

/// Generic core of [`read_timestamp_with_reconnect`], so a mock transport can drive it.
async fn read_timestamp_reconnecting<P>(
    provider: EthProvider<P>,
    factory: Option<ProviderFactory<P>>,
    chain_id: u64,
    e3_id: &E3id,
) -> (Result<u64>, Option<EthProvider<P>>)
where
    P: alloy::providers::Provider + Clone + 'static,
{
    let first = e3_evm::helpers::get_current_timestamp_from_provider(provider.clone()).await;
    let (Err(first_error), Some(factory)) = (&first, factory.as_ref()) else {
        return (first, None);
    };
    warn!(
        %e3_id,
        error = %first_error,
        "Timestamp read failed; reconnecting the read provider and retrying once"
    );
    let replacement = match factory().await {
        Ok(replacement) if replacement.chain_id() == chain_id => replacement,
        Ok(replacement) => {
            warn!(
                %e3_id,
                expected_chain_id = chain_id,
                actual_chain_id = replacement.chain_id(),
                "Refusing a reconnected finalizer provider for another chain"
            );
            return (first, None);
        }
        Err(reconnect_error) => {
            warn!(
                %e3_id,
                error = %reconnect_error,
                "Unable to reconnect the finalizer read provider"
            );
            return (first, None);
        }
    };
    let second = e3_evm::helpers::get_current_timestamp_from_provider(replacement.clone()).await;
    (second, Some(replacement))
}

/// CommitteeFinalizer is an actor that listens to CommitteeRequested events and dispatches
/// CommitteeFinalizeRequested events after the submission deadline has passed.
pub struct CommitteeFinalizer {
    bus: BusHandle,
    pending_committees: HashMap<E3id, SpawnHandle>,
    recovery: Persistable<CommitteeFinalizerRecoveryState>,
    chain_providers: HashMap<u64, FinalizerChainProvider>,
    effects_enabled: bool,
}

impl CommitteeFinalizer {
    fn from_recovery(
        bus: &BusHandle,
        recovery: Persistable<CommitteeFinalizerRecoveryState>,
        chain_providers: HashMap<u64, FinalizerChainProvider>,
    ) -> Self {
        Self {
            bus: bus.clone(),
            pending_committees: HashMap::new(),
            recovery,
            chain_providers,
            effects_enabled: false,
        }
    }

    pub async fn attach_with_recovery(
        bus: &BusHandle,
        repository: Repository<CommitteeFinalizerRecoveryState>,
        chain_providers: HashMap<u64, FinalizerChainProvider>,
    ) -> Result<Addr<Self>> {
        let recovery = repository
            .load_or_default(CommitteeFinalizerRecoveryState::default())
            .await?;
        ensure!(
            recovery.try_get()?.schema_version == COMMITTEE_FINALIZER_RECOVERY_SCHEMA_VERSION,
            "unsupported committee-finalizer recovery schema"
        );
        let addr = CommitteeFinalizer::from_recovery(bus, recovery, chain_providers).start();

        // Subscribe to state-building / cleanup events immediately
        bus.subscribe_all(
            &[
                EventType::Shutdown,
                EventType::E3Failed,
                EventType::E3StageChanged,
                EventType::E3RequestComplete,
                EventType::TicketGenerated,
                EventType::CommitteeRequested,
                EventType::CommitteeFinalized,
                EventType::EffectsEnabled,
            ],
            addr.clone().recipient(),
        );

        Ok(addr)
    }

    fn schedule_committee(
        &mut self,
        request: RecoveredCommitteeRequest,
        party_index: u64,
        ctx: &mut Context<Self>,
    ) {
        let e3_id = request.request.e3_id.clone();
        if self.pending_committees.contains_key(&e3_id) {
            return;
        }

        let committee_deadline = request.request.committee_deadline;
        let request_e3_id = request.request.e3_id.clone();
        let ec = request.context.clone();
        let pending_key = e3_id.clone();
        let e3_id_for_async = e3_id.clone();
        let chain_id = e3_id.chain_id();
        let chain_provider = self.chain_providers.get(&chain_id).cloned();

        let fut = async move {
            let Some(chain_provider) = chain_provider else {
                error!(
                    e3_id = %e3_id_for_async,
                    "No RPC provider configured for chain {chain_id}"
                );
                return (None, None);
            };
            let (timestamp, replacement) =
                read_timestamp_with_reconnect(chain_provider, chain_id, &e3_id_for_async).await;
            match timestamp {
                Ok(timestamp) => (Some(timestamp), replacement),
                Err(e) => {
                    error!(
                        e3_id = %e3_id_for_async,
                        error = %e,
                        "Failed to get current timestamp from RPC"
                    );
                    (None, replacement)
                }
            }
        };

        let handle = ctx.spawn(
            fut.into_actor(self)
                .then(move |(current_timestamp, replacement), act, ctx| {
                    if let Some(replacement) = replacement {
                        if let Some(entry) = act.chain_providers.get_mut(&chain_id) {
                            entry.provider = replacement;
                        }
                    }
                    if let Some(current_timestamp) = current_timestamp {
                        let seconds_until_deadline = finalization_delay_seconds(
                            committee_deadline,
                            current_timestamp,
                            party_index,
                        );

                        info!(
                            e3_id = %e3_id,
                            party_index,
                            committee_deadline,
                            current_timestamp,
                            seconds_to_wait = seconds_until_deadline,
                            "Scheduling committee finalization"
                        );

                        let e3_id_clone = e3_id.clone();
                        let ec_clone = ec.clone();

                        let handle = ctx.run_later(
                            Duration::from_secs(seconds_until_deadline),
                            move |act, _ctx| {
                                info!(e3_id = %e3_id_clone, party_index, "Dispatching CommitteeFinalizeRequested event");
                                act.pending_committees.remove(&e3_id_clone);
                                if let Err(error) = act.bus.publish(
                                    CommitteeFinalizeRequested {
                                        e3_id: request_e3_id.clone(),
                                    },
                                    ec_clone.clone(),
                                ) {
                                    act.bus.with_ec(&ec_clone).err(EType::Sortition, error);
                                    act.schedule_retry(e3_id_clone.clone(), _ctx);
                                }
                            },
                        );

                        act.pending_committees.insert(e3_id.clone(), handle);
                    } else {
                        act.schedule_retry(e3_id.clone(), ctx);
                    }

                    async {}.into_actor(act)
                }),
        );
        self.pending_committees.insert(pending_key, handle);
    }

    fn schedule_retry(&mut self, e3_id: E3id, ctx: &mut Context<Self>) {
        let retry_e3_id = e3_id.clone();
        let handle = ctx.run_later(
            Duration::from_secs(FINALIZATION_RPC_RETRY_SECONDS),
            move |actor, ctx| {
                actor.pending_committees.remove(&retry_e3_id);
                actor.schedule_if_ready(&retry_e3_id, ctx);
            },
        );
        self.pending_committees.insert(e3_id, handle);
    }

    fn schedule_if_ready(&mut self, e3_id: &E3id, ctx: &mut Context<Self>) {
        if !self.effects_enabled {
            return;
        }

        let Some(recovery) = self.recovery.get() else {
            return;
        };
        let Some(request) = recovery.pending_requests.get(e3_id) else {
            return;
        };
        let Some(party_index) = recovery
            .tickets
            .get(e3_id)
            .and_then(|ticket| ticket.party_index)
        else {
            return;
        };

        self.schedule_committee(request.clone(), party_index, ctx);
    }
}

impl Actor for CommitteeFinalizer {
    type Context = Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

#[cfg(test)]
mod tests {
    use super::{finalization_delay_seconds, FINALIZE_INTERVAL_SECONDS};

    /// Longest block interval observed on Sepolia. The stagger must exceed it,
    /// plus the log read that cancels a pending attempt.
    const OBSERVED_BLOCK_INTERVAL_SECONDS: u64 = 18;

    #[test]
    fn the_first_member_attempts_right_after_the_deadline() {
        assert_eq!(finalization_delay_seconds(1_000, 900, 0), 101);
    }

    #[test]
    fn each_member_waits_for_the_previous_attempt_to_reach_the_chain() {
        let first = finalization_delay_seconds(1_000, 1_000, 0);
        let second = finalization_delay_seconds(1_000, 1_000, 1);

        assert!(
            second - first > OBSERVED_BLOCK_INTERVAL_SECONDS,
            "stagger {} must exceed one block interval",
            second - first
        );
    }

    #[test]
    fn a_passed_deadline_keeps_the_stagger() {
        assert_eq!(
            finalization_delay_seconds(1_000, 5_000, 3),
            1 + 3 * FINALIZE_INTERVAL_SECONDS
        );
    }

    mod reconnect {
        use super::super::read_timestamp_reconnecting;
        use alloy::{
            providers::{Provider, ProviderBuilder},
            transports::mock::Asserter,
        };
        use e3_events::E3id;
        use e3_evm::helpers::{EthProvider, ProviderFactory};
        use std::sync::Arc;

        async fn provider_on_chain(
            asserter: &Asserter,
            chain_id_hex: &str,
        ) -> EthProvider<impl Provider + Clone> {
            asserter.push_success(&chain_id_hex);
            EthProvider::new(ProviderBuilder::new().connect_mocked_client(asserter.clone()))
                .await
                .expect("mock chain ID must decode")
        }

        fn block_with_timestamp(timestamp: u64) -> alloy::rpc::types::Block {
            let mut block: alloy::rpc::types::Block = Default::default();
            block.header.inner.timestamp = timestamp;
            block
        }

        /// Observed on a 5-node swarm: after a 90 s RPC outage every node's finalizer logged
        /// `Failed to get current timestamp from RPC` every 30 s until the committee window
        /// closed, because the startup provider clone had given up reconnecting. The
        /// finalizer must rebuild the provider through its factory and retry.
        #[actix::test]
        async fn dead_provider_is_replaced_before_the_timestamp_read_fails() {
            let dead = Asserter::new();
            let dead_provider = provider_on_chain(&dead, "0x1").await;
            dead.push_failure_msg("backend connection task has stopped");

            let healthy = Asserter::new();
            let healthy_provider = provider_on_chain(&healthy, "0x1").await;
            healthy.push_success(&block_with_timestamp(1_700_000_042));
            let factory: ProviderFactory<_> = Arc::new(move || {
                let provider = healthy_provider.clone();
                Box::pin(async move { Ok(provider) })
            });

            let (timestamp, replacement) =
                read_timestamp_reconnecting(dead_provider, Some(factory), 1, &E3id::new("7", 1))
                    .await;

            assert_eq!(timestamp.unwrap(), 1_700_000_042);
            assert!(
                replacement.is_some(),
                "the reconnected provider must be adopted"
            );
        }

        #[actix::test]
        async fn without_a_factory_the_error_is_returned_unchanged() {
            let dead = Asserter::new();
            let dead_provider = provider_on_chain(&dead, "0x1").await;
            dead.push_failure_msg("backend connection task has stopped");

            let (timestamp, replacement) =
                read_timestamp_reconnecting(dead_provider, None, 1, &E3id::new("7", 1)).await;

            assert!(timestamp
                .unwrap_err()
                .to_string()
                .contains("Failed to get latest block"));
            assert!(replacement.is_none());
        }

        #[actix::test]
        async fn a_wrong_chain_reconnect_is_refused() {
            let dead = Asserter::new();
            let dead_provider = provider_on_chain(&dead, "0x1").await;
            dead.push_failure_msg("backend connection task has stopped");

            let other = Asserter::new();
            let other_provider = provider_on_chain(&other, "0x2").await;
            let factory: ProviderFactory<_> = Arc::new(move || {
                let provider = other_provider.clone();
                Box::pin(async move { Ok(provider) })
            });

            let (timestamp, replacement) =
                read_timestamp_reconnecting(dead_provider, Some(factory), 1, &E3id::new("7", 1))
                    .await;

            assert!(timestamp.is_err());
            assert!(replacement.is_none());
        }
    }
}
