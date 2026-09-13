// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Ciphernode registry EVM boundary.
//!
//! The actor owns subscription, routing, and in-flight submission state. Contract
//! reads and transactions live in `transactions`; message handling lives in
//! `handlers`.

use crate::contracts::ICiphernodeRegistry;
use crate::domain::ciphernode_registry_events::{
    decode_committee_request, derive_sortition_seed, extractor, extractor_with_sortition_seed,
    legacy_sortition_seed,
};
use crate::domain::error_decoder::{
    contains_error_selector, decode_error_from_str, format_evm_error,
};
use crate::domain::log_timestamp::from_log_chain_id_to_ts;
use crate::domain::publication_replay::ReplaySubmissionGate;
use crate::helpers::{
    encode_zk_proof, send_tx_idempotent, send_tx_with_retry, transaction_nonce_guard, EthProvider,
    ProviderFactory, TxOutcome,
};
use crate::messages::{EvmEvent, EvmEventProcessor, EvmLog, EvmLogRejected, InterfoldEvmEvent};
use actix::prelude::*;
use alloy::{
    primitives::{Address, Bytes, B256, U256},
    providers::{Provider, WalletProvider},
    rpc::types::{Filter, TransactionReceipt},
    sol_types::{SolError, SolEvent},
};
use anyhow::{Context as _, Result};
use e3_events::{
    prelude::*, AggregatorChanged, BusHandle, CommitteeFinalizeRequested,
    DkgFoldAttestationContextEstablished, E3RequestComplete, E3id, EType, EffectsEnabled,
    EventSubscriber, EventType, InterfoldEvent, InterfoldEventData, Proof, PublicKeyAggregated,
    Shutdown, TicketGenerated, TicketId, DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION,
};
use e3_utils::{require_successful_receipt, ArcBytes, NotifySync, MAILBOX_LIMIT};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tracing::{debug, error, info, warn};

const EVENT_FORWARD_TIMEOUT: Duration = Duration::from_secs(5);
const ENTROPY_WAIT_TIMEOUT: Duration = Duration::from_secs(300);

#[path = "effects.rs"]
mod effects;
#[path = "handlers.rs"]
mod handlers;

#[allow(unused_imports)]
pub use effects::{
    fetch_accusation_vote_validity, fetch_dkg_fold_attestation_verifier, fetch_randomness_provider,
    fetch_randomness_providers, finalize_committee_on_registry, publish_committee_to_registry,
    submit_ticket_to_registry,
};

/// Connects to CiphernodeRegistry.sol converting EVM events to InterfoldEvents.
pub struct CiphernodeRegistrySolReader<P> {
    provider: EthProvider<P>,
    provider_factory: Option<ProviderFactory<P>>,
    confirmations: u64,
    next: EvmEventProcessor,
}

impl<P: Provider + Clone + 'static> Actor for CiphernodeRegistrySolReader<P> {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT)
    }
}

async fn parse_registry_log<P: Provider + Clone + 'static>(
    mut provider: EthProvider<P>,
    provider_factory: Option<ProviderFactory<P>>,
    confirmations: u64,
    log: EvmLog,
) -> (EthProvider<P>, Result<Option<EvmEvent>>) {
    let result = async {
        let block = log.log.block_number.context(
            "provider log is missing its block number; pending or malformed logs cannot be ordered",
        )?;
        let log_index = log.log.log_index.context(
            "provider log is missing its log index; malformed logs cannot be ordered deterministically",
        )?;

        if is_control_plane_event(log.log.topics().first()) {
            return Ok(None);
        }

        let event = if let Some(request) =
            decode_committee_request(log.log.data(), log.log.topics())
        {
            let expected_entropy_block = block
                .checked_add(1)
                .context("committee entropy block overflow")?;
            let seed = if request.entropyBlock == U256::from(expected_entropy_block) {
                let confirmed_at = expected_entropy_block
                    .checked_add(confirmations)
                    .context("committee entropy confirmation height overflow")?;

                tokio::time::timeout(ENTROPY_WAIT_TIMEOUT, async {
                    loop {
                        let read_result = async {
                            let head = provider.provider().get_block_number().await?;
                            if head < confirmed_at {
                                return Ok(None);
                            }
                            provider
                                .provider()
                                .get_block_by_number(expected_entropy_block.into())
                                .await
                        }
                        .await;

                        match read_result {
                            Ok(Some(block)) => {
                                break derive_sortition_seed(block.header.hash, request.e3Id)
                            }
                            Ok(None) => (),
                            Err(error) => {
                                warn!(
                                    e3_id = %request.e3Id,
                                    %error,
                                    "Unable to read the entropy block; reconnecting"
                                );
                                if let Some(factory) = provider_factory.as_ref() {
                                    match factory().await {
                                        Ok(replacement)
                                            if replacement.chain_id() == log.chain_id =>
                                        {
                                            provider = replacement
                                        }
                                        Ok(replacement) => warn!(
                                            e3_id = %request.e3Id,
                                            expected_chain_id = log.chain_id,
                                            actual_chain_id = replacement.chain_id(),
                                            "Refusing an entropy provider for another chain"
                                        ),
                                        Err(reconnect_error) => warn!(
                                            e3_id = %request.e3Id,
                                            error = %reconnect_error,
                                            "Unable to reconnect to the entropy provider"
                                        ),
                                    }
                                }
                            }
                        }
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                })
                .await
                .with_context(|| {
                    format!(
                        "committee {} entropy block {} was not readable within {:?}",
                        request.e3Id, expected_entropy_block, ENTROPY_WAIT_TIMEOUT
                    )
                })?
            } else {
                // Older deployments stored the request-time seed in the same event field.
                debug!(
                    e3_id = %request.e3Id,
                    "Replaying a committee request that predates delayed sortition entropy"
                );
                legacy_sortition_seed(request.entropyBlock)
            };

            extractor_with_sortition_seed(log.log.data(), log.log.topics(), log.chain_id, seed)
        } else {
            extractor(log.log.data(), log.log.topics(), log.chain_id)
        }
        .context("contract log matched the CiphernodeRegistry address but could not be decoded")?;

        let timestamp = from_log_chain_id_to_ts(log.timestamp, log_index, log.chain_id);
        Ok(Some(EvmEvent::new(
            log.id,
            event,
            block,
            timestamp,
            log.chain_id,
        )))
    }
    .await;

    (provider, result)
}

fn is_control_plane_event(topic: Option<&B256>) -> bool {
    matches!(
        topic,
        Some(value)
            if *value == ICiphernodeRegistry::CommitteeRandomnessRequested::SIGNATURE_HASH
                || *value == ICiphernodeRegistry::RandomnessProviderSet::SIGNATURE_HASH
                || *value
                    == ICiphernodeRegistry::RandomnessCircuitBreakerTripped::SIGNATURE_HASH
                || *value == ICiphernodeRegistry::RandomnessRequestTimeoutSet::SIGNATURE_HASH
    )
}

#[cfg(test)]
mod control_plane_event_tests {
    use super::*;

    #[test]
    fn acknowledges_randomness_control_plane_events() {
        for topic in [
            ICiphernodeRegistry::CommitteeRandomnessRequested::SIGNATURE_HASH,
            ICiphernodeRegistry::RandomnessProviderSet::SIGNATURE_HASH,
            ICiphernodeRegistry::RandomnessCircuitBreakerTripped::SIGNATURE_HASH,
            ICiphernodeRegistry::RandomnessRequestTimeoutSet::SIGNATURE_HASH,
        ] {
            assert!(is_control_plane_event(Some(&topic)));
        }
        assert!(!is_control_plane_event(None));
        assert!(!is_control_plane_event(Some(
            &ICiphernodeRegistry::TicketSubmitted::SIGNATURE_HASH,
        )));
    }
}

async fn forward_registry_event(next: EvmEventProcessor, event: InterfoldEvmEvent) -> Result<()> {
    tokio::time::timeout(EVENT_FORWARD_TIMEOUT, next.send(event))
        .await
        .context("timed out while forwarding a ciphernode registry event")?
        .context("ciphernode registry event destination stopped")?;
    Ok(())
}

impl<P: Provider + Clone + 'static> CiphernodeRegistrySolReader<P> {
    pub fn setup_with_factory(
        next: &EvmEventProcessor,
        provider: EthProvider<P>,
        provider_factory: Option<ProviderFactory<P>>,
        confirmations: u64,
    ) -> Addr<Self> {
        Self {
            provider,
            provider_factory,
            confirmations,
            next: next.clone(),
        }
        .start()
    }
}

impl<P: Provider + Clone + 'static> Handler<InterfoldEvmEvent> for CiphernodeRegistrySolReader<P> {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvmEvent, ctx: &mut Self::Context) -> Self::Result {
        match msg.clone() {
            InterfoldEvmEvent::Log(log) => {
                debug!("processing event({})", msg.get_id());
                let id = log.id;
                let chain_id = log.chain_id;
                let provider = self.provider.clone();
                let provider_factory = self.provider_factory.clone();
                let confirmations = self.confirmations;
                let next = self.next.clone();

                ctx.wait(
                    async move {
                        let (provider, parsed) =
                            parse_registry_log(provider, provider_factory, confirmations, log)
                                .await;
                        let event = match parsed {
                            Ok(Some(event)) => InterfoldEvmEvent::Event(event),
                            Ok(None) => InterfoldEvmEvent::Processed(id),
                            Err(parse_error) => {
                                error!(
                                    %id,
                                    chain_id,
                                    error = %parse_error,
                                    "Rejecting EVM log and failing the chain ingestion pipeline"
                                );
                                InterfoldEvmEvent::Rejected(EvmLogRejected::new(
                                    id,
                                    chain_id,
                                    parse_error.to_string(),
                                ))
                            }
                        };
                        let result = forward_registry_event(next, event).await;
                        (provider, result)
                    }
                    .into_actor(self)
                    .map(move |(provider, result), actor, ctx| {
                        actor.provider = provider;
                        if let Err(forward_error) = result {
                            error!(
                                %id,
                                chain_id,
                                error = %forward_error,
                                "Ciphernode registry event delivery failed; stopping the parser"
                            );
                            ctx.stop();
                        }
                    }),
                );
            }
            hist @ InterfoldEvmEvent::HistoricalSyncComplete(..) => {
                let next = self.next.clone();
                ctx.wait(
                    async move { forward_registry_event(next, hist).await }
                        .into_actor(self)
                        .map(|result, _, ctx| {
                            if let Err(forward_error) = result {
                                error!(
                                    error = %forward_error,
                                    "Registry sync marker delivery failed; stopping the parser"
                                );
                                ctx.stop();
                            }
                        }),
                );
            }
            _ => (),
        }
    }
}

/// Writer for publishing committees to CiphernodeRegistry.
pub struct CiphernodeRegistrySolWriter<P> {
    provider: EthProvider<P>,
    contract_address: Address,
    bus: BusHandle,
    effects_enabled: bool,
    active_aggregators: HashMap<E3id, bool>,
    completed_requests: HashSet<E3id>,
    request_registries: HashMap<E3id, Address>,
    publication: ReplaySubmissionGate<E3id, PublicKeyAggregated>,
    ticket_submissions: ReplaySubmissionGate<E3id, TicketGenerated>,
    committee_finalizations: ReplaySubmissionGate<E3id, CommitteeFinalizeRequested>,
}

impl<P: Provider + WalletProvider + Clone + 'static> CiphernodeRegistrySolWriter<P> {
    pub fn new(
        bus: &BusHandle,
        provider: EthProvider<P>,
        contract_address: Address,
        request_registries: HashMap<E3id, Address>,
    ) -> Result<Self> {
        Self::new_with_recovery(
            bus,
            provider,
            contract_address,
            request_registries,
            HashMap::new(),
            HashMap::new(),
        )
    }

    pub fn new_with_recovery(
        bus: &BusHandle,
        provider: EthProvider<P>,
        contract_address: Address,
        request_registries: HashMap<E3id, Address>,
        active_aggregators: HashMap<E3id, bool>,
        recovered_tickets: HashMap<E3id, TicketGenerated>,
    ) -> Result<Self> {
        let mut ticket_submissions = ReplaySubmissionGate::new();
        for (e3_id, ticket) in recovered_tickets {
            ticket_submissions.record(e3_id, ticket);
        }
        Ok(Self {
            provider,
            contract_address,
            bus: bus.clone(),
            effects_enabled: false,
            active_aggregators,
            completed_requests: HashSet::new(),
            request_registries,
            publication: ReplaySubmissionGate::new(),
            ticket_submissions,
            committee_finalizations: ReplaySubmissionGate::new(),
        })
    }

    pub fn attach(
        bus: &BusHandle,
        provider: EthProvider<P>,
        contract_address: Address,
        request_registries: HashMap<E3id, Address>,
    ) {
        Self::attach_with_recovery(
            bus,
            provider,
            contract_address,
            request_registries,
            HashMap::new(),
            HashMap::new(),
        );
    }

    pub fn attach_with_recovery(
        bus: &BusHandle,
        provider: EthProvider<P>,
        contract_address: Address,
        request_registries: HashMap<E3id, Address>,
        active_aggregators: HashMap<E3id, bool>,
        recovered_tickets: HashMap<E3id, TicketGenerated>,
    ) {
        let addr = CiphernodeRegistrySolWriter::new_with_recovery(
            bus,
            provider,
            contract_address,
            request_registries,
            active_aggregators,
            recovered_tickets,
        )
        .expect("failed to create CiphernodeRegistrySolWriter")
        .start();

        bus.subscribe_all(
            &[
                EventType::EffectsEnabled,
                EventType::AggregatorChanged,
                EventType::DkgFoldAttestationContextEstablished,
                EventType::PublicKeyAggregated,
                EventType::LbfvPublicKeyAggregated,
                EventType::CommitteeFinalizeRequested,
                EventType::TicketGenerated,
                EventType::E3RequestComplete,
                EventType::Shutdown,
            ],
            addr.into(),
        );
    }

    fn is_active_aggregator_for(&self, e3_id: &E3id) -> bool {
        self.active_aggregators.get(e3_id).copied().unwrap_or(false)
    }
}

/// Wrapper for a reader and writer.
pub struct CiphernodeRegistrySol;

impl CiphernodeRegistrySol {
    pub fn attach_writer<P>(
        bus: &BusHandle,
        provider: EthProvider<P>,
        contract_address: Address,
        request_registries: HashMap<E3id, Address>,
    ) where
        P: Provider + WalletProvider + Clone + 'static,
    {
        CiphernodeRegistrySolWriter::attach(bus, provider, contract_address, request_registries);
    }

    pub fn attach_writer_with_recovery<P>(
        bus: &BusHandle,
        provider: EthProvider<P>,
        contract_address: Address,
        request_registries: HashMap<E3id, Address>,
        active_aggregators: HashMap<E3id, bool>,
        recovered_tickets: HashMap<E3id, TicketGenerated>,
    ) where
        P: Provider + WalletProvider + Clone + 'static,
    {
        CiphernodeRegistrySolWriter::attach_with_recovery(
            bus,
            provider,
            contract_address,
            request_registries,
            active_aggregators,
            recovered_tickets,
        );
    }
}
