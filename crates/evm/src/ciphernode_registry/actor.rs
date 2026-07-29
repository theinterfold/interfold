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

use crate::actors::evm_parser::EvmParser;
use crate::contracts::ICiphernodeRegistry;
use crate::domain::ciphernode_registry_events::extractor;
use crate::domain::error_decoder::{decode_error_from_str, format_evm_error};
use crate::helpers::{encode_zk_proof, send_tx_with_retry, EthProvider};
use crate::messages::{EvmEventProcessor, InterfoldEvmEvent};
use crate::{EvmEffectOutbox, EvmEffectOutboxRepositoryFactory, EvmEffectOutboxState};
use actix::prelude::*;
use alloy::{
    primitives::{Address, Bytes, B256, U256},
    providers::{Provider, WalletProvider},
    rpc::types::TransactionReceipt,
};
use anyhow::Result;
use e3_data::{Repositories, Repository};
use e3_events::{
    prelude::*, AggregatorChanged, BusHandle, CommitteeFinalizeRequested, E3RequestComplete, E3id,
    EType, EffectsEnabled, EventSubscriber, EventType, InterfoldEvent, InterfoldEventData,
    PublicKeyAggregated, Shutdown, TicketGenerated, TicketId,
};
use e3_utils::{require_successful_receipt, NotifySync, MAILBOX_LIMIT};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};
use tracing::{error, info};

#[path = "effects.rs"]
mod effects;
#[path = "handlers.rs"]
mod handlers;

#[allow(unused_imports)]
pub use effects::{fetch_accusation_vote_validity, fetch_dkg_fold_attestation_verifier};

/// Connects to CiphernodeRegistry.sol converting EVM events to InterfoldEvents.
pub struct CiphernodeRegistrySolReader;

impl CiphernodeRegistrySolReader {
    pub fn setup(next: &EvmEventProcessor) -> Addr<EvmParser> {
        EvmParser::new(next, extractor).start()
    }
}

/// Writer for publishing committees to CiphernodeRegistry.
pub struct CiphernodeRegistrySolWriter<P> {
    provider: EthProvider<P>,
    contract_address: Address,
    bus: BusHandle,
    effects_enabled: bool,
    active_aggregators: HashMap<E3id, bool>,
    outbox: EvmEffectOutbox<RegistryEffect>,
    /// Session-local concurrency guard around durable semantic outbox keys.
    submitting: HashSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum RegistryEffect {
    SubmitTicket(TicketGenerated),
    FinalizeCommittee(CommitteeFinalizeRequested),
    PublishCommittee(PublicKeyAggregated),
}

impl RegistryEffect {
    fn key(&self) -> String {
        match self {
            Self::SubmitTicket(event) => {
                crate::semantic_effect_key("submit_ticket", &event.e3_id, &event.ticket_id)
            }
            Self::FinalizeCommittee(event) => {
                crate::semantic_effect_key("finalize_committee", &event.e3_id, &())
            }
            Self::PublishCommittee(event) => crate::semantic_effect_key(
                "publish_committee",
                &event.e3_id,
                &(
                    &event.pubkey,
                    event.pk_commitment,
                    &event.dkg_aggregator_proof,
                    &event.dkg_attestation_bundle,
                ),
            ),
        }
    }
}

#[derive(Message)]
#[rtype(result = "()")]
struct DrainRegistryOutbox;

#[derive(Message)]
#[rtype(result = "()")]
struct ExecuteRegistryEffect {
    key: String,
    effect: RegistryEffect,
    status: crate::EvmEffectStatus,
}

impl<P: Provider + WalletProvider + Clone + 'static> CiphernodeRegistrySolWriter<P> {
    async fn new(
        bus: &BusHandle,
        provider: EthProvider<P>,
        contract_address: Address,
        repository: Repository<EvmEffectOutboxState<RegistryEffect>>,
    ) -> Result<Self> {
        Ok(Self {
            provider,
            contract_address,
            bus: bus.clone(),
            effects_enabled: false,
            active_aggregators: HashMap::new(),
            outbox: EvmEffectOutbox::load(repository).await?,
            submitting: HashSet::new(),
        })
    }

    async fn attach(
        bus: &BusHandle,
        provider: EthProvider<P>,
        contract_address: Address,
        repository: Repository<EvmEffectOutboxState<RegistryEffect>>,
    ) -> Result<Addr<Self>> {
        let addr = CiphernodeRegistrySolWriter::new(bus, provider, contract_address, repository)
            .await?
            .start();

        bus.subscribe_all(
            &[
                EventType::EffectsEnabled,
                EventType::AggregatorChanged,
                EventType::PublicKeyAggregated,
                EventType::CommitteeFinalizeRequested,
                EventType::TicketGenerated,
                EventType::E3RequestComplete,
                EventType::Shutdown,
            ],
            addr.clone().into(),
        );
        Ok(addr)
    }

    fn is_active_aggregator_for(&self, e3_id: &E3id) -> bool {
        self.active_aggregators.get(e3_id).copied().unwrap_or(false)
    }
}

/// Wrapper for a reader and writer.
pub struct CiphernodeRegistrySol;

impl CiphernodeRegistrySol {
    pub fn attach(processor: &Recipient<InterfoldEvmEvent>) -> Addr<EvmParser> {
        CiphernodeRegistrySolReader::setup(processor)
    }

    pub async fn attach_writer<P>(
        bus: &BusHandle,
        provider: EthProvider<P>,
        contract_address: Address,
        repositories: &Repositories,
    ) -> Result<Addr<CiphernodeRegistrySolWriter<P>>>
    where
        P: Provider + WalletProvider + Clone + 'static,
    {
        let signer = provider.provider().default_signer_address();
        let writer_scope = format!("ciphernode_registry/{contract_address}/{signer}");
        let repository = repositories.evm_effect_outbox(&writer_scope, provider.chain_id());
        CiphernodeRegistrySolWriter::attach(bus, provider, contract_address, repository).await
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<crate::GetEvmWriterHealth>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ResponseFuture<crate::EvmWriterHealth>;

    fn handle(
        &mut self,
        message: crate::GetEvmWriterHealth,
        _: &mut Self::Context,
    ) -> Self::Result {
        let outbox = self.outbox.clone();
        let chain_id = self.provider.chain_id();
        let contract_address = self.contract_address.to_string();
        let effects_enabled = self.effects_enabled;
        let in_flight_effects = self.submitting.len();
        Box::pin(async move {
            let summary = outbox.summary(message.now_ms).await;
            crate::EvmWriterHealth {
                writer: "ciphernode_registry".to_owned(),
                chain_id,
                contract_address,
                effects_enabled,
                pending_effects: summary.pending_effects,
                oldest_pending_age_ms: summary.oldest_pending_age_ms,
                in_flight_effects,
            }
        })
    }
}
