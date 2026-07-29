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
use crate::helpers::{encode_zk_proof, send_tx_with_retry, transaction_nonce_guard, EthProvider};
use crate::messages::{EvmEventProcessor, InterfoldEvmEvent};
use actix::prelude::*;
use alloy::{
    primitives::{Address, Bytes, B256, U256},
    providers::{Provider, WalletProvider},
    rpc::types::TransactionReceipt,
};
use anyhow::Result;
use e3_events::{
    prelude::*, AggregatorChanged, BusHandle, CommitteeFinalizeRequested, E3RequestComplete, E3id,
    EType, EffectsEnabled, EventSubscriber, EventType, InterfoldEvent, InterfoldEventData, Proof,
    PublicKeyAggregated, Shutdown, TicketGenerated, TicketId,
};
use e3_utils::{require_successful_receipt, ArcBytes, NotifySync, MAILBOX_LIMIT};
use std::collections::{HashMap, HashSet};
use tracing::{error, info};

#[path = "effects.rs"]
mod effects;
#[path = "handlers.rs"]
mod handlers;

#[allow(unused_imports)]
pub use effects::{
    fetch_accusation_vote_validity, fetch_dkg_fold_attestation_verifier,
    finalize_committee_on_registry, publish_committee_to_registry, submit_ticket_to_registry,
};

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
    /// Session-local concurrency guard. On-chain preflight is the durable
    /// cross-restart idempotency boundary.
    submitting: HashSet<E3id>,
}

impl<P: Provider + WalletProvider + Clone + 'static> CiphernodeRegistrySolWriter<P> {
    pub fn new(
        bus: &BusHandle,
        provider: EthProvider<P>,
        contract_address: Address,
    ) -> Result<Self> {
        Ok(Self {
            provider,
            contract_address,
            bus: bus.clone(),
            effects_enabled: false,
            active_aggregators: HashMap::new(),
            submitting: HashSet::new(),
        })
    }

    pub fn attach(bus: &BusHandle, provider: EthProvider<P>, contract_address: Address) {
        let addr = CiphernodeRegistrySolWriter::new(bus, provider, contract_address)
            .expect("failed to create CiphernodeRegistrySolWriter")
            .start();

        bus.subscribe_all(
            &[
                EventType::EffectsEnabled,
                EventType::AggregatorChanged,
                EventType::PublicKeyAggregated,
                EventType::CommitteeFinalizeRequested,
                EventType::TicketGenerated,
                EventType::EffectRetry,
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
    pub fn attach(processor: &Recipient<InterfoldEvmEvent>) -> Addr<EvmParser> {
        CiphernodeRegistrySolReader::setup(processor)
    }

    pub fn attach_writer<P>(bus: &BusHandle, provider: EthProvider<P>, contract_address: Address)
    where
        P: Provider + WalletProvider + Clone + 'static,
    {
        CiphernodeRegistrySolWriter::attach(bus, provider, contract_address);
    }
}
