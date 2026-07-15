// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Interfold contract publication boundary.

use crate::contracts::IInterfold;
use crate::domain::error_decoder::format_evm_error;
use crate::domain::plaintext_publication::validate_plaintext_output;
use crate::helpers::{encode_zk_proof, transaction_nonce_guard, EthProvider};
use crate::send_tx_with_retry;
use actix::prelude::*;
use alloy::{
    primitives::{Address, Bytes, U256},
    providers::{Provider, WalletProvider},
    rpc::types::TransactionReceipt,
};
use anyhow::Result;
use e3_events::{
    prelude::*, AggregatorChanged, BusHandle, E3RequestComplete, E3Stage, E3StageChanged, E3id,
    EType, EffectsEnabled, EventType, InterfoldEvent, InterfoldEventData, PlaintextAggregated,
    Proof, Shutdown,
};
use e3_utils::{require_successful_receipt, NotifySync, MAILBOX_LIMIT};
use std::collections::{HashMap, HashSet};
use tracing::info;

#[path = "effects.rs"]
mod effects;
#[path = "handlers.rs"]
mod handlers;

/// Consumes events from the event bus and calls EVM methods on the Interfold contract.
pub struct InterfoldSolWriter<P> {
    provider: EthProvider<P>,
    contract_address: Address,
    bus: BusHandle,
    effects_enabled: bool,
    active_aggregators: HashMap<E3id, bool>,
    /// Session-local concurrency guard. The contract preflight remains the
    /// durable cross-restart idempotency boundary.
    submitting: HashSet<E3id>,
}

impl<P: Provider + WalletProvider + Clone + 'static> InterfoldSolWriter<P> {
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
        let addr = InterfoldSolWriter::new(bus, provider, contract_address)
            .expect("failed to create InterfoldSolWriter")
            .start();
        bus.subscribe_all(
            &[
                EventType::EffectsEnabled,
                EventType::AggregatorChanged,
                EventType::PlaintextAggregated,
                EventType::E3StageChanged,
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

impl<P: Provider + WalletProvider + Clone + 'static> Actor for InterfoldSolWriter<P> {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT)
    }
}
