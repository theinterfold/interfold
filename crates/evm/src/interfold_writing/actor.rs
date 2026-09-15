// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Interfold contract publication boundary.

use crate::contracts::{ICiphernodeRegistry, IInterfold};
use crate::domain::error_decoder::{contains_error_selector, format_evm_error};
use crate::domain::plaintext_publication::validate_plaintext_output;
use crate::domain::plaintext_publication::{
    failure_watch_delay, failure_watch_party_id, FailureStageDiscoveryGate,
};
use crate::domain::publication_replay::ReplaySubmissionGate;
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
    prelude::*, AggregatorChanged, BusHandle, CiphernodeSelected,
    DkgFoldAttestationContextEstablished, E3RequestComplete, E3Stage, E3StageChanged, E3id, EType,
    EffectsEnabled, EventType, InterfoldEvent, InterfoldEventData, PlaintextAggregated, Proof,
    Shutdown, DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION,
};
use e3_utils::{require_successful_receipt, NotifySync, MAILBOX_LIMIT};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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
    publication: ReplaySubmissionGate<E3id, PlaintextAggregated>,
    committee_party_ids: HashMap<E3id, u64>,
    request_registries: HashMap<E3id, Address>,
    failure_stages: HashMap<E3id, E3Stage>,
    failure_timers: HashMap<E3id, SpawnHandle>,
    failure_stage_discoveries: FailureStageDiscoveryGate,
    failure_settlements: ReplaySubmissionGate<E3id, ()>,
}

impl<P: Provider + WalletProvider + Clone + 'static> InterfoldSolWriter<P> {
    pub fn new(
        bus: &BusHandle,
        provider: EthProvider<P>,
        contract_address: Address,
    ) -> Result<Self> {
        Self::new_with_recovery(
            bus,
            provider,
            contract_address,
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashSet::new(),
        )
    }

    pub fn new_with_recovery(
        bus: &BusHandle,
        provider: EthProvider<P>,
        contract_address: Address,
        active_aggregators: HashMap<E3id, bool>,
        committee_party_ids: HashMap<E3id, u64>,
        request_registries: HashMap<E3id, Address>,
        failure_stages: HashMap<E3id, E3Stage>,
        pending_failure_settlements: HashSet<E3id>,
    ) -> Result<Self> {
        let mut failure_settlements = ReplaySubmissionGate::new();
        for e3_id in pending_failure_settlements {
            failure_settlements.record(e3_id, ());
        }

        Ok(Self {
            provider,
            contract_address,
            bus: bus.clone(),
            effects_enabled: false,
            active_aggregators,
            publication: ReplaySubmissionGate::new(),
            committee_party_ids,
            request_registries,
            failure_stages,
            failure_timers: HashMap::new(),
            failure_stage_discoveries: FailureStageDiscoveryGate::default(),
            failure_settlements,
        })
    }

    pub fn attach(bus: &BusHandle, provider: EthProvider<P>, contract_address: Address) {
        Self::attach_with_recovery(
            bus,
            provider,
            contract_address,
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashSet::new(),
        );
    }

    pub fn attach_with_recovery(
        bus: &BusHandle,
        provider: EthProvider<P>,
        contract_address: Address,
        active_aggregators: HashMap<E3id, bool>,
        committee_party_ids: HashMap<E3id, u64>,
        request_registries: HashMap<E3id, Address>,
        failure_stages: HashMap<E3id, E3Stage>,
        pending_failure_settlements: HashSet<E3id>,
    ) {
        let addr = InterfoldSolWriter::new_with_recovery(
            bus,
            provider,
            contract_address,
            active_aggregators,
            committee_party_ids,
            request_registries,
            failure_stages,
            pending_failure_settlements,
        )
        .expect("failed to create InterfoldSolWriter")
        .start();
        bus.subscribe_all(
            &[
                EventType::EffectsEnabled,
                EventType::AggregatorChanged,
                EventType::CiphernodeSelected,
                EventType::DkgFoldAttestationContextEstablished,
                EventType::PlaintextAggregated,
                EventType::E3StageChanged,
                EventType::E3RequestComplete,
                EventType::Shutdown,
            ],
            addr.into(),
        );
    }

    fn is_active_aggregator_for(&self, e3_id: &E3id) -> bool {
        self.active_aggregators.get(e3_id).copied().unwrap_or(false)
    }

    fn now_unix_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

#[derive(Message, Debug, Clone)]
#[rtype(result = "()")]
struct ResolveFailureDeadline {
    e3_id: E3id,
    stage: E3Stage,
}

#[derive(Message, Debug, Clone)]
#[rtype(result = "()")]
struct DiscoverFailureStage {
    e3_id: E3id,
}

#[derive(Message, Debug, Clone)]
#[rtype(result = "()")]
struct MarkFailedAtDeadline {
    e3_id: E3id,
    stage: E3Stage,
}

#[derive(Message, Debug, Clone)]
#[rtype(result = "()")]
struct ProcessFailedE3 {
    e3_id: E3id,
}

impl<P: Provider + WalletProvider + Clone + 'static> Actor for InterfoldSolWriter<P> {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT)
    }
}
