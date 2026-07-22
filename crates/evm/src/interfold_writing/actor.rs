// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Interfold contract publication boundary.

use crate::contracts::IInterfold;
use crate::domain::error_decoder::{decode_error_from_str, format_evm_error};
use crate::domain::plaintext_publication::validate_plaintext_output;
use crate::helpers::{encode_zk_proof, EthProvider};
use crate::send_tx_with_retry;
use crate::{EvmEffectOutbox, EvmEffectOutboxRepositoryFactory, EvmEffectOutboxState};
use actix::prelude::*;
use alloy::{
    primitives::{Address, Bytes, U256},
    providers::{Provider, WalletProvider},
    rpc::types::TransactionReceipt,
};
use anyhow::Result;
use e3_data::{Repositories, Repository};
use e3_events::{
    prelude::*, AggregatorChanged, AggregatorFailoverExhausted, AggregatorPhase, BusHandle,
    E3RequestComplete, E3Stage, E3StageChanged, E3id, EType, EffectsEnabled, EventType,
    InterfoldEvent, InterfoldEventData, PlaintextAggregated, Proof, Shutdown,
};
use e3_utils::{require_successful_receipt, NotifySync, MAILBOX_LIMIT};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};
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
    outbox: EvmEffectOutbox<InterfoldEffect>,
    submitting: HashSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum InterfoldEffect {
    PublishPlaintext(PlaintextAggregated),
    ProcessFailure(E3StageChanged),
    RefreshFailoverLease(FailoverLeaseRefresh),
    MarkFailure(AggregatorFailoverExhausted),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FailoverLeaseRefresh {
    e3_id: E3id,
    phase: AggregatorPhase,
}

impl InterfoldEffect {
    fn key(&self) -> String {
        match self {
            Self::PublishPlaintext(event) => crate::semantic_effect_key(
                "publish_plaintext",
                &event.e3_id,
                &(&event.decrypted_output, &event.decryption_aggregator_proofs),
            ),
            Self::ProcessFailure(event) => {
                crate::semantic_effect_key("process_failure", &event.e3_id, &())
            }
            Self::RefreshFailoverLease(event) => {
                crate::semantic_effect_key("refresh_failover_lease", &event.e3_id, &event.phase)
            }
            Self::MarkFailure(event) => {
                crate::semantic_effect_key("mark_failure", &event.e3_id, &event.phase)
            }
        }
    }
}

#[derive(Message)]
#[rtype(result = "()")]
struct DrainInterfoldOutbox;

#[derive(Message)]
#[rtype(result = "()")]
struct ExecuteInterfoldEffect {
    key: String,
    effect: InterfoldEffect,
    status: crate::EvmEffectStatus,
}

impl<P: Provider + WalletProvider + Clone + 'static> InterfoldSolWriter<P> {
    async fn new(
        bus: &BusHandle,
        provider: EthProvider<P>,
        contract_address: Address,
        repository: Repository<EvmEffectOutboxState<InterfoldEffect>>,
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

    pub async fn attach(
        bus: &BusHandle,
        provider: EthProvider<P>,
        contract_address: Address,
        repositories: &Repositories,
    ) -> Result<Addr<Self>> {
        let signer = provider.provider().default_signer_address();
        let writer_scope = format!("interfold/{contract_address}/{signer}");
        let repository = repositories.evm_effect_outbox(&writer_scope, provider.chain_id());
        let addr = InterfoldSolWriter::new(bus, provider, contract_address, repository)
            .await?
            .start();
        bus.subscribe_all(
            &[
                EventType::EffectsEnabled,
                EventType::AggregatorChanged,
                EventType::PlaintextAggregated,
                EventType::E3StageChanged,
                EventType::CommitteeFinalized,
                EventType::CiphertextOutputPublished,
                EventType::AggregatorFailoverExhausted,
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

impl<P: Provider + WalletProvider + Clone + 'static> Actor for InterfoldSolWriter<P> {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
        ctx.run_interval(Duration::from_secs(30), |actor, ctx| {
            if actor.effects_enabled {
                ctx.notify(DrainInterfoldOutbox);
            }
        });
    }
}
