// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Subscribes to `AccusationQuorumReached` events and submits committee-attested
//! slash proposals on the SlashingManager contract. Prefers party-attributed
//! `proposeSlashByDkgParty` when DKG anchors resolve, and falls back to
//! operator-attributed `proposeSlash` otherwise.

use crate::contracts::{ICiphernodeRegistry, ISlashingManager};
use crate::domain::attestation_evidence::encode_attestation_evidence;
use crate::domain::error_decoder::{decode_error_from_str, format_evm_error};
use crate::domain::slash_submission::{
    should_submit_slash, submission_delay, submission_rank, SlashIntentKey,
};
use crate::helpers::EthProvider;
use crate::send_tx_with_retry;
use crate::{EvmEffectOutbox, EvmEffectOutboxRepositoryFactory, EvmEffectOutboxState};
use actix::prelude::*;
use actix::Addr;
use alloy::{
    primitives::{Address, Bytes, U256},
    providers::{Provider, WalletProvider},
    rpc::types::TransactionReceipt,
};
use anyhow::Result;
use e3_data::Repositories;
use e3_events::prelude::*;
use e3_events::BusHandle;
use e3_events::EventType;
use e3_events::InterfoldEvent;
use e3_events::InterfoldEventData;
use e3_events::Shutdown;
use e3_events::{AccusationQuorumReached, EType};
use e3_utils::{require_successful_receipt, NotifySync, MAILBOX_LIMIT};
use std::{collections::HashSet, time::Duration};
use tracing::{info, warn};

#[path = "effects.rs"]
mod effects;
#[path = "handlers.rs"]
mod handlers;

/// Submits `AccusationQuorumReached` events as slash proposals on-chain.
pub struct SlashingManagerSolWriter<P> {
    provider: EthProvider<P>,
    contract_address: Address,
    bus: BusHandle,
    effects_enabled: bool,
    outbox: EvmEffectOutbox<AccusationQuorumReached>,
    submitting: HashSet<String>,
}

#[derive(Message)]
#[rtype(result = "()")]
struct ExecuteSlashIntent {
    key: String,
    event: AccusationQuorumReached,
    status: crate::EvmEffectStatus,
}

#[derive(Message)]
#[rtype(result = "()")]
struct SlashSubmissionFinished {
    key: String,
}

#[derive(Message)]
#[rtype(result = "()")]
struct DrainSlashOutbox;

impl<P: Provider + WalletProvider + Clone + 'static> SlashingManagerSolWriter<P> {
    pub async fn new(
        bus: &BusHandle,
        provider: EthProvider<P>,
        contract_address: Address,
        repository: e3_data::Repository<EvmEffectOutboxState<AccusationQuorumReached>>,
    ) -> Result<Self> {
        Ok(Self {
            provider,
            contract_address,
            bus: bus.clone(),
            effects_enabled: false,
            outbox: EvmEffectOutbox::load(repository).await?,
            submitting: HashSet::new(),
        })
    }

    pub async fn attach(
        bus: &BusHandle,
        provider: EthProvider<P>,
        contract_address: Address,
        repositories: &Repositories,
    ) -> Result<Addr<SlashingManagerSolWriter<P>>> {
        let signer = provider.provider().default_signer_address();
        let writer_scope = format!("slashing_manager/{contract_address}/{signer}");
        let repository = repositories.evm_effect_outbox(&writer_scope, provider.chain_id());
        let addr = SlashingManagerSolWriter::new(bus, provider, contract_address, repository)
            .await?
            .start();
        bus.subscribe_all(
            &[
                EventType::AccusationQuorumReached,
                EventType::EffectsEnabled,
                EventType::Shutdown,
            ],
            addr.clone().into(),
        );
        Ok(addr)
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Actor for SlashingManagerSolWriter<P> {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
        ctx.run_interval(Duration::from_secs(30), |actor, ctx| {
            if actor.effects_enabled {
                ctx.notify(DrainSlashOutbox);
            }
        });
    }
}
