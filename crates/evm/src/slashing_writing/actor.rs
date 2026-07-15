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
use crate::domain::error_decoder::format_evm_error;
use crate::domain::slash_submission::{
    should_submit_slash, submission_delay, submission_rank, SlashIntentKey,
    SlashSubmissionDecision, SlashSubmissionGate,
};
use crate::helpers::{transaction_nonce_guard, EthProvider};
use crate::send_tx_with_retry;
use actix::prelude::*;
use actix::Addr;
use alloy::{
    primitives::{Address, Bytes, U256},
    providers::{Provider, WalletProvider},
    rpc::types::TransactionReceipt,
};
use anyhow::Result;
use e3_events::prelude::*;
use e3_events::BusHandle;
use e3_events::EventType;
use e3_events::InterfoldEvent;
use e3_events::InterfoldEventData;
use e3_events::Shutdown;
use e3_events::{AccusationQuorumReached, EType};
use e3_utils::{require_successful_receipt, NotifySync, MAILBOX_LIMIT};
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
    submissions: SlashSubmissionGate,
}

#[derive(Message)]
#[rtype(result = "()")]
struct SubmitSlashIntent {
    key: SlashIntentKey,
    event: AccusationQuorumReached,
}

#[derive(Message)]
#[rtype(result = "()")]
struct SlashSubmissionFinished {
    key: SlashIntentKey,
    terminal: bool,
}

impl<P: Provider + WalletProvider + Clone + 'static> SlashingManagerSolWriter<P> {
    pub fn new(
        bus: &BusHandle,
        provider: EthProvider<P>,
        contract_address: Address,
    ) -> Result<Self> {
        Ok(Self {
            provider,
            contract_address,
            bus: bus.clone(),
            submissions: SlashSubmissionGate::new(),
        })
    }

    pub async fn attach(
        bus: &BusHandle,
        provider: EthProvider<P>,
        contract_address: Address,
    ) -> Result<Addr<SlashingManagerSolWriter<P>>> {
        let addr = SlashingManagerSolWriter::new(bus, provider, contract_address)?.start();
        bus.subscribe_all(
            &[
                EventType::AccusationQuorumReached,
                EventType::EffectRetry,
                EventType::EvmLogObserved,
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
    }
}
