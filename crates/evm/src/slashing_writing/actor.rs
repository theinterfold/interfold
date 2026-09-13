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
    classify_slash_policy, is_slashable_outcome, should_submit_slash, slash_reason,
    slash_submission_error_is_terminal, submission_delay, submission_rank, SlashIntentKey,
    SlashPolicyState, SlashSubmissionDecision, SlashSubmissionGate,
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
use e3_data::{AutoPersist, Persistable, Repository};
use e3_events::prelude::*;
use e3_events::BusHandle;
use e3_events::EventType;
use e3_events::InterfoldEvent;
use e3_events::InterfoldEventData;
use e3_events::Shutdown;
use e3_events::{AccusationQuorumReached, CommitteeMemberExcluded, EType, SlashExecuted};
use e3_utils::{require_successful_receipt, NotifySync, MAILBOX_LIMIT};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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
    recovery: Option<Persistable<SlashingWriterRecoveryState>>,
}

const SLASH_SUBMISSION_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(30);
pub const SLASHING_WRITER_RECOVERY_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingWriterRecoveryState {
    pub schema_version: u32,
    pending: BTreeMap<SlashIntentKey, AccusationQuorumReached>,
}

impl Default for SlashingWriterRecoveryState {
    fn default() -> Self {
        Self {
            schema_version: SLASHING_WRITER_RECOVERY_SCHEMA_VERSION,
            pending: BTreeMap::new(),
        }
    }
}

impl SlashingWriterRecoveryState {
    pub fn record(&mut self, event: AccusationQuorumReached) -> Result<()> {
        self.pending
            .entry(SlashIntentKey::from_quorum(&event)?)
            .or_insert(event);
        Ok(())
    }

    fn acknowledge(&mut self, key: &SlashIntentKey) {
        self.pending.remove(key);
    }

    pub fn acknowledge_exclusion(&mut self, event: &CommitteeMemberExcluded) -> Result<()> {
        self.acknowledge(&SlashIntentKey::from_exclusion(event)?);
        Ok(())
    }

    pub fn acknowledge_execution(&mut self, event: &SlashExecuted) -> Result<()> {
        if let Some(key) = SlashIntentKey::from_execution(event)? {
            self.acknowledge(&key);
        }
        Ok(())
    }

    fn pending_events(&self) -> Vec<AccusationQuorumReached> {
        self.pending.values().cloned().collect()
    }
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
    acknowledge_recovery: bool,
    retry_event: Option<AccusationQuorumReached>,
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
            recovery: None,
        })
    }

    fn from_recovery(
        bus: &BusHandle,
        provider: EthProvider<P>,
        contract_address: Address,
        recovery: Persistable<SlashingWriterRecoveryState>,
    ) -> Result<Self> {
        let mut submissions = SlashSubmissionGate::new();
        for event in recovery.try_get()?.pending_events() {
            submissions.admit(event)?;
        }
        Ok(Self {
            provider,
            contract_address,
            bus: bus.clone(),
            submissions,
            recovery: Some(recovery),
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
                EventType::CommitteeMemberExcluded,
                EventType::SlashExecuted,
                EventType::EffectsEnabled,
                EventType::Shutdown,
            ],
            addr.clone().into(),
        );
        Ok(addr)
    }

    pub async fn attach_with_recovery(
        bus: &BusHandle,
        provider: EthProvider<P>,
        contract_address: Address,
        repository: Repository<SlashingWriterRecoveryState>,
    ) -> Result<Addr<SlashingManagerSolWriter<P>>> {
        let recovery = repository
            .load_or_default(SlashingWriterRecoveryState::default())
            .await?;
        anyhow::ensure!(
            recovery.try_get()?.schema_version == SLASHING_WRITER_RECOVERY_SCHEMA_VERSION,
            "unsupported slashing-writer recovery schema"
        );
        let addr = Self::from_recovery(bus, provider, contract_address, recovery)?.start();
        bus.subscribe_all(
            &[
                EventType::AccusationQuorumReached,
                EventType::CommitteeMemberExcluded,
                EventType::SlashExecuted,
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

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::{AccusationOutcome, E3id, ProofType};

    fn slash_intent() -> AccusationQuorumReached {
        AccusationQuorumReached {
            e3_id: E3id::new("7", 1),
            accuser: Address::repeat_byte(1),
            accused: Address::repeat_byte(2),
            proof_type: ProofType::C1PkGeneration,
            proof_instance: 0,
            votes_for: Vec::new(),
            outcome: AccusationOutcome::AccusedFaulted,
            evidence: Bytes::new(),
        }
    }

    #[test]
    fn outbox_coalesces_and_acknowledges() -> Result<()> {
        let intent = slash_intent();
        let mut recovery = SlashingWriterRecoveryState::default();
        recovery.record(intent.clone())?;
        recovery.record(intent.clone())?;
        assert_eq!(recovery.pending_events(), vec![intent.clone()]);

        recovery.acknowledge_exclusion(&CommitteeMemberExcluded {
            e3_id: intent.e3_id.clone(),
            node: intent.accused,
            proof_type: intent.proof_type,
            party_id: None,
        })?;
        assert!(recovery.pending_events().is_empty());

        recovery.record(intent.clone())?;
        recovery.acknowledge_execution(&SlashExecuted {
            e3_id: intent.e3_id,
            proposal_id: 1,
            operator: intent.accused,
            reason: intent.proof_type.attestation_slash_reason().0,
            ticket_amount: 0,
            ciphernode_bond_amount: 0,
        })?;
        assert!(recovery.pending_events().is_empty());
        Ok(())
    }
}
