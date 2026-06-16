// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::actors::evm_parser::EvmParser;
use crate::contracts::ICiphernodeRegistry;
use crate::domain::ciphernode_registry_events::extractor;
use crate::domain::error_decoder::{decode_error_from_str, format_evm_error};
use crate::helpers::{encode_zk_proof, send_tx_with_retry, EthProvider};
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
use e3_utils::{ArcBytes, NotifySync, MAILBOX_LIMIT};
use std::collections::{HashMap, HashSet};
use tracing::{error, info};

/// Connects to CiphernodeRegistry.sol converting EVM events to InterfoldEvents
pub struct CiphernodeRegistrySolReader;

impl CiphernodeRegistrySolReader {
    pub fn setup(next: &EvmEventProcessor) -> Addr<EvmParser> {
        EvmParser::new(next, extractor).start()
    }
}

/// Writer for publishing committees to CiphernodeRegistry
pub struct CiphernodeRegistrySolWriter<P> {
    provider: EthProvider<P>,
    contract_address: Address,
    bus: BusHandle,
    effects_enabled: bool,
    active_aggregators: HashMap<E3id, bool>,
    /// E3s for which a `publishCommittee` submission is currently in flight.
    /// Guards against firing a second on-chain tx for the same E3 before the
    /// first is observed (wasted gas / nonce contention, H13). The authoritative
    /// cross-restart idempotency remains the on-chain `should_publish_committee`
    /// preflight; this only dedups concurrent in-session submissions. Entries
    /// are cleared on failure so a genuine retry can proceed.
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

impl<P: Provider + WalletProvider + Clone + 'static> Actor for CiphernodeRegistrySolWriter<P> {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT)
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<InterfoldEvent>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        match msg.into_data() {
            InterfoldEventData::EffectsEnabled(data) => self.notify_sync(ctx, data),
            InterfoldEventData::AggregatorChanged(data) => self.notify_sync(ctx, data),
            InterfoldEventData::PublicKeyAggregated(data) => {
                // Only publish if the src and destination chains match
                if self.provider.chain_id() == data.e3_id.chain_id() {
                    ctx.notify(data);
                }
            }
            InterfoldEventData::CommitteeFinalizeRequested(data) => {
                if self.provider.chain_id() == data.e3_id.chain_id() {
                    ctx.notify(data);
                }
            }
            InterfoldEventData::TicketGenerated(data) => {
                // Submit ticket if chain matches
                if self.provider.chain_id() == data.e3_id.chain_id() {
                    ctx.notify(data);
                }
            }
            InterfoldEventData::E3RequestComplete(data) => self.notify_sync(ctx, data),
            InterfoldEventData::Shutdown(data) => self.notify_sync(ctx, data),
            _ => (),
        }
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<EffectsEnabled>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ();

    fn handle(&mut self, _: EffectsEnabled, _: &mut Self::Context) -> Self::Result {
        self.effects_enabled = true;
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<AggregatorChanged>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: AggregatorChanged, _: &mut Self::Context) -> Self::Result {
        self.active_aggregators.insert(msg.e3_id, msg.is_aggregator);
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<E3RequestComplete>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: E3RequestComplete, _: &mut Self::Context) -> Self::Result {
        self.active_aggregators.remove(&msg.e3_id);
        self.submitting.remove(&msg.e3_id);
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<TicketGenerated>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ResponseFuture<()>;

    fn handle(&mut self, msg: TicketGenerated, _: &mut Self::Context) -> Self::Result {
        if !self.effects_enabled {
            return Box::pin(async {});
        }

        match msg.ticket_id {
            TicketId::Score(ticket_id) => {
                info!(
                    "Score sortition ticket generated for E3 {:?}, submitting to contract",
                    msg.e3_id
                );

                let e3_id = msg.e3_id.clone();
                let contract_address = self.contract_address;
                let provider = self.provider.clone();
                let bus = self.bus.clone();

                Box::pin(async move {
                    info!("Submitting ticket {} for E3 {:?}", ticket_id, e3_id);

                    let result =
                        submit_ticket_to_registry(provider, contract_address, e3_id, ticket_id)
                            .await;
                    match result {
                        Ok(receipt) => {
                            info!(tx=%receipt.transaction_hash, "Ticket submitted to registry");
                        }
                        Err(err) => {
                            error!("Failed to submit ticket: {}", format_evm_error(&err));
                            bus.err(EType::Evm, err);
                        }
                    }
                })
            }
        }
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<CommitteeFinalizeRequested>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ResponseFuture<()>;

    fn handle(&mut self, msg: CommitteeFinalizeRequested, _: &mut Self::Context) -> Self::Result {
        if !self.effects_enabled {
            return Box::pin(async {});
        }

        let e3_id = msg.e3_id.clone();
        let contract_address = self.contract_address;
        let provider = self.provider.clone();
        let bus = self.bus.clone();

        Box::pin(async move {
            match should_finalize_committee(provider.clone(), contract_address, e3_id.clone()).await
            {
                Ok(false) => {
                    info!(e3_id = %e3_id, "Skipping finalizeCommittee; on-chain state is not finalizable");
                    return;
                }
                Err(err) => {
                    error!(
                        "Failed to preflight finalizeCommittee: {}",
                        format_evm_error(&err)
                    );
                    return;
                }
                Ok(true) => {}
            }

            info!("Finalizing committee for E3 {:?}", e3_id);

            let result = finalize_committee_on_registry(provider, contract_address, e3_id).await;
            match result {
                Ok(receipt) => {
                    info!(tx=%receipt.transaction_hash, "Committee finalized on registry");
                }
                Err(err) => {
                    error!("Failed to finalize committee: {}", format_evm_error(&err));
                    bus.err(EType::Evm, err);
                }
            }
        })
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<PublicKeyAggregated>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ResponseFuture<()>;

    fn handle(&mut self, msg: PublicKeyAggregated, ctx: &mut Self::Context) -> Self::Result {
        if !self.effects_enabled || !self.is_active_aggregator_for(&msg.e3_id) {
            return Box::pin(async {});
        }

        // Don't fire a second on-chain submission for an E3 whose publishCommittee
        // tx is already in flight (H13). The on-chain preflight below is still the
        // authoritative idempotency guard across restarts.
        if !self.submitting.insert(msg.e3_id.clone()) {
            info!(e3_id = %msg.e3_id, "publishCommittee already in flight; skipping duplicate submission");
            return Box::pin(async {});
        }

        let e3_id = msg.e3_id.clone();
        let pubkey = msg.pubkey.clone();
        let pk_commitment = msg.pk_commitment;
        let dkg_aggregator_proof = msg.dkg_aggregator_proof.clone();
        let dkg_attestation_bundle = msg.dkg_attestation_bundle.clone();
        let contract_address = self.contract_address;
        let provider = self.provider.clone();
        let bus = self.bus.clone();
        let self_addr = ctx.address();

        Box::pin(async move {
            match should_publish_committee(provider.clone(), contract_address, e3_id.clone()).await
            {
                Ok(false) => {
                    info!(e3_id = %e3_id, "Skipping publishCommittee; committee public key already published");
                    return;
                }
                Err(err) => {
                    error!(
                        "Failed to preflight publishCommittee: {}",
                        format_evm_error(&err)
                    );
                    // Transient read failure: allow a later event to retry.
                    self_addr.do_send(ClearSubmitting(e3_id));
                    return;
                }
                Ok(true) => {}
            }

            let result = publish_committee_to_registry(
                provider,
                contract_address,
                e3_id.clone(),
                pubkey,
                pk_commitment,
                dkg_aggregator_proof.as_ref(),
                dkg_attestation_bundle.as_ref().map(|b| b.as_ref()),
            )
            .await;
            match result {
                Ok(receipt) => {
                    info!(tx=%receipt.transaction_hash, "Committee published to registry");
                }
                Err(err) => {
                    error!("Failed to publish committee: {}", format_evm_error(&err));
                    // Submission failed: clear the in-flight marker so a retry can proceed.
                    self_addr.do_send(ClearSubmitting(e3_id));
                    bus.err(EType::Evm, err);
                }
            }
        })
    }
}

/// Internal message: clear the in-flight `publishCommittee` marker for an E3 so
/// a subsequent submission attempt is allowed after a failure (H13).
#[derive(Message)]
#[rtype(result = "()")]
struct ClearSubmitting(E3id);

impl<P: Provider + WalletProvider + Clone + 'static> Handler<ClearSubmitting>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: ClearSubmitting, _: &mut Self::Context) -> Self::Result {
        self.submitting.remove(&msg.0);
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<Shutdown>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ();

    fn handle(&mut self, _: Shutdown, ctx: &mut Self::Context) -> Self::Result {
        ctx.stop();
    }
}

pub async fn submit_ticket_to_registry<P: Provider + WalletProvider + Clone + 'static>(
    provider: EthProvider<P>,
    contract_address: Address,
    e3_id: E3id,
    ticket_number: u64,
) -> Result<TransactionReceipt> {
    let e3_id_u256: U256 = e3_id.try_into()?;
    let ticket_number_u256 = U256::from(ticket_number);

    send_tx_with_retry("submitTicket", &["CommitteeNotRequested"], || {
        let provider = provider.clone();
        async move {
            info!("Calling: contract.submitTicket(..)");
            let from_address = provider.provider().default_signer_address();
            let current_nonce = provider
                .provider()
                .get_transaction_count(from_address)
                .pending()
                .await?;
            let contract = ICiphernodeRegistry::new(contract_address, provider.provider());
            let builder = contract
                .submitTicket(e3_id_u256, ticket_number_u256)
                .nonce(current_nonce);
            let receipt = builder.send().await?.get_receipt().await?;
            Ok(receipt)
        }
    })
    .await
}

pub async fn finalize_committee_on_registry<P: Provider + WalletProvider + Clone + 'static>(
    provider: EthProvider<P>,
    contract_address: Address,
    e3_id: E3id,
) -> Result<TransactionReceipt> {
    let e3_id_u256: U256 = e3_id.try_into()?;

    send_tx_with_retry(
        "finalizeCommittee",
        &[
            "SubmissionWindowNotClosed",
            "CommitteeNotRequested",
            "ThresholdNotMet",
        ],
        || {
            let provider = provider.clone();
            async move {
                info!("Calling: contract.finalizeCommittee(..)");
                let from_address = provider.provider().default_signer_address();
                let current_nonce = provider
                    .provider()
                    .get_transaction_count(from_address)
                    .pending()
                    .await?;
                let contract = ICiphernodeRegistry::new(contract_address, provider.provider());
                let builder = contract.finalizeCommittee(e3_id_u256).nonce(current_nonce);
                let receipt = builder.send().await?.get_receipt().await?;
                Ok(receipt)
            }
        },
    )
    .await
}

async fn should_finalize_committee<P: Provider + WalletProvider + Clone + 'static>(
    provider: EthProvider<P>,
    contract_address: Address,
    e3_id: E3id,
) -> Result<bool> {
    let e3_id_u256: U256 = e3_id.try_into()?;
    let contract = ICiphernodeRegistry::new(contract_address, provider.provider());
    if contract.isOpen(e3_id_u256).call().await? {
        return Ok(false);
    }

    match contract.finalizeCommittee(e3_id_u256).call().await {
        Ok(_) => Ok(true),
        Err(err) => {
            let err = anyhow::Error::from(err);
            let decoded = decode_error_from_str(&format!("{err:?}"));

            if decoded.as_deref().is_some_and(|message| {
                message.contains("CommitteeAlreadyFinalized")
                    || message.contains("CommitteeNotRequested")
                    || message.contains("SubmissionWindowNotClosed")
                    || message.contains("ThresholdNotMet")
            }) {
                return Ok(false);
            }

            Err(err)
        }
    }
}

async fn should_publish_committee<P: Provider + WalletProvider + Clone + 'static>(
    provider: EthProvider<P>,
    contract_address: Address,
    e3_id: E3id,
) -> Result<bool> {
    let e3_id_u256: U256 = e3_id.try_into()?;
    let contract = ICiphernodeRegistry::new(contract_address, provider.provider());
    match contract.committeePublicKey(e3_id_u256).call().await {
        Ok(_) => Ok(false),
        Err(err) => {
            let err = anyhow::Error::from(err);
            let decoded = decode_error_from_str(&format!("{err:?}"));

            if decoded
                .as_deref()
                .is_some_and(|message| message.contains("CommitteeNotPublished"))
            {
                return Ok(true);
            }

            Err(err)
        }
    }
}

pub async fn publish_committee_to_registry<P: Provider + WalletProvider + Clone + 'static>(
    provider: EthProvider<P>,
    contract_address: Address,
    e3_id: E3id,
    public_key: ArcBytes,
    pk_commitment: [u8; 32],
    dkg_aggregator_proof: Option<&Proof>,
    dkg_attestation_bundle: Option<&[u8]>,
) -> Result<TransactionReceipt> {
    let e3_id_u256: U256 = e3_id.try_into()?;
    let public_key_bytes = Bytes::from(public_key.extract_bytes());
    let pk_commitment_b256 = B256::from(pk_commitment);

    // `proof` is empty when `proofAggregationEnabled = false`; the contract
    // trusts `pk_commitment` directly in that case.
    let proof: Bytes = match dkg_aggregator_proof {
        Some(p) => encode_zk_proof(p)?,
        None => Bytes::new(),
    };
    let attestation_bundle: Bytes = match dkg_attestation_bundle {
        Some(b) => Bytes::copy_from_slice(b),
        None => Bytes::new(),
    };

    // RPC may not have synced finalization yet
    send_tx_with_retry("publishCommittee", &["CommitteeNotFinalized"], || {
        let provider = provider.clone();
        let public_key_bytes = public_key_bytes.clone();
        let proof = proof.clone();
        let attestation_bundle = attestation_bundle.clone();
        async move {
            info!("Calling: contract.publishCommittee(..)");
            let from_address = provider.provider().default_signer_address();
            let current_nonce = provider
                .provider()
                .get_transaction_count(from_address)
                .pending()
                .await?;
            let contract = ICiphernodeRegistry::new(contract_address, provider.provider());
            let builder = contract
                .publishCommittee(
                    e3_id_u256,
                    public_key_bytes,
                    pk_commitment_b256,
                    proof,
                    attestation_bundle,
                )
                .nonce(current_nonce);
            let receipt = builder.send().await?.get_receipt().await?;
            Ok(receipt)
        }
    })
    .await
}

/// Read `CiphernodeRegistry.dkgFoldAttestationVerifier()` (EIP-712 verifying contract for fold attestations).
pub async fn fetch_dkg_fold_attestation_verifier<P: Provider + Clone>(
    provider: &P,
    registry_address: Address,
) -> Result<Option<Address>> {
    let contract = ICiphernodeRegistry::new(registry_address, provider);
    let verifier = contract.dkgFoldAttestationVerifier().call().await?;
    if verifier == Address::ZERO {
        Ok(None)
    } else {
        Ok(Some(verifier))
    }
}

/// Read `CiphernodeRegistry.accusationVoteValidity()` — registry-wide off-chain
/// freshness window (seconds) accusers stamp on `AccusationVote.deadline`.
/// Returns the raw `uint256` as `U256`; callers decide how to clamp it to
/// their own arithmetic type. `Ok(None)` is reserved for the case where the
/// registry has been governance-disabled (`accusationVoteValidity = 0`) so
/// the caller can short-circuit without producing votes that will never
/// verify on chain.
pub async fn fetch_accusation_vote_validity<P: Provider + Clone>(
    provider: &P,
    registry_address: Address,
) -> Result<Option<U256>> {
    let contract = ICiphernodeRegistry::new(registry_address, provider);
    let validity = contract.accusationVoteValidity().call().await?;
    if validity.is_zero() {
        Ok(None)
    } else {
        Ok(Some(validity))
    }
}

/// Wrapper for a reader and writer
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
