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
use crate::domain::slash_submission::{should_submit_slash, submission_delay, submission_rank};
use crate::helpers::EthProvider;
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
use e3_utils::NotifySync;
use tracing::{info, warn};

/// Submits `AccusationQuorumReached` events as slash proposals on-chain.
pub struct SlashingManagerSolWriter<P> {
    provider: EthProvider<P>,
    contract_address: Address,
    bus: BusHandle,
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
        })
    }

    pub async fn attach(
        bus: &BusHandle,
        provider: EthProvider<P>,
        contract_address: Address,
    ) -> Result<Addr<SlashingManagerSolWriter<P>>> {
        let addr = SlashingManagerSolWriter::new(bus, provider, contract_address)?.start();
        bus.subscribe_all(
            &[EventType::AccusationQuorumReached, EventType::Shutdown],
            addr.clone().into(),
        );
        Ok(addr)
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Actor for SlashingManagerSolWriter<P> {
    type Context = actix::Context<Self>;
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<InterfoldEvent>
    for SlashingManagerSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        match msg.into_data() {
            InterfoldEventData::AccusationQuorumReached(data) => {
                // Only submit if:
                // 1. This is the right chain
                // 2. The quorum decided the accused is at fault OR equivocated
                // 3. This node is among the top MAX_SLASH_SUBMITTERS voters
                //    (sorted ascending by address). The lowest-address voter
                //    submits immediately; higher-ranked fallback voters wait
                //    progressively longer (rank * SUBMITTER_DELAY_SECS) before
                //    attempting submission. On-chain DuplicateEvidence protection
                //    ensures at most one slash executes.
                let my_addr = self.provider.provider().default_signer_address();
                let rank = submission_rank(data.votes_for.iter().map(|v| v.voter), my_addr);

                if should_submit_slash(
                    self.provider.chain_id() == data.e3_id.chain_id(),
                    &data.outcome,
                    rank,
                ) {
                    ctx.notify(data);
                }
            }
            InterfoldEventData::Shutdown(data) => self.notify_sync(ctx, data),
            _ => (),
        }
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<AccusationQuorumReached>
    for SlashingManagerSolWriter<P>
{
    type Result = ResponseFuture<()>;

    fn handle(&mut self, msg: AccusationQuorumReached, _: &mut Self::Context) -> Self::Result {
        Box::pin({
            let contract_address = self.contract_address;
            let provider = self.provider.clone();
            let bus = self.bus.clone();
            let my_addr = self.provider.provider().default_signer_address();
            async move {
                // Compute this node's submission rank for staggered fallback
                let rank =
                    submission_rank(msg.votes_for.iter().map(|v| v.voter), my_addr).unwrap_or(0);

                // Fallback submitters wait before attempting, giving the primary
                // submitter time to land the transaction on-chain.
                if rank > 0 {
                    let delay = submission_delay(rank);
                    info!(
                        "Fallback submitter (rank {rank}): waiting {delay:?} before submission attempt"
                    );
                    tokio::time::sleep(delay).await;
                }

                let result = submit_slash_proposal(provider, contract_address, msg).await;
                match result {
                    Ok(receipt) => {
                        info!(tx=%receipt.transaction_hash, "Submitted attestation-based slash proposal on-chain");
                    }
                    Err(err) => {
                        let decoded = format_evm_error(&err);
                        let benign = decoded.contains("OperatorNotInCommittee")
                            || decoded.contains("VoterNotInCommittee")
                            || decoded.contains("DuplicateEvidence");
                        if rank > 0 || benign {
                            // Fallback submitters expect DuplicateEvidence reverts
                            // when the primary submitter has already landed the tx.
                            // Operator/VoterNotInCommittee indicate a stale off-chain accusation
                            // (e.g. cross-E3 race) — not a node-local fault.
                            warn!("Slash submission skipped (rank {rank}): {decoded}");
                        } else {
                            bus.err(
                                EType::Evm,
                                anyhow::anyhow!("Error submitting slash proposal: {decoded}"),
                            );
                        }
                    }
                }
            }
        })
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<Shutdown>
    for SlashingManagerSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, _: Shutdown, ctx: &mut Self::Context) -> Self::Result {
        ctx.stop();
    }
}

async fn submit_slash_proposal<P: Provider + WalletProvider + Clone>(
    provider: EthProvider<P>,
    contract_address: Address,
    data: AccusationQuorumReached,
) -> Result<TransactionReceipt> {
    let e3_id: U256 = data.e3_id.clone().try_into()?;
    let operator = data.accused;

    // Empty `votes_for` only reaches this point if upstream invariants broke
    // — `check_quorum` requires `len >= threshold_m >= 1` before emitting
    // `AccusedFaulted`/`Equivocation`. Refuse to submit malformed calldata
    // and surface a structured warning so an operator can debug the upstream
    // gossip/quorum path rather than seeing a generic ABI-decode revert
    // on chain.
    let proof_data = match encode_attestation_evidence(&data) {
        Some(bytes) => bytes,
        None => {
            warn!(
                e3_id = %data.e3_id,
                accused = %operator,
                outcome = %data.outcome,
                "Refusing to submit proposeSlash: AccusationQuorumReached has empty \
                 votes_for or empty evidence preimage — submission dropped"
            );
            return Err(anyhow::anyhow!(
                "AccusationQuorumReached has empty votes_for or evidence; refused proposeSlash submission \
                 (e3_id={}, accused={})",
                data.e3_id,
                operator
            ));
        }
    };

    let party_id =
        resolve_party_id_for_operator(provider.clone(), contract_address, e3_id, operator)
            .await
            .ok()
            .flatten();

    send_tx_with_retry("proposeSlash", &[], || {
        info!(
            "proposeSlash() e3_id={:?} operator={:?} party_id={:?}",
            e3_id, operator, party_id
        );
        let proof = Bytes::from(proof_data.clone());
        let provider = provider.clone();

        async move {
            let from_address = provider.provider().default_signer_address();
            let current_nonce = provider
                .provider()
                .get_transaction_count(from_address)
                .pending()
                .await?;
            let contract = ISlashingManager::new(contract_address, provider.provider());
            let receipt = if let Some(pid) = party_id {
                contract
                    .proposeSlashByDkgParty(e3_id, pid, proof)
                    .nonce(current_nonce)
                    .send()
                    .await?
                    .get_receipt()
                    .await?
            } else {
                contract
                    .proposeSlash(e3_id, operator, proof)
                    .nonce(current_nonce)
                    .send()
                    .await?
                    .get_receipt()
                    .await?
            };
            Ok(receipt)
        }
    })
    .await
}

async fn resolve_party_id_for_operator<P: Provider + WalletProvider + Clone>(
    provider: EthProvider<P>,
    contract_address: Address,
    e3_id: U256,
    operator: Address,
) -> Result<Option<U256>> {
    let slashing = ISlashingManager::new(contract_address, provider.provider());
    let registry = slashing.ciphernodeRegistry().call().await?;
    if registry == Address::ZERO {
        return Ok(None);
    }

    let registry_view = ICiphernodeRegistry::new(registry, provider.provider());
    let anchors = registry_view.getDkgAnchors(e3_id).call().await?;
    for pid in anchors.partyIds {
        let node = registry_view
            .canonicalCommitteeNodeAt(e3_id, pid)
            .call()
            .await?;
        if node == operator {
            return Ok(Some(pid));
        }
    }
    Ok(None)
}
