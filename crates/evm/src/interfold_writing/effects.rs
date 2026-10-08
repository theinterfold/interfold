// SPDX-License-Identifier: LGPL-3.0-only

//! Interfold contract reads and transaction effects.

use super::*;
use alloy::sol_types::SolError;
use e3_events::{AggregateId, CorrelationId, EventSource, EventStoreQueryResponse};
use std::ops::RangeInclusive;

/// Read one bounded page of deferred local intents from their durable history range.
pub(super) async fn read_plaintext_intents(
    store: &Recipient<EventStoreQueryBy<SeqAgg>>,
    e3_id: &E3id,
    range: RangeInclusive<u64>,
) -> Result<(Vec<PlaintextAggregated>, u64)> {
    let aggregate = AggregateId::from_chain_id(Some(e3_id.chain_id()));
    let mut cursor = *range.start();
    let (recipient, response) = e3_utils::actix::channel::oneshot::<EventStoreQueryResponse>();
    store
        .send(
            EventStoreQueryBy::<SeqAgg>::new(
                CorrelationId::new(),
                HashMap::from([(aggregate, cursor)]),
                recipient,
            )
            .with_limit(1024)
            .with_max_bytes(16 * 1024 * 1024),
        )
        .await?;
    let mut intents = Vec::new();
    for event in response.await?.into_events()? {
        if event.seq() > *range.end() {
            break;
        }
        anyhow::ensure!(
            event.aggregate_id() == aggregate && event.seq() == cursor,
            "plaintext publication recovery event-store sequence gap"
        );
        cursor += 1;
        if event.source() == EventSource::Local {
            if let InterfoldEventData::PlaintextAggregated(intent) = event.into_data() {
                if intent.e3_id == *e3_id {
                    intents.push(intent);
                }
            }
        }
    }
    anyhow::ensure!(
        cursor > *range.start(),
        "deferred plaintext history is missing"
    );
    Ok((intents, cursor))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::actors::interfold_sol_writer) enum MarkFailureOutcome {
    Marked,
    NotDue,
    StageAdvanced,
}

pub(in crate::actors::interfold_sol_writer) enum FailureSettlementOutcome {
    Submitted(Box<TransactionReceipt>),
    Pending,
    /// The refund manager rejects settlement with `SettlementBlocked` until the accusation
    /// window closes and no committee-affecting proposal is open.
    Blocked,
    Completed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SettlementPreflight {
    Pending,
    Completed,
    Ready,
}

fn settlement_preflight(stage: u8) -> Result<SettlementPreflight> {
    Ok(match stage {
        1..=4 => SettlementPreflight::Pending,
        5 => SettlementPreflight::Completed,
        6 => SettlementPreflight::Ready,
        _ => anyhow::bail!("cannot settle E3 failure at unknown contract stage {stage}"),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::actors::interfold_sol_writer) struct FailureSchedule {
    pub deadline: u64,
    pub permissionless_grace: u64,
}

fn requested_failure_deadline(
    committee_deadline: u64,
    committee_threshold_met: bool,
    dkg_window: u64,
) -> Result<u64> {
    if committee_threshold_met {
        committee_deadline
            .checked_add(dkg_window)
            .ok_or_else(|| anyhow::anyhow!("Requested-stage deadline overflowed"))
    } else {
        Ok(committee_deadline)
    }
}

pub(in crate::actors::interfold_sol_writer) async fn read_watched_failure_stage<
    P: Provider + WalletProvider + Clone,
>(
    provider: EthProvider<P>,
    contract_address: Address,
    e3_id: E3id,
) -> Result<Option<E3Stage>> {
    let e3_id: U256 = e3_id.try_into()?;
    let contract = IInterfold::new(contract_address, provider.provider());
    let stage = contract.getE3Stage(e3_id).call().await?;
    Ok(match stage {
        1 => Some(E3Stage::Requested),
        2 => Some(E3Stage::CommitteeFinalized),
        3 => Some(E3Stage::KeyPublished),
        4 => Some(E3Stage::CiphertextReady),
        _ => None,
    })
}

pub(in crate::actors::interfold_sol_writer) async fn read_failure_deadline<
    P: Provider + WalletProvider + Clone,
>(
    provider: EthProvider<P>,
    contract_address: Address,
    e3_id: E3id,
    stage: E3Stage,
    request_registry: Option<Address>,
) -> Result<FailureSchedule> {
    let e3_id: U256 = e3_id.try_into()?;
    let contract = IInterfold::new(contract_address, provider.provider());
    let deadline: u64 = match stage {
        E3Stage::Requested => {
            let registry_address = request_registry.ok_or_else(|| {
                anyhow::anyhow!("request-time registry is unavailable for Requested E3")
            })?;
            let registry = ICiphernodeRegistry::new(registry_address, provider.provider());
            let committee_deadline: u64 = registry
                .getCommitteeDeadline(e3_id)
                .call()
                .await?
                .try_into()
                .map_err(|_| anyhow::anyhow!("committee deadline does not fit in u64"))?;
            let committee_threshold_met = registry.committeeThresholdMet(e3_id).call().await?;
            let dkg_window = if committee_threshold_met {
                let dkg_window: u64 = contract
                    .getE3TimeoutConfig(e3_id)
                    .call()
                    .await?
                    .dkgWindow
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("DKG window does not fit in u64"))?;
                dkg_window
            } else {
                0
            };
            requested_failure_deadline(committee_deadline, committee_threshold_met, dkg_window)?
        }
        E3Stage::CommitteeFinalized | E3Stage::KeyPublished | E3Stage::CiphertextReady => {
            let deadlines = contract.getDeadlines(e3_id).call().await?;
            let deadline = match stage {
                E3Stage::CommitteeFinalized => deadlines.dkgDeadline,
                E3Stage::KeyPublished => deadlines.computeDeadline,
                E3Stage::CiphertextReady => deadlines.decryptionDeadline,
                _ => unreachable!(),
            };
            deadline
                .try_into()
                .map_err(|_| anyhow::anyhow!("E3 deadline does not fit in u64"))?
        }
        _ => anyhow::bail!("stage {stage:?} does not have a failure deadline"),
    };
    let permissionless_grace = contract
        .markFailedGracePeriod()
        .call()
        .await?
        .try_into()
        .map_err(|_| anyhow::anyhow!("mark-failed grace period does not fit in u64"))?;
    Ok(FailureSchedule {
        deadline,
        permissionless_grace,
    })
}

pub(in crate::actors::interfold_sol_writer) async fn mark_e3_failed_if_due<
    P: Provider + WalletProvider + Clone,
>(
    provider: EthProvider<P>,
    contract_address: Address,
    e3_id: E3id,
    expected_stage: E3Stage,
) -> Result<MarkFailureOutcome> {
    let raw_e3_id: U256 = e3_id.clone().try_into()?;
    let contract = IInterfold::new(contract_address, provider.provider());
    let current_stage = contract.getE3Stage(raw_e3_id).call().await?;
    if current_stage != failure_stage_code(&expected_stage)? {
        return Ok(MarkFailureOutcome::StageAdvanced);
    }

    let condition = contract.checkFailureCondition(raw_e3_id).call().await?;
    if !condition.canFail {
        return Ok(MarkFailureOutcome::NotDue);
    }

    info!(e3_id = %e3_id, stage = ?expected_stage, "markE3Failed() after canonical deadline");
    let _nonce_guard = transaction_nonce_guard(&provider).await;
    let from_address = provider.provider().default_signer_address();
    let current_nonce = provider
        .provider()
        .get_transaction_count(from_address)
        .pending()
        .await?;
    let contract = IInterfold::new(contract_address, provider.provider());
    let builder = contract.markE3Failed(raw_e3_id).nonce(current_nonce);
    let pending = builder.send().await?;
    drop(_nonce_guard);
    let receipt = pending.get_receipt().await?;
    require_successful_receipt("mark E3 failed", &receipt)?;
    Ok(MarkFailureOutcome::Marked)
}

fn failure_stage_code(stage: &E3Stage) -> Result<u8> {
    match stage {
        E3Stage::Requested => Ok(1),
        E3Stage::CommitteeFinalized => Ok(2),
        E3Stage::KeyPublished => Ok(3),
        E3Stage::CiphertextReady => Ok(4),
        _ => anyhow::bail!("stage {stage:?} is not watched for failure"),
    }
}

pub(in crate::actors::interfold_sol_writer) async fn publish_plaintext_output<
    P: Provider + WalletProvider + Clone,
>(
    provider: EthProvider<P>,
    contract_address: Address,
    e3_id: E3id,
    decrypted_output: Vec<u8>,
    decryption_aggregator_proof: Option<&Proof>,
) -> Result<TransactionReceipt> {
    let e3_id: U256 = e3_id.try_into()?;

    // Admission has checked the final proof's canonical decryption domain.
    let proof = encode_zk_proof(decryption_aggregator_proof.ok_or_else(|| {
        anyhow::anyhow!("mandatory decryption aggregator proof payload missing")
    })?)?;

    send_tx_with_retry(
        "publishPlaintextOutput",
        &["CiphertextOutputNotPublished"],
        || {
            info!("publishPlaintextOutput() e3_id={:?}", e3_id);
            let decrypted_output = Bytes::from(decrypted_output.clone());
            let proof = proof.clone();
            let provider = provider.clone();

            async move {
                let _nonce_guard = transaction_nonce_guard(&provider).await;
                let from_address = provider.provider().default_signer_address();
                let current_nonce = provider
                    .provider()
                    .get_transaction_count(from_address)
                    .pending()
                    .await?;
                let contract = IInterfold::new(contract_address, provider.provider());
                let builder = contract
                    .publishPlaintextOutput(e3_id, decrypted_output, proof)
                    .nonce(current_nonce);
                let pending = builder.send().await?;
                drop(_nonce_guard);
                let receipt = pending.get_receipt().await?;
                require_successful_receipt("publish plaintext output", &receipt)?;
                Ok(receipt)
            }
        },
    )
    .await
}

/// What the chain says about publishing an E3's plaintext now.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::actors::interfold_sol_writer) enum PlaintextPublication {
    /// The E3 waits for its plaintext.
    Publish,
    /// The E3 ended, or its plaintext is on chain: stop retrying.
    Done,
    /// The provider does not show the ciphertext yet, for example a node behind the others: retry.
    NotYet,
}

/// Only an E3 that waits for its plaintext accepts one. Any node that computed a result submits
/// it, so a completed or failed E3 must end the retries instead of reverting forever. An earlier
/// stage is a provider that lags the history the result came from, so it must not end them.
pub(in crate::actors::interfold_sol_writer) fn plaintext_publication(
    stage: u8,
    plaintext_published: bool,
) -> PlaintextPublication {
    match stage {
        CIPHERTEXT_READY_STAGE if plaintext_published => PlaintextPublication::Done,
        CIPHERTEXT_READY_STAGE => PlaintextPublication::Publish,
        COMPLETE_STAGE | FAILED_STAGE => PlaintextPublication::Done,
        _ => PlaintextPublication::NotYet,
    }
}

pub(in crate::actors::interfold_sol_writer) async fn should_publish_plaintext<
    P: Provider + WalletProvider + Clone,
>(
    provider: EthProvider<P>,
    contract_address: Address,
    e3_id: E3id,
) -> Result<PlaintextPublication> {
    let e3_id: U256 = e3_id.try_into()?;
    let contract = IInterfold::new(contract_address, provider.provider());
    let stage = contract.getE3Stage(e3_id).call().await?;
    if stage != CIPHERTEXT_READY_STAGE {
        return Ok(plaintext_publication(stage, false));
    }
    let e3 = contract.getE3(e3_id).call().await?;
    Ok(plaintext_publication(stage, !e3.plaintextOutput.is_empty()))
}

/// `E3Stage.CiphertextReady`, `Complete` and `Failed` in the Interfold contract.
const CIPHERTEXT_READY_STAGE: u8 = 4;
const COMPLETE_STAGE: u8 = 5;
const FAILED_STAGE: u8 = 6;

#[cfg(test)]
mod plaintext_publication_tests {
    use super::*;
    use alloy::{
        network::EthereumWallet, providers::ProviderBuilder, signers::local::PrivateKeySigner,
        sol_types::SolValue, transports::mock::Asserter,
    };

    /// A provider behind the node that aggregated the plaintext still shows the E3 before
    /// CiphertextReady. The writer must retry, not drop the plaintext as already published.
    #[actix::test]
    async fn a_lagging_provider_retries_the_plaintext() -> Result<()> {
        let asserter = Asserter::new();
        asserter.push_success(&"0x1");
        let provider = EthProvider::new(
            ProviderBuilder::new()
                .wallet(EthereumWallet::from(PrivateKeySigner::random()))
                .connect_mocked_client(asserter.clone()),
        )
        .await?;
        for stage in 0..CIPHERTEXT_READY_STAGE {
            asserter.push_success(&Bytes::from(U256::from(stage).abi_encode()));
            assert_eq!(
                should_publish_plaintext(provider.clone(), Address::ZERO, E3id::new("7", 1))
                    .await?,
                PlaintextPublication::NotYet,
                "stage {stage}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_ciphertext_ready_e3_is_published_once() {
        assert_eq!(
            plaintext_publication(CIPHERTEXT_READY_STAGE, false),
            PlaintextPublication::Publish
        );
        assert_eq!(
            plaintext_publication(CIPHERTEXT_READY_STAGE, true),
            PlaintextPublication::Done
        );
    }

    #[test]
    fn an_ended_e3_stops_the_retries() {
        for stage in [COMPLETE_STAGE, FAILED_STAGE] {
            assert_eq!(
                plaintext_publication(stage, false),
                PlaintextPublication::Done
            );
        }
    }
}

pub(in crate::actors::interfold_sol_writer) async fn process_e3_failure<
    P: Provider + WalletProvider + Clone,
>(
    provider: EthProvider<P>,
    contract_address: Address,
    e3_id: E3id,
) -> Result<FailureSettlementOutcome> {
    let e3_id: U256 = e3_id.try_into()?;

    info!("processE3Failure() e3_id={:?}", e3_id);

    let contract = IInterfold::new(contract_address, provider.provider());
    let stage = contract.getE3Stage(e3_id).call().await?;
    match settlement_preflight(stage)? {
        SettlementPreflight::Pending => return Ok(FailureSettlementOutcome::Pending),
        SettlementPreflight::Completed => return Ok(FailureSettlementOutcome::Completed),
        SettlementPreflight::Ready => {}
    }

    // Simulate first, so that a settlement that is not open yet does not hold the nonce guard.
    if let Err(error) = contract.processE3Failure(e3_id).call().await {
        if failure_settlement_is_blocked(&error) {
            return Ok(FailureSettlementOutcome::Blocked);
        }
        return Err(error.into());
    }

    let _nonce_guard = transaction_nonce_guard(&provider).await;
    let from_address = provider.provider().default_signer_address();
    let current_nonce = provider
        .provider()
        .get_transaction_count(from_address)
        .pending()
        .await?;
    let builder = contract.processE3Failure(e3_id).nonce(current_nonce);
    let pending = builder.send().await?;
    drop(_nonce_guard);
    let receipt = pending.get_receipt().await?;
    require_successful_receipt("process E3 failure", &receipt)?;
    Ok(FailureSettlementOutcome::Submitted(Box::new(receipt)))
}

pub(in crate::actors::interfold_sol_writer) fn failure_settlement_error_is_terminal(
    error: &anyhow::Error,
) -> bool {
    reverted_with::<IInterfold::NoPaymentToRefund>(error)
}

/// Return true when the refund manager does not accept settlement for this E3 yet.
///
/// Only decoded revert data counts. Error text from an RPC or transport failure can contain the
/// selector bytes, and that text must not defer settlement.
fn failure_settlement_is_blocked(error: &alloy::contract::Error) -> bool {
    error
        .as_decoded_error::<IInterfold::SettlementBlocked>()
        .is_some()
}

/// Whether `error` is a contract call that reverted with the custom error `E`.
///
/// Only the structured revert data of the call counts. A selector that merely appears in an
/// error message, for example in an RPC quota error, does not.
fn reverted_with<E: SolError>(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<alloy::contract::Error>()
            .is_some_and(|error| error.as_decoded_error::<E>().is_some())
    })
}

#[cfg(test)]
mod tests {
    use super::{
        failure_settlement_error_is_terminal, failure_settlement_is_blocked, failure_stage_code,
        requested_failure_deadline, settlement_preflight, SettlementPreflight,
    };
    use crate::contracts::IInterfold;
    use alloy::sol_types::SolError;
    use alloy::transports::TransportError;
    use e3_events::E3Stage;

    /// Build the error that `eth_call` returns for a contract revert with this revert data.
    fn eth_call_revert(selector: [u8; 4], words: usize) -> alloy::contract::Error {
        let response = format!(
            r#"{{"code":3,"message":"execution reverted","data":"0x{}{}"}}"#,
            hex::encode(selector),
            "00".repeat(32 * words)
        );
        rpc_error(&response)
    }

    /// Build the contract error for this JSON-RPC error response.
    fn rpc_error(response: &str) -> alloy::contract::Error {
        let error = TransportError::ErrorResp(serde_json::from_str(response).unwrap());
        alloy::contract::Error::TransportError(error)
    }

    #[test]
    fn local_failure_cannot_start_chain_settlement() {
        assert_eq!(
            settlement_preflight(2).unwrap(),
            SettlementPreflight::Pending
        );
        assert_eq!(
            settlement_preflight(5).unwrap(),
            SettlementPreflight::Completed
        );
        assert_eq!(settlement_preflight(6).unwrap(), SettlementPreflight::Ready);
    }

    #[test]
    fn all_contract_failure_stages_are_watched() {
        assert_eq!(failure_stage_code(&E3Stage::Requested).unwrap(), 1);
        assert_eq!(failure_stage_code(&E3Stage::CommitteeFinalized).unwrap(), 2);
        assert_eq!(failure_stage_code(&E3Stage::KeyPublished).unwrap(), 3);
        assert_eq!(failure_stage_code(&E3Stage::CiphertextReady).unwrap(), 4);
        assert!(failure_stage_code(&E3Stage::Complete).is_err());
    }

    #[test]
    fn requested_stage_uses_the_registry_deadline_and_frozen_dkg_window() {
        assert_eq!(requested_failure_deadline(100, false, 50).unwrap(), 100);
        assert_eq!(requested_failure_deadline(100, true, 50).unwrap(), 150);
        assert!(requested_failure_deadline(u64::MAX, true, 1).is_err());
    }

    #[test]
    fn settled_failure_stops_retries() {
        let error: anyhow::Error =
            eth_call_revert(IInterfold::NoPaymentToRefund::SELECTOR, 1).into();
        assert!(failure_settlement_error_is_terminal(&error));
        assert!(failure_settlement_error_is_terminal(
            &error.context("process E3 failure")
        ));
        assert!(!failure_settlement_error_is_terminal(&anyhow::anyhow!(
            "RPC connection reset"
        )));
    }

    /// A `NoPaymentToRefund` selector in the text of an error that is not a revert must not stop
    /// the retries.
    #[test]
    fn a_selector_in_an_error_message_is_not_a_revert() {
        let message = anyhow::anyhow!(
            "RPC rate limited; request tag 0x{}{}",
            hex::encode(IInterfold::NoPaymentToRefund::SELECTOR),
            "00".repeat(32)
        );
        assert!(!failure_settlement_error_is_terminal(&message));
    }

    #[test]
    fn settlement_simulation_separates_blocked_settled_and_other_reverts() {
        let blocked = eth_call_revert(IInterfold::SettlementBlocked::SELECTOR, 0);
        assert!(failure_settlement_is_blocked(&blocked));
        assert!(!failure_settlement_error_is_terminal(&blocked.into()));

        let settled = eth_call_revert(IInterfold::NoPaymentToRefund::SELECTOR, 1);
        assert!(!failure_settlement_is_blocked(&settled));
        assert!(failure_settlement_error_is_terminal(&settled.into()));

        let other = eth_call_revert(IInterfold::E3NotFailed::SELECTOR, 1);
        assert!(!failure_settlement_is_blocked(&other));
        assert!(!failure_settlement_error_is_terminal(&other.into()));

        assert!(!failure_settlement_error_is_terminal(&anyhow::anyhow!(
            "RPC connection reset"
        )));
    }

    #[test]
    fn selector_text_outside_revert_data_does_not_block_settlement() {
        // The selector is only in the message of an error that is not a revert.
        let message = rpc_error(r#"{"code":-32000,"message":"upstream failure 0xf51125bb"}"#);
        assert!(!failure_settlement_is_blocked(&message));

        // The data field has the selector, but the node does not report a revert.
        let data = rpc_error(r#"{"code":-32005,"message":"rate limited","data":"0xf51125bb"}"#);
        assert!(!failure_settlement_is_blocked(&data));
    }

    #[test]
    fn settlement_blocked_uses_the_refund_manager_selector() {
        assert_eq!(
            IInterfold::SettlementBlocked::SELECTOR,
            [0xf5, 0x11, 0x25, 0xbb]
        );
    }
}
