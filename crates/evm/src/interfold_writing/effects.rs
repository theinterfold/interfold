// SPDX-License-Identifier: LGPL-3.0-only

//! Interfold contract reads and transaction effects.

use super::*;
use alloy::sol_types::SolError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::actors::interfold_sol_writer) enum MarkFailureOutcome {
    Marked,
    NotDue,
    StageAdvanced,
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

    // Skip mode creates a non-empty mock-only C7 placeholder before this boundary.
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

pub(in crate::actors::interfold_sol_writer) async fn should_publish_plaintext<
    P: Provider + WalletProvider + Clone,
>(
    provider: EthProvider<P>,
    contract_address: Address,
    e3_id: E3id,
) -> Result<bool> {
    let e3_id: U256 = e3_id.try_into()?;
    let contract = IInterfold::new(contract_address, provider.provider());
    let e3 = contract.getE3(e3_id).call().await?;
    Ok(e3.plaintextOutput.is_empty())
}

pub(in crate::actors::interfold_sol_writer) async fn process_e3_failure<
    P: Provider + WalletProvider + Clone,
>(
    provider: EthProvider<P>,
    contract_address: Address,
    e3_id: E3id,
) -> Result<TransactionReceipt> {
    let e3_id: U256 = e3_id.try_into()?;

    info!("processE3Failure() e3_id={:?}", e3_id);

    let _nonce_guard = transaction_nonce_guard(&provider).await;
    let from_address = provider.provider().default_signer_address();
    let current_nonce = provider
        .provider()
        .get_transaction_count(from_address)
        .pending()
        .await?;
    let contract = IInterfold::new(contract_address, provider.provider());
    let builder = contract.processE3Failure(e3_id).nonce(current_nonce);
    let pending = builder.send().await?;
    drop(_nonce_guard);
    let receipt = pending.get_receipt().await?;
    require_successful_receipt("process E3 failure", &receipt)?;
    Ok(receipt)
}

pub(in crate::actors::interfold_sol_writer) fn failure_settlement_error_is_terminal(
    error: &anyhow::Error,
) -> bool {
    contains_error_selector(
        &format!("{error:?}"),
        IInterfold::NoPaymentToRefund::SELECTOR,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        failure_settlement_error_is_terminal, failure_stage_code, requested_failure_deadline,
    };
    use crate::contracts::IInterfold;
    use alloy::sol_types::SolError;
    use e3_events::E3Stage;

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
        let error = anyhow::anyhow!(
            "execution reverted: 0x{}{}",
            hex::encode(IInterfold::NoPaymentToRefund::SELECTOR),
            "00".repeat(32)
        );
        assert!(failure_settlement_error_is_terminal(&error));
        assert!(!failure_settlement_error_is_terminal(&anyhow::anyhow!(
            "RPC connection reset"
        )));
    }
}
