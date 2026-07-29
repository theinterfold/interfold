// SPDX-License-Identifier: LGPL-3.0-only

//! Idempotency preflights and CiphernodeRegistry contract effects.

use super::*;

pub(in crate::actors::ciphernode_registry_sol) async fn submit_ticket_to_registry<
    P: Provider + WalletProvider + Clone + 'static,
>(
    provider: EthProvider<P>,
    contract_address: Address,
    e3_id: E3id,
    ticket_number: u64,
    outbox: &EvmEffectOutbox<RegistryEffect>,
    outbox_key: &str,
) -> Result<TransactionReceipt> {
    let e3_id_u256: U256 = e3_id.try_into()?;
    let ticket_number_u256 = U256::from(ticket_number);

    send_tx_with_retry("submitTicket", &["CommitteeNotRequested"], || {
        let provider = provider.clone();
        let outbox = outbox.clone();
        let outbox_key = outbox_key.to_owned();
        async move {
            info!("Calling: contract.submitTicket(..)");
            let contract = ICiphernodeRegistry::new(contract_address, provider.provider());
            let request = contract
                .submitTicket(e3_id_u256, ticket_number_u256)
                .into_transaction_request();
            let pending =
                crate::send_prepared_transaction(&provider, request, &outbox, &outbox_key).await?;
            let receipt = pending.get_receipt().await?;
            require_successful_receipt("submit ticket", &receipt)?;
            Ok(receipt)
        }
    })
    .await
}

pub(in crate::actors::ciphernode_registry_sol) async fn finalize_committee_on_registry<
    P: Provider + WalletProvider + Clone + 'static,
>(
    provider: EthProvider<P>,
    contract_address: Address,
    e3_id: E3id,
    outbox: &EvmEffectOutbox<RegistryEffect>,
    outbox_key: &str,
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
            let outbox = outbox.clone();
            let outbox_key = outbox_key.to_owned();
            async move {
                info!("Calling: contract.finalizeCommittee(..)");
                let contract = ICiphernodeRegistry::new(contract_address, provider.provider());
                let request = contract
                    .finalizeCommittee(e3_id_u256)
                    .into_transaction_request();
                let pending =
                    crate::send_prepared_transaction(&provider, request, &outbox, &outbox_key)
                        .await?;
                let receipt = pending.get_receipt().await?;
                require_successful_receipt("finalize committee", &receipt)?;
                Ok(receipt)
            }
        },
    )
    .await
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::actors::ciphernode_registry_sol) enum FinalizeCommitteePreflight {
    Submit,
    Retry,
    Terminal,
}

pub(in crate::actors::ciphernode_registry_sol) async fn should_finalize_committee<
    P: Provider + WalletProvider + Clone + 'static,
>(
    provider: EthProvider<P>,
    contract_address: Address,
    e3_id: E3id,
) -> Result<FinalizeCommitteePreflight> {
    let e3_id_u256: U256 = e3_id.try_into()?;
    let contract = ICiphernodeRegistry::new(contract_address, provider.provider());
    if contract.isOpen(e3_id_u256).call().await? {
        return Ok(FinalizeCommitteePreflight::Retry);
    }

    match contract.finalizeCommittee(e3_id_u256).call().await {
        Ok(_) => Ok(FinalizeCommitteePreflight::Submit),
        Err(err) => {
            let err = anyhow::Error::from(err);
            let decoded = decode_error_from_str(&format!("{err:?}"));

            if decoded
                .as_deref()
                .is_some_and(|message| message.contains("CommitteeAlreadyFinalized"))
            {
                return Ok(FinalizeCommitteePreflight::Terminal);
            }
            if decoded.as_deref().is_some_and(|message| {
                message.contains("CommitteeNotRequested")
                    || message.contains("SubmissionWindowNotClosed")
            }) {
                return Ok(FinalizeCommitteePreflight::Retry);
            }

            Err(err)
        }
    }
}

pub(in crate::actors::ciphernode_registry_sol) async fn should_submit_ticket<
    P: Provider + WalletProvider + Clone + 'static,
>(
    provider: EthProvider<P>,
    contract_address: Address,
    e3_id: E3id,
    ticket_number: u64,
) -> Result<bool> {
    let e3_id_u256: U256 = e3_id.try_into()?;
    let contract = ICiphernodeRegistry::new(contract_address, provider.provider());
    match contract
        .submitTicket(e3_id_u256, U256::from(ticket_number))
        .call()
        .await
    {
        Ok(_) => Ok(true),
        Err(err) => {
            let err = anyhow::Error::from(err);
            let decoded = decode_error_from_str(&format!("{err:?}"));
            if decoded.as_deref().is_some_and(|message| {
                message.contains("NodeAlreadySubmitted")
                    || message.contains("CommitteeAlreadyFinalized")
                    || message.contains("CommitteeDeadlineReached")
            }) {
                return Ok(false);
            }
            Err(err)
        }
    }
}

pub(in crate::actors::ciphernode_registry_sol) async fn should_publish_committee<
    P: Provider + WalletProvider + Clone + 'static,
>(
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

pub(in crate::actors::ciphernode_registry_sol) async fn publish_committee_to_registry<
    P: Provider + WalletProvider + Clone + 'static,
>(
    provider: EthProvider<P>,
    contract_address: Address,
    event: PublicKeyAggregated,
    outbox: &EvmEffectOutbox<RegistryEffect>,
    outbox_key: &str,
) -> Result<TransactionReceipt> {
    let PublicKeyAggregated {
        e3_id,
        pubkey: public_key,
        pk_commitment,
        dkg_aggregator_proof,
        dkg_attestation_bundle,
        ..
    } = event;
    let e3_id_u256: U256 = e3_id.try_into()?;
    let public_key_bytes = Bytes::from(public_key.extract_bytes());
    let pk_commitment_b256 = B256::from(pk_commitment);

    // Skip mode creates non-empty mock-only placeholders before this boundary. An absent payload
    // is therefore always an internal error, while production verifiers still reject placeholders.
    let proof = encode_zk_proof(
        dkg_aggregator_proof
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("mandatory DKG aggregator proof payload missing"))?,
    )?;
    let attestation_bundle = Bytes::copy_from_slice(
        dkg_attestation_bundle
            .as_deref()
            .filter(|bundle| !bundle.is_empty())
            .ok_or_else(|| anyhow::anyhow!("mandatory DKG attestation bundle missing"))?,
    );

    // RPC may not have synced finalization yet
    send_tx_with_retry("publishCommittee", &["CommitteeNotFinalized"], || {
        let provider = provider.clone();
        let public_key_bytes = public_key_bytes.clone();
        let proof = proof.clone();
        let attestation_bundle = attestation_bundle.clone();
        let outbox = outbox.clone();
        let outbox_key = outbox_key.to_owned();
        async move {
            info!("Calling: contract.publishCommittee(..)");
            let contract = ICiphernodeRegistry::new(contract_address, provider.provider());
            let request = contract
                .publishCommittee(
                    e3_id_u256,
                    public_key_bytes,
                    pk_commitment_b256,
                    proof,
                    attestation_bundle,
                )
                .into_transaction_request();
            let pending =
                crate::send_prepared_transaction(&provider, request, &outbox, &outbox_key).await?;
            let receipt = pending.get_receipt().await?;
            require_successful_receipt("publish committee", &receipt)?;
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
