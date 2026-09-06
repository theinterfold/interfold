// SPDX-License-Identifier: LGPL-3.0-only

//! Idempotency preflights and CiphernodeRegistry contract effects.

use super::*;

const TICKET_GAS_SAFETY_MULTIPLIER: u64 = 2;

fn ticket_gas_limit(estimate: u64) -> u64 {
    estimate.saturating_mul(TICKET_GAS_SAFETY_MULTIPLIER)
}

/// Report whether a contract call contains this exact parameterless custom error.
fn reverts_with(error: &anyhow::Error, selector: [u8; 4]) -> bool {
    contains_error_selector(&format!("{error:?}"), selector)
}

pub async fn submit_ticket_to_registry<P: Provider + WalletProvider + Clone + 'static>(
    provider: EthProvider<P>,
    contract_address: Address,
    e3_id: E3id,
    ticket_number: u64,
) -> Result<TxOutcome> {
    let e3_id_u256: U256 = e3_id.try_into()?;
    let ticket_number_u256 = U256::from(ticket_number);

    let settled_provider = provider.clone();
    let settled = || async move {
        ticket_submission_settled(
            settled_provider,
            contract_address,
            e3_id_u256,
            ticket_number_u256,
        )
        .await
    };

    send_tx_idempotent("submitTicket", &["CommitteeNotRequested"], settled, || {
        let provider = provider.clone();
        async move {
            info!("Calling: contract.submitTicket(..)");
            let _nonce_guard = transaction_nonce_guard(&provider).await;
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
            // Nodes estimate concurrently before any ticket is mined. Earlier
            // insertions can make a later top-N update more expensive than its
            // estimate, so leave room for the request state to change.
            let estimated_gas = builder.estimate_gas().await?;
            let gas_limit = ticket_gas_limit(estimated_gas);
            debug!(
                estimated_gas,
                gas_limit, "Applying submitTicket gas safety margin"
            );
            let pending = builder.gas(gas_limit).send().await?;
            drop(_nonce_guard);
            let receipt = pending.get_receipt().await?;
            require_successful_receipt("submit ticket", &receipt)?;
            Ok(receipt)
        }
    })
    .await
}

/// Return true when retrying the same ticket can no longer change chain state.
pub(in crate::actors::ciphernode_registry_sol) fn ticket_submission_error_is_terminal(
    error: &anyhow::Error,
) -> bool {
    [
        ICiphernodeRegistry::CommitteeAlreadyFinalized::SELECTOR,
        ICiphernodeRegistry::CommitteeDeadlineReached::SELECTOR,
        ICiphernodeRegistry::InvalidTicketNumber::SELECTOR,
        ICiphernodeRegistry::NodeNotEligible::SELECTOR,
    ]
    .into_iter()
    .any(|selector| reverts_with(error, selector))
}

/// Report whether this node's ticket is already recorded on chain.
///
/// `submitTicket` reverts with `NodeAlreadySubmitted` for a sender that is
/// already in the submission set, so a retry that duplicates a mined
/// submission needs no further attempt.
async fn ticket_submission_settled<P: Provider + WalletProvider + Clone + 'static>(
    provider: EthProvider<P>,
    contract_address: Address,
    e3_id_u256: U256,
    ticket_number_u256: U256,
) -> Result<bool> {
    let from_address = provider.provider().default_signer_address();
    let contract = ICiphernodeRegistry::new(contract_address, provider.provider());
    match contract
        .submitTicket(e3_id_u256, ticket_number_u256)
        .from(from_address)
        .call()
        .await
    {
        Ok(_) => Ok(false),
        Err(err) => Ok(reverts_with(
            &anyhow::Error::from(err),
            ICiphernodeRegistry::NodeAlreadySubmitted::SELECTOR,
        )),
    }
}

/// Report whether committee finalization reached a terminal chain state.
///
/// Both `Finalized` and `Failed` reject another attempt with
/// `CommitteeAlreadyFinalized`. Neither state permits useful retry work.
async fn committee_finalization_terminal<P: Provider + WalletProvider + Clone + 'static>(
    provider: EthProvider<P>,
    contract_address: Address,
    e3_id_u256: U256,
) -> Result<bool> {
    let contract = ICiphernodeRegistry::new(contract_address, provider.provider());
    let Err(err) = contract.finalizeCommittee(e3_id_u256).call().await else {
        return Ok(false);
    };

    Ok(reverts_with(
        &anyhow::Error::from(err),
        ICiphernodeRegistry::CommitteeAlreadyFinalized::SELECTOR,
    ))
}

pub async fn finalize_committee_on_registry<P: Provider + WalletProvider + Clone + 'static>(
    provider: EthProvider<P>,
    contract_address: Address,
    e3_id: E3id,
) -> Result<TxOutcome> {
    let e3_id_u256: U256 = e3_id.clone().try_into()?;

    // Members finalize on a stagger. Another member can finalize between the
    // stagger tick and this call, so read the chain first. Without this check
    // the transaction is mined with a failed receipt and burns gas.
    if committee_finalization_terminal(provider.clone(), contract_address, e3_id_u256).await? {
        info!(e3_id = %e3_id, "Committee already finalized on chain; skipping finalizeCommittee");
        return Ok(TxOutcome::AlreadySettled);
    }

    let settled_provider = provider.clone();
    let settled = || async move {
        committee_finalization_terminal(settled_provider, contract_address, e3_id_u256).await
    };

    send_tx_idempotent(
        "finalizeCommittee",
        &[
            "SubmissionWindowNotClosed",
            "CommitteeNotRequested",
            "ThresholdNotMet",
        ],
        settled,
        || {
            let provider = provider.clone();
            async move {
                info!("Calling: contract.finalizeCommittee(..)");
                let _nonce_guard = transaction_nonce_guard(&provider).await;
                let from_address = provider.provider().default_signer_address();
                let current_nonce = provider
                    .provider()
                    .get_transaction_count(from_address)
                    .pending()
                    .await?;
                let contract = ICiphernodeRegistry::new(contract_address, provider.provider());
                let builder = contract.finalizeCommittee(e3_id_u256).nonce(current_nonce);
                let pending = builder.send().await?;
                drop(_nonce_guard);
                let receipt = pending.get_receipt().await?;
                require_successful_receipt("finalize committee", &receipt)?;
                Ok(receipt)
            }
        },
    )
    .await
}

pub(in crate::actors::ciphernode_registry_sol) async fn should_publish_committee<
    P: Provider + WalletProvider + Clone + 'static,
>(
    provider: EthProvider<P>,
    contract_address: Address,
    e3_id: E3id,
    expected_commitment: [u8; 32],
) -> Result<bool> {
    let e3_id_u256: U256 = e3_id.try_into()?;
    let contract = ICiphernodeRegistry::new(contract_address, provider.provider());
    match contract.committeePublicKey(e3_id_u256).call().await {
        Ok(commitment) => {
            let expected = B256::from(expected_commitment);
            if commitment != expected {
                anyhow::bail!(
                    "on-chain committee commitment {commitment} does not match local commitment {expected}"
                );
            }
            Ok(false)
        }
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
    pk_commitment: [u8; 32],
    dkg_aggregator_proof: Option<&Proof>,
    dkg_attestation_bundle: Option<&[u8]>,
    ckks_pk_proof_blob: Option<&[u8]>,
) -> Result<TxOutcome> {
    let e3_id_u256: U256 = e3_id.clone().try_into()?;
    let pk_commitment_b256 = B256::from(pk_commitment);

    // CKKS supplies a pre-encoded per-party blob for `CkksPkVerifier` (no
    // recursive pk-aggregation circuit exists, so there is no single proof to
    // encode). BFV keeps the folded `dkg_aggregator_proof` path. Either way an
    // absent payload is an internal error — never publish an empty blob.
    let proof =
        match ckks_pk_proof_blob {
            Some(blob) if !blob.is_empty() => Bytes::copy_from_slice(blob),
            Some(_) => anyhow::bail!("CKKS pk proof blob is present but empty"),
            None => encode_zk_proof(dkg_aggregator_proof.ok_or_else(|| {
                anyhow::anyhow!("mandatory DKG aggregator proof payload missing")
            })?)?,
        };
    let attestation_bundle = Bytes::copy_from_slice(
        dkg_attestation_bundle
            .filter(|bundle| !bundle.is_empty())
            .ok_or_else(|| anyhow::anyhow!("mandatory DKG attestation bundle missing"))?,
    );

    // The published commitment must equal ours, which `should_publish_committee`
    // enforces. A different commitment stays an error.
    let settled_provider = provider.clone();
    let settled = || async move {
        should_publish_committee(settled_provider, contract_address, e3_id, pk_commitment)
            .await
            .map(|should_publish| !should_publish)
    };

    // RPC may not have synced finalization yet
    send_tx_idempotent(
        "publishCommittee",
        &["CommitteeNotFinalized"],
        settled,
        || {
            let provider = provider.clone();
            let proof = proof.clone();
            let attestation_bundle = attestation_bundle.clone();
            async move {
                info!("Calling: contract.publishCommittee(..)");
                let _nonce_guard = transaction_nonce_guard(&provider).await;
                let from_address = provider.provider().default_signer_address();
                let current_nonce = provider
                    .provider()
                    .get_transaction_count(from_address)
                    .pending()
                    .await?;
                let contract = ICiphernodeRegistry::new(contract_address, provider.provider());
                let builder = contract
                    .publishCommittee(e3_id_u256, pk_commitment_b256, proof, attestation_bundle)
                    .nonce(current_nonce);
                let pending = builder.send().await?;
                drop(_nonce_guard);
                let receipt = pending.get_receipt().await?;
                require_successful_receipt("publish committee", &receipt)?;
                Ok(receipt)
            }
        },
    )
    .await
}

pub async fn publish_committee_public_key_to_registry<
    P: Provider + WalletProvider + Clone + 'static,
>(
    provider: EthProvider<P>,
    contract_address: Address,
    e3_id: E3id,
    public_key: ArcBytes,
) -> Result<TransactionReceipt> {
    let e3_id_u256: U256 = e3_id.try_into()?;
    let public_key_bytes = Bytes::from(public_key.extract_bytes());

    send_tx_with_retry(
        "publishCommitteePublicKey",
        &["CommitteeNotPublished"],
        || {
            let provider = provider.clone();
            let public_key_bytes = public_key_bytes.clone();
            async move {
                info!("Calling: contract.publishCommitteePublicKey(..)");
                let _nonce_guard = transaction_nonce_guard(&provider).await;
                let from_address = provider.provider().default_signer_address();
                let current_nonce = provider
                    .provider()
                    .get_transaction_count(from_address)
                    .pending()
                    .await?;
                let contract = ICiphernodeRegistry::new(contract_address, provider.provider());
                let builder = contract
                    .publishCommitteePublicKey(e3_id_u256, public_key_bytes)
                    .nonce(current_nonce);
                let pending = builder.send().await?;
                drop(_nonce_guard);
                let receipt = pending.get_receipt().await?;
                require_successful_receipt("publish committee public key", &receipt)?;
                Ok(receipt)
            }
        },
    )
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

/// Reads the provider used for future committee randomness requests.
pub async fn fetch_randomness_provider<P: Provider + Clone>(
    provider: &P,
    registry_address: Address,
) -> Result<Option<Address>> {
    let contract = ICiphernodeRegistry::new(registry_address, provider);
    let randomness_provider = contract.randomnessProvider().call().await?;
    if randomness_provider == Address::ZERO {
        Ok(None)
    } else {
        Ok(Some(randomness_provider))
    }
}

/// Reads every provider needed to replay committee randomness history.
pub async fn fetch_randomness_providers<P: Provider + Clone>(
    provider: &P,
    registry_address: Address,
    from_block: u64,
) -> Result<Vec<Address>> {
    const LOG_CHUNK_SIZE: u64 = 10_000;
    let base_filter = Filter::new()
        .address(registry_address)
        .event_signature(ICiphernodeRegistry::RandomnessProviderSet::SIGNATURE_HASH);
    let mut providers = Vec::new();
    let mut seen = HashSet::new();
    let head = provider.get_block_number().await?;
    let mut start = from_block;
    while start <= head {
        let end = start.saturating_add(LOG_CHUNK_SIZE - 1).min(head);
        let filter = base_filter.clone().from_block(start).to_block(end);
        for log in provider.get_logs(&filter).await? {
            let event = ICiphernodeRegistry::RandomnessProviderSet::decode_log_data(log.data())
                .context("invalid RandomnessProviderSet event")?;
            if event.randomnessProvider != Address::ZERO && seen.insert(event.randomnessProvider) {
                providers.push(event.randomnessProvider);
            }
        }
        if end == head {
            break;
        }
        start = end + 1;
    }

    if let Some(current) = fetch_randomness_provider(provider, registry_address).await? {
        if seen.insert(current) {
            providers.push(current);
        }
    }
    Ok(providers)
}

#[cfg(test)]
mod tests {
    use super::{reverts_with, ticket_gas_limit, ticket_submission_error_is_terminal};
    use crate::contracts::ICiphernodeRegistry;
    use alloy::sol_types::{Revert, SolError};

    fn selector_error(selector: [u8; 4]) -> anyhow::Error {
        anyhow::anyhow!(
            "RPC request failed with revert data 0x{}",
            hex::encode(selector)
        )
    }

    #[test]
    fn ticket_retry_stops_only_for_permanent_contract_outcomes() {
        for selector in [
            ICiphernodeRegistry::CommitteeAlreadyFinalized::SELECTOR,
            ICiphernodeRegistry::CommitteeDeadlineReached::SELECTOR,
            ICiphernodeRegistry::InvalidTicketNumber::SELECTOR,
            ICiphernodeRegistry::NodeNotEligible::SELECTOR,
        ] {
            assert!(ticket_submission_error_is_terminal(&selector_error(
                selector
            )));
        }

        assert!(!ticket_submission_error_is_terminal(&anyhow::anyhow!(
            "RPC connection reset while decoding CommitteeDeadlineReached"
        )));

        let string_revert = Revert::from("CommitteeDeadlineReached").abi_encode();
        assert!(!ticket_submission_error_is_terminal(&anyhow::anyhow!(
            "revert data 0x{}",
            hex::encode(string_revert)
        )));
    }

    #[test]
    fn committee_finalization_terminal_requires_the_exact_custom_error() {
        let selector = ICiphernodeRegistry::CommitteeAlreadyFinalized::SELECTOR;
        assert!(reverts_with(&selector_error(selector), selector));
        assert!(!reverts_with(
            &anyhow::anyhow!("CommitteeAlreadyFinalized"),
            selector
        ));
    }

    #[test]
    fn doubles_ticket_gas_estimate_without_overflow() {
        assert_eq!(ticket_gas_limit(250_000), 500_000);
        assert_eq!(ticket_gas_limit(u64::MAX), u64::MAX);
    }
}
