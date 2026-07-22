// SPDX-License-Identifier: LGPL-3.0-only

//! SlashingManager contract effects.

use super::*;

pub(in crate::actors::slashing_manager_sol_writer) async fn submit_slash_proposal<
    P: Provider + WalletProvider + Clone,
>(
    provider: EthProvider<P>,
    contract_address: Address,
    data: AccusationQuorumReached,
    outbox: &EvmEffectOutbox<AccusationQuorumReached>,
    outbox_key: &str,
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
        let outbox = outbox.clone();
        let outbox_key = outbox_key.to_owned();

        async move {
            let contract = ISlashingManager::new(contract_address, provider.provider());
            let request = if let Some(pid) = party_id {
                contract
                    .proposeSlashByDkgParty(e3_id, pid, proof)
                    .into_transaction_request()
            } else {
                contract
                    .proposeSlash(e3_id, operator, proof)
                    .into_transaction_request()
            };
            let pending =
                crate::send_prepared_transaction(&provider, request, &outbox, &outbox_key).await?;
            let receipt = pending.get_receipt().await?;
            require_successful_receipt("submit slashing evidence", &receipt)?;
            Ok(receipt)
        }
    })
    .await
}

pub(in crate::actors::slashing_manager_sol_writer) async fn should_submit_slash_proposal<
    P: Provider + WalletProvider + Clone,
>(
    provider: EthProvider<P>,
    contract_address: Address,
    data: AccusationQuorumReached,
) -> Result<bool> {
    let e3_id: U256 = data.e3_id.clone().try_into()?;
    let operator = data.accused;
    let proof =
        Bytes::from(encode_attestation_evidence(&data).ok_or_else(|| {
            anyhow::anyhow!("AccusationQuorumReached has empty votes or evidence")
        })?);
    let party_id =
        resolve_party_id_for_operator(provider.clone(), contract_address, e3_id, operator)
            .await
            .ok()
            .flatten();
    let contract = ISlashingManager::new(contract_address, provider.provider());
    let result = if let Some(party_id) = party_id {
        contract
            .proposeSlashByDkgParty(e3_id, party_id, proof)
            .call()
            .await
    } else {
        contract.proposeSlash(e3_id, operator, proof).call().await
    };

    match result {
        Ok(_) => Ok(true),
        Err(error) => {
            let error = anyhow::Error::from(error);
            let decoded = decode_error_from_str(&format!("{error:?}"));
            if decoded.as_deref().is_some_and(|message| {
                message.contains("DuplicateEvidence")
                    || message.contains("OperatorNotInCommittee")
                    || message.contains("VoterNotInCommittee")
            }) {
                return Ok(false);
            }
            Err(error)
        }
    }
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
