// SPDX-License-Identifier: LGPL-3.0-only

//! Interfold contract reads and transaction effects.

use super::*;

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

pub(in crate::actors::interfold_sol_writer) async fn should_process_e3_failure<
    P: Provider + WalletProvider + Clone,
>(
    provider: EthProvider<P>,
    contract_address: Address,
    e3_id: E3id,
) -> Result<bool> {
    let e3_id: U256 = e3_id.try_into()?;
    let contract = IInterfold::new(contract_address, provider.provider());
    match contract.processE3Failure(e3_id).call().await {
        Ok(_) => Ok(true),
        Err(err) => {
            let err = anyhow::Error::from(err);
            let decoded = crate::domain::error_decoder::decode_error_from_str(&format!("{err:?}"));
            if decoded.as_deref().is_some_and(failure_retry_is_terminal) {
                return Ok(false);
            }
            Err(err)
        }
    }
}

fn failure_retry_is_terminal(message: &str) -> bool {
    message.contains("NoPaymentToRefund")
}

#[cfg(test)]
mod tests {
    use super::failure_retry_is_terminal;

    #[test]
    fn failure_preflight_only_suppresses_an_already_processed_refund() {
        assert!(failure_retry_is_terminal("NoPaymentToRefund(7)"));
        assert!(!failure_retry_is_terminal("E3NotFailed(7)"));
        assert!(!failure_retry_is_terminal("RpcTransportError"));
    }
}
