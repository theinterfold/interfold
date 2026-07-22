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
    outbox: &EvmEffectOutbox<InterfoldEffect>,
    outbox_key: &str,
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
            let outbox = outbox.clone();
            let outbox_key = outbox_key.to_owned();

            async move {
                let contract = IInterfold::new(contract_address, provider.provider());
                let request = contract
                    .publishPlaintextOutput(e3_id, decrypted_output, proof)
                    .into_transaction_request();
                let pending =
                    crate::send_prepared_transaction(&provider, request, &outbox, &outbox_key)
                        .await?;
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
    outbox: &EvmEffectOutbox<InterfoldEffect>,
    outbox_key: &str,
) -> Result<TransactionReceipt> {
    let e3_id: U256 = e3_id.try_into()?;

    info!("processE3Failure() e3_id={:?}", e3_id);

    let contract = IInterfold::new(contract_address, provider.provider());
    let request = contract.processE3Failure(e3_id).into_transaction_request();
    let pending = crate::send_prepared_transaction(&provider, request, outbox, outbox_key).await?;
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
        Err(error) => {
            let error = anyhow::Error::from(error);
            let decoded = decode_error_from_str(&format!("{error:?}"));
            if decoded
                .as_deref()
                .is_some_and(|message| message.contains("NoPaymentToRefund"))
            {
                return Ok(false);
            }
            Err(error)
        }
    }
}
