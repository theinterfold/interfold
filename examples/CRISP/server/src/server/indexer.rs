// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::server::token_holders::{get_mock_token_holders, EtherscanClient};
use crate::server::{
    models::{CreditMode, CurrentRound, CustomParams},
    program_server_request::run_compute,
    repo::{CrispE3Repository, CurrentRoundRepository},
    token_holders::{build_tree, compute_token_holder_hashes},
    CONFIG,
};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::sol_types::{sol_data, SolType};
use alloy_primitives::{Address, U256};
use crisp_utils::decode_tally;
use e3_sdk::{
    evm_helpers::{
        contracts::{InterfoldRead, ReadWrite},
        events::{
            CiphertextOutputPublished, CommitteePublished, E3Requested, PlaintextOutputPublished,
        },
        retry::call_with_retry,
    },
    indexer::{DataStore, InterfoldIndexer, SharedStore},
};
use evm_helpers::{CRISPContractFactory, InputPublished};
use eyre::Context;
use log::{info, warn};
use num_bigint::BigUint;
use std::error::Error;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

pub async fn register_e3_requested(
    indexer: InterfoldIndexer<impl DataStore, ReadWrite>,
) -> Result<InterfoldIndexer<impl DataStore, ReadWrite>> {
    // E3Requested
    indexer
        .add_event_handler(move |event: E3Requested, ctx| {
            let store = ctx.store();
            let e3_id = event.e3Id.to::<u64>();
            let mut repo = CrispE3Repository::new(store.clone(), e3_id);

            let contract = ctx.contract();

            info!("[e3_id={}] E3Requested: {:?}", e3_id, event);

            async move {
                // 0xcd6f4a4f = E3DoesNotExist()
                let e3 = call_with_retry("get_e3", &["0xcd6f4a4f"], || {
                    let contract = contract.clone();
                    let event_e3_id = event.e3Id;
                    async move {
                        contract
                            .get_e3(event_e3_id)
                            .await
                            .map_err(|e| anyhow::anyhow!("{}", e))
                    }
                })
                .await
                .map_err(|e| eyre::eyre!("{}", e))?;

                // Use sol_data types instead of primitives
                type CustomParamsTuple = (sol_data::Address, sol_data::Uint<256>, sol_data::Uint<256>, sol_data::Uint<256>, sol_data::Uint<256>);

                let decoded = <CustomParamsTuple as SolType>::abi_decode(&event.e3.customParams)
                    .with_context(|| "Failed to decode custom params from E3 event")?;

                let credit_mode = CreditMode::try_from(decoded.3.to::<u64>())?;
                let credits = match credit_mode {
                    CreditMode::Constant => {
                        info!("[e3_id={}] Credit mode: Constant", e3_id);
                        Some(decoded.4.to_string())
                    }
                    CreditMode::Custom => {
                        info!("[e3_id={}] Credit mode: Custom", e3_id);
                        None
                    }
                };

                let credits_clone = credits.clone();

                let custom_params = CustomParams {
                    token_address: decoded.0.to_string(),
                    balance_threshold: decoded.1.to_string(),
                    num_options: decoded.2.to_string(),
                    credit_mode,
                    credits,
                };

                let balance_threshold =
                    BigUint::parse_bytes(custom_params.balance_threshold.as_bytes(), 10)
                        .ok_or_else(|| eyre::eyre!("Invalid balance threshold"))?;
                let token_address: Address = custom_params
                    .token_address
                    .parse()
                    .with_context(|| "Invalid token address")?;

                let input_window = [e3.inputWindow[0].to::<u64>(), e3.inputWindow[1].to::<u64>()];

                // Get token holders from Etherscan API or mocked data.
                let token_holders = if matches!(CONFIG.chain_id, 31337 | 1337) {
                    info!(
                        "[e3_id={}] Using mocked token holders for local network (chain_id: {})",
                        e3_id, CONFIG.chain_id
                    );

                    get_mock_token_holders()
                } else {
                    info!(
                        "[e3_id={}] Using Etherscan API for network (chain_id: {})",
                        e3_id, CONFIG.chain_id
                    );

                    let etherscan_client =
                        EtherscanClient::new(CONFIG.etherscan_api_key.clone(), CONFIG.chain_id);

                    match custom_params.credit_mode {
                        CreditMode::Constant => {
                            let credits_str = credits_clone.expect("credits must be set for Constant mode");
                            let credits_u256: alloy_primitives::Uint<256, 4> = U256::from_str_radix(&credits_str, 10)
                            .map_err(|e| eyre::eyre!("Failed to parse credits: {}", e))?;

                            etherscan_client
                            .get_token_holders_with_constant_balance(
                                token_address,
                                // the block is the one before the request
                                event.e3.requestBlock.to::<u64>() - 1u64,
                                credits_u256
                            )
                            .await
                            .map_err(|e| eyre::eyre!("Etherscan error: {}", e))?
                        }
                        CreditMode::Custom => {
                            etherscan_client
                            .get_token_holders_with_voting_power(
                                token_address,
                                // the block is the one before the request
                                event.e3.requestBlock.to::<u64>() - 1u64,
                                &CONFIG.http_rpc_url,
                                U256::from_str_radix(&balance_threshold.to_string(), 10).map_err(
                                    |e| {
                                        eyre::eyre!(
                                            "[e3_id={}] Failed to convert balance threshold to U256: {}",
                                            e3_id,
                                            e
                                        )
                                    },
                                )?,
                            )
                            .await
                            .map_err(|e| eyre::eyre!("Etherscan error: {}", e))?
                        }
                    }
                };

                if token_holders.is_empty() {
                    return Err(eyre::eyre!(
                        "[e3_id={}] No eligible token holders found for token address {}.",
                        e3_id,
                        token_address
                    ));
                }

                // save the e3 details
                repo.initialize_round(custom_params, e3.requester.to_string(), input_window[1])
                .await?;

                // Store eligible addresses in the repository.
                repo.set_eligible_addresses(token_holders.clone())
                    .await?;

                // Compute Poseidon hashes for token holder address + balance pairs.
                let token_holder_hashes = compute_token_holder_hashes(&token_holders)
                    .with_context(|| "Failed to compute token holder hashes")?;

                repo.set_token_holder_hashes(token_holder_hashes.clone())
                    .await?;

                let tree =
                    build_tree(token_holder_hashes).with_context(|| "Failed to build tree")?;
                let merkle_root = tree
                    .root()
                    .ok_or_else(|| eyre::eyre!("Failed to get merkle root from tree"))?;

                info!("[e3_id={}] Merkle root: {}", e3_id, merkle_root);

                // Convert merkle root from hex string to U256.
                let merkle_root_bytes = hex::decode(&merkle_root)
                    .with_context(|| format!("[e3_id={}] Merkle root is not valid hex", e3_id))?;
                let merkle_root_u256 = U256::from_be_slice(&merkle_root_bytes);

                // Convert e3Id from u64 to U256
                let e3_id_u256 = U256::from(e3_id);

                info!(
                    "[e3_id={}] Calling setMerkleRoot with root: {}",
                    e3_id, merkle_root_u256
                );

                let contract = CRISPContractFactory::create_write(
                    &CONFIG.http_rpc_url,
                    &CONFIG.e3_program_address,
                    &CONFIG.private_key,
                )
                .await
                .with_context(|| {
                    format!("[e3_id={}] Failed to create CRISP contract", e3_id)
                })?;

                let receipt = contract
                    .set_merkle_root(e3_id_u256, merkle_root_u256)
                    .await
                    .with_context(|| {
                        format!("[e3_id={}] Failed to call setMerkleRoot", e3_id)
                    })?;

                info!(
                    "[e3_id={}] setMerkleRoot successful. TxHash: {:?}",
                    e3_id, receipt.transaction_hash
                );

                Ok(())
            }
        })
        .await;
    Ok(indexer)
}

async fn handle_e3_input_deadline_expiration(
    e3_id: u64,
    store: SharedStore<impl DataStore>,
) -> eyre::Result<()> {
    let mut repo = CrispE3Repository::new(store.clone(), e3_id);
    let e3: e3_sdk::indexer::models::E3 = repo.get_e3().await?;

    repo.update_status("Expired").await?;

    let voter_count = repo.get_vote_count().await?;
    let votes = repo.get_ciphertext_inputs().await?;

    if voter_count > 0 && votes.is_empty() {
        warn!(
            "[e3_id={}] {} voter(s) recorded but no InputPublished ciphertexts indexed — \
             skipping FHE compute (check CRISP indexer + on-chain publishInput)",
            e3_id, voter_count
        );
        repo.update_status("Finished").await?;
        info!("[e3_id={}] E3 request handled successfully.", e3_id);
        return Ok(());
    }

    if !votes.is_empty() {
        info!(
            "[e3_id={}] Starting computation for E3 ({} ciphertext input(s), {} voter(s))",
            e3_id,
            votes.len(),
            voter_count
        );
        repo.update_status("Computing").await?;

        let (id, status) = run_compute(
            e3_id,
            e3.e3_params,
            votes,
            format!(
                "{}/state/add-result",
                CONFIG.interfold_server_url_for_clients()
            ),
        )
        .await
        .map_err(|e| eyre::eyre!("Error sending run compute request: {e}"))?;

        if id != e3_id {
            return Err(eyre::eyre!(
                "Computation request returned unexpected E3 ID: expected {}, got {}",
                e3_id,
                id
            ));
        }

        if status != "processing" {
            return Err(eyre::eyre!(
                "Computation request failed with status: {}",
                status
            ));
        }

        info!("[e3_id={}] Request Computation for E3", e3_id);

        repo.update_status("PublishingCiphertext").await?;
    } else {
        info!(
            "[e3_id={}] E3 has no votes to decrypt. Setting status to Finished.",
            e3_id
        );
        repo.update_status("Finished").await?;
    }
    info!("[e3_id={}] E3 request handled successfully.", e3_id);

    Ok(())
}

pub async fn register_ciphertext_output_published(
    indexer: InterfoldIndexer<impl DataStore, ReadWrite>,
) -> Result<InterfoldIndexer<impl DataStore, ReadWrite>> {
    // CiphertextOutputPublished
    indexer
        .add_event_handler(move |event: CiphertextOutputPublished, ctx| {
            let store = ctx.store();
            let e3_id = event.e3Id.to::<u64>();
            let mut repo = CrispE3Repository::new(store, e3_id);
            async move {
                info!("[e3_id={}] Handling CiphertextOutputPublished", e3_id);
                repo.update_status("CiphertextPublished").await?;
                Ok(())
            }
        })
        .await;
    Ok(indexer)
}

pub async fn register_plaintext_output_published(
    indexer: InterfoldIndexer<impl DataStore, ReadWrite>,
) -> Result<InterfoldIndexer<impl DataStore, ReadWrite>> {
    // PlaintextOutputPublished
    indexer
        .add_event_handler(move |event: PlaintextOutputPublished, ctx| {
            let store = ctx.store();
            let e3_id = event.e3Id.to::<u64>();
            let mut repo = CrispE3Repository::new(store, e3_id);
            async move {
                info!("[e3_id={}] Handling PlaintextOutputPublished", e3_id);

                let num_options = repo.get_num_options().await?;

                // The plaintextOutput from the event contains the result of the FHE computation.
                // Decode the tally using the utility function.
                let vote_counts = decode_tally(&event.plaintextOutput, num_options)?;

                for (i, count) in vote_counts.iter().enumerate() {
                    info!("[e3_id={}] Option index: {} votes: {:?}", e3_id, i, count);
                }

                repo.set_votes(vote_counts).await?;
                repo.update_status("Finished").await?;
                Ok(())
            }
        })
        .await;
    Ok(indexer)
}

pub async fn register_committee_published(
    indexer: InterfoldIndexer<impl DataStore, ReadWrite>,
) -> Result<InterfoldIndexer<impl DataStore, ReadWrite>> {
    // CommitteePublished
    indexer
        .add_event_handler(move |event: CommitteePublished, ctx| {
            async move {
                let store = ctx.store();
                let e3_id = event.e3Id.to::<u64>();
                let mut repo = CrispE3Repository::new(store.clone(), e3_id);
                let mut current_round_repo = CurrentRoundRepository::new(store);
                info!("[e3_id={}] Handling CommitteePublished", e3_id);
                // Get current time
                let now = get_current_timestamp_rpc().await?;
                info!("[e3_id={}] Current time: {}", event.e3Id, now);

                repo.start_round().await?;

                current_round_repo
                    .set_current_round(CurrentRound { id: e3_id })
                    .await?;

                let expiration = repo.get_input_deadline().await?;

                info!("[e3_id={}] Registering hook for {}", e3_id, expiration);
                ctx.do_later(expiration, move |_, ctx| {
                    handle_e3_input_deadline_expiration(e3_id, ctx.store())
                });

                Ok(())
            }
        })
        .await;
    Ok(indexer)
}

pub async fn get_current_timestamp_rpc() -> eyre::Result<u64> {
    let provider = ProviderBuilder::new().connect(&CONFIG.http_rpc_url).await?;
    let block = provider
        .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
        .await?
        .ok_or_else(|| eyre::eyre!("Latest block not found"))?;

    Ok(block.header.timestamp)
}

pub async fn register_input_published(
    indexer: InterfoldIndexer<impl DataStore, ReadWrite>,
) -> Result<InterfoldIndexer<impl DataStore, ReadWrite>> {
    indexer
        .add_event_handler(move |event: InputPublished, ctx| {
            let e3_id = event.e3Id.to::<u64>();
            let store = ctx.store();
            let mut repo = CrispE3Repository::new(store.clone(), e3_id);
            async move {
                println!(
                    "InputPublished: e3_id={}, index={}, data=0x{}...",
                    event.e3Id,
                    event.index,
                    hex::encode(&event.encryptedVote[..8.min(event.encryptedVote.len())])
                );

                repo.insert_ciphertext_input(event.encryptedVote.to_vec(), event.index.to::<u64>())
                    .await?;
                Ok(())
            }
        })
        .await;
    Ok(indexer)
}

pub async fn start_indexer(
    url: &str,
    contract_address: &str,
    registry_address: &str,
    crisp_address: &str,
    store: SharedStore<impl DataStore>,
    private_key: &str,
) -> Result<()> {
    info!("CRISP: Creating indexer...");
    let crisp_indexer = InterfoldIndexer::new_with_write_contract(
        url,
        &[contract_address, registry_address, crisp_address],
        store,
        private_key,
    )
    .await?;
    info!("CRISP: Indexer registering handlers...");

    let crisp_indexer = register_e3_requested(crisp_indexer).await?;
    let crisp_indexer = register_ciphertext_output_published(crisp_indexer).await?;
    let crisp_indexer = register_plaintext_output_published(crisp_indexer).await?;
    let crisp_indexer = register_committee_published(crisp_indexer).await?;
    let crisp_indexer = register_input_published(crisp_indexer).await?;
    info!("CRISP: Indexer finished registering handlers!");
    crisp_indexer.listen().await?;
    info!("CRISP: Indexer listen loop has finished!");
    Ok(())
}
