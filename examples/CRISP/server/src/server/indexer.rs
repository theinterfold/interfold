// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::server::log_repo::{LogRepository, StoredLog};
use crate::server::models::e3_id_to_u256;
use crate::server::token_holders::{
    get_mock_token_holders, try_fetch_requester_census, EtherscanClient,
};
use crate::server::{
    data_availability::{AvailabilityService, AvailableInputReference},
    models::{CensusMode, CreditMode, CurrentRound, CustomParams, E3Crisp, TokenHolder},
    program_server_request::{run_compute, RoundInputs},
    repo::{CrispE3Repository, CurrentRoundRepository, InputSnapshot},
    token_holders::{build_tree, compute_token_holder_hashes},
    CONFIG,
};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::sol_types::{sol_data, SolType};
use alloy_primitives::{Address, U256};
use crisp_utils::decode_tally;
use e3_fhe_params::decode_bfv_params_arc;
use e3_sdk::indexer::INDEXER_CURSOR_KEY;
use e3_sdk::{
    evm_helpers::{
        contracts::{E3Stage, InterfoldContractFactory, InterfoldRead, ReadWrite},
        events::{
            CiphertextOutputPublished, CiphertextOutputReferencePublished,
            CommitteePublicKeyChunkPublished, CommitteePublished, E3Requested,
            PlaintextOutputPublished,
        },
        retry::call_with_retry_attempts,
    },
    indexer::{DataStore, IndexerContext, InterfoldIndexer, SharedStore},
};
use evm_helpers::{
    CRISPContract, CRISPContractFactory, CRISPReadProvider, InputCommitted, InputPublished,
};
use eyre::Context;
use log::{error, info, warn};
use num_bigint::BigUint;
use std::time::Duration;
use std::{collections::HashMap, error::Error, sync::Arc, sync::LazyLock};
use tokio::{sync::Notify, time::sleep};

/// Wakes `retry_pending_discovery` when a round records a missing census.
static DISCOVERY_OWED: LazyLock<Notify> = LazyLock::new(Notify::new);

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

/// Attempts of a read that needs the block of an `E3Requested` event: `getE3`, and the stored
/// divisor of a CUSTOM-credit round.
///
/// The subscription delivers the event when one node has the block. The HTTP provider spreads
/// reads over nodes that can trail that node by most of a block. Until they have it, `getE3`
/// reverts with `E3DoesNotExist` and the stored divisor reads as zero. Five attempts wait
/// 2 + 4 + 8 + 16 = 30 s in total, which covers more than two Sepolia blocks. Nothing retries a
/// live handler error, so a shorter wait for `getE3` loses the round. A shorter wait for the
/// divisor defers the census to the retry pass.
const E3_VISIBLE_ATTEMPTS: u32 = 5;

fn is_configured_e3_program(event_program: Address, configured_program: Address) -> bool {
    event_program == configured_program
}

fn stage_ends_input_retrieval(stage: &E3Stage) -> bool {
    matches!(
        stage,
        E3Stage::CiphertextReady | E3Stage::Complete | E3Stage::Failed
    )
}

/// Read the divisor and snapshot `CRISPProgram` stored for a CUSTOM-credit round, or `None` after
/// `E3_VISIBLE_ATTEMPTS`. The contract never stores a zero divisor for such a round, so a zero read
/// is a node that lacks the request block, and it is retried like a failed read.
async fn read_stored_scale(
    crisp: &CRISPContract<CRISPReadProvider>,
    e3_id: U256,
    label: &str,
) -> Option<(U256, u64)> {
    call_with_retry_attempts(
        "stored_voting_power_scale",
        &[],
        E3_VISIBLE_ATTEMPTS,
        || async {
            crisp
                .stored_voting_power_scale(e3_id)
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?
                .ok_or_else(|| {
                    anyhow::anyhow!("the provider holds no stored divisor and snapshot for the round")
                })
        },
    )
    .await
    .inspect_err(|error| {
        warn!(
            "[e3_id={}] Failed to read the stored voting-power divisor and snapshot after retries: {:#}",
            label, error
        )
    })
    .ok()
}

/// Discover the holders a client draws mask targets from.
///
/// Asked only when the round declared it. Probing every requester and falling back on failure
/// would turn a broken census provider into a token vote over the wrong electorate, silently:
/// the round would run, and nothing would error. Checked before the local-network branch because
/// a declared census is exact on any network, including a devnet where the mock holders would
/// otherwise be substituted. Etherscan being down carries no eligibility meaning for an on-chain
/// round: the contract reads power per input, so the only cost is mask cover.
///
/// One function for both callers: the `E3Requested` handler and the retry pass for a round that
/// was registered without a census, because its divisor and snapshot could not be read or its
/// discovery failed. Both callers therefore refuse the same lists. `stored` is the divisor and
/// snapshot of a CUSTOM-credit round, or `None` for a CONSTANT-credit round. A CUSTOM-credit census
/// is read at that snapshot, not at `snapshot_timepoint`: the divisor bounds the census sum only at
/// the timepoint whose supply sized it. Off a local chain, a CUSTOM-credit round without them fails
/// discovery.
async fn discover_holders(
    e3_id: &str,
    custom_params: &CustomParams,
    requester: Address,
    token_address: Address,
    snapshot_timepoint: u64,
    balance_threshold: &BigUint,
    stored: Option<(U256, u64)>,
) -> eyre::Result<Vec<TokenHolder>> {
    let holders = if custom_params.census_mode == CensusMode::ByRequester {
        let credits_str = match custom_params.credit_mode {
            CreditMode::Constant => custom_params
                .credits
                .clone()
                .expect("credits must be set for Constant mode"),
            // A requester-supplied census names *who* may vote, not how much each vote
            // weighs, so it only has meaning when every voter carries the same credits.
            // `CRISPProgram.validate` rejects this pairing on chain, so reaching it here
            // means the round was requested against a different program.
            CreditMode::Custom => {
                return Err(eyre::eyre!(
                    "[e3_id={}] CensusMode::ByRequester requires \
                         CreditMode::Constant; got Custom",
                    e3_id
                ))
            }
        };

        info!(
            "[e3_id={}] Census mode: ByRequester; asking {}",
            e3_id, requester
        );

        let census = try_fetch_requester_census(requester, e3_id, &CONFIG.http_rpc_url)
            .await
            .ok_or_else(|| {
                eyre::eyre!(
                    "[e3_id={}] Round declared CensusMode::ByRequester but \
                             requester {} returned no census. Refusing to fall back to \
                             token discovery, which would enfranchise the wrong voters.",
                    e3_id,
                    requester
                )
            })?;

        census
            .into_iter()
            .map(|address| TokenHolder {
                address: address.to_string(),
                balance: credits_str.clone(),
            })
            .collect()
    } else if matches!(CONFIG.chain_id, 31337 | 1337) {
        info!(
            "[e3_id={}] Using mocked token holders for local network (chain_id: {})",
            e3_id, CONFIG.chain_id
        );

        // A CONSTANT round carries its credits, as on every other chain. A CUSTOM round gets 1, so
        // ten accounts stay below the plaintext modulus of every preset.
        get_mock_token_holders(match custom_params.credit_mode {
            CreditMode::Constant => custom_params
                .credits
                .as_deref()
                .expect("credits must be set for Constant mode"),
            CreditMode::Custom => "1",
        })
    } else {
        info!(
            "[e3_id={}] Using Etherscan API for network (chain_id: {})",
            e3_id, CONFIG.chain_id
        );

        let etherscan_client =
            EtherscanClient::new(CONFIG.etherscan_api_key.clone(), CONFIG.chain_id);

        match custom_params.credit_mode {
            CreditMode::Constant => {
                let credits_str = custom_params
                    .credits
                    .clone()
                    .expect("credits must be set for Constant mode");
                let credits_u256: alloy_primitives::Uint<256, 4> =
                    U256::from_str_radix(&credits_str, 10)
                        .map_err(|e| eyre::eyre!("Failed to parse credits: {}", e))?;

                etherscan_client
                    .get_token_holders_with_constant_balance(
                        token_address,
                        snapshot_timepoint,
                        &CONFIG.http_rpc_url,
                        credits_u256,
                    )
                    .await
                    .context("Etherscan token-holder discovery failed")?
            }
            CreditMode::Custom => {
                let (divisor, snapshot) = stored.ok_or_else(|| {
                    eyre::eyre!(
                        "[e3_id={}] No voting-power divisor and snapshot are known for this \
                         CUSTOM-credit round, so the census cannot be built in the units the \
                         contract reads back.",
                        e3_id
                    )
                })?;

                etherscan_client
                    .get_token_holders_with_voting_power(
                        token_address,
                        snapshot,
                        &CONFIG.http_rpc_url,
                        U256::from_str_radix(&balance_threshold.to_string(), 10).map_err(|e| {
                            eyre::eyre!(
                                "[e3_id={}] Failed to convert balance threshold to U256: {}",
                                e3_id,
                                e
                            )
                        })?,
                        divisor,
                    )
                    .await
                    .context("Etherscan token-holder discovery failed")?
            }
        }
    };

    // A census-tree list is the electorate, so an empty one admits no ballot and fails discovery.
    // An on-chain list only indexes mask targets, so the handler warns about an empty one instead.
    if holders.is_empty() && custom_params.census_mode != CensusMode::Onchain {
        return Err(eyre::eyre!(
            "[e3_id={}] No eligible token holders found for token address {}.",
            e3_id,
            token_address
        ));
    }
    Ok(holders)
}

/// The holders to register a round with, and whether its discovery is still owed.
///
/// A failed discovery never drops the round. The `E3Requested` log is not replayed once the cursor
/// passes it, so the round registers and the retry pass builds the census. The cause is usually
/// transient: a rate limit, a rejected API key, or a voter whose votes could not be read. An
/// on-chain round stays votable meanwhile. A new census-tree round takes no ballot until the retry
/// pass posts its root.
fn holders_or_owed(
    e3_id: &str,
    is_onchain_census: bool,
    discovery: eyre::Result<Vec<TokenHolder>>,
) -> (Vec<TokenHolder>, bool) {
    let error = match discovery {
        Ok(holders) => return (holders, false),
        Err(error) => error,
    };
    if is_onchain_census {
        warn!(
            "[e3_id={}] CensusMode::Onchain holder discovery failed: {:#}. The round is still \
             recorded and votable — eligibility is read from the token at publish time — but \
             clients have no mask targets until a retry succeeds.",
            e3_id, error
        );
    } else {
        warn!(
            "[e3_id={}] Census discovery failed: {:#}. The round keeps any census it holds, and \
             a new round takes no ballot until a retry posts its root.",
            e3_id, error
        );
    }
    (Vec::new(), true)
}

fn order_token_holders(holders: &mut [TokenHolder]) {
    holders.sort_unstable_by(|left, right| {
        left.address
            .to_ascii_lowercase()
            .cmp(&right.address.to_ascii_lowercase())
            .then_with(|| left.balance.cmp(&right.balance))
            .then_with(|| left.address.cmp(&right.address))
    });
}

/// Post the census root of a Merkle round to `CRISPProgram`, unless that root is already set.
async fn ensure_merkle_root(e3_id: &str, token_holder_hashes: Vec<String>) -> eyre::Result<()> {
    let tree = build_tree(token_holder_hashes).with_context(|| "Failed to build tree")?;
    let merkle_root = tree
        .root()
        .ok_or_else(|| eyre::eyre!("Failed to get merkle root from tree"))?;
    info!("[e3_id={}] Merkle root: {}", e3_id, merkle_root);
    let merkle_root_bytes = hex::decode(&merkle_root)
        .with_context(|| format!("[e3_id={}] Merkle root is not valid hex", e3_id))?;
    let merkle_root_u256 = U256::from_be_slice(&merkle_root_bytes);
    let e3_id_u256 = U256::from_str_radix(e3_id, 10)
        .with_context(|| format!("[e3_id={}] Invalid E3 ID", e3_id))?;
    info!(
        "[e3_id={}] Ensuring CRISPProgram Merkle root: {}",
        e3_id, merkle_root_u256
    );
    let contract = CRISPContractFactory::create_write(
        &CONFIG.http_rpc_url,
        &CONFIG.e3_program_address,
        &CONFIG.private_key,
    )
    .await
    .with_context(|| format!("[e3_id={}] Failed to create CRISP contract", e3_id))?;
    let stored_root = contract.get_merkle_root(e3_id_u256).await?;
    if stored_root == merkle_root_u256 {
        info!(
            "[e3_id={}] Merkle root is already set to the expected value",
            e3_id
        );
    } else if stored_root.is_zero() {
        match contract.set_merkle_root(e3_id_u256, merkle_root_u256).await {
            Ok(receipt) => info!(
                "[e3_id={}] setMerkleRoot successful. TxHash: {:?}",
                e3_id, receipt.transaction_hash
            ),
            Err(error) => {
                // A live subscription and its overlap replay can race here. Accept
                // the losing transaction only when the desired root landed.
                let root_after_error = contract.get_merkle_root(e3_id_u256).await?;
                if root_after_error != merkle_root_u256 {
                    return Err(error).with_context(|| {
                        format!("[e3_id={}] Failed to call setMerkleRoot", e3_id)
                    });
                }
                info!(
                    "[e3_id={}] Merkle root was set by a concurrent handler",
                    e3_id
                );
            }
        }
    } else {
        return Err(eyre::eyre!(
            "[e3_id={}] CRISPProgram has a different Merkle root: expected {}, got {}",
            e3_id,
            merkle_root_u256,
            stored_root
        ));
    }
    Ok(())
}

pub async fn register_e3_requested(
    indexer: InterfoldIndexer<impl DataStore, ReadWrite>,
) -> Result<InterfoldIndexer<impl DataStore, ReadWrite>> {
    let configured_program: Address = CONFIG
        .e3_program_address
        .parse()
        .with_context(|| "Invalid configured E3 program address")?;

    // E3Requested
    indexer
        .add_event_handler(move |event: E3Requested, ctx| {
            let store = ctx.store();
            let e3_id = event.e3Id.to_string();
            let mut repo = CrispE3Repository::new(store.clone(), &e3_id);

            let contract = ctx.contract();
            async move {
                if !is_configured_e3_program(event.e3.e3Program, configured_program) {
                    info!(
                        "[e3_id={}] Ignoring E3Requested for unrelated program {}",
                        e3_id, event.e3.e3Program
                    );
                    return Ok(());
                }

                info!("[e3_id={}] E3Requested: {:?}", e3_id, event);

                // 0xcd6f4a4f = E3DoesNotExist()
                let e3 = call_with_retry_attempts(
                    "get_e3",
                    &["0xcd6f4a4f"],
                    E3_VISIBLE_ATTEMPTS,
                    || {
                        let contract = contract.clone();
                        let event_e3_id = event.e3Id;
                        async move {
                            contract
                                .get_e3(event_e3_id)
                                .await
                                .map_err(|e| anyhow::anyhow!("{}", e))
                        }
                    },
                )
                .await
                .map_err(|e| eyre::eyre!("{}", e))?;

                // Use sol_data types instead of primitives
                // Seven fields. The seventh is the requested voting-power divisor: the contract
                // stores a non-zero request for a CUSTOM-credit round, and computes the minimum
                // divisor for a zero request.
                type CustomParamsTuple = (
                    sol_data::Address,
                    sol_data::Uint<256>,
                    sol_data::Uint<256>,
                    sol_data::Uint<256>,
                    sol_data::Uint<256>,
                    sol_data::Uint<256>,
                    sol_data::Uint<256>,
                );

                let decoded = <CustomParamsTuple as SolType>::abi_decode(&event.e3.customParams)
                    .with_context(|| "Failed to decode custom params from E3 event")?;

                // `saturating_to` rather than `to`: these fields are attacker-chosen ABI data, and
                // `to::<u64>()` panics on a value above `u64::MAX`. Clamping lets the `TryFrom`
                // impls reject it as an unknown mode instead.
                let credit_mode = CreditMode::try_from(decoded.3.saturating_to::<u64>())?;
                let census_mode = CensusMode::try_from(decoded.5.saturating_to::<u64>())?;
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

                let custom_params = CustomParams {
                    token_address: decoded.0.to_string(),
                    balance_threshold: decoded.1.to_string(),
                    num_options: decoded.2.to_string(),
                    credit_mode,
                    credits,
                    census_mode,
                    voting_power_divisor: decoded.6.to_string(),
                };

                let balance_threshold =
                    BigUint::parse_bytes(custom_params.balance_threshold.as_bytes(), 10)
                        .ok_or_else(|| eyre::eyre!("Invalid balance threshold"))?;
                let token_address: Address = custom_params
                    .token_address
                    .parse()
                    .with_context(|| "Invalid token address")?;

                let input_window = [e3.inputWindow[0].to::<u64>(), e3.inputWindow[1].to::<u64>()];
                let crisp = CRISPContractFactory::create_read(
                    &CONFIG.http_rpc_url,
                    &CONFIG.e3_program_address,
                )
                .await
                .with_context(|| "Failed to create CRISP contract reader")?;
                let voting_end_time = crisp
                    .input_commitment_deadline(event.e3Id)
                    .await
                    .with_context(|| {
                        format!("[e3_id={e3_id}] Failed to read the input commitment deadline")
                    })?;

                // The census is built one tick before the request, as the request timepoint
                // itself is not final when the E3 is requested.
                //
                // `requestBlock` is a timestamp, not a block height — the ticket token runs
                // an EIP-6372 `mode=timestamp` clock, and `Interfold.request` assigns
                // `block.timestamp` to match the checkpoints it is compared against. The
                // name is historical.
                let snapshot_timepoint = event.e3.requestBlock.to::<u64>().saturating_sub(1);

                // An on-chain census has nothing for the coordinator to build. `CRISPProgram`
                // reads each voter's power with `getPastVotes` when the input is published, so
                // there is no holder list to enumerate and no root to post — `setMerkleRoot` is
                // not just unnecessary here, it is unused: `_eligibility` never reads it in this
                // mode. The round is still recorded, because the API serves its metadata.
                // An on-chain census is not an eligibility input: `_eligibility` reads each
                // voter's power with `getPastVotes` when the input is published and never looks at
                // `merkleRoot`. The holder list is still discovered and stored, because clients
                // need somewhere to draw mask targets from — a mask is written to someone else's
                // slot, so without a list of who holds power there is nobody to mask.
                //
                // The distinction matters for what a wrong list can do. For a Merkle round the
                // list *is* the electorate, so an omission disenfranchises. Here it is an index
                // over what the chain already decides, so an omission costs mask cover and nothing
                // else — it can never enfranchise anyone the contract would refuse.
                let is_onchain_census = custom_params.census_mode == CensusMode::Onchain;
                if is_onchain_census {
                    info!(
                        "[e3_id={}] CensusMode::Onchain — discovering holders for mask targets; \
                         no merkle root will be posted",
                        e3_id
                    );
                }

                // Only a CUSTOM-credit round stores a divisor and a snapshot. Without them the
                // census cannot be built in the units the contract reads back, so the round
                // registers and its discovery is deferred to the retry pass. An `Err` here would
                // not defer anything: the live listener logs it and moves on, which drops the round.
                let stored = if custom_params.credit_mode == CreditMode::Custom {
                    read_stored_scale(&crisp, event.e3Id, &e3_id).await
                } else {
                    None
                };
                let divisor_unavailable =
                    custom_params.credit_mode == CreditMode::Custom && stored.is_none();
                if divisor_unavailable {
                    warn!(
                        "[e3_id={}] The stored voting-power divisor and snapshot are unavailable. \
                         Registering the round without holder discovery rather than building a \
                         census in units the contract may not use.",
                        e3_id
                    );
                }

                // Get token holders from Etherscan API or mocked data. Lifted into
                // `discover_holders` so the retry pass for a round registered without a census
                // runs the same code with the same refusals.
                let discovery: eyre::Result<Vec<TokenHolder>> = if divisor_unavailable {
                    Ok(Vec::new())
                } else {
                    discover_holders(
                        &e3_id,
                        &custom_params,
                        e3.requester,
                        token_address,
                        snapshot_timepoint,
                        &balance_threshold,
                        stored,
                    )
                    .await
                };

                let (mut token_holders, discovery_failed) =
                    holders_or_owed(&e3_id, is_onchain_census, discovery);

                // `discover_holders` refuses an empty census-tree list. An empty on-chain list
                // costs mask cover and nothing else, so the round goes ahead.
                if is_onchain_census
                    && token_holders.is_empty()
                    && !divisor_unavailable
                    && !discovery_failed
                {
                    warn!(
                        "[e3_id={}] CensusMode::Onchain discovery found no holders for {}. The \
                         round is still recorded and votable — eligibility is read from the token \
                         at publish time — but clients have no mask targets to draw from.",
                        e3_id, token_address
                    );
                }

                // The Merkle root must not depend on HashMap iteration order or RPC log order.
                // A retry must produce the same root from the same snapshot.
                order_token_holders(&mut token_holders);

                // save the e3 details
                repo.initialize_round(
                    custom_params,
                    event.e3.e3Program,
                    e3.requester.to_string(),
                    voting_end_time,
                    input_window[1],
                    snapshot_timepoint,
                )
                .await?;

                // Store the census, or record the debt so `retry_pending_discovery` settles it
                // later. Two causes of debt:
                //
                //   - discovery was SKIPPED for want of a divisor and snapshot, not refused; or
                //   - discovery RAN and failed, which `holders_or_owed` absorbs to keep the round.
                //
                // The event is not replayed once the cursor passes it, so nothing else would
                // retry. The retry task is woken below, after `record_round`: it scans the round
                // index and sleeps when nothing is owed, so waking it here could let it run before
                // this round is listed, find nothing, and sleep with the debt unpaid.
                let owed = divisor_unavailable || discovery_failed;
                let root_leaves =
                    store_census(&mut repo, token_holders, is_onchain_census, owed).await?;

                CurrentRoundRepository::new(store.clone())
                    .record_round(&e3_id)
                    .await?;

                // The round is listed, so the retry task can find its debt. Wake the one task
                // started at registration instead of spawning another: each task rescans every
                // owed round, so one per debt multiplied the discovery calls.
                if owed {
                    DISCOVERY_OWED.notify_one();
                }

                // No leaves for an on-chain census: `_eligibility` never reads `merkleRoot` in
                // that mode, so posting one would spend gas to publish a value nothing consults —
                // and would imply the list gates eligibility when it does not. No leaves for an
                // owed census either: the retry pass posts its root.
                if let Some(leaves) = root_leaves {
                    ensure_merkle_root(&e3_id, leaves).await?;
                }

                // Committee and request handlers run concurrently for live logs. If the key was
                // indexed while census preparation was still running, this closes that race.
                activate_round_if_ready(e3_id.clone(), ctx).await?;

                Ok(())
            }
        })
        .await;
    Ok(indexer)
}

/// What the indexer holds for a round, measured against what `CRISPProgram` committed.
enum IndexedInputs {
    /// The indexer holds every input, and this is the snapshot it holds them in.
    Complete(InputSnapshot),
    /// Its count does not match the contract after the bounded wait.
    Mismatch { indexed: usize, published: usize },
}

/// The round's inputs, once the indexer holds every one `CRISPProgram` committed.
///
/// Polls rather than reading once: the deadline callback and the last `InputPublished` handler race,
/// and the gap is the few seconds it takes one log to be delivered and stored.
///
/// Both counts are re-read on every attempt. Re-reading only the chain would compare a moving number
/// against a fixed one, so the loop could never converge — it would wait out every attempt and then
/// report the same shortfall it started with, in exactly the race it exists to absorb.
///
/// Returns the snapshot the two counts agree on, or the last pair when they never do, so the caller
/// reports the shortfall rather than looping forever.
async fn wait_for_indexed_inputs<S: DataStore>(
    e3_id: &str,
    repo: &CrispE3Repository<S>,
) -> eyre::Result<IndexedInputs> {
    const ATTEMPTS: u32 = 10;
    const INTERVAL: Duration = Duration::from_secs(3);

    let e3_id_u256 = e3_id_to_u256(e3_id).map_err(|e| eyre::eyre!("{e}"))?;
    let contract =
        CRISPContractFactory::create_read(&CONFIG.http_rpc_url, &CONFIG.e3_program_address).await?;

    for attempt in 0..=ATTEMPTS {
        let published = contract.get_published_input_count(e3_id_u256).await? as usize;
        let snapshot = repo.get_input_snapshot().await?;
        let indexed = snapshot.ciphertexts.len();

        // Equality is required. Fewer entries means that an accepted input is missing. More
        // entries means that the local index contains data the contract did not accept. Either
        // case would make the OpenVM input root differ from the contract's root.
        if indexed == published {
            return Ok(IndexedInputs::Complete(snapshot));
        }

        if attempt == ATTEMPTS {
            return Ok(IndexedInputs::Mismatch { indexed, published });
        }

        info!(
            "[e3_id={}] waiting for the indexer: {} of {} input(s) stored",
            e3_id, indexed, published
        );
        sleep(INTERVAL).await;
    }

    unreachable!("the loop returns on its final attempt")
}

/// When the deadline handler runs again after a round it could not compute.
///
/// Each offset is a separate `do_later` registration made when the round starts, rather than the
/// handler re-arming itself: `do_later` drops a callback once it has run, and a handler that failed
/// has no way back into the schedule. The offsets are wider than the indexer wait inside the
/// handler, so two passes do not overlap.
const DEADLINE_RETRY_OFFSETS: [u64; 3] = [60, 180, 420];

const ROUND_ACTIVATION_RETRY_OFFSETS: [u64; 5] = [1, 5, 30, 120, 600];

fn deadline_attempt_times(expiration: u64, now: u64) -> [u64; 4] {
    let first = expiration.max(now);
    [
        first,
        first.saturating_add(DEADLINE_RETRY_OFFSETS[0]),
        first.saturating_add(DEADLINE_RETRY_OFFSETS[1]),
        first.saturating_add(DEADLINE_RETRY_OFFSETS[2]),
    ]
}

async fn handle_e3_input_deadline_expiration_logged<S: DataStore>(
    e3_id: String,
    store: SharedStore<S>,
) -> eyre::Result<()> {
    if let Err(error) = handle_e3_input_deadline_expiration(e3_id.clone(), store).await {
        error!("[e3_id={}] CRISP deadline pass failed: {}", e3_id, error);
    }
    Ok(())
}

async fn activate_round_if_ready<S: DataStore>(
    e3_id: String,
    ctx: Arc<IndexerContext<S, ReadWrite>>,
) -> eyre::Result<bool> {
    let store = ctx.store();
    let mut repo = CrispE3Repository::new(store.clone(), &e3_id);
    if !repo.has_crisp_record().await? || !repo.has_indexed_public_key().await? {
        return Ok(false);
    }

    let expiration = repo.get_input_deadline().await?;
    if !repo.try_start_round().await? {
        return Ok(true);
    }

    let now = chrono::Utc::now().timestamp().max(0) as u64;
    for at in deadline_attempt_times(expiration, now) {
        let e3_id = e3_id.clone();
        ctx.do_later(at, move |_, ctx| {
            handle_e3_input_deadline_expiration_logged(e3_id.clone(), ctx.store())
        });
    }

    let mut current_round_repo = CurrentRoundRepository::new(store);
    current_round_repo
        .set_current_round(CurrentRound { id: e3_id.clone() })
        .await?;
    info!(
        "[e3_id={}] Activated CRISP round and registered deadline callbacks",
        e3_id
    );
    Ok(true)
}

fn schedule_round_activation_retries<S: DataStore>(
    e3_id: &str,
    ctx: &Arc<IndexerContext<S, ReadWrite>>,
) {
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    for offset in ROUND_ACTIVATION_RETRY_OFFSETS {
        let e3_id = e3_id.to_string();
        ctx.do_later(now.saturating_add(offset), move |_, ctx| {
            let e3_id = e3_id.clone();
            async move {
                if let Err(error) = activate_round_if_ready(e3_id.clone(), ctx).await {
                    error!(
                        "[e3_id={}] Deferred CRISP round activation failed: {}",
                        e3_id, error
                    );
                }
                Ok(())
            }
        });
    }
}

async fn restore_round_deadline_callback<S: DataStore>(
    indexer: &InterfoldIndexer<S, ReadWrite>,
    store: SharedStore<S>,
    e3_id: String,
    now: u64,
) -> Result<()> {
    let mut repo = CrispE3Repository::new(store.clone(), &e3_id);
    let mut status = repo.get_status().await?;
    let has_indexed_public_key = repo.has_indexed_public_key().await?;
    if status == "Active" && !has_indexed_public_key {
        repo.update_status("Requested").await?;
        status = "Requested".to_string();
        warn!(
            "[e3_id={}] Reset an active round to pending because no verified public key is indexed",
            e3_id
        );
    }
    if status == "Requested" && has_indexed_public_key && repo.try_start_round().await? {
        let mut current_round_repo = CurrentRoundRepository::new(store.clone());
        current_round_repo
            .set_current_round(CurrentRound { id: e3_id.clone() })
            .await?;
        status = "Active".to_string();
        info!(
            "[e3_id={}] Activated a requested round whose verified key was indexed before restart",
            e3_id
        );
    }
    if status == "Computing" || status == "PublishingCiphertext" {
        // Submission is intentionally at-least-once across the CRISP and program-server process
        // boundary. A crash can lose the HTTP response or webhook, so keeping this claim would
        // strand the round. A retry can repeat proof work, but it cannot publish a second result:
        // Interfold accepts ciphertext output only from KeyPublished, and the callback treats an
        // already-published output as success.
        repo.update_status("Expired").await?;
        status = "Expired".to_string();
        warn!(
            "[e3_id={}] Reset an interrupted compute submission so it can be retried",
            e3_id
        );
    }
    if status != "Active" && status != "Expired" {
        return Ok(());
    }

    let expiration = repo.get_input_deadline().await?;
    for at in deadline_attempt_times(expiration, now) {
        let e3_id = e3_id.clone();
        indexer.schedule_at(at, move |_, ctx| {
            handle_e3_input_deadline_expiration_logged(e3_id.clone(), ctx.store())
        });
    }
    info!(
        "[e3_id={}] Restored deadline callbacks for CRISP round in status {}",
        e3_id, status
    );
    Ok(())
}

async fn restore_round_deadline_callbacks<S: DataStore>(
    indexer: &InterfoldIndexer<S, ReadWrite>,
) -> Result<()> {
    let store = indexer.get_store();
    let round_ids = CurrentRoundRepository::new(store.clone())
        .get_round_ids()
        .await?;
    let now = chrono::Utc::now().timestamp().max(0) as u64;

    for e3_id in round_ids {
        if let Err(error) =
            restore_round_deadline_callback(indexer, store.clone(), e3_id.clone(), now).await
        {
            error!(
                "[e3_id={}] Could not restore CRISP deadline callbacks: {}",
                e3_id, error
            );
        }
    }

    Ok(())
}

/// Store key holding the `INDEX_LOG_CONTRACTS` set as of the previous run.
///
/// Coverage records outlive the configuration that created them, and the store has no delete. This
/// is what lets a restart tell "this address has been indexed continuously" from "this address is
/// back after a spell of not being indexed", so the second case can narrow its claim instead of
/// asserting history that was never fetched.
const LOG_INDEX_CONFIG_KEY: &str = "_logs:_config";

async fn handle_e3_input_deadline_expiration(
    e3_id: String,
    store: SharedStore<impl DataStore>,
) -> eyre::Result<()> {
    let mut repo = CrispE3Repository::new(store.clone(), &e3_id);
    let e3: e3_sdk::indexer::models::E3 = repo.get_e3().await?;

    let crisp =
        CRISPContractFactory::create_read(&CONFIG.http_rpc_url, &CONFIG.e3_program_address).await?;
    let pending = crisp
        .pending_input_count(e3_id_to_u256(&e3_id).map_err(|error| eyre::eyre!(error.to_string()))?)
        .await?;
    if pending != 0 {
        // The input root already includes these reserved leaves, but Ethereum has not verified
        // their Avail receipts. Starting OpenVM now would waste the proof: CRISPProgram.verify
        // refuses every output until this reaches zero. InputPublished recovery wakes this handler
        // again as each delayed VectorX proof lands.
        return Err(eyre::eyre!(
            "[e3_id={}] {} input(s) still await data-availability finalization; refusing to compute",
            e3_id,
            pending
        ));
    }

    // This transition is atomic. A delayed callback must not move a round from
    // `PublishingCiphertext` or `CiphertextPublished` back to `Expired` and compute it twice.
    if !repo.try_mark_expired().await? {
        return Ok(());
    }
    let voter_count = repo.get_vote_count().await?;

    // The contract is the authority on how many inputs there are, and this callback can run before
    // the last committed input is indexed. Computation is one-shot, so starting short would tally
    // a subset and derive a root the contract rejects — a failure with no other symptom.
    //
    // The snapshot comes back from the same call, read once. Assembling the request from separate
    // reads lets an input event land between them, which pairs a ciphertext with another
    // input's commitment and derives a root `CRISPProgram` rejects.
    let snapshot = match wait_for_indexed_inputs(&e3_id, &repo).await? {
        IndexedInputs::Complete(snapshot) => snapshot,
        IndexedInputs::Mismatch { indexed, published } => {
            // Leave the round "Expired" and unfinished so a later pass can still compute it. The
            // retries registered at `DEADLINE_RETRY_OFFSETS` come back to it. Marking it finished
            // here would either omit an accepted input or tally local data that is not in the
            // contract's root.
            return Err(eyre::eyre!(
                "[e3_id={}] the indexer holds {} input(s), but CRISPProgram accepted {}; \
                 refusing to compute while the counts differ. A retry pass runs at +{}s from the \
                 input deadline. If every pass reports this, the index is inconsistent and needs \
                 attention.",
                e3_id,
                indexed,
                published,
                DEADLINE_RETRY_OFFSETS
                    .iter()
                    .map(|offset| offset.to_string())
                    .collect::<Vec<_>>()
                    .join("s, +")
            ));
        }
    };
    let votes = snapshot.ciphertexts.clone();

    if voter_count > 0 && votes.is_empty() {
        return Err(eyre::eyre!(
            "[e3_id={}] {} active voter slot(s) are recorded, but the input snapshot is empty; \
             refusing to finish an inconsistent round",
            e3_id,
            voter_count
        ));
    }

    if !votes.is_empty() {
        info!(
            "[e3_id={}] Starting computation for E3 ({} ciphertext input(s), {} voter(s))",
            e3_id,
            votes.len(),
            voter_count
        );
        // The local concurrency barrier. Two passes can be inside the indexer wait at once, so the
        // transition to "Computing" has to decide which one proceeds. It must use one store
        // operation, not a read followed by a write. Restart recovery remains at-least-once because
        // the contract, not this process, is the durable idempotency boundary.
        //
        // Claimed here rather than before the wait: a pass that gives up on a short index leaves
        // the round "Expired" so a later pass can still take it, and claiming earlier would pin it
        // to "Computing" and strand it.
        if !repo.try_claim_computing().await? {
            info!(
                "[e3_id={}] another pass is already computing this round; nothing to do",
                e3_id
            );
            return Ok(());
        }

        let submission = async {
            let (id, status) = run_compute(
                &e3_id,
                e3.chain_id,
                e3.interfold_address,
                e3.encryption_scheme_id,
                e3.committee_public_key_hash,
                e3.e3_params,
                RoundInputs {
                    ciphertexts: snapshot.ciphertexts,
                    commitments: snapshot.commitments,
                    slots: snapshot.slots,
                    parents: snapshot.parents,
                },
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

            Ok::<(), eyre::Report>(())
        }
        .await;

        if let Err(submission_error) = submission {
            if let Err(release_error) = repo.release_compute_claim().await {
                error!(
                    "[e3_id={}] Failed to release compute claim after submission error: {}",
                    e3_id, release_error
                );
            }
            return Err(submission_error.into());
        }

        info!("[e3_id={}] Request Computation for E3", e3_id);

        if !repo.mark_compute_submitted().await? {
            let status = repo
                .get_status()
                .await
                .unwrap_or_else(|_| "unknown".to_owned());
            warn!(
                "[e3_id={}] Compute response arrived after the round advanced to {}; leaving that state unchanged",
                e3_id, status
            );
        }
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
            let e3_id = event.e3Id.to_string();
            let mut repo = CrispE3Repository::new(store, &e3_id);
            async move {
                info!("[e3_id={}] Handling CiphertextOutputPublished", e3_id);
                repo.update_status("CiphertextPublished").await?;
                Ok(())
            }
        })
        .await;
    Ok(indexer)
}

pub async fn register_ciphertext_output_reference_published(
    indexer: InterfoldIndexer<impl DataStore, ReadWrite>,
) -> Result<InterfoldIndexer<impl DataStore, ReadWrite>> {
    indexer
        .add_event_handler(move |event: CiphertextOutputReferencePublished, ctx| {
            let store = ctx.store();
            let e3_id = event.e3Id.to_string();
            let mut repo = CrispE3Repository::new(store, &e3_id);
            async move {
                info!(
                    "[e3_id={}] Handling CiphertextOutputReferencePublished",
                    e3_id
                );
                repo.update_status("CiphertextPublished").await?;
                Ok(())
            }
        })
        .await;
    Ok(indexer)
}

/// Record the tally that `PlaintextOutputPublished` carries, and finish the round.
///
/// The Interfold contract emits the event for the rounds of every program. The server stores no
/// record for a round that another program requested, so the event changes nothing for that round.
/// `decode_tally` reads the ballot layout of this server, and each `CRISPProgram` deployment fixes
/// the layout of its rounds. A stored round of another program therefore finishes with an empty
/// tally. So does a round stored without its program, because its layout is unknown.
async fn record_plaintext_output<S: DataStore>(
    repo: &mut CrispE3Repository<S>,
    e3_id: &str,
    plaintext_output: &[u8],
    configured_program: Address,
) -> eyre::Result<()> {
    let Some(round) = repo.try_get_crisp().await? else {
        info!(
            "[e3_id={}] Ignoring PlaintextOutputPublished for a round without a CRISP record",
            e3_id
        );
        return Ok(());
    };
    let same_program = round
        .e3_program
        .parse::<Address>()
        .is_ok_and(|program| is_configured_e3_program(program, configured_program));

    if same_program {
        let vote_counts = decode_tally(plaintext_output, round.num_options.parse()?)?;
        for (i, count) in vote_counts.iter().enumerate() {
            info!("[e3_id={}] Option index: {} votes: {:?}", e3_id, i, count);
        }
        repo.set_votes(vote_counts).await?;
    } else {
        warn!(
            "[e3_id={}] Leaving the tally empty: the round's program '{}' is not the configured \
             program {}, so its ballot layout can differ",
            e3_id, round.e3_program, configured_program
        );
    }

    repo.update_status("Finished").await
}

pub async fn register_plaintext_output_published(
    indexer: InterfoldIndexer<impl DataStore, ReadWrite>,
) -> Result<InterfoldIndexer<impl DataStore, ReadWrite>> {
    let configured_program: Address = CONFIG
        .e3_program_address
        .parse()
        .with_context(|| "Invalid configured E3 program address")?;

    // PlaintextOutputPublished
    indexer
        .add_event_handler(move |event: PlaintextOutputPublished, ctx| {
            let store = ctx.store();
            let e3_id = event.e3Id.to_string();
            let mut repo = CrispE3Repository::new(store, &e3_id);
            async move {
                info!("[e3_id={}] Handling PlaintextOutputPublished", e3_id);
                record_plaintext_output(
                    &mut repo,
                    &e3_id,
                    &event.plaintextOutput,
                    configured_program,
                )
                .await?;
                Ok(())
            }
        })
        .await;
    Ok(indexer)
}

pub async fn register_committee_published(
    indexer: InterfoldIndexer<impl DataStore, ReadWrite>,
) -> Result<InterfoldIndexer<impl DataStore, ReadWrite>> {
    indexer
        .add_event_handler(move |event: CommitteePublished, ctx| {
            async move {
                let e3_id = event.e3Id.to_string();
                info!("[e3_id={}] Handling CommitteePublished", e3_id);

                if !activate_round_if_ready(e3_id.clone(), ctx.clone()).await? {
                    warn!(
                        "[e3_id={}] Committee event arrived, but the verified public key or CRISP request record is unavailable; round remains pending",
                        e3_id
                    );
                    schedule_round_activation_retries(&e3_id, &ctx);
                }

                Ok(())
            }
        })
        .await;
    Ok(indexer)
}

pub async fn register_committee_public_key_chunks(
    indexer: InterfoldIndexer<impl DataStore, ReadWrite>,
) -> Result<InterfoldIndexer<impl DataStore, ReadWrite>> {
    indexer
        .add_event_handler(
            move |event: CommitteePublicKeyChunkPublished, ctx| async move {
                // Do not assume chunks arrive in index order. The normal writer sends them in
                // order, but the contract deliberately permits a committee member to repair any
                // missing chunk. Whichever event completes the generic indexer's assembly must be
                // able to activate the round.
                let e3_id = event.e3Id.to_string();
                if !activate_round_if_ready(e3_id.clone(), ctx.clone()).await? {
                    schedule_round_activation_retries(&e3_id, &ctx);
                }
                Ok(())
            },
        )
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
    availability: Arc<AvailabilityService>,
) -> Result<InterfoldIndexer<impl DataStore, ReadWrite>> {
    indexer
        .add_event_handler(move |event: InputPublished, ctx| {
            let availability = Arc::clone(&availability);
            let e3_id = event.e3Id.to_string();
            let store = ctx.store();
            async move {
                let reference = AvailableInputReference::from_event(e3_id, &event);
                availability
                    .record_input_reference(&reference)
                    .map_err(|error| eyre::eyre!(error.to_string()))?;
                match store_available_input(
                    store.clone(),
                    Arc::clone(&availability),
                    reference.clone(),
                )
                .await
                {
                    Ok(()) => {
                        let e3_id = reference.e3_id.clone();
                        tokio::spawn(resume_expired_round(e3_id, store));
                    }
                    Err(error) => {
                        warn!(
                            "[e3_id={}] Input {} is committed but not retrievable yet: {}",
                            reference.e3_id, reference.index, error
                        );
                    }
                }
                Ok(())
            }
        })
        .await;
    Ok(indexer)
}

/// Index a committed ciphertext immediately when this availability service holds its bytes.
///
/// VectorX finalization can take hours. Reserving the input index on Ethereum preserves CRISP's
/// parent chain, and this local copy lets a later vote or mask extend that entry during the wait.
/// Other indexers that do not hold the staged object simply learn it from `InputPublished` later.
pub async fn register_input_committed(
    indexer: InterfoldIndexer<impl DataStore, ReadWrite>,
    availability: Arc<AvailabilityService>,
) -> Result<InterfoldIndexer<impl DataStore, ReadWrite>> {
    indexer
        .add_event_handler(move |event: InputCommitted, ctx| {
            let availability = Arc::clone(&availability);
            let store = ctx.store();
            async move {
                let hash = format!("0x{}", hex::encode(event.encryptedVoteHash));
                let Some(ciphertext) = availability
                    .object(&hash)
                    .map_err(|error| eyre::eyre!(error.to_string()))?
                else {
                    // This is normal for a secondary indexer. The verified InputPublished event
                    // supplies Avail coordinates later; advancing the cursor is safe because no
                    // unverified bytes are needed for final computation.
                    return Ok(());
                };
                e3_data_availability::verify_retrieved_bytes(
                    e3_data_availability::DataReference {
                        content_hash: event.encryptedVoteHash.0,
                        block_number: 0,
                        leaf_index: 0,
                    },
                    ciphertext.clone(),
                )
                .map_err(|error| eyre::eyre!(error.to_string()))?;
                store_input_bytes(
                    store,
                    event.e3Id.to_string(),
                    ciphertext,
                    event.index.to::<u64>(),
                    event.encryptedVoteCommitment.0,
                    event.slotAddress.into(),
                    event.parentIndexPlusOne.to::<u64>(),
                )
                .await
                .map_err(|error| eyre::eyre!(error.to_string()))?;
                Ok::<(), eyre::Report>(())
            }
        })
        .await;
    Ok(indexer)
}

async fn store_available_input<S: DataStore>(
    store: SharedStore<S>,
    availability: Arc<AvailabilityService>,
    reference: AvailableInputReference,
) -> Result<()> {
    let ciphertext = availability.retrieve(reference.data_reference()).await?;
    store_input_bytes(
        store,
        reference.e3_id.clone(),
        ciphertext,
        reference.index,
        reference.commitment,
        reference.slot,
        reference.parent_index_plus_one,
    )
    .await?;
    availability.complete_input_reference(&reference)?;
    info!(
        "[e3_id={}] Retrieved input {} from data availability",
        reference.e3_id, reference.index
    );
    Ok(())
}

async fn store_input_bytes<S: DataStore>(
    store: SharedStore<S>,
    e3_id: String,
    ciphertext: Vec<u8>,
    index: u64,
    commitment: [u8; 32],
    slot: [u8; 20],
    parent_index_plus_one: u64,
) -> Result<()> {
    let mut repo = CrispE3Repository::new(store, &e3_id);
    let e3 = repo.get_e3().await?;
    let params = decode_bfv_params_arc(&e3.e3_params)?;
    repo.insert_ciphertext_input(
        ciphertext,
        index,
        commitment,
        slot,
        parent_index_plus_one,
        &params,
    )
    .await?;
    Ok(())
}

async fn resume_expired_round<S: DataStore>(e3_id: String, store: SharedStore<S>) {
    let repo = CrispE3Repository::new(store.clone(), &e3_id);
    let Ok(e3) = repo.get_e3().await else {
        return;
    };
    let Ok(now) = get_current_timestamp_rpc().await else {
        return;
    };
    if now >= e3.input_window[1] {
        if let Err(error) = handle_e3_input_deadline_expiration(e3_id.clone(), store).await {
            warn!(
                "[e3_id={}] Could not resume computation after retrieving an input: {}",
                e3_id, error
            );
        }
    }
}

async fn recover_round_deadlines<S: DataStore>(store: SharedStore<S>) {
    let ids = match CurrentRoundRepository::new(store.clone())
        .get_round_ids()
        .await
    {
        Ok(ids) => ids,
        Err(error) => {
            warn!("Could not recover CRISP round deadlines: {error}");
            return;
        }
    };

    let mut pending = Vec::new();
    for e3_id in ids {
        let repo = CrispE3Repository::new(store.clone(), &e3_id);
        let Ok(status) = repo.get_status().await else {
            continue;
        };
        if status != "Requested" && status != "Active" && status != "Expired" {
            continue;
        }
        let Ok(e3) = repo.get_e3().await else {
            continue;
        };
        pending.push((e3_id, e3.input_window[1]));
    }
    if pending.is_empty() {
        return;
    }

    // This is a fallback for restored block callbacks, not one perpetual task per historical
    // round. One provider and one bounded loop cover all unfinished rounds, then the task exits.
    let provider = match ProviderBuilder::new().connect(&CONFIG.http_rpc_url).await {
        Ok(provider) => provider,
        Err(error) => {
            warn!("Could not connect the CRISP deadline recovery watchdog: {error}");
            return;
        }
    };
    while !pending.is_empty() {
        let head = tokio::time::timeout(
            Duration::from_secs(15),
            provider.get_block_by_number(alloy::eips::BlockNumberOrTag::Latest),
        )
        .await;
        let now = match head {
            Ok(Ok(Some(block))) => block.header.timestamp,
            Ok(Ok(None)) => {
                sleep(Duration::from_secs(30)).await;
                continue;
            }
            Ok(Err(error)) => {
                warn!("CRISP deadline recovery could not read the latest block: {error}");
                sleep(Duration::from_secs(30)).await;
                continue;
            }
            Err(_) => {
                warn!("CRISP deadline recovery timed out while reading the latest block");
                sleep(Duration::from_secs(30)).await;
                continue;
            }
        };

        let mut index = 0;
        while index < pending.len() {
            if now < pending[index].1 {
                index += 1;
                continue;
            }
            let (e3_id, _) = pending.swap_remove(index);
            if let Err(error) =
                handle_e3_input_deadline_expiration(e3_id.clone(), store.clone()).await
            {
                warn!(
                    "[e3_id={}] Recovered deadline handler could not start computation: {}",
                    e3_id, error
                );
            }
        }
        if !pending.is_empty() {
            sleep(Duration::from_secs(30)).await;
        }
    }
}

/// What the retry pass does with one round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingDiscoveryStep {
    /// Nothing owed.
    Skip,
    /// Owed, but the round can take no more ballots: there is nobody left to mask. Clear it.
    Forgive,
    /// Owed and still votable: read the divisor again and run discovery.
    Retry,
}

fn pending_discovery_step(round: &E3Crisp) -> PendingDiscoveryStep {
    if !round.discovery_pending {
        return PendingDiscoveryStep::Skip;
    }
    if round.status == "Requested" || round.status == "Active" {
        PendingDiscoveryStep::Retry
    } else {
        PendingDiscoveryStep::Forgive
    }
}

/// Store the census that discovery found, or record that the round still owes one.
///
/// Returns the leaf hashes to post as the census root, or `None` when no root is due: the census
/// is owed, or it is on-chain. An owed census writes no list, so a new round keeps the empty lists
/// from `initialize_round`. A round whose `E3Requested` arrives again and fails discovery keeps the
/// census it holds until the retry pass rebuilds it, and a rebuilt Merkle census must match the
/// posted root.
async fn store_census<S: DataStore>(
    repo: &mut CrispE3Repository<S>,
    holders: Vec<TokenHolder>,
    is_onchain_census: bool,
    owed: bool,
) -> eyre::Result<Option<Vec<String>>> {
    if owed {
        repo.set_discovery_pending(true).await?;
        return Ok(None);
    }
    // Poseidon hashes exist to build the census tree, and an on-chain census has no tree:
    // `_eligibility` reads power from the token per input. The addresses are all a client needs
    // there: a mask is written to someone else's slot, so it needs a list of who holds power, not
    // a membership proof.
    let leaves = if is_onchain_census {
        None
    } else {
        Some(
            compute_token_holder_hashes(&holders)
                .with_context(|| "Failed to compute token holder hashes")?,
        )
    };
    repo.set_eligible_addresses(holders).await?;
    if let Some(hashes) = &leaves {
        repo.set_token_holder_hashes(hashes.clone()).await?;
    }
    Ok(leaves)
}

/// Settle holder discovery for rounds that were registered without a census.
///
/// A round carries `discovery_pending` when its census could not be built at `E3Requested`:
/// either the stored voting-power divisor and snapshot could not be read, or discovery itself
/// failed. A new round in this state serves no mask targets, and a Merkle one takes no ballot until
/// this pass posts its root. A round whose `E3Requested` arrives again keeps the census it holds
/// until this pass rebuilds it. The event is not replayed once the cursor passes it, so this pass
/// is the only retry. It reads the divisor and snapshot again for each such CUSTOM-credit round
/// and, when they answer, runs the same discovery the handler would have run. A round that has
/// ended is dropped from the pass: it takes no more ballots.
///
/// One task for the process, started at registration. It sleeps on `DISCOVERY_OWED` while nothing
/// is owed. `notify_one` keeps a permit when the task is mid-pass, so debt recorded after the pass
/// read that round is still picked up.
async fn retry_pending_discovery<S: DataStore>(store: SharedStore<S>) {
    let crisp = loop {
        match CRISPContractFactory::create_read(&CONFIG.http_rpc_url, &CONFIG.e3_program_address)
            .await
        {
            Ok(crisp) => break crisp,
            Err(error) => {
                warn!("Could not start the pending-discovery retry reader: {error}");
                sleep(Duration::from_secs(60)).await;
            }
        }
    };
    loop {
        let ids = match CurrentRoundRepository::new(store.clone())
            .get_round_ids()
            .await
        {
            Ok(ids) => ids,
            Err(error) => {
                warn!("Could not list rounds for pending discovery: {error}");
                sleep(Duration::from_secs(60)).await;
                continue;
            }
        };
        let mut owed = 0usize;
        for e3_id in ids {
            let mut repo = CrispE3Repository::new(store.clone(), &e3_id);
            let Ok(round) = repo.get_crisp().await else {
                continue;
            };
            match pending_discovery_step(&round) {
                PendingDiscoveryStep::Skip => continue,
                PendingDiscoveryStep::Forgive => {
                    if let Err(error) = repo.set_discovery_pending(false).await {
                        warn!(
                            "[e3_id={}] Could not clear pending discovery: {error}",
                            e3_id
                        );
                    }
                    continue;
                }
                PendingDiscoveryStep::Retry => {}
            }
            owed += 1;
            let Ok(e3_id_value) = e3_id_to_u256(&e3_id) else {
                continue;
            };
            // Only a CUSTOM-credit round has a divisor and a snapshot. Still unreadable: keep the
            // debt for the next pass.
            let stored = match round.credit_mode {
                CreditMode::Constant => None,
                CreditMode::Custom => match read_stored_scale(&crisp, e3_id_value, &e3_id).await {
                    None => continue,
                    stored => stored,
                },
            };
            match settle_pending_discovery(&mut repo, &e3_id, &round, stored).await {
                Ok(count) => {
                    info!(
                        "[e3_id={}] Pending holder discovery settled with {} holders",
                        e3_id, count
                    );
                    owed -= 1;
                }
                Err(error) => {
                    warn!(
                        "[e3_id={}] Pending holder discovery failed, will retry: {:#}",
                        e3_id, error
                    );
                }
            }
        }
        if owed == 0 {
            DISCOVERY_OWED.notified().await;
        } else {
            sleep(Duration::from_secs(60)).await;
        }
    }
}

/// Run the discovery a round was owed, store the holders, and clear the debt.
///
/// Returns the holder count. The debt is cleared only after the holders are stored, so a
/// failure between the two leaves the round owed rather than served an empty census. A Merkle
/// round also gets its root posted and its leaf hashes stored first.
async fn settle_pending_discovery<S: DataStore>(
    repo: &mut CrispE3Repository<S>,
    e3_id: &str,
    round: &E3Crisp,
    stored: Option<(U256, u64)>,
) -> eyre::Result<usize> {
    let custom_params = CustomParams {
        token_address: round.token_address.clone(),
        balance_threshold: round.balance_threshold.clone(),
        num_options: round.num_options.clone(),
        credit_mode: round.credit_mode,
        credits: round.credits.clone(),
        census_mode: round.census_mode,
        // The round does not retain the requested divisor. The stored value passed to
        // `discover_holders` is the source, and this field is informational.
        voting_power_divisor: "0".to_owned(),
    };
    let requester: Address = round
        .requester
        .parse()
        .with_context(|| "Invalid stored requester address")?;
    let token_address: Address = round
        .token_address
        .parse()
        .with_context(|| "Invalid stored token address")?;
    let balance_threshold = BigUint::parse_bytes(round.balance_threshold.as_bytes(), 10)
        .ok_or_else(|| eyre::eyre!("Invalid stored balance threshold"))?;
    let mut holders = discover_holders(
        e3_id,
        &custom_params,
        requester,
        token_address,
        round.snapshot_block,
        &balance_threshold,
        stored,
    )
    .await?;
    let count = holders.len();
    order_token_holders(&mut holders);
    if round.census_mode != CensusMode::Onchain {
        let hashes = compute_token_holder_hashes(&holders)?;
        ensure_merkle_root(e3_id, hashes.clone()).await?;
        repo.set_token_holder_hashes(hashes).await?;
    }
    repo.set_eligible_addresses(holders).await?;
    repo.set_discovery_pending(false).await?;
    Ok(count)
}

async fn recover_available_inputs<S: DataStore>(
    store: SharedStore<S>,
    availability: Arc<AvailabilityService>,
) {
    let interfold = match InterfoldContractFactory::create_read(
        &CONFIG.http_rpc_url,
        &CONFIG.interfold_address,
    )
    .await
    {
        Ok(interfold) => interfold,
        Err(error) => {
            warn!("Could not start the available-input recovery reader: {error}");
            return;
        }
    };
    loop {
        let mut terminal_e3s = HashMap::<String, bool>::new();
        let references = match availability.pending_input_references() {
            Ok(references) => references,
            Err(error) => {
                warn!("Could not scan durable available-input references: {error}");
                sleep(Duration::from_secs(30)).await;
                continue;
            }
        };
        for reference in references {
            let round = CrispE3Repository::new(store.clone(), &reference.e3_id);
            let status = round.get_status().await.ok();
            let locally_terminal =
                matches!(status.as_deref(), Some("CiphertextPublished" | "Finished"));
            let chain_terminal = if locally_terminal {
                false
            } else if let Some(terminal) = terminal_e3s.get(&reference.e3_id) {
                *terminal
            } else {
                let terminal = match e3_id_to_u256(&reference.e3_id) {
                    Ok(e3_id) => {
                        tokio::time::timeout(Duration::from_secs(15), interfold.get_e3_stage(e3_id))
                            .await
                            .is_ok_and(|result| {
                                result.as_ref().is_ok_and(stage_ends_input_retrieval)
                            })
                    }
                    Err(_) => false,
                };
                terminal_e3s.insert(reference.e3_id.clone(), terminal);
                terminal
            };
            if locally_terminal || chain_terminal {
                if let Err(error) = availability.complete_input_reference(&reference) {
                    warn!(
                        "[e3_id={}] Could not remove an obsolete input reference: {}",
                        reference.e3_id, error
                    );
                }
                continue;
            }
            match store_available_input(store.clone(), Arc::clone(&availability), reference.clone())
                .await
            {
                Ok(()) => {
                    // The scheduled deadline retries are finite. If Avail or its RPC was down
                    // through all of them, successful background retrieval must wake computation
                    // instead of leaving an otherwise complete round stranded forever.
                    tokio::spawn(resume_expired_round(reference.e3_id.clone(), store.clone()));
                }
                Err(error) => {
                    warn!(
                        "[e3_id={}] Input {} retrieval will retry: {}",
                        reference.e3_id, reference.index, error
                    );
                }
            }
        }
        sleep(Duration::from_secs(30)).await;
    }
}

/// Persist every log from a watched contract, so `/chain/logs` can answer from the store.
///
/// Untyped on purpose — see `log_repo`. A failed write IS propagated: the catch-up uses a handler
/// error to hold the cursor back, and an index that quietly missed a log while the cursor moved
/// past it answers later queries short while looking authoritative.
pub async fn register_log_index(
    indexer: InterfoldIndexer<impl DataStore, ReadWrite>,
    log_contracts: &[String],
) -> Result<InterfoldIndexer<impl DataStore, ReadWrite>> {
    // Lowercased once so the per-log membership test is a plain comparison.
    let wanted: Vec<String> = log_contracts.iter().map(|a| a.to_lowercase()).collect();

    indexer
        .add_raw_log_handler(move |log, ctx| {
            let mut repo = LogRepository::new(ctx.store());
            let wanted = wanted.clone();
            async move {
                // Watched for the typed handlers is not the same as wanted in the log index: a
                // busy token emits thousands of transfers nobody queries, and retaining them costs
                // storage and write amplification for nothing.
                if !wanted.contains(&log.address().to_string().to_lowercase()) {
                    return Ok(());
                }

                // A log with no block number or index cannot be placed. `unwrap_or_default()`
                // filed it at block 0, log 0 — a position that both collides with any other
                // unplaceable log and sits below every coverage record, so it would be silently
                // dropped from every query anyway. Skipping it is the same outcome, said out loud.
                let (Some(block_number), Some(log_index)) = (log.block_number, log.log_index)
                else {
                    warn!(
                        "Skipping a log with no block position from {}",
                        log.address()
                    );
                    return Ok(());
                };

                let stored = StoredLog {
                    removed: log.removed,
                    address: log.address().to_string(),
                    topics: log.topics().iter().map(|t| t.to_string()).collect(),
                    data: log.data().data.to_string(),
                    block_number,
                    transaction_hash: log.transaction_hash.map(|h| h.to_string()),
                    log_index,
                    block_hash: log.block_hash.map(|h| h.to_string()),
                    transaction_index: log.transaction_index,
                };

                // Propagated, not logged and dropped. The cursor is a claim that everything below
                // it has been applied, and `catch_up` relies on a handler error to stop the
                // cursor advancing past a failed window — swallowing this disarmed exactly that
                // safety net, and one transient store failure became a permanent hole underneath
                // an index that still reported the range as covered.
                repo.append(stored)
                    .await
                    .map_err(|e| eyre::eyre!("indexing a log failed: {e}"))?;

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
    availability: Arc<AvailabilityService>,
    private_key: &str,
    index_start_block: Option<u64>,
    index_chunk_size: Option<u64>,
    index_contracts: &[String],
    index_log_contracts: &[String],
) -> Result<()> {
    info!("CRISP: Creating indexer...");

    // The E3 stack, plus whatever the deployment asked to be readable through `/chain/*`. Watching
    // the extra addresses is what lets their logs be served from the store instead of forwarded
    // upstream on every request; the typed handlers below dispatch on event signature, so a
    // contract that emits nothing they recognise simply flows past them into the log index.
    //
    // `INDEX_LOG_CONTRACTS` is documented as a subset of `INDEX_CONTRACTS`, but nothing enforces
    // that, and an entry listed only there would never reach the subscription or the backfill
    // filter — while coverage was still recorded for it below. Every query for that address then
    // passed the coverage test and was answered from an empty index: an authoritative empty log
    // list. Watching the union costs nothing and removes the way to configure that.
    let mut watched: Vec<&str> = vec![contract_address, registry_address, crisp_address];
    for address in index_contracts.iter().chain(index_log_contracts.iter()) {
        if !watched.iter().any(|w| w.eq_ignore_ascii_case(address)) {
            watched.push(address);
        }
    }

    let recovery_store = store.clone();
    tokio::spawn(recover_available_inputs(
        recovery_store,
        Arc::clone(&availability),
    ));
    let crisp_indexer =
        InterfoldIndexer::new_with_write_contract(url, &watched, store, private_key).await?;
    info!("CRISP: Indexer registering handlers...");

    let crisp_indexer = register_e3_requested(crisp_indexer).await?;
    let crisp_indexer = register_ciphertext_output_published(crisp_indexer).await?;
    let crisp_indexer = register_ciphertext_output_reference_published(crisp_indexer).await?;
    let crisp_indexer = register_plaintext_output_published(crisp_indexer).await?;
    let crisp_indexer = register_committee_published(crisp_indexer).await?;
    let crisp_indexer = register_committee_public_key_chunks(crisp_indexer).await?;
    let crisp_indexer = register_input_committed(crisp_indexer, Arc::clone(&availability)).await?;
    let crisp_indexer = register_input_published(crisp_indexer, availability).await?;
    let crisp_indexer = register_log_index(crisp_indexer, index_log_contracts).await?;
    tokio::spawn(recover_round_deadlines(crisp_indexer.get_store()));
    tokio::spawn(retry_pending_discovery(crisp_indexer.get_store()));
    info!("CRISP: Indexer finished registering handlers!");

    // Resolve where indexing will ACTUALLY begin, ONCE, and drive both the backfill configuration
    // and the coverage claim from that single value.
    //
    // Reading it twice was a silent hole. Coverage used to come from `get_head_block_rpc` over the
    // HTTP URL, while the catch-up read its own head over the WebSocket URL later in startup —
    // possibly a different node, certainly a later moment. The HTTP read is the lower of the two,
    // which is the unsafe direction: coverage claimed blocks that indexing then skipped over, and
    // `ensure_coverage_from` never overwrites, so the wrong bound persisted for the life of the
    // database.
    //
    // Three cases:
    //
    //   - A resumed database already carries coverage from its first run, and the cursor may sit
    //     far above a since-lowered INDEX_START_BLOCK. Re-claiming the lower bound would assert
    //     history that will never be fetched, so existing coverage is left untouched.
    //   - INDEX_START_BLOCK set: that is the start, and the catch-up uses the same number.
    //   - Fresh database, nothing configured: read the head here and PIN the backfill to it, so
    //     the catch-up cannot resolve a different (later) start than the one claimed below.
    let store = crisp_indexer.get_store();

    // A read ERROR is not an absent record. `unwrap_or(None)` conflated them, so one transient
    // store failure made a resumed database look fresh — pinning the coverage claim to the current
    // head and discarding the record describing everything indexed so far. Propagated instead:
    // startup is exactly the moment a broken store should be loud, and every later decision here
    // is derived from this value.
    let resumed: Option<u64> = store
        .get(INDEXER_CURSOR_KEY)
        .await
        .map_err(|e| eyre::eyre!("reading the indexer cursor failed: {e}"))?;

    let start_block = match (resumed, index_start_block) {
        // `ensure_coverage_from` leaves an existing record alone, so this only fills a gap left by
        // an older database that predates log indexing.
        (Some(cursor), _) => Some(cursor.saturating_add(1)),
        (None, Some(configured)) => Some(configured),
        (None, None) => match crisp_indexer.head_block().await {
            Ok(head) => Some(head),
            Err(e) => {
                error!("Could not read the head to pin the index start: {e}");
                None
            }
        },
    };

    // Close the gap left by every restart and dropped socket before subscribing. On a resumed
    // database the stored cursor wins regardless of what is passed here; on a fresh one this pins
    // the start to the very block coverage is about to claim.
    crisp_indexer.configure_backfill(
        if resumed.is_some() {
            index_start_block
        } else {
            start_block
        },
        index_chunk_size,
    );

    // Record where the log index starts for each watched contract, before any log arrives, so a
    // contract that has emitted nothing yet does not look uncovered forever.
    {
        if !index_log_contracts.is_empty() {
            let coverage_from = start_block;

            if let Some(coverage_from) = coverage_from {
                // The set that was log-indexed on the previous run. An address present now but
                // absent then was not indexed during the gap, so whatever coverage its earlier
                // run left behind overstates what is in the store.
                //
                // An Err here must NOT read as "no previous set". That would mark every address
                // newly added and narrow its coverage to the current head — permanently discarding
                // the record for history that is still sitting in the store, so `/chain/logs`
                // would stop serving a range it can answer perfectly well. On a read failure the
                // rebase is skipped entirely: leaving a claim alone is recoverable, narrowing one
                // wrongly is not.
                let previous: Option<Vec<String>> = match store.get(LOG_INDEX_CONFIG_KEY).await {
                    Ok(previous) => Some(previous.unwrap_or_default()),
                    Err(e) => {
                        error!(
                            "Could not read the previous log-index configuration: {e}. Leaving \
                             every coverage record as it stands this run."
                        );
                        None
                    }
                };

                let mut repo = LogRepository::new(store.clone());
                for address in index_log_contracts {
                    // Unknown previous set ⇒ treated as already indexed, which only ever widens
                    // what is claimed by filling a missing record, never narrows an existing one.
                    let was_indexed = previous.as_ref().is_none_or(|previous| {
                        previous
                            .iter()
                            .any(|entry| entry.eq_ignore_ascii_case(address))
                    });

                    let recorded = if was_indexed {
                        repo.ensure_coverage_from(address, coverage_from).await
                    } else {
                        // Newly added (or re-added after a removal): claim only from here on.
                        repo.rebase_coverage(address, coverage_from)
                            .await
                            .and(repo.ensure_coverage_from(address, coverage_from).await)
                    };

                    if let Err(e) = recorded {
                        error!("Could not record log coverage for {address}: {e}");
                    }
                }

                // Only when the comparison above actually happened. Recording the current set
                // after a failed read would tell the NEXT run that every address was already
                // indexed, so an address genuinely added during this run would never have its
                // stale coverage narrowed — the read failure would outlive itself.
                if previous.is_some() {
                    let mut store = store;
                    let current: Vec<String> = index_log_contracts.to_vec();
                    if let Err(e) = store.insert(LOG_INDEX_CONFIG_KEY, &current).await {
                        error!("Could not record the log-index configuration: {e}");
                    }
                }
            }
        }
    }

    restore_round_deadline_callbacks(&crisp_indexer).await?;
    crisp_indexer.listen().await?;
    info!("CRISP: Indexer listen loop has finished!");
    Ok(())
}

#[cfg(test)]
mod census_order_tests {
    use super::order_token_holders;
    use crate::server::{models::TokenHolder, token_holders::hashes::compute_token_holder_hashes};

    #[test]
    fn the_same_voters_produce_the_same_leaf_order_after_replay() {
        let mut first = vec![
            TokenHolder {
                address: "0x0000000000000000000000000000000000000002".to_string(),
                balance: "1".to_string(),
            },
            TokenHolder {
                address: "0x0000000000000000000000000000000000000001".to_string(),
                balance: "1".to_string(),
            },
        ];
        let mut replay = first.clone();
        replay.reverse();

        order_token_holders(&mut first);
        order_token_holders(&mut replay);

        assert_eq!(first, replay);
        assert_eq!(
            compute_token_holder_hashes(&first).unwrap(),
            compute_token_holder_hashes(&replay).unwrap()
        );
    }
}

#[cfg(test)]
mod e3_request_tests {
    use super::{
        deadline_attempt_times, is_configured_e3_program, stage_ends_input_retrieval, E3Stage,
    };
    use alloy::primitives::Address;

    #[test]
    fn e3_requests_only_match_the_configured_program() {
        let configured = Address::repeat_byte(0x11);

        assert!(is_configured_e3_program(configured, configured));
        assert!(!is_configured_e3_program(
            Address::repeat_byte(0x22),
            configured
        ));
    }

    #[test]
    fn restart_spreads_overdue_deadline_attempts_from_now() {
        assert_eq!(deadline_attempt_times(100, 200), [200, 260, 380, 620]);
        assert_eq!(deadline_attempt_times(300, 200), [300, 360, 480, 720]);
    }

    #[test]
    fn terminal_chain_stages_release_input_retrievals() {
        assert!(stage_ends_input_retrieval(&E3Stage::CiphertextReady));
        assert!(stage_ends_input_retrieval(&E3Stage::Complete));
        assert!(stage_ends_input_retrieval(&E3Stage::Failed));
        assert!(!stage_ends_input_retrieval(&E3Stage::KeyPublished));
    }
}

#[cfg(test)]
mod stored_divisor_tests {
    use super::read_stored_scale;
    use alloy::primitives::{bytes, Address, B256, U256};
    use alloy::providers::{ext::AnvilApi, ProviderBuilder};
    use evm_helpers::CRISPContractFactory;
    use std::time::Duration;

    /// `CRISPProgram` never stores a zero divisor for a CUSTOM-credit round. A zero read is a node
    /// that does not have the request block yet. Taking it as final defers the census to the retry
    /// pass.
    #[tokio::test]
    async fn a_zero_read_from_a_lagging_node_is_retried() {
        let anvil = alloy::node_bindings::Anvil::new().try_spawn().unwrap();
        let node = ProviderBuilder::new().connect_http(anvil.endpoint_url());
        let program = Address::repeat_byte(1);
        // PUSH1 0 SLOAD PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN: every call returns slot 0.
        node.anvil_set_code(program, bytes!("60005460005260206000f3"))
            .await
            .unwrap();
        let crisp = CRISPContractFactory::create_read(&anvil.endpoint(), &program.to_string())
            .await
            .unwrap();

        // The first read sees zero; the slot is set before the retry 2 s later.
        let (stored, _) = tokio::join!(read_stored_scale(&crisp, U256::from(1), "1"), async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            node.anvil_set_storage_at(program, U256::ZERO, B256::with_last_byte(5))
                .await
                .unwrap()
        });
        assert_eq!(stored, Some((U256::from(5), 5)));
    }
}

#[cfg(test)]
mod pending_discovery_tests {
    use super::{holders_or_owed, pending_discovery_step, store_census, PendingDiscoveryStep};
    use crate::server::models::{CensusMode, CreditMode, CustomParams, E3Crisp, TokenHolder};
    use crate::server::repo::CrispE3Repository;
    use alloy_primitives::Address;
    use e3_sdk::indexer::{InMemoryStore, SharedStore};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn round(status: &str, pending: bool) -> E3Crisp {
        E3Crisp {
            emojis: ["one".to_string(), "two".to_string()],
            start_time: 0,
            voting_end_time: 100,
            end_time: 100,
            status: status.to_string(),
            tally: vec![],
            token_holder_hashes: vec![],
            eligible_addresses: vec![],
            token_address: "0x0000000000000000000000000000000000000001".to_string(),
            balance_threshold: "1".to_string(),
            ciphertext_inputs: vec![],
            input_commitments: vec![],
            input_slots: vec![],
            input_usable: vec![],
            input_parents: vec![],
            input_ciphertext_hashes: vec![],
            requester: "0x0000000000000000000000000000000000000002".to_string(),
            num_options: "2".to_string(),
            credit_mode: CreditMode::Constant,
            credits: Some("1".to_string()),
            snapshot_block: 1,
            census_mode: CensusMode::Onchain,
            discovery_pending: pending,
            e3_program: String::new(),
        }
    }

    /// Zenith #19 follow-up. A round registered without a census because its divisor could not
    /// be read is retried while ballots can still be masked, and forgiven once they cannot.
    #[test]
    fn discovery_is_retried_only_while_the_round_is_votable() {
        assert_eq!(
            pending_discovery_step(&round("Requested", true)),
            PendingDiscoveryStep::Retry
        );
        assert_eq!(
            pending_discovery_step(&round("Active", true)),
            PendingDiscoveryStep::Retry
        );
        for ended in [
            "Expired",
            "Computing",
            "PublishingCiphertext",
            "Finished",
            "Failed",
        ] {
            assert_eq!(
                pending_discovery_step(&round(ended, true)),
                PendingDiscoveryStep::Forgive,
                "{ended}"
            );
        }
        assert_eq!(
            pending_discovery_step(&round("Requested", false)),
            PendingDiscoveryStep::Skip
        );
    }

    /// A failed discovery owes a retry, and the debt is in the store, not in the handler. A round
    /// whose `E3Requested` arrives again and fails discovery keeps the census it holds: voters
    /// still need its leaf hashes to prove membership against the posted root.
    #[tokio::test]
    async fn a_failed_discovery_owes_a_retry_and_keeps_the_stored_census() {
        let store = SharedStore::new(Arc::new(RwLock::new(InMemoryStore::new())));
        let mut repo = CrispE3Repository::new(store.clone(), "7");
        let params = CustomParams {
            token_address: "0x0000000000000000000000000000000000000001".to_string(),
            balance_threshold: "1".to_string(),
            num_options: "2".to_string(),
            credit_mode: CreditMode::Constant,
            credits: Some("1".to_string()),
            census_mode: CensusMode::Token,
            voting_power_divisor: "0".to_string(),
        };
        repo.initialize_round(
            params,
            Address::ZERO,
            "0x0000000000000000000000000000000000000002".into(),
            100,
            100,
            1,
        )
        .await
        .unwrap();
        let holders = vec![TokenHolder {
            address: "0x0000000000000000000000000000000000000003".to_string(),
            balance: "5".to_string(),
        }];
        let leaves = store_census(&mut repo, holders.clone(), false, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            pending_discovery_step(&repo.get_crisp().await.unwrap()),
            PendingDiscoveryStep::Skip
        );

        assert_eq!(
            store_census(&mut repo, Vec::new(), false, true)
                .await
                .unwrap(),
            None
        );
        let replayed = CrispE3Repository::new(store.clone(), "7")
            .get_crisp()
            .await
            .unwrap();
        assert_eq!(replayed.eligible_addresses, holders);
        assert_eq!(replayed.token_holder_hashes, leaves);
        assert_eq!(
            pending_discovery_step(&replayed),
            PendingDiscoveryStep::Retry
        );
    }

    /// A stored round written before the field existed decodes as not pending: those rounds
    /// were registered by a handler that failed outright rather than deferred, so there is no
    /// debt to invent.
    #[test]
    fn a_legacy_round_owes_no_discovery() {
        let mut encoded = serde_json::to_value(round("Active", true)).unwrap();
        encoded.as_object_mut().unwrap().remove("discovery_pending");
        let decoded: E3Crisp = serde_json::from_value(encoded).unwrap();
        assert!(!decoded.discovery_pending);
    }

    /// The `E3Requested` log is not replayed, so a census-tree round whose discovery failed and
    /// was not recorded as owed would never get a root, and nobody could vote in it.
    #[test]
    fn a_failed_census_tree_discovery_is_owed_rather_than_fatal() {
        let (holders, owed) = holders_or_owed("1", false, Err(eyre::eyre!("rate limited")));
        assert!(holders.is_empty());
        assert!(owed);
    }
}

#[cfg(test)]
mod plaintext_output_tests {
    use super::record_plaintext_output;
    use crate::server::models::{CensusMode, CreditMode, CustomParams, E3Crisp};
    use crate::server::repo::{CrispE3Repository, CRISP_KEY_PREFIX};
    use alloy_primitives::Address;
    use crisp_utils::MAX_MSG_NON_ZERO_COEFFS;
    use e3_sdk::indexer::{DataStore, InMemoryStore, SharedStore};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    /// Each `CRISPProgram` deployment fixes the ballot layout of its rounds, and the server decodes
    /// its own layout only. A round of another program, or a round stored without its program,
    /// finishes with an empty tally. The server does not read it under the wrong layout. A round
    /// without a record stays without one, and its event does not fail the indexer.
    #[tokio::test]
    async fn only_a_round_of_the_configured_program_gets_a_tally() {
        let configured = Address::repeat_byte(0x11);
        let store = SharedStore::new(Arc::new(RwLock::new(InMemoryStore::new())));
        let params = || CustomParams {
            token_address: "0x0000000000000000000000000000000000000001".to_string(),
            balance_threshold: "1".to_string(),
            num_options: "2".to_string(),
            credit_mode: CreditMode::Constant,
            credits: Some("1".to_string()),
            census_mode: CensusMode::Token,
            voting_power_divisor: "0".to_string(),
        };
        // One little-endian u64 per coefficient: 3 on option 0 and 5 on option 1.
        let mut output = vec![0u8; 8 * MAX_MSG_NON_ZERO_COEFFS];
        output[0] = 3;
        output[8] = 5;

        for (e3_id, program, keeps_program, tally) in [
            ("1", configured, true, vec!["3", "5"]),
            ("2", Address::repeat_byte(0x22), true, vec![]),
            ("3", configured, false, vec![]),
        ] {
            let mut repo = CrispE3Repository::new(store.clone(), e3_id);
            repo.initialize_round(params(), program, "requester".to_string(), 100, 100, 1)
                .await
                .unwrap();
            if !keeps_program {
                // A stored record without `e3_program` decodes it as empty.
                store
                    .clone()
                    .modify(
                        &format!("{CRISP_KEY_PREFIX}{e3_id}"),
                        |round: Option<E3Crisp>| {
                            round.map(|mut round| {
                                round.e3_program.clear();
                                round
                            })
                        },
                    )
                    .await
                    .unwrap();
            }

            record_plaintext_output(&mut repo, e3_id, &output, configured)
                .await
                .unwrap();

            let round = repo.get_crisp().await.unwrap();
            assert_eq!(round.tally, tally, "round {e3_id}");
            assert_eq!(round.status, "Finished", "round {e3_id}");
        }

        // The server stores no record for a round that another program requested.
        let mut repo = CrispE3Repository::new(store.clone(), "4");
        record_plaintext_output(&mut repo, "4", &output, configured)
            .await
            .unwrap();
        assert!(!repo.has_crisp_record().await.unwrap());
    }
}
