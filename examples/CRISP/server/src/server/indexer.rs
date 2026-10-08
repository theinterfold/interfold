// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::supervise;
use crate::server::log_repo::{LogRepository, StoredLog};
use crate::server::models::e3_id_to_u256;
use crate::server::token_holders::{
    get_mock_token_holders, try_fetch_requester_census, EtherscanClient,
};
use crate::server::{
    data_availability::{AvailabilityService, AvailableInputReference},
    models::{CensusMode, CreditMode, CurrentRound, CustomParams, E3Crisp, TokenHolder},
    program_server_request::run_compute,
    repo::{CrispE3Repository, CurrentRoundRepository, InputSnapshot},
    rpc,
    token_holders::{build_tree, compute_token_holder_hashes},
    CONFIG,
};
use alloy::hex::encode_prefixed;
use alloy::sol_types::{sol_data, SolType};
use alloy_primitives::{Address, U256};
use crisp_utils::decode_tally;
use e3_fhe_params::decode_bfv_params_arc;
use e3_sdk::indexer::INDEXER_CURSOR_KEY;
use e3_sdk::{
    evm_helpers::{
        contracts::{
            E3Stage, InterfoldContract, InterfoldContractFactory, InterfoldRead, ReadOnly,
            ReadWrite,
        },
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
    CRISPContract, CRISPContractFactory, CRISPReadProvider, CRISPWriteProvider, InputCommitted,
    InputPublished,
};
use eyre::{bail, eyre, Context};
use log::{error, info, warn};
use std::time::Duration;
use std::{collections::HashMap, fmt::Display, future::Future, sync::Arc, sync::LazyLock};
use tokio::{sync::Notify, time::sleep};

const REQUESTED: &str = "Requested";
const ACTIVE: &str = "Active";
const EXPIRED: &str = "Expired";
const COMPUTING: &str = "Computing";
const PUBLISHING_CIPHERTEXT: &str = "PublishingCiphertext";
const CIPHERTEXT_PUBLISHED: &str = "CiphertextPublished";
const FINISHED: &str = "Finished";

/// Wakes `retry_pending_discovery` when a round records a missing census.
static DISCOVERY_OWED: LazyLock<Notify> = LazyLock::new(Notify::new);

/// Attempts of a read that needs the block of an `E3Requested` event: `getE3`, and the stored
/// divisor of a CUSTOM-credit round.
///
/// The subscription delivers the event when one node has the block, but the HTTP provider spreads
/// reads over nodes that can trail it by most of a block. Until they catch up, `getE3` reverts
/// with `E3DoesNotExist` and the stored divisor reads as zero. Five attempts wait
/// 2 + 4 + 8 + 16 = 30 s, which covers more than two Sepolia blocks. Nothing retries a live
/// handler error, so a shorter `getE3` wait loses the round. A shorter divisor wait defers the
/// census to the retry pass.
const E3_VISIBLE_ATTEMPTS: u32 = 5;

/// Upper bound on one contract read. The CRISP and Interfold contract readers carry their own
/// HTTP client, so they need this bound; the shared `rpc` providers already have one.
const READ_TIMEOUT: Duration = rpc::UPSTREAM_TIMEOUT;

/// Upper bound on a `setMerkleRoot` transaction, receipt included.
const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(300);

/// Seconds after the first deadline pass at which the handler runs again.
///
/// Each offset is a separate `do_later` registration made when the round starts: `do_later` drops a
/// callback once it has run, so a handler that failed cannot re-arm itself. The offsets exceed the
/// indexer wait inside the handler, so two passes do not overlap.
const DEADLINE_ATTEMPT_OFFSETS: [u64; 4] = [0, 60, 180, 420];

const ROUND_ACTIVATION_RETRY_OFFSETS: [u64; 5] = [1, 5, 30, 120, 600];

/// Store key holding the `INDEX_LOG_CONTRACTS` set of the previous run.
///
/// Coverage records outlive the configuration that made them and the store cannot delete. This set
/// lets a restart tell an address that was indexed continuously from one that is back after a gap,
/// so the second narrows its coverage claim instead of asserting history nobody fetched.
const LOG_INDEX_CONFIG_KEY: &str = "_logs:_config";

fn report(error: impl Display) -> eyre::Report {
    eyre!("{error:#}")
}

async fn within<T>(
    limit: Duration,
    call: impl Future<Output = eyre::Result<T>>,
) -> eyre::Result<T> {
    tokio::time::timeout(limit, call)
        .await
        .map_err(|_| eyre!("the call did not finish within {limit:?}"))?
}

fn unix_now() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0)
}

async fn crisp_read() -> eyre::Result<CRISPContract<CRISPReadProvider>> {
    CRISPContractFactory::create_read(&CONFIG.http_rpc_url, &CONFIG.e3_program_address)
        .await
        .context("Failed to create the CRISP contract reader")
}

async fn crisp_write() -> eyre::Result<CRISPContract<CRISPWriteProvider>> {
    CRISPContractFactory::create_write(
        &CONFIG.http_rpc_url,
        &CONFIG.e3_program_address,
        &CONFIG.private_key,
    )
    .await
    .context("Failed to create the CRISP contract writer")
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
            within(READ_TIMEOUT, crisp.stored_voting_power_scale(e3_id))
                .await
                .map_err(|error| anyhow::anyhow!("{error:#}"))?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "the provider holds no stored divisor and snapshot for the round"
                    )
                })
        },
    )
    .await
    .inspect_err(|error| {
        warn!(
            "[e3_id={label}] Failed to read the stored voting-power divisor and snapshot after \
             retries: {error:#}"
        )
    })
    .ok()
}

/// Discover the holders a client draws mask targets from.
///
/// Asked only when the round declared it. Probing every requester and falling back on failure
/// would turn a broken census provider into a token vote over the wrong electorate, silently. A
/// declared census is checked before the local-network branch because it is exact on any network.
/// Etherscan being down carries no eligibility meaning for an on-chain round: the contract reads
/// power per input, so the only cost is mask cover.
///
/// The `E3Requested` handler and the retry pass for a round registered without a census share this
/// function, so both refuse the same lists. `stored` is the divisor and snapshot of a CUSTOM-credit
/// round, or `None` for a CONSTANT-credit round. A CUSTOM-credit census is read at that snapshot,
/// not at `snapshot_timepoint`: the divisor bounds the census sum only at the timepoint whose
/// supply sized it. Off a local chain, a CUSTOM-credit round without them fails discovery.
async fn discover_holders(
    e3_id: &str,
    params: &CustomParams,
    requester: Address,
    snapshot_timepoint: u64,
    stored: Option<(U256, u64)>,
) -> eyre::Result<Vec<TokenHolder>> {
    let credits = match (params.credit_mode, params.credits.as_deref()) {
        (CreditMode::Constant, Some(credits)) => Some(credits),
        (CreditMode::Constant, None) => {
            bail!("[e3_id={e3_id}] a Constant-credit round carries no credits")
        }
        (CreditMode::Custom, _) => None,
    };

    let holders = if params.census_mode == CensusMode::ByRequester {
        // A requester-supplied census names who may vote, not how much a vote weighs, so it only
        // means something when every voter carries the same credits. `CRISPProgram.validate`
        // rejects the other pairing on chain, so reaching it means a different program.
        let Some(credits) = credits else {
            bail!(
                "[e3_id={e3_id}] CensusMode::ByRequester requires CreditMode::Constant; got Custom"
            )
        };
        info!("[e3_id={e3_id}] Census mode: ByRequester; asking {requester}");
        let census = try_fetch_requester_census(requester, e3_id, &CONFIG.http_rpc_url)
            .await
            .ok_or_else(|| {
                eyre!(
                    "[e3_id={e3_id}] Round declared CensusMode::ByRequester but requester \
                     {requester} returned no census. Refusing to fall back to token discovery, \
                     which would enfranchise the wrong voters."
                )
            })?;
        census
            .into_iter()
            .map(|address| TokenHolder {
                address: address.to_string(),
                balance: credits.to_string(),
            })
            .collect()
    } else if CONFIG.is_local_chain() {
        info!(
            "[e3_id={e3_id}] Using mocked token holders for local network (chain_id: {})",
            CONFIG.chain_id
        );
        // A CONSTANT round carries its credits, as on every other chain. A CUSTOM round gets 1, so
        // ten accounts stay below the plaintext modulus of every preset.
        get_mock_token_holders(credits.unwrap_or("1"))
    } else {
        info!(
            "[e3_id={e3_id}] Using Etherscan API for network (chain_id: {})",
            CONFIG.chain_id
        );
        let token_address: Address = params
            .token_address
            .parse()
            .context("Invalid token address")?;
        let client = EtherscanClient::new(CONFIG.etherscan_api_key.clone(), CONFIG.chain_id);
        let discovery = match credits {
            Some(credits) => {
                let credits = U256::from_str_radix(credits, 10)
                    .map_err(|error| eyre!("Failed to parse credits: {error}"))?;
                client
                    .get_token_holders_with_constant_balance(
                        token_address,
                        snapshot_timepoint,
                        &CONFIG.http_rpc_url,
                        credits,
                    )
                    .await
            }
            None => {
                let (divisor, snapshot) = stored.ok_or_else(|| {
                    eyre!(
                        "[e3_id={e3_id}] No voting-power divisor and snapshot are known for this \
                         CUSTOM-credit round, so the census cannot be built in the units the \
                         contract reads back."
                    )
                })?;
                let threshold =
                    U256::from_str_radix(&params.balance_threshold, 10).map_err(|error| {
                        eyre!(
                            "[e3_id={e3_id}] Failed to convert balance threshold to U256: {error}"
                        )
                    })?;
                client
                    .get_token_holders_with_voting_power(
                        token_address,
                        snapshot,
                        &CONFIG.http_rpc_url,
                        threshold,
                        divisor,
                    )
                    .await
            }
        };
        discovery.context("Etherscan token-holder discovery failed")?
    };

    // A census-tree list is the electorate, so an empty one admits no ballot and fails discovery.
    // An on-chain list only indexes mask targets, so the handler warns about an empty one instead.
    if holders.is_empty() && params.census_mode != CensusMode::Onchain {
        bail!(
            "[e3_id={e3_id}] No eligible token holders found for token address {}.",
            params.token_address
        );
    }
    Ok(holders)
}

/// The holders to register a round with, and whether its discovery is still owed.
///
/// A failed discovery never drops the round: the `E3Requested` log is not replayed once the cursor
/// passes it, so the round registers and the retry pass builds the census. The cause is usually
/// transient (a rate limit, a rejected API key). An on-chain round stays votable meanwhile. A new
/// census-tree round takes no ballot until the retry pass posts its root.
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
            "[e3_id={e3_id}] CensusMode::Onchain holder discovery failed: {error:#}. The round is \
             recorded and votable, but clients have no mask targets until a retry succeeds."
        );
    } else {
        warn!(
            "[e3_id={e3_id}] Census discovery failed: {error:#}. The round keeps any census it \
             holds, and a new round takes no ballot until a retry posts its root."
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
    let tree = build_tree(token_holder_hashes).context("Failed to build tree")?;
    let merkle_root = tree
        .root()
        .ok_or_else(|| eyre!("Failed to get merkle root from tree"))?;
    info!("[e3_id={e3_id}] Merkle root: {merkle_root}");
    let merkle_root_bytes = hex::decode(&merkle_root)
        .with_context(|| format!("[e3_id={e3_id}] Merkle root is not valid hex"))?;
    let merkle_root = U256::from_be_slice(&merkle_root_bytes);
    let e3_id_u256 = U256::from_str_radix(e3_id, 10)
        .with_context(|| format!("[e3_id={e3_id}] Invalid E3 ID"))?;
    info!("[e3_id={e3_id}] Ensuring CRISPProgram Merkle root: {merkle_root}");

    let contract = crisp_write().await?;
    let stored_root = within(READ_TIMEOUT, contract.get_merkle_root(e3_id_u256)).await?;
    if stored_root == merkle_root {
        info!("[e3_id={e3_id}] Merkle root is already set to the expected value");
    } else if stored_root.is_zero() {
        match within(
            TRANSACTION_TIMEOUT,
            contract.set_merkle_root(e3_id_u256, merkle_root),
        )
        .await
        {
            Ok(receipt) => info!(
                "[e3_id={e3_id}] setMerkleRoot successful. TxHash: {:?}",
                receipt.transaction_hash
            ),
            Err(error) => {
                // A live subscription and its overlap replay can race here. Accept the losing
                // transaction only when the desired root landed.
                let landed = within(READ_TIMEOUT, contract.get_merkle_root(e3_id_u256))
                    .await
                    .is_ok_and(|root| root == merkle_root);
                if !landed {
                    return Err(error)
                        .with_context(|| format!("[e3_id={e3_id}] Failed to call setMerkleRoot"));
                }
                info!("[e3_id={e3_id}] Merkle root was set by a concurrent handler");
            }
        }
    } else {
        bail!(
            "[e3_id={e3_id}] CRISPProgram has a different Merkle root: expected {merkle_root}, got {stored_root}"
        );
    }
    Ok(())
}

async fn handle_e3_requested<S: DataStore>(
    event: E3Requested,
    ctx: Arc<IndexerContext<S, ReadWrite>>,
    configured_program: Address,
) -> eyre::Result<()> {
    let e3_id = event.e3Id.to_string();
    if event.e3.e3Program != configured_program {
        info!(
            "[e3_id={e3_id}] Ignoring E3Requested for unrelated program {}",
            event.e3.e3Program
        );
        return Ok(());
    }
    info!("[e3_id={e3_id}] E3Requested: {event:?}");

    let store = ctx.store();
    let mut repo = CrispE3Repository::new(store.clone(), &e3_id);
    let contract = ctx.contract();

    // 0xcd6f4a4f = E3DoesNotExist()
    let e3 = call_with_retry_attempts("get_e3", &["0xcd6f4a4f"], E3_VISIBLE_ATTEMPTS, || async {
        within(READ_TIMEOUT, contract.get_e3(event.e3Id))
            .await
            .map_err(|error| anyhow::anyhow!("{error:#}"))
    })
    .await
    .map_err(report)?;

    // The seventh field is the requested voting-power divisor: the contract stores a non-zero
    // request for a CUSTOM-credit round and computes the minimum divisor for a zero request.
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
        .context("Failed to decode custom params from E3 event")?;

    // `saturating_to`, not `to`: these fields are attacker-chosen ABI data and `to::<u64>()`
    // panics above `u64::MAX`. Clamping lets the `TryFrom` impls reject an unknown mode.
    let credit_mode = CreditMode::try_from(decoded.3.saturating_to::<u64>())?;
    let census_mode = CensusMode::try_from(decoded.5.saturating_to::<u64>())?;
    let credits = match credit_mode {
        CreditMode::Constant => Some(decoded.4.to_string()),
        CreditMode::Custom => None,
    };
    info!("[e3_id={e3_id}] Credit mode: {credit_mode:?}");

    let custom_params = CustomParams {
        token_address: decoded.0.to_string(),
        balance_threshold: decoded.1.to_string(),
        num_options: decoded.2.to_string(),
        credit_mode,
        credits,
        census_mode,
        voting_power_divisor: decoded.6.to_string(),
    };

    let input_deadline = e3.inputWindow[1].saturating_to::<u64>();
    let crisp = crisp_read().await?;
    let voting_end_time = within(READ_TIMEOUT, crisp.input_commitment_deadline(event.e3Id))
        .await
        .with_context(|| format!("[e3_id={e3_id}] Failed to read the input commitment deadline"))?;

    // The census is built one tick before the request, as the request timepoint itself is not
    // final when the E3 is requested. `requestBlock` is a timestamp, not a block height: the
    // ticket token runs an EIP-6372 `mode=timestamp` clock, and `Interfold.request` assigns
    // `block.timestamp` to match the checkpoints it is compared against.
    let snapshot_timepoint = event
        .e3
        .requestBlock
        .saturating_to::<u64>()
        .saturating_sub(1);

    // An on-chain census is not an eligibility input: `_eligibility` reads each voter's power with
    // `getPastVotes` when the input is published and never reads `merkleRoot`, so no root is
    // posted. The holder list is still discovered and stored, because a mask is written to someone
    // else's slot and clients need a list of who holds power to draw targets from. An omission
    // costs mask cover and cannot enfranchise anyone the contract would refuse. For a Merkle round
    // the list is the electorate, so an omission disenfranchises.
    let is_onchain_census = custom_params.census_mode == CensusMode::Onchain;
    if is_onchain_census {
        info!("[e3_id={e3_id}] CensusMode::Onchain: discovering holders for mask targets only");
    }

    // Only a CUSTOM-credit round stores a divisor and a snapshot. Without them the census cannot
    // be built in the units the contract reads back, so the round registers and its discovery
    // moves to the retry pass. An `Err` here would drop the round: the live listener logs it and
    // moves on.
    let stored = if custom_params.credit_mode == CreditMode::Custom {
        read_stored_scale(&crisp, event.e3Id, &e3_id).await
    } else {
        None
    };
    let divisor_unavailable = custom_params.credit_mode == CreditMode::Custom && stored.is_none();
    if divisor_unavailable {
        warn!(
            "[e3_id={e3_id}] The stored voting-power divisor and snapshot are unavailable. \
             Registering the round without holder discovery rather than building a census in \
             units the contract may not use."
        );
    }

    let discovery = if divisor_unavailable {
        Ok(Vec::new())
    } else {
        discover_holders(
            &e3_id,
            &custom_params,
            e3.requester,
            snapshot_timepoint,
            stored,
        )
        .await
    };
    let (mut token_holders, discovery_failed) =
        holders_or_owed(&e3_id, is_onchain_census, discovery);

    // `discover_holders` refuses an empty census-tree list. An empty on-chain list costs mask cover
    // and nothing else, so the round goes ahead.
    if is_onchain_census && token_holders.is_empty() && !divisor_unavailable && !discovery_failed {
        warn!(
            "[e3_id={e3_id}] CensusMode::Onchain discovery found no holders for {}. The round is \
             recorded and votable, but clients have no mask targets to draw from.",
            custom_params.token_address
        );
    }

    // The Merkle root must not depend on HashMap iteration order or RPC log order: a retry must
    // produce the same root from the same snapshot.
    order_token_holders(&mut token_holders);

    repo.initialize_round(
        custom_params,
        event.e3.e3Program,
        e3.requester.to_string(),
        voting_end_time,
        input_deadline,
        snapshot_timepoint,
    )
    .await?;

    // Store the census, or record the debt so `retry_pending_discovery` settles it later. The
    // debt covers a discovery skipped for want of a divisor and one that ran and failed. The event
    // is not replayed once the cursor passes it, so nothing else would retry.
    let owed = divisor_unavailable || discovery_failed;
    let root_leaves = store_census(&mut repo, token_holders, is_onchain_census, owed).await?;

    CurrentRoundRepository::new(store)
        .record_round(&e3_id)
        .await?;

    // Wake the retry task only after `record_round`: it sleeps when nothing is owed, so waking it
    // before the round is listed lets it find nothing and sleep with the debt unpaid. `notify_one`
    // keeps a permit, so one task serves every debt.
    if owed {
        DISCOVERY_OWED.notify_one();
    }

    // No leaves for an on-chain census (nothing consults a root) or an owed one (the retry pass
    // posts its root).
    if let Some(leaves) = root_leaves {
        ensure_merkle_root(&e3_id, leaves).await?;
    }

    // Committee and request handlers run concurrently for live logs. If the key was indexed while
    // census preparation was still running, this closes that race.
    activate_round_if_ready(&e3_id, &ctx).await?;
    Ok(())
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
/// Polls because the deadline callback and the last `InputPublished` handler race, and the gap is
/// the few seconds one log needs to be delivered and stored. Both counts are re-read on every
/// attempt: re-reading only the chain would compare a moving number against a fixed one and never
/// converge. Returns the last pair when they never agree, so the caller reports the shortfall.
async fn wait_for_indexed_inputs<S: DataStore>(
    e3_id: &str,
    repo: &CrispE3Repository<S>,
) -> eyre::Result<IndexedInputs> {
    const ATTEMPTS: u32 = 10;
    const INTERVAL: Duration = Duration::from_secs(3);

    let e3_id_u256 = e3_id_to_u256(e3_id).map_err(report)?;
    let contract = crisp_read().await?;

    let mut attempt = 0;
    loop {
        let published = usize::try_from(
            within(READ_TIMEOUT, contract.get_published_input_count(e3_id_u256)).await?,
        )?;
        let snapshot = repo.get_input_snapshot().await?;
        let indexed = snapshot.ciphertexts.len();

        // Fewer entries means an accepted input is missing. More means the local index holds data
        // the contract did not accept. Either makes the OpenVM input root differ from the
        // contract's root, so equality is required.
        if indexed == published {
            return Ok(IndexedInputs::Complete(snapshot));
        }
        if attempt == ATTEMPTS {
            return Ok(IndexedInputs::Mismatch { indexed, published });
        }
        attempt += 1;
        info!("[e3_id={e3_id}] waiting for the indexer: {indexed} of {published} input(s) stored");
        sleep(INTERVAL).await;
    }
}

fn deadline_attempt_times(expiration: u64, now: u64) -> [u64; 4] {
    let first = expiration.max(now);
    DEADLINE_ATTEMPT_OFFSETS.map(|offset| first.saturating_add(offset))
}

/// One scheduled deadline pass. Failures are logged, not returned: `do_later` drops the callback
/// either way, and the other offsets retry.
async fn deadline_pass<S: DataStore>(e3_id: String, store: SharedStore<S>) -> eyre::Result<()> {
    if let Err(error) = handle_e3_input_deadline_expiration(e3_id.clone(), store).await {
        error!("[e3_id={e3_id}] CRISP deadline pass failed: {error:#}");
    }
    Ok(())
}

/// Start the round and register its deadline passes, once its record and verified key exist.
/// Returns whether the round is active.
async fn activate_round_if_ready<S: DataStore>(
    e3_id: &str,
    ctx: &Arc<IndexerContext<S, ReadWrite>>,
) -> eyre::Result<bool> {
    let store = ctx.store();
    let mut repo = CrispE3Repository::new(store.clone(), e3_id);
    if !repo.has_crisp_record().await? || !repo.has_indexed_public_key().await? {
        return Ok(false);
    }

    let expiration = repo.get_input_deadline().await?;
    if !repo.try_start_round().await? {
        return Ok(true);
    }

    for at in deadline_attempt_times(expiration, unix_now()) {
        let e3_id = e3_id.to_string();
        ctx.do_later(at, move |_, ctx| deadline_pass(e3_id.clone(), ctx.store()));
    }

    CurrentRoundRepository::new(store)
        .set_current_round(CurrentRound {
            id: e3_id.to_string(),
        })
        .await?;
    info!("[e3_id={e3_id}] Activated CRISP round and registered deadline callbacks");
    Ok(true)
}

fn schedule_round_activation_retries<S: DataStore>(
    e3_id: &str,
    ctx: &Arc<IndexerContext<S, ReadWrite>>,
) {
    let now = unix_now();
    for offset in ROUND_ACTIVATION_RETRY_OFFSETS {
        let e3_id = e3_id.to_string();
        ctx.do_later(now.saturating_add(offset), move |_, ctx| {
            let e3_id = e3_id.clone();
            async move {
                if let Err(error) = activate_round_if_ready(&e3_id, &ctx).await {
                    error!("[e3_id={e3_id}] Deferred CRISP round activation failed: {error:#}");
                }
                Ok(())
            }
        });
    }
}

/// Bring one stored round back into the schedule after a restart.
async fn restore_round_deadline_callback<S: DataStore>(
    indexer: &InterfoldIndexer<S, ReadWrite>,
    e3_id: &str,
    now: u64,
) -> eyre::Result<()> {
    let store = indexer.get_store();
    let mut repo = CrispE3Repository::new(store.clone(), e3_id);
    let mut status = repo.get_status().await?;
    let has_indexed_public_key = repo.has_indexed_public_key().await?;
    if status == ACTIVE && !has_indexed_public_key {
        repo.update_status(REQUESTED).await?;
        status = REQUESTED.to_string();
        warn!(
            "[e3_id={e3_id}] Reset an active round to pending: no verified public key is indexed"
        );
    }
    if status == REQUESTED && has_indexed_public_key && repo.try_start_round().await? {
        CurrentRoundRepository::new(store)
            .set_current_round(CurrentRound {
                id: e3_id.to_string(),
            })
            .await?;
        status = ACTIVE.to_string();
        info!("[e3_id={e3_id}] Activated a requested round whose verified key was indexed earlier");
    }
    if matches!(status.as_str(), COMPUTING | PUBLISHING_CIPHERTEXT) {
        // Submission is at-least-once across the CRISP and program-server process boundary. A
        // crash can lose the HTTP response or webhook, so keeping this claim would strand the
        // round. A retry can repeat proof work but cannot publish a second result: Interfold
        // accepts ciphertext output only from KeyPublished, and the callback treats an
        // already-published output as success.
        repo.update_status(EXPIRED).await?;
        status = EXPIRED.to_string();
        warn!("[e3_id={e3_id}] Reset an interrupted compute submission so it can be retried");
    }
    if !matches!(status.as_str(), ACTIVE | EXPIRED) {
        return Ok(());
    }

    let expiration = repo.get_input_deadline().await?;
    for at in deadline_attempt_times(expiration, now) {
        let e3_id = e3_id.to_string();
        indexer.schedule_at(at, move |_, ctx| deadline_pass(e3_id.clone(), ctx.store()));
    }
    info!("[e3_id={e3_id}] Restored deadline callbacks for CRISP round in status {status}");
    Ok(())
}

async fn restore_round_deadline_callbacks<S: DataStore>(
    indexer: &InterfoldIndexer<S, ReadWrite>,
) -> eyre::Result<()> {
    let round_ids = CurrentRoundRepository::new(indexer.get_store())
        .get_round_ids()
        .await?;
    let now = unix_now();
    for e3_id in round_ids {
        if let Err(error) = restore_round_deadline_callback(indexer, &e3_id, now).await {
            error!("[e3_id={e3_id}] Could not restore CRISP deadline callbacks: {error:#}");
        }
    }
    Ok(())
}

/// Compute a round once its input deadline has passed.
async fn handle_e3_input_deadline_expiration<S: DataStore>(
    e3_id: String,
    store: SharedStore<S>,
) -> eyre::Result<()> {
    let mut repo = CrispE3Repository::new(store, &e3_id);
    let e3 = repo.get_e3().await?;

    let pending = within(
        READ_TIMEOUT,
        crisp_read()
            .await?
            .pending_input_count(e3_id_to_u256(&e3_id).map_err(report)?),
    )
    .await?;
    if pending != 0 {
        // The input root already includes these reserved leaves, but Ethereum has not verified
        // their Avail receipts. Starting OpenVM now would waste the proof: CRISPProgram.verify
        // refuses every output until this reaches zero. InputPublished recovery wakes this handler
        // again as each delayed VectorX proof lands.
        bail!(
            "[e3_id={e3_id}] {pending} input(s) still await data-availability finalization; refusing to compute"
        );
    }

    // Atomic: a delayed callback must not move a round from `PublishingCiphertext` or
    // `CiphertextPublished` back to `Expired` and compute it twice.
    if !repo.try_mark_expired().await? {
        return Ok(());
    }
    let voter_count = repo.get_vote_count().await?;

    // The contract is the authority on how many inputs there are, and this callback can run before
    // the last committed input is indexed. Computation is one-shot, so starting short would tally a
    // subset and derive a root the contract rejects, with no other symptom. The snapshot comes
    // back from the same call: assembling the request from separate reads lets an input event land
    // between them and pairs a ciphertext with another input's commitment.
    let snapshot = match wait_for_indexed_inputs(&e3_id, &repo).await? {
        IndexedInputs::Complete(snapshot) => snapshot,
        IndexedInputs::Mismatch { indexed, published } => {
            // The round stays "Expired" and unfinished so a later pass can still compute it.
            // Marking it finished would omit an accepted input or tally local data that is not in
            // the contract's root.
            let retries = DEADLINE_ATTEMPT_OFFSETS[1..]
                .iter()
                .map(|offset| format!("+{offset}s"))
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "[e3_id={e3_id}] the indexer holds {indexed} input(s), but CRISPProgram accepted \
                 {published}; refusing to compute while the counts differ. Retry passes run at \
                 {retries} from the input deadline. If every pass reports this, the index is \
                 inconsistent and needs attention."
            );
        }
    };

    if snapshot.ciphertexts.is_empty() {
        if voter_count > 0 {
            bail!(
                "[e3_id={e3_id}] {voter_count} active voter slot(s) are recorded, but the input \
                 snapshot is empty; refusing to finish an inconsistent round"
            );
        }
        info!("[e3_id={e3_id}] E3 has no votes to decrypt. Setting status to Finished.");
        repo.update_status(FINISHED).await?;
    } else {
        info!(
            "[e3_id={e3_id}] Starting computation for E3 ({} ciphertext input(s), {voter_count} voter(s))",
            snapshot.ciphertexts.len()
        );
        // The local concurrency barrier: two passes can be inside the indexer wait at once, so one
        // store operation decides which proceeds. Restart recovery stays at-least-once because the
        // contract, not this process, is the durable idempotency boundary. Claimed after the wait:
        // a pass that gives up on a short index leaves the round "Expired" for a later pass.
        if !repo.try_claim_computing().await? {
            info!("[e3_id={e3_id}] another pass is already computing this round; nothing to do");
            return Ok(());
        }
        if let Err(error) = run_compute(&e3_id, e3, snapshot).await {
            if let Err(release_error) = repo.release_compute_claim().await {
                error!(
                    "[e3_id={e3_id}] Failed to release compute claim after submission error: {release_error:#}"
                );
            }
            return Err(error);
        }
        info!("[e3_id={e3_id}] Request Computation for E3");

        if !repo.mark_compute_submitted().await? {
            let status = repo
                .get_status()
                .await
                .unwrap_or_else(|_| "unknown".to_owned());
            warn!(
                "[e3_id={e3_id}] Compute response arrived after the round advanced to {status}; leaving that state unchanged"
            );
        }
    }
    info!("[e3_id={e3_id}] E3 request handled successfully.");
    Ok(())
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
            "[e3_id={e3_id}] Ignoring PlaintextOutputPublished for a round without a CRISP record"
        );
        return Ok(());
    };
    let same_program = round
        .e3_program
        .parse::<Address>()
        .is_ok_and(|program| program == configured_program);

    if same_program {
        let vote_counts = decode_tally(plaintext_output, round.num_options.parse()?)?;
        for (i, count) in vote_counts.iter().enumerate() {
            info!("[e3_id={e3_id}] Option index: {i} votes: {count:?}");
        }
        repo.set_votes(vote_counts).await?;
    } else {
        warn!(
            "[e3_id={e3_id}] Leaving the tally empty: the round's program '{}' is not the \
             configured program {configured_program}, so its ballot layout can differ",
            round.e3_program
        );
    }

    repo.update_status(FINISHED).await
}

/// Index a committed ciphertext immediately when this availability service holds its bytes.
///
/// VectorX finalization can take hours. Reserving the input index on Ethereum preserves CRISP's
/// parent chain, and this local copy lets a later vote or mask extend that entry during the wait.
/// Other indexers that do not hold the staged object learn it from `InputPublished` later.
async fn handle_input_committed<S: DataStore>(
    event: InputCommitted,
    ctx: Arc<IndexerContext<S, ReadWrite>>,
    availability: Arc<AvailabilityService>,
) -> eyre::Result<()> {
    let hash = encode_prefixed(event.encryptedVoteHash);
    let Some(ciphertext) = availability.object(&hash).map_err(report)? else {
        // Normal for a secondary indexer. The verified InputPublished event supplies the Avail
        // coordinates later, and no unverified bytes are needed for final computation.
        return Ok(());
    };
    let ciphertext = e3_data_availability::verify_retrieved_bytes(
        e3_data_availability::DataReference {
            content_hash: event.encryptedVoteHash.0,
            block_number: 0,
            leaf_index: 0,
        },
        ciphertext,
    )
    .map_err(report)?;
    store_input_bytes(
        ctx.store(),
        &event.e3Id.to_string(),
        ciphertext,
        u64::try_from(event.index)?,
        event.encryptedVoteCommitment.0,
        event.slotAddress.into(),
        u64::try_from(event.parentIndexPlusOne)?,
    )
    .await
}

async fn handle_input_published<S: DataStore>(
    event: InputPublished,
    ctx: Arc<IndexerContext<S, ReadWrite>>,
    availability: Arc<AvailabilityService>,
) -> eyre::Result<()> {
    let reference =
        AvailableInputReference::from_event(event.e3Id.to_string(), &event).map_err(report)?;
    availability
        .record_input_reference(&reference)
        .map_err(report)?;
    let store = ctx.store();
    match store_available_input(store.clone(), &availability, &reference).await {
        Ok(()) => {
            tokio::spawn(resume_expired_round(reference.e3_id, store));
        }
        // The durable reference stays, and `recover_available_inputs` retries it.
        Err(error) => warn!(
            "[e3_id={}] Input {} is committed but not retrievable yet: {error:#}",
            reference.e3_id, reference.index
        ),
    }
    Ok(())
}

async fn store_available_input<S: DataStore>(
    store: SharedStore<S>,
    availability: &AvailabilityService,
    reference: &AvailableInputReference,
) -> eyre::Result<()> {
    let ciphertext = availability
        .retrieve(reference.data_reference())
        .await
        .map_err(report)?;
    store_input_bytes(
        store,
        &reference.e3_id,
        ciphertext,
        reference.index,
        reference.commitment,
        reference.slot,
        reference.parent_index_plus_one,
    )
    .await?;
    availability
        .complete_input_reference(reference)
        .map_err(report)?;
    info!(
        "[e3_id={}] Retrieved input {} from data availability",
        reference.e3_id, reference.index
    );
    Ok(())
}

async fn store_input_bytes<S: DataStore>(
    store: SharedStore<S>,
    e3_id: &str,
    ciphertext: Vec<u8>,
    index: u64,
    commitment: [u8; 32],
    slot: [u8; 20],
    parent_index_plus_one: u64,
) -> eyre::Result<()> {
    let mut repo = CrispE3Repository::new(store, e3_id);
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

/// Run the deadline handler for a round whose deadline has passed, after an input arrived late.
async fn resume_expired_round<S: DataStore>(e3_id: String, store: SharedStore<S>) {
    if let Err(error) = try_resume_expired_round(&e3_id, store).await {
        warn!("[e3_id={e3_id}] Could not resume computation after retrieving an input: {error:#}");
    }
}

async fn try_resume_expired_round<S: DataStore>(
    e3_id: &str,
    store: SharedStore<S>,
) -> eyre::Result<()> {
    let e3 = CrispE3Repository::new(store.clone(), e3_id)
        .get_e3()
        .await?;
    let now = rpc::latest_timestamp(rpc::provider().await?).await?;
    if now >= e3.input_window[1] {
        handle_e3_input_deadline_expiration(e3_id.to_string(), store).await?;
    }
    Ok(())
}

/// The input deadline of a round that may still need its deadline pass, if it does.
async fn deadline_awaiting_pass<S: DataStore>(
    store: SharedStore<S>,
    e3_id: &str,
) -> eyre::Result<Option<u64>> {
    let repo = CrispE3Repository::new(store, e3_id);
    if !matches!(
        repo.get_status().await?.as_str(),
        REQUESTED | ACTIVE | EXPIRED
    ) {
        return Ok(None);
    }
    Ok(Some(repo.get_e3().await?.input_window[1]))
}

/// Fallback for restored block callbacks: one provider and one bounded loop cover every unfinished
/// round, then the task ends. A failed pass is final here, since the scheduled retries cover it.
async fn recover_round_deadlines<S: DataStore>(store: SharedStore<S>) -> eyre::Result<()> {
    let mut pending = Vec::new();
    for e3_id in CurrentRoundRepository::new(store.clone())
        .get_round_ids()
        .await?
    {
        match deadline_awaiting_pass(store.clone(), &e3_id).await {
            Ok(Some(deadline)) => pending.push((e3_id, deadline)),
            Ok(None) => {}
            Err(error) => {
                warn!("[e3_id={e3_id}] Could not read the round for deadline recovery: {error:#}")
            }
        }
    }
    if pending.is_empty() {
        return Ok(());
    }

    let provider = rpc::provider().await?;
    while !pending.is_empty() {
        match rpc::latest_timestamp(provider).await {
            Ok(now) => {
                let (due, waiting): (Vec<_>, Vec<_>) = pending
                    .into_iter()
                    .partition(|(_, deadline)| now >= *deadline);
                pending = waiting;
                for (e3_id, _) in due {
                    if let Err(error) =
                        handle_e3_input_deadline_expiration(e3_id.clone(), store.clone()).await
                    {
                        warn!(
                            "[e3_id={e3_id}] Recovered deadline handler could not start computation: {error:#}"
                        );
                    }
                }
            }
            Err(error) => {
                warn!("CRISP deadline recovery could not read the latest block: {error:#}")
            }
        }
        if !pending.is_empty() {
            sleep(Duration::from_secs(30)).await;
        }
    }
    Ok(())
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
        PendingDiscoveryStep::Skip
    } else if matches!(round.status.as_str(), REQUESTED | ACTIVE) {
        PendingDiscoveryStep::Retry
    } else {
        PendingDiscoveryStep::Forgive
    }
}

/// Store the census that discovery found, or record that the round still owes one.
///
/// Returns the leaf hashes to post as the census root, or `None` when no root is due: the census
/// is owed, or it is on-chain. An owed census writes no list, so a new round keeps the empty lists
/// from `initialize_round`, and a round whose `E3Requested` arrives again keeps the census it holds
/// until the retry pass rebuilds it. A rebuilt Merkle census must match the posted root.
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
    // An on-chain census has no tree, and `_eligibility` reads power from the token per input. A
    // client only needs the addresses: a mask goes to someone else's slot, so it needs a list of
    // who holds power, not a membership proof.
    let leaves = if is_onchain_census {
        None
    } else {
        Some(
            compute_token_holder_hashes(&holders)
                .context("Failed to compute token holder hashes")?,
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
/// A round carries `discovery_pending` when its census could not be built at `E3Requested`: the
/// stored voting-power divisor and snapshot could not be read, or discovery itself failed. The
/// event is not replayed once the cursor passes it, so this pass is the only retry. It reads the
/// divisor again for each such CUSTOM-credit round and, when it answers, runs the discovery the
/// handler would have run. A round that has ended is dropped from the pass.
///
/// One task for the process. It sleeps on `DISCOVERY_OWED` while nothing is owed. `notify_one`
/// keeps a permit when the task is mid-pass, so debt recorded after the pass read that round is
/// still picked up.
async fn retry_pending_discovery<S: DataStore>(store: SharedStore<S>) -> eyre::Result<()> {
    let crisp = crisp_read().await?;
    loop {
        let ids = CurrentRoundRepository::new(store.clone())
            .get_round_ids()
            .await?;
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
                        warn!("[e3_id={e3_id}] Could not clear pending discovery: {error:#}");
                    }
                    continue;
                }
                PendingDiscoveryStep::Retry => owed += 1,
            }
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
                    info!("[e3_id={e3_id}] Pending holder discovery settled with {count} holders");
                    owed -= 1;
                }
                Err(error) => {
                    warn!("[e3_id={e3_id}] Pending holder discovery failed, will retry: {error:#}")
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
/// Returns the holder count. The debt is cleared only after the holders are stored, so a failure
/// between the two leaves the round owed rather than served an empty census. A Merkle round also
/// gets its root posted and its leaf hashes stored first.
async fn settle_pending_discovery<S: DataStore>(
    repo: &mut CrispE3Repository<S>,
    e3_id: &str,
    round: &E3Crisp,
    stored: Option<(U256, u64)>,
) -> eyre::Result<usize> {
    let params = CustomParams {
        token_address: round.token_address.clone(),
        balance_threshold: round.balance_threshold.clone(),
        num_options: round.num_options.clone(),
        credit_mode: round.credit_mode,
        credits: round.credits.clone(),
        census_mode: round.census_mode,
        // The round does not retain the requested divisor. `stored` is the source, and this field
        // is informational.
        voting_power_divisor: "0".to_owned(),
    };
    let requester: Address = round
        .requester
        .parse()
        .context("Invalid stored requester address")?;
    let mut holders =
        discover_holders(e3_id, &params, requester, round.snapshot_block, stored).await?;
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

/// Whether the chain says a round no longer needs its inputs retrieved. An unreadable stage is not
/// terminal.
async fn chain_ends_input_retrieval(interfold: &InterfoldContract<ReadOnly>, e3_id: &str) -> bool {
    let Ok(e3_id) = e3_id_to_u256(e3_id) else {
        return false;
    };
    within(READ_TIMEOUT, interfold.get_e3_stage(e3_id))
        .await
        .is_ok_and(|stage| stage_ends_input_retrieval(&stage))
}

/// Retrieve the inputs whose `InputPublished` reference is stored but whose bytes are not yet
/// indexed, until the round no longer needs them.
async fn recover_available_inputs<S: DataStore>(
    store: SharedStore<S>,
    availability: Arc<AvailabilityService>,
) -> eyre::Result<()> {
    let interfold =
        InterfoldContractFactory::create_read(&CONFIG.http_rpc_url, &CONFIG.interfold_address)
            .await?;
    loop {
        let mut chain_terminal = HashMap::<String, bool>::new();
        for reference in availability.pending_input_references().map_err(report)? {
            let round = CrispE3Repository::new(store.clone(), &reference.e3_id);
            let locally_terminal = matches!(
                round.get_status().await.as_deref(),
                Ok(CIPHERTEXT_PUBLISHED | FINISHED)
            );
            let terminal = locally_terminal
                || match chain_terminal.get(&reference.e3_id) {
                    Some(terminal) => *terminal,
                    None => {
                        let terminal =
                            chain_ends_input_retrieval(&interfold, &reference.e3_id).await;
                        chain_terminal.insert(reference.e3_id.clone(), terminal);
                        terminal
                    }
                };
            if terminal {
                if let Err(error) = availability.complete_input_reference(&reference) {
                    warn!(
                        "[e3_id={}] Could not remove an obsolete input reference: {error:#}",
                        reference.e3_id
                    );
                }
                continue;
            }
            match store_available_input(store.clone(), &availability, &reference).await {
                // The scheduled deadline retries are finite. If Avail or its RPC was down through
                // all of them, a successful background retrieval must wake computation instead of
                // leaving a complete round stranded.
                Ok(()) => {
                    tokio::spawn(resume_expired_round(reference.e3_id, store.clone()));
                }
                Err(error) => warn!(
                    "[e3_id={}] Input {} retrieval will retry: {error:#}",
                    reference.e3_id, reference.index
                ),
            }
        }
        sleep(Duration::from_secs(30)).await;
    }
}

/// Persist every log from a watched contract, so `/chain/logs` can answer from the store.
///
/// A failed write IS propagated: the catch-up uses a handler error to hold the cursor back, and
/// an index that quietly missed a log while the cursor moved past it answers later queries short
/// while looking authoritative.
async fn index_log<S: DataStore>(
    log: alloy::rpc::types::Log,
    ctx: Arc<IndexerContext<S, ReadWrite>>,
    wanted: Arc<[Address]>,
) -> eyre::Result<()> {
    // Watched for the typed handlers is not the same as wanted in the log index: a busy token
    // emits thousands of transfers nobody queries.
    if !wanted.contains(&log.address()) {
        return Ok(());
    }
    // A log with no block number or index cannot be placed. Filing it at block 0 would collide
    // with every other unplaceable log and sit below every coverage record.
    let (Some(block_number), Some(log_index)) = (log.block_number, log.log_index) else {
        warn!(
            "Skipping a log with no block position from {}",
            log.address()
        );
        return Ok(());
    };

    LogRepository::new(ctx.store())
        .append(StoredLog {
            removed: log.removed,
            address: log.address().to_string(),
            topics: log.topics().iter().map(|t| t.to_string()).collect(),
            data: log.data().data.to_string(),
            block_number,
            transaction_hash: log.transaction_hash.map(|h| h.to_string()),
            log_index,
            block_hash: log.block_hash.map(|h| h.to_string()),
            transaction_index: log.transaction_index,
        })
        .await
        .context("indexing a log failed")
}

async fn mark_ciphertext_published<S: DataStore>(
    e3_id: U256,
    store: SharedStore<S>,
    event_name: &str,
) -> eyre::Result<()> {
    info!("[e3_id={e3_id}] Handling {event_name}");
    CrispE3Repository::new(store, e3_id)
        .update_status(CIPHERTEXT_PUBLISHED)
        .await
}

async fn register_handlers<S: DataStore>(
    indexer: &InterfoldIndexer<S, ReadWrite>,
    availability: Arc<AvailabilityService>,
    log_contracts: &[Address],
) -> eyre::Result<()> {
    let configured_program: Address = CONFIG
        .e3_program_address
        .parse()
        .context("Invalid configured E3 program address")?;
    let wanted: Arc<[Address]> = log_contracts.into();

    indexer
        .add_event_handler(move |event: E3Requested, ctx| {
            handle_e3_requested(event, ctx, configured_program)
        })
        .await;
    indexer
        .add_event_handler(|event: CiphertextOutputPublished, ctx| {
            mark_ciphertext_published(event.e3Id, ctx.store(), "CiphertextOutputPublished")
        })
        .await;
    indexer
        .add_event_handler(|event: CiphertextOutputReferencePublished, ctx| {
            mark_ciphertext_published(
                event.e3Id,
                ctx.store(),
                "CiphertextOutputReferencePublished",
            )
        })
        .await;
    indexer
        .add_event_handler(move |event: PlaintextOutputPublished, ctx| async move {
            let e3_id = event.e3Id.to_string();
            info!("[e3_id={e3_id}] Handling PlaintextOutputPublished");
            let mut repo = CrispE3Repository::new(ctx.store(), &e3_id);
            record_plaintext_output(
                &mut repo,
                &e3_id,
                &event.plaintextOutput,
                configured_program,
            )
            .await
        })
        .await;
    indexer
        .add_event_handler(|event: CommitteePublished, ctx| async move {
            let e3_id = event.e3Id.to_string();
            info!("[e3_id={e3_id}] Handling CommitteePublished");
            if !activate_round_if_ready(&e3_id, &ctx).await? {
                warn!(
                    "[e3_id={e3_id}] Committee event arrived, but the verified public key or CRISP request record is unavailable; round remains pending"
                );
                schedule_round_activation_retries(&e3_id, &ctx);
            }
            Ok(())
        })
        .await;
    // Chunks can arrive out of index order, because the contract lets a committee member repair
    // any missing chunk. Whichever event completes the generic indexer's assembly must be able to
    // activate the round.
    indexer
        .add_event_handler(|event: CommitteePublicKeyChunkPublished, ctx| async move {
            let e3_id = event.e3Id.to_string();
            if !activate_round_if_ready(&e3_id, &ctx).await? {
                schedule_round_activation_retries(&e3_id, &ctx);
            }
            Ok(())
        })
        .await;
    let committed_availability = Arc::clone(&availability);
    indexer
        .add_event_handler(move |event: InputCommitted, ctx| {
            handle_input_committed(event, ctx, Arc::clone(&committed_availability))
        })
        .await;
    indexer
        .add_event_handler(move |event: InputPublished, ctx| {
            handle_input_published(event, ctx, Arc::clone(&availability))
        })
        .await;
    indexer
        .add_raw_log_handler(move |log, ctx| index_log(log, ctx, Arc::clone(&wanted)))
        .await;
    Ok(())
}

/// Start the tasks that run beside the indexer, each restarted when it fails or panics. They read
/// and write the store directly, so the indexer does not own them and a restart of the indexer
/// never duplicates them.
pub fn spawn_recovery_tasks<S: DataStore>(
    store: SharedStore<S>,
    availability: Arc<AvailabilityService>,
) {
    tokio::spawn(supervise("available-input recovery", {
        let store = store.clone();
        move || recover_available_inputs(store.clone(), Arc::clone(&availability))
    }));
    tokio::spawn(supervise("round-deadline recovery", {
        let store = store.clone();
        move || recover_round_deadlines(store.clone())
    }));
    tokio::spawn(supervise("pending-discovery retry", move || {
        retry_pending_discovery(store.clone())
    }));
}

/// Record where the log index starts for each watched contract, before any log arrives, so a
/// contract that has emitted nothing yet does not look uncovered forever.
async fn claim_log_coverage<S: DataStore>(
    mut store: SharedStore<S>,
    log_contracts: &[Address],
    from_block: u64,
) {
    // An error here must NOT read as "no previous set": that would mark every address newly added
    // and narrow its coverage to the current head, discarding the record for history that is still
    // in the store. On a read failure every record stays as it stands: leaving a claim alone is
    // recoverable, narrowing one wrongly is not.
    let previous: Option<Vec<String>> = match store.get(LOG_INDEX_CONFIG_KEY).await {
        Ok(previous) => Some(previous.unwrap_or_default()),
        Err(error) => {
            error!(
                "Could not read the previous log-index configuration: {error}. Leaving every \
                 coverage record as it stands this run."
            );
            None
        }
    };

    let mut repo = LogRepository::new(store.clone());
    for address in log_contracts {
        let address = address.to_string();
        // An unknown previous set counts as already indexed, which only widens a claim by filling
        // a missing record and never narrows an existing one.
        let was_indexed = previous.as_ref().is_none_or(|previous| {
            previous
                .iter()
                .any(|entry| entry.eq_ignore_ascii_case(&address))
        });
        let recorded = if was_indexed {
            repo.ensure_coverage_from(&address, from_block).await
        } else {
            // Newly added, or back after a removal: claim only from here on.
            repo.rebase_coverage(&address, from_block)
                .await
                .and(repo.ensure_coverage_from(&address, from_block).await)
        };
        if let Err(error) = recorded {
            error!("Could not record log coverage for {address}: {error:#}");
        }
    }

    // Only after the comparison above ran. Recording the current set after a failed read would
    // tell the next run every address was already indexed, so an address added during this run
    // would never have its stale coverage narrowed.
    if previous.is_some() {
        let current: Vec<String> = log_contracts.iter().map(ToString::to_string).collect();
        if let Err(error) = store.insert(LOG_INDEX_CONFIG_KEY, &current).await {
            error!("Could not record the log-index configuration: {error}");
        }
    }
}

/// Build the indexer, register its handlers, catch up, and listen. A failure anywhere ends the
/// call, and the supervisor builds a fresh indexer. Only this part is safe to rerun: the
/// recovery tasks are started once by `spawn_recovery_tasks`.
pub async fn run_indexer<S: DataStore>(
    store: SharedStore<S>,
    availability: Arc<AvailabilityService>,
) -> eyre::Result<()> {
    info!("CRISP: Creating indexer...");
    let log_contracts = CONFIG.index_log_contracts();

    // The E3 stack plus whatever the deployment asked to read through `/chain/*`. Watching those
    // addresses lets their logs be served from the store instead of forwarded upstream; the typed
    // handlers dispatch on event signature, so a contract that emits nothing they recognise flows
    // past them into the log index. `INDEX_LOG_CONTRACTS` should be a subset of `INDEX_CONTRACTS`,
    // but nothing enforces it, and an address listed only there would get coverage records while
    // never reaching the subscription: every query for it would then be answered from an empty
    // index. Watching the union removes that way to misconfigure.
    let mut watched = vec![
        CONFIG.interfold_address.clone(),
        CONFIG.ciphernode_registry_address.clone(),
        CONFIG.e3_program_address.clone(),
    ];
    for address in CONFIG.index_contracts().iter().chain(&log_contracts) {
        let address = address.to_string();
        if !watched.iter().any(|w| w.eq_ignore_ascii_case(&address)) {
            watched.push(address);
        }
    }
    let watched: Vec<&str> = watched.iter().map(String::as_str).collect();

    let indexer = InterfoldIndexer::new_with_write_contract(
        &CONFIG.ws_rpc_url,
        &watched,
        store,
        &CONFIG.private_key,
    )
    .await?;
    info!("CRISP: Indexer registering handlers...");
    register_handlers(&indexer, availability, &log_contracts).await?;
    info!("CRISP: Indexer finished registering handlers!");

    // Resolve where indexing begins once, and drive both the backfill and the coverage claim from
    // that value. Two reads can differ (another node, a later moment), and a coverage claim below
    // the real start persists for the life of the database, because `ensure_coverage_from` never
    // overwrites.
    let store = indexer.get_store();
    // A read ERROR is not an absent record: treating it as one would make a resumed database look
    // fresh and pin the claim to the current head.
    let resumed: Option<u64> = store
        .get(INDEXER_CURSOR_KEY)
        .await
        .map_err(|error| eyre!("reading the indexer cursor failed: {error}"))?;
    let start_block = match (resumed, CONFIG.index_start_block) {
        // A resumed database already carries coverage from its first run, and the cursor may sit
        // far above a since-lowered INDEX_START_BLOCK. Existing coverage is left alone;
        // `ensure_coverage_from` only fills the gap an older database left.
        (Some(cursor), _) => Some(cursor.saturating_add(1)),
        (None, Some(configured)) => Some(configured),
        // A fresh database with nothing configured: pin the backfill to the head read here, so the
        // catch-up cannot resolve a later start than the one claimed below.
        (None, None) => match indexer.head_block().await {
            Ok(head) => Some(head),
            Err(error) => {
                error!("Could not read the head to pin the index start: {error}");
                None
            }
        },
    };

    // On a resumed database the stored cursor wins whatever is passed here.
    indexer.configure_backfill(
        if resumed.is_some() {
            CONFIG.index_start_block
        } else {
            start_block
        },
        CONFIG.index_chunk_size,
    );
    if let (false, Some(from_block)) = (log_contracts.is_empty(), start_block) {
        claim_log_coverage(store, &log_contracts, from_block).await;
    }

    restore_round_deadline_callbacks(&indexer).await?;
    indexer.listen().await?;
    bail!("the indexer's listen loop ended")
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
    use super::{deadline_attempt_times, stage_ends_input_retrieval, E3Stage};

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
