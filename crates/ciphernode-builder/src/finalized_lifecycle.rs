// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Startup reconciliation of the local E3 lifecycle with the finalized chain lifecycle.

use crate::{ciphernode_builder::validate_chain_id, ProviderCache};
use alloy::primitives::Address;
use anyhow::{anyhow, bail, Context, Result};
use e3_config::chain_config::ChainConfig;
use e3_events::{E3Stage, E3id, FailureReason};
use e3_evm::{read_finalized_e3_lifecycles, FinalizedE3Lifecycle};
use e3_request::{E3LifecycleRepositoryFactory, RouterRepositoryFactory};
use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    time::Duration,
};
use tracing::{info, warn};

/// Upper bound at startup for connecting to one chain, and for each batch of its finalized
/// lifecycle reads.
const FINALIZED_LIFECYCLE_READ_TIMEOUT: Duration = Duration::from_secs(60);
/// Most restored contexts that one finalized lifecycle read checks within one deadline: at most
/// three RPC calls each.
const FINALIZED_LIFECYCLE_READ_BATCH: usize = 16;
/// Delays in seconds before the retries of one batch read after an RPC error.
const FINALIZED_LIFECYCLE_READ_RETRY_DELAYS: [u64; 2] = [1, 3];

/// Record in the local lifecycle the E3s of restored request contexts that are finished at the
/// finalized block of their chain.
///
/// An E3 is finished when it is complete, or failed without accusation or slashing work. Startup
/// runs this before it reads the lifecycle for its restart decisions, so the router completes
/// these contexts at `EffectsEnabled` and the other recovery paths treat them as terminal. The node
/// does not read a chain that the configuration disables, so the contexts of that chain resume
/// without the check. Any other restored context that startup cannot check fails startup.
pub(crate) async fn reconcile_finalized_lifecycle<State>(
    repositories: &e3_data::Repositories,
    chains: &[ChainConfig],
    provider_cache: &mut ProviderCache<State>,
) -> Result<()> {
    let lifecycle_store = repositories.e3_lifecycle();
    let mut lifecycle = lifecycle_store.read().await?.unwrap_or_default();
    let contexts = repositories
        .request_router_checkpoint()
        .read()
        .await?
        .map(|checkpoint| checkpoint.contexts)
        .unwrap_or_default();
    let mut unchecked = active_contexts_by_chain(&contexts, &lifecycle);
    let mut finished = Vec::new();
    for chain in chains.iter().filter(|chain| chain.enabled.unwrap_or(true)) {
        if unchecked.is_empty() {
            break;
        }
        let connect = async {
            let provider = provider_cache.ensure_read_provider(chain).await?;
            validate_chain_id(chain, provider.chain_id())?;
            Ok(provider)
        };
        let provider =
            within_deadline(&chain.name, FINALIZED_LIFECYCLE_READ_TIMEOUT, connect).await?;
        let chain_id = provider.chain_id();
        let Some(e3_ids) = unchecked.remove(&chain_id) else {
            continue;
        };
        let contract = chain.contracts.interfold.address()?;
        let provider = &provider;
        let lifecycles = read_in_batches(&chain.name, &e3_ids, |batch| async move {
            read_finalized_e3_lifecycles(provider, contract, batch)
                .await
                .with_context(|| {
                    format!(
                        "could not read the finalized E3 lifecycle on chain {chain_id}; startup cannot confirm whether restored request contexts are finished"
                    )
                })
        })
        .await?;
        let chain_finished = finished_e3s(chain_id, contract, &lifecycles)?;
        info!(
            chain_id,
            checked = e3_ids.len(),
            finished = chain_finished.len(),
            "Checked restored request contexts against the finalized block"
        );
        finished.extend(chain_finished);
    }
    for chain in chains.iter().filter(|chain| !chain.enabled.unwrap_or(true)) {
        let Some(e3_ids) = chain
            .chain_id
            .and_then(|chain_id| unchecked.remove(&chain_id))
        else {
            continue;
        };
        warn!(
            chain = %chain.name,
            ?e3_ids,
            "Restored request contexts belong to a disabled chain; they resume without the finalized-block check"
        );
    }
    if let Some((chain_id, e3_ids)) = unchecked.into_iter().next() {
        bail!(
            "restored request contexts for E3s {e3_ids:?} belong to chain {chain_id}, which the configuration does not have; startup cannot confirm whether they are finished. If this node still serves chain {chain_id}, add it with a working RPC endpoint. If the node moved to another network, keep the old chain entry with `enabled: false` and `chain_id: {chain_id}`, which resumes these contexts without the check, or delete the old state with `interfold node reset-data`"
        );
    }
    if finished.is_empty() {
        return Ok(());
    }
    // Only non-terminal local stages were checked, so this cannot replace a terminal stage.
    lifecycle.extend(finished);
    lifecycle_store.write_sync(&lifecycle).await
}

/// Group the restored contexts whose local lifecycle stage is not terminal by chain.
fn active_contexts_by_chain(
    contexts: &[E3id],
    lifecycle: &HashMap<E3id, E3Stage>,
) -> BTreeMap<u64, Vec<E3id>> {
    let mut by_chain: BTreeMap<u64, Vec<E3id>> = BTreeMap::new();
    for e3_id in contexts {
        if !lifecycle.get(e3_id).is_some_and(E3Stage::is_terminal) {
            by_chain
                .entry(e3_id.chain_id())
                .or_default()
                .push(e3_id.clone());
        }
    }
    by_chain
}

/// Select the E3s that are finished at the finalized block, with their canonical stage.
///
/// A complete E3 and an E3 that failed without accusation or slashing work are finished. A failed
/// E3 that needs accusation or slashing work keeps its context. An E3 that is not yet at the
/// finalized block keeps its context and waits for finality. An E3 that chain head does not have
/// is an error.
fn finished_e3s(
    chain_id: u64,
    contract: Address,
    lifecycles: &[(E3id, FinalizedE3Lifecycle)],
) -> Result<Vec<(E3id, E3Stage)>> {
    let mut finished = Vec::new();
    for (e3_id, lifecycle) in lifecycles {
        match lifecycle {
            FinalizedE3Lifecycle::Finalized {
                stage: E3Stage::Complete,
                ..
            } => finished.push((e3_id.clone(), E3Stage::Complete)),
            FinalizedE3Lifecycle::Finalized {
                stage: E3Stage::Failed,
                failure_reason,
            } => {
                if failure_reason
                    .as_ref()
                    .is_some_and(FailureReason::ends_without_slashing)
                {
                    finished.push((e3_id.clone(), E3Stage::Failed));
                } else {
                    warn!(
                        %e3_id,
                        ?failure_reason,
                        "Keeping the restored context of a failed E3 for its accusation and slashing work"
                    );
                }
            }
            FinalizedE3Lifecycle::Finalized { .. } | FinalizedE3Lifecycle::AwaitingFinality => {}
            FinalizedE3Lifecycle::Unknown => bail!(
                "restored E3 {e3_id} is not in the Interfold contract {contract} at the latest block of chain {chain_id}; startup cannot confirm whether its context is finished. The RPC endpoint can be behind the chain, or the node data can belong to another deployment. Check that the endpoint is synced and that the configured Interfold address is right. Run `interfold node reset-data` only when the node data belongs to another deployment"
            ),
        }
    }
    Ok(finished)
}

/// Read the finalized lifecycles of `e3_ids` in batches, each within its own deadline, so a slow
/// but working endpoint finishes any number of restored contexts, and a stuck one still fails
/// startup after one deadline. A batch that fails is read again after each retry delay, within
/// the same deadline.
async fn read_in_batches<'a, Read, Batch>(
    chain: &str,
    e3_ids: &'a [E3id],
    mut read: Read,
) -> Result<Vec<(E3id, FinalizedE3Lifecycle)>>
where
    Read: FnMut(&'a [E3id]) -> Batch,
    Batch: Future<Output = Result<Vec<(E3id, FinalizedE3Lifecycle)>>>,
{
    let mut lifecycles = Vec::with_capacity(e3_ids.len());
    for batch in e3_ids.chunks(FINALIZED_LIFECYCLE_READ_BATCH) {
        let read_with_retries = async {
            let mut result = read(batch).await;
            for delay_secs in FINALIZED_LIFECYCLE_READ_RETRY_DELAYS {
                let Err(error) = &result else {
                    break;
                };
                warn!(chain, error = %error, "Reading the finalized E3 lifecycle failed; retrying");
                tokio::time::sleep(Duration::from_secs(delay_secs)).await;
                result = read(batch).await;
            }
            result
        };
        lifecycles.extend(
            within_deadline(chain, FINALIZED_LIFECYCLE_READ_TIMEOUT, read_with_retries).await?,
        );
    }
    Ok(lifecycles)
}

/// Fail when `read` does not end before the timeout.
async fn within_deadline<T>(
    chain: &str,
    timeout: Duration,
    read: impl Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout(timeout, read).await.map_err(|_| {
        anyhow!(
            "timed out after {}s while reading the finalized E3 lifecycle on chain '{chain}'; startup cannot confirm whether restored request contexts are finished. Check the RPC endpoint of chain '{chain}'",
            timeout.as_secs_f64()
        )
    })?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finalized(stage: E3Stage, failure_reason: Option<FailureReason>) -> FinalizedE3Lifecycle {
        FinalizedE3Lifecycle::Finalized {
            stage,
            failure_reason,
        }
    }

    fn restored_ids(count: usize) -> Vec<E3id> {
        (0..count)
            .map(|index| E3id::new(index.to_string(), 1))
            .collect()
    }

    /// A failed E3 takes two RPC calls. At 250 ms each, 128 restored contexts take 64 s, longer
    /// than one deadline. Each batch has its own deadline, so a slow but working endpoint still
    /// finishes.
    #[tokio::test(start_paused = true)]
    async fn many_restored_failures_reconcile_with_a_slow_endpoint() -> Result<()> {
        let e3_ids = restored_ids(128);
        let lifecycles = read_in_batches("slow", &e3_ids, |batch| async move {
            tokio::time::sleep(Duration::from_millis(500) * batch.len() as u32).await;
            Ok(batch
                .iter()
                .map(|e3_id| {
                    let failed = finalized(E3Stage::Failed, Some(FailureReason::NoInputsReceived));
                    (e3_id.clone(), failed)
                })
                .collect())
        })
        .await?;
        assert_eq!(lifecycles.len(), e3_ids.len());
        Ok(())
    }

    /// A stuck endpoint still fails startup after one deadline.
    #[tokio::test(start_paused = true)]
    async fn a_stuck_endpoint_fails_startup_after_one_deadline() {
        let e3_ids = restored_ids(128);
        let started = tokio::time::Instant::now();
        let error = read_in_batches("stuck", &e3_ids, |_| std::future::pending())
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("timed out"), "{error:#}");
        let waited = started.elapsed();
        assert!(
            waited >= FINALIZED_LIFECYCLE_READ_TIMEOUT
                && waited < FINALIZED_LIFECYCLE_READ_TIMEOUT + Duration::from_secs(1),
            "{waited:?}"
        );
    }

    /// An RPC error is read again after each retry delay. The read fails startup only when the
    /// last retry also fails.
    #[tokio::test(start_paused = true)]
    async fn a_failed_batch_read_is_retried() -> Result<()> {
        let e3_ids = restored_ids(3);
        let read_failing_first = |failures: usize| {
            let mut calls = 0;
            read_in_batches("flaky", &e3_ids, move |batch| {
                calls += 1;
                let fail = calls <= failures;
                async move {
                    if fail {
                        bail!("connection reset");
                    }
                    Ok(batch
                        .iter()
                        .map(|e3_id| (e3_id.clone(), FinalizedE3Lifecycle::AwaitingFinality))
                        .collect())
                }
            })
        };

        let retries = FINALIZED_LIFECYCLE_READ_RETRY_DELAYS.len();
        assert_eq!(read_failing_first(retries).await?.len(), e3_ids.len());
        let error = read_failing_first(retries + 1).await.unwrap_err();
        assert!(error.to_string().contains("connection reset"), "{error:#}");
        Ok(())
    }

    #[test]
    fn complete_and_non_slashing_failures_are_finished() -> Result<()> {
        let ids: Vec<E3id> = (1..=6).map(|id| E3id::new(id.to_string(), 1)).collect();
        let lifecycles = vec![
            (ids[0].clone(), finalized(E3Stage::Complete, None)),
            (
                ids[1].clone(),
                finalized(E3Stage::Failed, Some(FailureReason::RequesterCancelled)),
            ),
            (
                ids[2].clone(),
                finalized(E3Stage::Failed, Some(FailureReason::DKGInvalidShares)),
            ),
            (ids[3].clone(), finalized(E3Stage::Failed, None)),
            (ids[4].clone(), finalized(E3Stage::KeyPublished, None)),
            (ids[5].clone(), FinalizedE3Lifecycle::AwaitingFinality),
        ];

        let finished = finished_e3s(1, Address::ZERO, &lifecycles)?;

        assert_eq!(
            finished,
            vec![
                (ids[0].clone(), E3Stage::Complete),
                (ids[1].clone(), E3Stage::Failed),
            ]
        );
        Ok(())
    }

    #[test]
    fn an_e3_missing_at_chain_head_fails_startup() {
        let e3_id = E3id::new("9", 5);

        let error = finished_e3s(
            5,
            Address::ZERO,
            &[(e3_id.clone(), FinalizedE3Lifecycle::Unknown)],
        )
        .unwrap_err();

        assert!(error.to_string().contains(&format!(
            "restored E3 {e3_id} is not in the Interfold contract"
        )));
        assert!(error.to_string().contains("of chain 5"));
        assert!(error.to_string().contains("endpoint is synced"));
    }

    #[test]
    fn only_contexts_with_a_non_terminal_local_stage_are_checked() {
        let (active, failed, unknown_stage, other_chain) = (
            E3id::new("1", 1),
            E3id::new("2", 1),
            E3id::new("3", 1),
            E3id::new("4", 2),
        );
        let lifecycle = HashMap::from([
            (active.clone(), E3Stage::CommitteeFinalized),
            (failed.clone(), E3Stage::Failed),
            (other_chain.clone(), E3Stage::Requested),
        ]);
        let contexts = vec![
            active.clone(),
            failed,
            unknown_stage.clone(),
            other_chain.clone(),
        ];

        let by_chain = active_contexts_by_chain(&contexts, &lifecycle);

        assert_eq!(
            by_chain,
            BTreeMap::from([(1, vec![active, unknown_stage]), (2, vec![other_chain])])
        );
    }

    fn anvil_chain(rpc_url: String, interfold: Address) -> ChainConfig {
        use e3_config::{
            contract::{Contract, ContractAddresses},
            rpc::RpcAuth,
        };
        let contract = |address: Address| Contract::AddressOnly(address.to_string());
        ChainConfig {
            enabled: Some(true),
            name: "anvil".to_owned(),
            rpc_url,
            rpc_auth: RpcAuth::default(),
            contracts: ContractAddresses {
                interfold: contract(interfold),
                ciphernode_registry: contract(Address::ZERO),
                bonding_registry: contract(Address::ZERO),
                e3_program: None,
                fee_token: None,
                slashing_manager: None,
                dkg_fold_attestation_verifier: None,
                faucet: None,
            },
            finalization_ms: None,
            chain_id: None,
            ingestion_confirmations: Some(0),
            rpc_poll_interval_ms: None,
            rpc_log_range_blocks: None,
            data_availability: None,
        }
    }

    /// Store restored request contexts and their local lifecycle stages.
    async fn restored_store(
        lifecycle: HashMap<E3id, E3Stage>,
    ) -> Result<std::sync::Arc<e3_data::Repositories>> {
        use actix::Actor;
        use e3_data::{DataStore, InMemStore, RepositoriesFactory};
        use e3_events::RequestRouterCheckpoint;

        let repositories = std::sync::Arc::new(
            DataStore::from_in_mem(&InMemStore::new(false).start()).repositories(),
        );
        repositories
            .request_router_checkpoint()
            .write_sync(&RequestRouterCheckpoint {
                contexts: lifecycle.keys().cloned().collect(),
                completed: Default::default(),
                replay_cursors: Default::default(),
            })
            .await?;
        repositories.e3_lifecycle().write_sync(&lifecycle).await?;
        Ok(repositories)
    }

    /// Reconcile two restored contexts against a local chain whose Interfold contract answers
    /// every call with `answer`. Return the persisted lifecycle before and after the contract code
    /// is final.
    async fn reconcile_on_anvil(
        answer: u8,
        restored: &E3id,
        terminal_locally: (&E3id, E3Stage),
    ) -> Result<(HashMap<E3id, E3Stage>, HashMap<E3id, E3Stage>)> {
        use alloy::{
            node_bindings::Anvil,
            primitives::Bytes,
            providers::{ext::AnvilApi, ProviderBuilder},
        };

        let anvil = Anvil::new().try_spawn()?;
        assert_eq!(restored.chain_id(), anvil.chain_id());
        let chain_head = ProviderBuilder::new().connect_http(anvil.endpoint_url());
        let interfold = Address::repeat_byte(0x42);
        // PUSH1 answer, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
        let code = Bytes::from(vec![
            0x60, answer, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
        ]);
        chain_head.anvil_mine(Some(3), None).await?;
        chain_head.anvil_set_code(interfold, code).await?;
        chain_head.anvil_mine(Some(1), None).await?;
        let repositories = restored_store(HashMap::from([
            (restored.clone(), E3Stage::KeyPublished),
            (terminal_locally.0.clone(), terminal_locally.1),
        ]))
        .await?;
        let chains = [anvil_chain(anvil.endpoint(), interfold)];
        let mut provider_cache = ProviderCache::new();
        let persisted = || async {
            Ok::<_, anyhow::Error>(
                repositories
                    .e3_lifecycle()
                    .read()
                    .await?
                    .unwrap_or_default(),
            )
        };

        // The finalized block trails chain head by 64 blocks on anvil.
        reconcile_finalized_lifecycle(&repositories, &chains, &mut provider_cache).await?;
        let before_finality = persisted().await?;
        chain_head.anvil_mine(Some(64), None).await?;
        reconcile_finalized_lifecycle(&repositories, &chains, &mut provider_cache).await?;
        Ok((before_finality, persisted().await?))
    }

    #[actix::test]
    async fn an_e3_complete_at_the_finalized_block_becomes_complete_locally() -> Result<()> {
        let (restored, failed_locally) = (E3id::new("1", 31337), E3id::new("2", 31337));

        let (before_finality, after_finality) =
            reconcile_on_anvil(5, &restored, (&failed_locally, E3Stage::Failed)).await?;

        assert_eq!(before_finality.get(&restored), Some(&E3Stage::KeyPublished));
        assert_eq!(after_finality.get(&restored), Some(&E3Stage::Complete));
        assert_eq!(after_finality.get(&failed_locally), Some(&E3Stage::Failed));
        Ok(())
    }

    #[actix::test]
    async fn an_e3_that_timed_out_at_the_finalized_block_becomes_failed_locally() -> Result<()> {
        let (restored, complete_locally) = (E3id::new("1", 31337), E3id::new("2", 31337));

        // 6 is the Failed stage and the ComputeTimeout failure reason.
        let (before_finality, after_finality) =
            reconcile_on_anvil(6, &restored, (&complete_locally, E3Stage::Complete)).await?;

        assert_eq!(before_finality.get(&restored), Some(&E3Stage::KeyPublished));
        assert_eq!(after_finality.get(&restored), Some(&E3Stage::Failed));
        assert_eq!(
            after_finality.get(&complete_locally),
            Some(&E3Stage::Complete)
        );
        Ok(())
    }

    #[actix::test]
    async fn a_terminal_stage_only_at_chain_head_is_not_final() -> Result<()> {
        use alloy::{
            node_bindings::Anvil,
            primitives::bytes,
            providers::{ext::AnvilApi, ProviderBuilder},
        };

        let anvil = Anvil::new().try_spawn()?;
        let chain_head = ProviderBuilder::new().connect_http(anvil.endpoint_url());
        let interfold = Address::repeat_byte(0x42);
        // The finalized block answers 1 (`Requested`); chain head answers 5 (`Complete`).
        chain_head
            .anvil_set_code(interfold, bytes!("600160005260206000f3"))
            .await?;
        chain_head.anvil_mine(Some(70), None).await?;
        chain_head
            .anvil_set_code(interfold, bytes!("600560005260206000f3"))
            .await?;
        chain_head.anvil_mine(Some(1), None).await?;
        let restored = E3id::new("1", anvil.chain_id());
        let repositories =
            restored_store(HashMap::from([(restored.clone(), E3Stage::KeyPublished)])).await?;

        reconcile_finalized_lifecycle(
            &repositories,
            &[anvil_chain(anvil.endpoint(), interfold)],
            &mut ProviderCache::new(),
        )
        .await?;

        let lifecycle = repositories
            .e3_lifecycle()
            .read()
            .await?
            .unwrap_or_default();
        assert_eq!(lifecycle.get(&restored), Some(&E3Stage::KeyPublished));
        Ok(())
    }

    /// A chain entry with `enabled: false`, for example of the network that the node served
    /// before. Startup does not connect to it.
    fn disabled_chain(chain_id: u64) -> ChainConfig {
        ChainConfig {
            enabled: Some(false),
            chain_id: Some(chain_id),
            ..anvil_chain("http://127.0.0.1:1".to_owned(), Address::ZERO)
        }
    }

    #[actix::test]
    async fn a_restored_context_of_a_disabled_chain_resumes_unchecked() -> Result<()> {
        let restored = E3id::new("1", 11_155_111);
        let repositories =
            restored_store(HashMap::from([(restored.clone(), E3Stage::Requested)])).await?;

        reconcile_finalized_lifecycle(
            &repositories,
            &[disabled_chain(11_155_111)],
            &mut ProviderCache::new(),
        )
        .await?;

        let lifecycle = repositories
            .e3_lifecycle()
            .read()
            .await?
            .unwrap_or_default();
        assert_eq!(lifecycle.get(&restored), Some(&E3Stage::Requested));
        Ok(())
    }

    #[actix::test]
    async fn a_restored_context_of_a_chain_without_configuration_fails_startup() -> Result<()> {
        let repositories = restored_store(HashMap::from([(
            E3id::new("1", 11_155_111),
            E3Stage::Requested,
        )]))
        .await?;

        let error = reconcile_finalized_lifecycle(
            &repositories,
            &[disabled_chain(1)],
            &mut ProviderCache::new(),
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("chain 11155111"), "{error:#}");
        assert!(
            error.to_string().contains("interfold node reset-data"),
            "{error:#}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_read_that_does_not_end_fails_with_the_chain_name() {
        let error = within_deadline(
            "sepolia",
            Duration::from_millis(10),
            std::future::pending::<Result<()>>(),
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("timed out"));
        assert!(error.to_string().contains("'sepolia'"));
    }
}
