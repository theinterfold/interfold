// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Read-only, operator-facing on-chain status queries.

mod scan_cache;

use crate::{
    adapters::log_fetcher::{fetch_logs_adapting, LogProvider},
    contracts::{IBondingRegistry, ICiphernodeRegistry, IInterfold},
    domain::reorg::confirmed_head,
    helpers::get_current_timestamp_from_provider,
    ProviderConfig,
};
use alloy::{
    eips::BlockId,
    primitives::{Address, U256},
    providers::Provider,
    rpc::types::{Filter, Log},
    sol_types::SolEvent,
};
use anyhow::Context as _;
use e3_config::{chain_config::ChainConfig, ContractAddresses};
use e3_events::E3Stage;
use scan_cache::{SavedScan, ScanKey};
use serde::Serialize;
use std::{collections::BTreeMap, path::PathBuf, str::FromStr};
use tracing::{debug, warn};

#[derive(Clone, Debug, Serialize)]
pub struct OperatorChainStatus {
    pub chain_id: u64,
    pub chain_name: String,
    pub registered_nodes: String,
    pub active_nodes: String,
    pub operator_registered: bool,
    pub operator_active: bool,
    /// `BondingRegistry.eligibilityAt(operator, latest block timestamp)`. Unlike
    /// `operator_active`, it also applies the admission cooldown and the admission policy, which
    /// decide whether sortition for a new committee can select the operator. `None` when the
    /// read fails.
    pub operator_eligible: Option<bool>,
    pub exit_in_progress: bool,
    pub ticket_balance: String,
    pub available_tickets: String,
    pub ciphernode_bond: String,
    pub bond_owner: String,
}

pub async fn fetch_operator_status(
    chain: &ChainConfig,
    operator: Address,
) -> anyhow::Result<OperatorChainStatus> {
    let provider = ProviderConfig::for_chain(chain)?
        .create_readonly_provider()
        .await?;
    let client = provider.provider().clone();
    let bonding_address = Address::from_str(chain.contracts.bonding_registry.address_str())?;
    let registry_address = Address::from_str(chain.contracts.ciphernode_registry.address_str())?;
    let bonding = IBondingRegistry::new(bonding_address, client.clone());
    let registry = ICiphernodeRegistry::new(registry_address, client);

    // A failed eligibility read makes only `operator_eligible` unknown.
    let eligibility = async {
        let timestamp = get_current_timestamp_from_provider(provider.clone()).await?;
        let eligibility = bonding
            .eligibilityAt(operator, U256::from(timestamp))
            .call()
            .await?;
        anyhow::Ok(eligibility.active)
    };
    let (reads, operator_eligible) = tokio::join!(
        async {
            tokio::try_join!(
                async { bonding.getTicketBalance(operator).call().await },
                async { bonding.getCiphernodeBond(operator).call().await },
                async { bonding.availableTickets(operator).call().await },
                async { bonding.isRegistered(operator).call().await },
                async { bonding.isActive(operator).call().await },
                async { bonding.numActiveOperators().call().await },
                async { registry.numCiphernodes().call().await },
                async { bonding.hasExitInProgress(operator).call().await },
                async { bonding.bondOwnerOf(operator).call().await },
            )
        },
        eligibility,
    );
    let (
        ticket_balance,
        ciphernode_bond,
        available_tickets,
        operator_registered,
        operator_active,
        active_nodes,
        registered_nodes,
        exit_in_progress,
        bond_owner,
    ) = reads?;
    let operator_eligible = operator_eligible
        .inspect_err(|error| {
            debug!(chain = %chain.name, %error, "Could not read operator eligibility");
        })
        .ok();

    Ok(OperatorChainStatus {
        chain_id: provider.chain_id(),
        chain_name: chain.name.clone(),
        registered_nodes: registered_nodes.to_string(),
        active_nodes: active_nodes.to_string(),
        operator_registered,
        operator_active,
        operator_eligible,
        exit_in_progress,
        ticket_balance: ticket_balance.to_string(),
        available_tickets: available_tickets.to_string(),
        ciphernode_bond: ciphernode_bond.to_string(),
        bond_owner: bond_owner.to_string(),
    })
}

/// Membership of an operator in a committee that holds its collateral.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitteeMembership {
    /// Holds a provisional seat while sortition for the E3 is open.
    Candidate,
    /// Active member of the finalized committee.
    Member,
    /// Expelled from the finalized committee.
    Expelled,
}

/// A committee that holds the operator's collateral until `releaseCommittee(e3Id)` runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorCommittee {
    pub e3_id: U256,
    pub membership: CommitteeMembership,
    pub e3_stage: E3Stage,
}

/// How [`fetch_operator_committees`] reads the obligation history.
#[derive(Clone, Debug)]
pub struct CommitteeScan {
    /// The chain's widest `eth_getLogs` block range (`rpc_log_range_blocks`).
    pub max_log_window: u64,
    /// Confirmations that a block needs before the scan saves it (`ingestion_confirmations`).
    pub confirmations: u64,
    /// Directory of the saved scans. `None` reads the whole history on every call.
    pub cache_dir: Option<PathBuf>,
}

/// Lists the committees that hold `operator`'s collateral, in E3 ID order.
///
/// An open obligation makes an exit claim revert with `OperatorInActiveCommittee`. The bonding
/// registry indexes the open obligations of an operator in `committeeObligationAt`, which
/// [`tracked_obligations`] reads. A registry deployed before that view, or one with committees
/// requested before it, needs the events instead: the registry emits `CommitteeObligationUpdated`,
/// with the operator as an indexed topic, each time it opens or releases an obligation, so the
/// last event for an E3 tells whether the obligation is open. That history grows with the chain,
/// and scripts run `ciphernode status` often, so the scan saves its progress and the next call
/// reads only the new blocks. See [`scan_open_obligations`].
pub async fn fetch_operator_committees<P: Provider + Clone>(
    provider: &P,
    contracts: &ContractAddresses,
    operator: Address,
    scan: &CommitteeScan,
) -> anyhow::Result<Vec<OperatorCommittee>> {
    let interfold = contracts
        .interfold
        .address()
        .context("invalid interfold address")?;
    let interfold = IInterfold::new(interfold, provider.clone());
    let bonding_registry = contracts
        .bonding_registry
        .address()
        .context("invalid bonding_registry address")?;
    let open =
        match tracked_obligations(provider, bonding_registry, operator, scan.confirmations).await {
            Some(open) => open,
            None => {
                let key = ScanKey {
                    chain_id: provider.get_chain_id().await?,
                    bonding_registry,
                    deploy_block: contracts.bonding_registry.deploy_block().unwrap_or(0),
                    operator,
                };
                scan_open_obligations(provider, &key, scan).await?
            }
        };

    let mut committees = Vec::new();
    for (e3_id, registry) in open {
        // The registry that opened the obligation owns the committee of that E3.
        let registry = ICiphernodeRegistry::new(registry, provider.clone());
        let (active, member, stage) = tokio::try_join!(
            async {
                registry
                    .isCommitteeMemberActive(e3_id, operator)
                    .call()
                    .await
            },
            async { registry.isCommitteeMember(e3_id, operator).call().await },
            async { interfold.getE3Stage(e3_id).call().await },
        )?;
        // Sortition opens the obligation when it ranks the operator. Only finalization makes the
        // operator a member.
        let membership = match (active, member) {
            (true, _) => CommitteeMembership::Member,
            (false, true) => CommitteeMembership::Expelled,
            (false, false) => CommitteeMembership::Candidate,
        };
        committees.push(OperatorCommittee {
            e3_id,
            membership,
            e3_stage: E3Stage::try_from(stage)
                .with_context(|| format!("E3 {e3_id} reports a stage this node does not know"))?,
        });
    }
    Ok(committees)
}

/// The open obligations of `operator` from the views of the bonding registry, by E3 ID, with the
/// registry that owns each committee.
///
/// All views are read at the confirmed head, the block where the event scan stops, named by its
/// hash ([`confirmed_block`]). The registry indexes only the committees that it tracks, which are
/// some of the open ones, so an obligation at every index below `unresolvedCommitteesOf` means that
/// it tracks them all. Returns `None` when a read fails: the registry has no such views, as a
/// registry deployed before them, or an index reverts because the operator is in a committee
/// requested before the registry tracked them, and only the events list it.
async fn tracked_obligations<P: Provider + Clone>(
    provider: &P,
    bonding_registry: Address,
    operator: Address,
    confirmations: u64,
) -> Option<BTreeMap<U256, Address>> {
    let bonding = IBondingRegistry::new(bonding_registry, provider.clone());
    let reads = async {
        let block = confirmed_block(provider, confirmations).await?;
        let count: u64 = bonding
            .unresolvedCommitteesOf(operator)
            .block(block)
            .call()
            .await?
            .try_into()?;
        let mut open = BTreeMap::new();
        for index in 0..count {
            let obligation = bonding
                .committeeObligationAt(operator, U256::from(index))
                .block(block)
                .call()
                .await?;
            open.insert(obligation.e3Id, obligation.registry);
        }
        anyhow::ensure!(
            open.len() as u64 == count,
            "the registry indexed an E3 twice"
        );
        anyhow::Ok(open)
    };
    reads
        .await
        .inspect_err(|error| {
            debug!(%error, "Bonding registry obligation views incomplete; reading the events");
        })
        .ok()
}

/// The confirmed head, named by its hash: two branches hold different states at one height, and a
/// load-balanced endpoint can serve both, so reads at one number can see two states.
async fn confirmed_block<P: Provider>(provider: &P, confirmations: u64) -> anyhow::Result<BlockId> {
    let number = confirmed_head(provider.get_block_number().await?, confirmations);
    let block = provider
        .get_block_by_number(number.into())
        .await?
        .with_context(|| format!("the provider has no block {number}"))?;
    Ok(BlockId::hash_canonical(block.header.hash))
}

/// Returns the obligations of `key.operator` that are open at the confirmed head, by E3 ID, with
/// the registry that opened each one.
///
/// A saved scan is resumed while the provider still has its last block under the saved hash, so a
/// repeated call reads only the blocks after it. Another hash at that height means that a reorg
/// replaced the block, and the scan starts again from the deploy block. The hash is checked again
/// after the new blocks are read: a reorg during the read would leave the saved obligations and the
/// new blocks on different branches. When the provider has no block at that height, as a node
/// behind its peers, the result is returned and not saved. The scan saves blocks up to the
/// confirmed head only, the depth that node ingestion waits for.
async fn scan_open_obligations<L: LogProvider>(
    provider: &L,
    key: &ScanKey,
    scan: &CommitteeScan,
) -> anyhow::Result<BTreeMap<U256, Address>> {
    let head = confirmed_head(provider.fetch_block_number().await?, scan.confirmations);
    let mut saved = scan
        .cache_dir
        .as_deref()
        .and_then(|dir| SavedScan::load(dir, key));
    // At most two passes: a pass that finds the saved block replaced reads the history again.
    loop {
        let (from_block, mut open, resumed) = match saved.take() {
            Some(saved) => match provider.fetch_block_hash(saved.block).await? {
                Some(hash) if hash == saved.block_hash => {
                    let resumed = (saved.block, saved.block_hash);
                    (saved.block + 1, saved.into_open(), Some(resumed))
                }
                Some(_) => (key.deploy_block, BTreeMap::new(), None),
                None => return Ok(saved.into_open()),
            },
            None => (key.deploy_block, BTreeMap::new(), None),
        };
        if from_block > head {
            return Ok(open);
        }

        // Read before the logs: a reorg after this read replaces the block, and the next call then
        // finds another hash and reads the history again.
        let head_hash = match scan.cache_dir {
            Some(_) => provider.fetch_block_hash(head).await?,
            None => None,
        };
        let filter = Filter::new()
            .address(key.bonding_registry)
            .event_signature(IBondingRegistry::CommitteeObligationUpdated::SIGNATURE_HASH)
            .topic3(key.operator.into_word());
        let logs = fetch_logs_adapting(
            provider,
            &filter,
            from_block,
            head,
            key.chain_id,
            scan.max_log_window,
        )
        .await?;
        apply_obligation_updates(&mut open, logs)?;

        if let Some((block, block_hash)) = resumed {
            match provider.fetch_block_hash(block).await? {
                Some(hash) if hash == block_hash => {}
                Some(_) => continue,
                None => return Ok(open),
            }
        }
        if let (Some(dir), Some(block_hash)) = (scan.cache_dir.as_deref(), head_hash) {
            if let Err(error) = SavedScan::new(key, head, block_hash, &open).save(dir) {
                warn!(
                    %error,
                    dir = %dir.display(),
                    "Could not save the committee obligation scan; the next call reads the history again"
                );
            }
        }
        return Ok(open);
    }
}

/// Applies `CommitteeObligationUpdated` logs to `open`: each E3 whose last update opened the
/// obligation, with the registry that sent the update.
///
/// `logs` must be in chain order, as `fetch_logs_adapting` returns them, because the last update of
/// an E3 decides whether its obligation is open.
fn apply_obligation_updates(
    open: &mut BTreeMap<U256, Address>,
    logs: Vec<Log>,
) -> anyhow::Result<()> {
    for log in logs {
        let event = IBondingRegistry::CommitteeObligationUpdated::decode_log_data(log.data())
            .context("invalid CommitteeObligationUpdated event")?;
        if event.active {
            open.insert(event.e3Id, event.registry);
        } else {
            open.remove(&event.e3Id);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        primitives::{Bytes, B256},
        providers::ProviderBuilder,
        rpc::{
            client::RpcClient,
            json_rpc::{RequestPacket, Response, ResponsePacket, ResponsePayload},
        },
        sol_types::{SolCall, SolValue},
        transports::{TransportErrorKind, TransportFut},
    };
    use async_trait::async_trait;
    use serde_json::value::RawValue;
    use std::sync::Mutex;

    /// A chain that serves `logs` by block range and counts the `eth_getLogs` requests. Each block
    /// has a hash, and a test replaces one to model a reorg.
    struct ScanChain {
        state: Mutex<ScanChainState>,
    }

    struct ScanChainState {
        head: u64,
        logs: Vec<Log>,
        replaced: BTreeMap<u64, B256>,
        get_logs_calls: u32,
        /// A reorg that the next `eth_getLogs` request applies first.
        reorg_at_next_read: Option<(u64, Log)>,
    }

    impl ScanChainState {
        /// Gives `block` another hash and adds `log`, as a branch that replaced the block.
        fn replace(&mut self, block: u64, log: Log) {
            self.replaced.insert(block, B256::repeat_byte(0xee));
            self.logs.push(log);
            self.logs
                .sort_by_key(|log| (log.block_number, log.log_index));
        }
    }

    impl ScanChain {
        fn new(head: u64, logs: Vec<Log>) -> Self {
            Self {
                state: Mutex::new(ScanChainState {
                    head,
                    logs,
                    replaced: BTreeMap::new(),
                    get_logs_calls: 0,
                    reorg_at_next_read: None,
                }),
            }
        }

        fn mine(&self, head: u64, log: Log) {
            let mut state = self.state.lock().unwrap();
            state.head = head;
            state.logs.push(log);
        }

        fn reorg(&self, block: u64, head: u64, log: Log) {
            let mut state = self.state.lock().unwrap();
            state.head = head;
            state.replace(block, log);
        }

        /// The reorg happens while the scan runs, right before its next `eth_getLogs` request.
        fn reorg_during_next_read(&self, block: u64, log: Log) {
            self.state.lock().unwrap().reorg_at_next_read = Some((block, log));
        }

        fn get_logs_calls(&self) -> u32 {
            self.state.lock().unwrap().get_logs_calls
        }
    }

    #[async_trait]
    impl LogProvider for ScanChain {
        async fn fetch_logs(&self, filter: &Filter) -> anyhow::Result<Vec<Log>> {
            let mut state = self.state.lock().unwrap();
            state.get_logs_calls += 1;
            if let Some((block, log)) = state.reorg_at_next_read.take() {
                state.replace(block, log);
            }
            let from = filter.get_from_block().unwrap_or_default();
            let to = filter.get_to_block().unwrap_or(state.head);
            Ok(state
                .logs
                .iter()
                .filter(|log| log.block_number.is_some_and(|b| from <= b && b <= to))
                .cloned()
                .collect())
        }

        async fn fetch_block_number(&self) -> anyhow::Result<u64> {
            Ok(self.state.lock().unwrap().head)
        }

        async fn fetch_block_timestamp(&self, _block_number: u64) -> anyhow::Result<u64> {
            Ok(0)
        }

        async fn fetch_block_hash(&self, block_number: u64) -> anyhow::Result<Option<B256>> {
            let state = self.state.lock().unwrap();
            Ok((block_number <= state.head).then(|| {
                state
                    .replaced
                    .get(&block_number)
                    .copied()
                    .unwrap_or_else(|| B256::from(U256::from(block_number)))
            }))
        }
    }

    fn scan_key() -> ScanKey {
        ScanKey {
            chain_id: 1,
            bonding_registry: Address::repeat_byte(0xbb),
            deploy_block: 0,
            operator: Address::repeat_byte(0xaa),
        }
    }

    fn saved_scan(dir: &std::path::Path) -> CommitteeScan {
        CommitteeScan {
            max_log_window: 100,
            confirmations: 1,
            cache_dir: Some(dir.to_path_buf()),
        }
    }

    fn open_ids(open: BTreeMap<U256, Address>) -> Vec<u64> {
        open.into_keys().map(|e3_id| e3_id.to::<u64>()).collect()
    }

    /// `ciphernode status` runs from scripts, and before the saved scan every call read the whole
    /// obligation history: one `eth_getLogs` for each window since the deploy block.
    #[tokio::test]
    async fn a_repeated_scan_reads_only_the_new_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let (key, scan) = (scan_key(), saved_scan(dir.path()));
        let registry = Address::repeat_byte(0x01);
        let chain = ScanChain::new(
            1_000,
            vec![
                obligation_log(100, 0, 1, registry, true),
                obligation_log(900, 0, 2, registry, true),
            ],
        );

        let open = scan_open_obligations(&chain, &key, &scan).await.unwrap();
        assert_eq!(open_ids(open), vec![1, 2]);
        assert_eq!(
            chain.get_logs_calls(),
            10,
            "blocks 0..=999 in windows of 100"
        );

        chain.mine(1_100, obligation_log(1_050, 0, 1, registry, false));
        let open = scan_open_obligations(&chain, &key, &scan).await.unwrap();
        assert_eq!(open_ids(open), vec![2]);
        assert_eq!(chain.get_logs_calls(), 11, "only blocks 1000..=1099");
    }

    #[tokio::test]
    async fn a_replaced_saved_block_restarts_the_scan() {
        let dir = tempfile::tempdir().unwrap();
        let (key, scan) = (scan_key(), saved_scan(dir.path()));
        let registry = Address::repeat_byte(0x01);
        let chain = ScanChain::new(1_000, vec![obligation_log(100, 0, 1, registry, true)]);
        scan_open_obligations(&chain, &key, &scan).await.unwrap();
        assert_eq!(chain.get_logs_calls(), 10);

        // A reorg replaced the saved block 999, and the new branch holds an earlier obligation.
        chain.reorg(999, 1_010, obligation_log(500, 0, 3, registry, true));
        let open = scan_open_obligations(&chain, &key, &scan).await.unwrap();
        assert_eq!(open_ids(open), vec![1, 3]);
        assert_eq!(chain.get_logs_calls(), 21, "blocks 0..=1009 again");
    }

    #[tokio::test]
    async fn a_reorg_during_a_resumed_scan_restarts_it() {
        let dir = tempfile::tempdir().unwrap();
        let (key, scan) = (scan_key(), saved_scan(dir.path()));
        let registry = Address::repeat_byte(0x01);
        let chain = ScanChain::new(1_000, vec![obligation_log(100, 0, 1, registry, true)]);
        scan_open_obligations(&chain, &key, &scan).await.unwrap();
        assert_eq!(chain.get_logs_calls(), 10);

        // The resumed scan finds the saved block 999, and then a branch that holds an earlier
        // obligation replaces it while the new blocks are read.
        chain.mine(1_100, obligation_log(1_050, 0, 2, registry, true));
        chain.reorg_during_next_read(999, obligation_log(500, 0, 3, registry, true));
        let open = scan_open_obligations(&chain, &key, &scan).await.unwrap();
        assert_eq!(open_ids(open), vec![1, 2, 3]);
        assert_eq!(
            chain.get_logs_calls(),
            22,
            "blocks 1000..=1099, then 0..=1099 again"
        );

        let open = scan_open_obligations(&chain, &key, &scan).await.unwrap();
        assert_eq!(
            open_ids(open),
            vec![1, 2, 3],
            "the saved scan is of the new branch"
        );
        assert_eq!(chain.get_logs_calls(), 22);
    }

    /// A node at height 100 that serves the obligation views of `obligations`, with `count` as the
    /// operator's count, and checks that every view call names the confirmed head by its hash. An
    /// index past `obligations` reverts.
    fn views_node(count: u64, obligations: Vec<(u64, Address)>) -> impl Provider + Clone {
        let block_hash = B256::repeat_byte(0x42);
        let transport = tower::service_fn(move |packet: RequestPacket| -> TransportFut<'static> {
            let obligations = obligations.clone();
            Box::pin(async move {
                let RequestPacket::Single(request) = packet else {
                    panic!("unexpected RPC batch")
                };
                let params: serde_json::Value = request
                    .params()
                    .map(|params| serde_json::from_str(params.get()).unwrap())
                    .unwrap_or_default();
                let result = match request.method() {
                    "eth_blockNumber" => serde_json::json!("0x64"),
                    "eth_getBlockByNumber" => {
                        assert_eq!(params[0], "0x63", "the head minus one confirmation");
                        let mut block: alloy::rpc::types::Block = Default::default();
                        block.header.hash = block_hash;
                        serde_json::to_value(block).unwrap()
                    }
                    "eth_call" => {
                        let at = serde_json::to_value(BlockId::hash_canonical(block_hash)).unwrap();
                        assert_eq!(params[1], at, "a view read at another block");
                        let input = params[0]["input"]
                            .as_str()
                            .or_else(|| params[0]["data"].as_str())
                            .unwrap();
                        let input = hex::decode(input.trim_start_matches("0x")).unwrap();
                        if input
                            .starts_with(&IBondingRegistry::unresolvedCommitteesOfCall::SELECTOR)
                        {
                            serde_json::json!(Bytes::from(U256::from(count).abi_encode()))
                        } else {
                            let call =
                                IBondingRegistry::committeeObligationAtCall::abi_decode(&input)
                                    .unwrap();
                            let Some(&(e3_id, registry)) =
                                obligations.get(call.index.to::<usize>())
                            else {
                                return Err(TransportErrorKind::custom_str("execution reverted"));
                            };
                            serde_json::json!(Bytes::from(
                                (U256::from(e3_id), registry).abi_encode_params()
                            ))
                        }
                    }
                    method => panic!("unexpected RPC {method}"),
                };
                Ok(ResponsePacket::Single(Response {
                    id: request.id().clone(),
                    payload: ResponsePayload::Success(
                        RawValue::from_string(result.to_string()).unwrap(),
                    ),
                }))
            })
        });
        ProviderBuilder::new().connect_client(RpcClient::new(transport, true))
    }

    #[tokio::test]
    async fn the_views_list_every_obligation() {
        let (registry, operator) = (Address::repeat_byte(0x01), Address::repeat_byte(0xaa));
        let node = views_node(2, vec![(9, registry), (7, registry)]);

        let open = tracked_obligations(&node, Address::ZERO, operator, 1).await;
        assert_eq!(
            open,
            Some(BTreeMap::from([
                (U256::from(7), registry),
                (U256::from(9), registry)
            ]))
        );
    }

    /// The registry tracks only the committees requested after its upgrade. An index of an
    /// untracked one reverts, and an index that answers twice for one E3 leaves another out.
    #[tokio::test]
    async fn an_incomplete_index_falls_back_to_the_events() {
        let (registry, operator) = (Address::repeat_byte(0x01), Address::repeat_byte(0xaa));
        let untracked = views_node(2, vec![(7, registry)]);
        assert_eq!(
            tracked_obligations(&untracked, Address::ZERO, operator, 1).await,
            None
        );

        let repeated = views_node(2, vec![(7, registry), (7, registry)]);
        assert_eq!(
            tracked_obligations(&repeated, Address::ZERO, operator, 1).await,
            None
        );
    }

    fn obligation_log(block: u64, index: u64, e3_id: u64, registry: Address, active: bool) -> Log {
        let event = IBondingRegistry::CommitteeObligationUpdated {
            e3Id: U256::from(e3_id),
            registry,
            operator: Address::repeat_byte(0xaa),
            active,
        };
        Log {
            inner: alloy::primitives::Log {
                address: Address::repeat_byte(0xbb),
                data: event.encode_log_data(),
            },
            block_number: Some(block),
            log_index: Some(index),
            ..Default::default()
        }
    }

    #[test]
    fn open_obligations_follow_the_last_update_in_chain_order() {
        let registry = Address::repeat_byte(0x01);
        let replacement = Address::repeat_byte(0x02);
        let logs = vec![
            obligation_log(10, 3, 1, registry, true),
            obligation_log(12, 0, 2, registry, true),
            // A better ticket displaced the operator from E3 2 in the same block.
            obligation_log(12, 1, 2, registry, false),
            // E3 3 is still open, under another registry.
            obligation_log(15, 0, 3, replacement, true),
            // E3 1 is released after the E3 ended.
            obligation_log(20, 0, 1, registry, false),
        ];

        let mut open = BTreeMap::new();
        apply_obligation_updates(&mut open, logs).unwrap();

        assert_eq!(
            open.into_iter().collect::<Vec<_>>(),
            vec![(U256::from(3), replacement)]
        );
    }
}
