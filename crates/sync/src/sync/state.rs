// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::SyncRepositoryFactory;
use anyhow::{ensure, Context, Result};
use e3_data::Repositories;
use e3_events::{AggregateId, EvmEventConfig, EvmEventConfigChain};
use std::collections::{BTreeMap, HashMap};

/// Latest event information in store for a single aggregate.
#[derive(Clone)]
pub struct AggregateState {
    ts: u128,
    aggregate_id: AggregateId,
    seq: u64,
    block: u64,
}

impl AggregateState {
    pub fn new(aggregate_id: AggregateId, seq: u64, block: u64, ts: u128) -> Self {
        Self {
            aggregate_id,
            seq,
            block,
            ts,
        }
    }
}

/// Snapshot metadata describing where each aggregate left off (sequence, block, hlc timestamp).
///
/// The transforms (`to_evm_config`, `to_net_config`, `to_sequence_map`, `aggregates`) are pure
/// and unit-tested below. `read_from_disk` is the only I/O entry point and simply hydrates the
/// value object from the persisted aggregate repositories.
#[derive(Clone)]
pub struct SnapshotMeta {
    aggregate_state: Vec<AggregateState>,
}

impl SnapshotMeta {
    /// Build directly from already-loaded aggregate state (pure constructor).
    pub fn new(aggregate_state: Vec<AggregateState>) -> Self {
        Self { aggregate_state }
    }

    /// Load the SnapshotMeta from the Snapshot on disk
    pub async fn read_from_disk(
        ids: Vec<AggregateId>,
        initial_evm_config: &EvmEventConfig,
        repositories: &Repositories,
    ) -> Result<Self> {
        let mut aggregate_state = Vec::new();
        for aggregate_id in ids {
            let deploy_block = aggregate_id
                .to_chain_id()
                .and_then(|chain_id| initial_evm_config.deploy_block(chain_id))
                .unwrap_or(0);
            let seq_repo = repositories.aggregate_seq(aggregate_id);
            let block_repo = repositories.aggregate_block(aggregate_id);
            let ts_repo = repositories.aggregate_ts(aggregate_id);
            let seq = seq_repo.read().await?.unwrap_or(0);
            let block = block_repo.read().await?.unwrap_or(deploy_block);
            let ts = ts_repo.read().await?.unwrap_or(0);
            aggregate_state.push(AggregateState::new(aggregate_id, seq, block, ts));
        }

        Ok(Self { aggregate_state })
    }

    /// Return an EVM replay config with snapshot cursors and the configured confirmation policy.
    pub fn to_evm_config(&self, configured: &EvmEventConfig) -> Result<EvmEventConfig> {
        let mut map = BTreeMap::new();
        for state in &self.aggregate_state {
            let Some(chain_id) = state.aggregate_id.to_chain_id() else {
                continue;
            };
            let confirmations = configured
                .get(&chain_id)
                .with_context(|| {
                    format!(
                        "snapshot aggregate {} has no configured EVM chain",
                        state.aggregate_id
                    )
                })?
                .confirmations();
            map.insert(
                chain_id,
                EvmEventConfigChain::new(state.block).with_confirmations(confirmations),
            );
        }
        Ok(EvmEventConfig::from_config(map))
    }

    pub fn to_net_config(&self) -> BTreeMap<AggregateId, u128> {
        self.aggregate_state
            .iter()
            .map(|s| (s.aggregate_id, s.ts))
            .collect()
    }

    /// Return a map between AggregateIds and Sequence
    pub fn to_sequence_map(&self) -> HashMap<AggregateId, u64> {
        self.aggregate_state
            .iter()
            .fold(HashMap::new(), |mut acc, item| {
                acc.insert(item.aggregate_id, item.seq);
                acc
            })
    }

    /// Refuse replay when aggregate snapshots cover events that the router did not checkpoint.
    pub fn ensure_request_router_covers(
        &self,
        request_router_cursors: &HashMap<AggregateId, u64>,
    ) -> Result<()> {
        for state in &self.aggregate_state {
            let router_cursor = request_router_cursors
                .get(&state.aggregate_id)
                .copied()
                .unwrap_or(0);
            ensure!(
                router_cursor >= state.seq,
                "request-router checkpoint for aggregate {} stops at sequence {}, before snapshot sequence {}; refusing unsafe replay",
                state.aggregate_id,
                router_cursor,
                state.seq
            );
        }
        Ok(())
    }

    pub fn aggregates(&self) -> Vec<AggregateId> {
        self.aggregate_state
            .iter()
            .map(|s| s.aggregate_id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> SnapshotMeta {
        SnapshotMeta::new(vec![
            // aggregate 1 -> chain 1
            AggregateState::new(AggregateId::new(1), 10, 100, 1000),
            // aggregate 2 -> chain 2
            AggregateState::new(AggregateId::new(2), 20, 200, 2000),
            // aggregate 0 -> no chain id
            AggregateState::new(AggregateId::new(0), 5, 50, 500),
        ])
    }

    #[test]
    fn to_sequence_map_collects_all_aggregates() {
        let map = meta().to_sequence_map();
        assert_eq!(map[&AggregateId::new(1)], 10);
        assert_eq!(map[&AggregateId::new(2)], 20);
        assert_eq!(map[&AggregateId::new(0)], 5);
        assert_eq!(map.len(), 3);
    }

    #[test]
    fn stale_request_router_checkpoint_fails_replay_preflight() {
        let router_cursors = HashMap::from([(AggregateId::new(1), 4), (AggregateId::new(2), 25)]);

        let error = meta()
            .ensure_request_router_covers(&router_cursors)
            .expect_err("aggregate 1 must not replay past stale router state");

        assert!(error.to_string().contains("aggregate 1"));
        assert!(error.to_string().contains("sequence 4"));
    }

    #[test]
    fn to_net_config_maps_aggregate_to_timestamp() {
        let map = meta().to_net_config();
        assert_eq!(map[&AggregateId::new(1)], 1000);
        assert_eq!(map[&AggregateId::new(2)], 2000);
        assert_eq!(map[&AggregateId::new(0)], 500);
    }

    #[test]
    fn to_evm_config_only_includes_aggregates_with_a_chain() {
        let configured = EvmEventConfig::from_config(BTreeMap::from([
            (1, EvmEventConfigChain::new(0).with_confirmations(1)),
            (2, EvmEventConfigChain::new(0).with_confirmations(4)),
        ]));
        let config = meta().to_evm_config(&configured).unwrap();
        // aggregate 0 has no chain id and must be excluded.
        let chains = config.chains();
        assert!(chains.contains(&1));
        assert!(chains.contains(&2));
        assert_eq!(chains.len(), 2);
        assert_eq!(config.deploy_block(1), Some(100));
        assert_eq!(config.deploy_block(2), Some(200));
        assert_eq!(config.get(&1).unwrap().confirmations(), 1);
        assert_eq!(config.get(&2).unwrap().confirmations(), 4);
    }

    #[test]
    fn to_evm_config_rejects_a_snapshot_chain_without_policy() {
        let error = meta()
            .to_evm_config(&EvmEventConfig::new())
            .expect_err("configured chains must cover every chain snapshot");

        assert!(error.to_string().contains("has no configured EVM chain"));
    }

    #[test]
    fn aggregates_lists_every_aggregate_id() {
        let ids = meta().aggregates();
        assert_eq!(
            ids,
            vec![
                AggregateId::new(1),
                AggregateId::new(2),
                AggregateId::new(0)
            ]
        );
    }
}
