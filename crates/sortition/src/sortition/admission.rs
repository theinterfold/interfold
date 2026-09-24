// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Historical admission rules, derived from chain events without per-request RPC reads.

use crate::domain::node_registry::{NodeState, NodeStateStore, StateCheckpoint};
use alloy::primitives::Address;
use anyhow::{ensure, Result};
use e3_events::{AdmissionChange, AdmissionPolicy, AdmissionUpdated};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, collections::HashMap};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ChainAdmission {
    policies: Vec<StateCheckpoint<AdmissionPolicy>>,
    starts: HashMap<Address, Vec<StateCheckpoint<u64>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdmissionState {
    pub schema_version: u32,
    pub chains: HashMap<u64, ChainAdmission>,
}

impl Default for AdmissionState {
    fn default() -> Self {
        Self {
            schema_version: 2,
            chains: HashMap::new(),
        }
    }
}

fn at<T: Clone + Default>(history: &[StateCheckpoint<T>], timepoint: u64) -> T {
    let index = history.partition_point(|entry| entry.timepoint <= timepoint);
    index
        .checked_sub(1)
        .map(|i| history[i].value.clone())
        .unwrap_or_default()
}

fn record<T>(history: &mut Vec<StateCheckpoint<T>>, timepoint: u64, value: T) -> Result<()> {
    if let Some(last) = history.last_mut() {
        ensure!(
            last.timepoint <= timepoint,
            "admission history is out of order"
        );
        if last.timepoint == timepoint {
            last.value = value;
            return Ok(());
        }
    }
    history.push(StateCheckpoint { timepoint, value });
    Ok(())
}

impl AdmissionState {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 2,
            "unsupported admission snapshot schema {}",
            self.schema_version
        );
        Ok(())
    }

    pub fn record(&mut self, event: &AdmissionUpdated) -> Result<()> {
        let chain = self.chains.entry(event.chain_id).or_default();
        match &event.change {
            AdmissionChange::Policy(policy) => {
                record(&mut chain.policies, event.timepoint, policy.clone())
            }
            AdmissionChange::Started { operator } => record(
                chain.starts.entry(operator.parse()?).or_default(),
                event.timepoint,
                event.timepoint,
            ),
        }
    }

    pub fn filter<'a>(
        &self,
        chain_id: u64,
        timepoint: u64,
        nodes: &'a NodeStateStore,
    ) -> Cow<'a, NodeStateStore> {
        let Some(chain) = self.chains.get(&chain_id) else {
            return Cow::Borrowed(nodes);
        };
        let policy = at(&chain.policies, timepoint);
        if !policy.cooldown_enabled && !policy.admissions_paused {
            return Cow::Borrowed(nodes);
        }
        let mut filtered = nodes.clone();
        filtered.nodes.retain(|address, node| {
            address.parse::<Address>().ok().is_some_and(|operator| {
                let since = chain
                    .starts
                    .get(&operator)
                    .map(|h| at(h, timepoint))
                    .unwrap_or_default();
                allowed(since, timepoint, &policy, node)
            })
        });
        Cow::Owned(filtered)
    }
}

fn allowed(since: u64, timepoint: u64, policy: &AdmissionPolicy, node: &NodeState) -> bool {
    let (boundary, enabled, duration) = if policy.admissions_paused {
        if !node.active_at(policy.pause_timepoint) {
            return false;
        }
        (
            policy.pause_timepoint,
            policy.pause_cooldown_enabled,
            policy.pause_cooldown_duration,
        )
    } else {
        (timepoint, policy.cooldown_enabled, policy.cooldown_duration)
    };
    since <= boundary && (since == 0 || !enabled || boundary - since >= duration)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::backends::{SortitionBackend, SortitionList},
        domain::node_registry::SortitionSnapshot,
        BondOwnerState,
    };
    use alloy::primitives::U256;
    use e3_events::{BondOwnerSet, E3id, Seed};

    fn policy(state: &mut AdmissionState, timepoint: u64, policy: AdmissionPolicy) {
        state
            .record(&AdmissionUpdated {
                chain_id: 1,
                timepoint,
                change: AdmissionChange::Policy(policy),
            })
            .unwrap();
    }

    fn started(state: &mut AdmissionState, operator: Address, timepoint: u64) {
        state
            .record(&AdmissionUpdated {
                chain_id: 1,
                timepoint,
                change: AdmissionChange::Started {
                    operator: operator.to_string(),
                },
            })
            .unwrap();
    }

    fn node() -> NodeState {
        NodeState {
            active: true,
            active_history: vec![StateCheckpoint {
                timepoint: 1,
                value: true,
            }],
            ticket_balance: U256::from(1),
            ticket_balance_history: vec![StateCheckpoint {
                timepoint: 1,
                value: U256::from(1),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn maturity_pause_and_disable_matrix() {
        let node = node();
        for since in [0, 1, 50, 99, 100, 101] {
            for timepoint in [100, 199, 200, 201, 1000] {
                for enabled in [false, true] {
                    for paused in [false, true] {
                        for duration in [0, 100, 1000] {
                            let policy = AdmissionPolicy {
                                cooldown_enabled: enabled,
                                cooldown_duration: duration,
                                admissions_paused: paused,
                                pause_timepoint: 100,
                                pause_cooldown_enabled: true,
                                pause_cooldown_duration: 100,
                            };
                            let expected = if paused {
                                since <= 100 && (since == 0 || since + 100 <= 100)
                            } else {
                                since <= timepoint
                                    && (since == 0 || !enabled || since + duration <= timepoint)
                            };
                            assert_eq!(
                                allowed(since, timepoint, &policy, &node),
                                expected,
                                "since={since} t={timepoint} policy={policy:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn policy_and_owner_changes_preserve_snapshots_after_restart() {
        let operator = Address::repeat_byte(1);
        let nodes = NodeStateStore {
            nodes: HashMap::from([(operator.to_string(), node())]),
            ..Default::default()
        };
        let mut state = AdmissionState::default();
        started(&mut state, operator, 10);
        policy(
            &mut state,
            20,
            AdmissionPolicy {
                cooldown_enabled: true,
                cooldown_duration: 100,
                ..Default::default()
            },
        );
        let selected = |s: &AdmissionState, t| {
            s.filter(1, t, &nodes)
                .nodes
                .contains_key(&operator.to_string())
        };
        assert!(selected(&state, 19));
        assert!(!selected(&state, 109));
        assert!(selected(&state, 110));
        started(&mut state, operator, 120);
        assert!(selected(&state, 119));
        assert!(!selected(&state, 120));
        policy(
            &mut state,
            150,
            AdmissionPolicy {
                admissions_paused: true,
                pause_timepoint: 149,
                pause_cooldown_enabled: true,
                pause_cooldown_duration: 100,
                ..Default::default()
            },
        );
        assert!(!selected(&state, 300));
        policy(
            &mut state,
            400,
            AdmissionPolicy {
                cooldown_enabled: true,
                cooldown_duration: 100,
                ..Default::default()
            },
        );
        assert!(selected(&state, 400));
        let restored: AdmissionState =
            bincode::deserialize(&bincode::serialize(&state).unwrap()).unwrap();
        restored.validate().unwrap();
        for t in 0..500 {
            assert_eq!(selected(&state, t), selected(&restored, t));
        }
        assert!(matches!(state.filter(2, 200, &nodes), Cow::Borrowed(_)));
        assert!(matches!(state.filter(1, 19, &nodes), Cow::Borrowed(_)));
        assert!(state
            .record(&AdmissionUpdated {
                chain_id: 1,
                timepoint: 100,
                change: AdmissionChange::Started {
                    operator: operator.to_string()
                }
            })
            .is_err());
    }

    #[test]
    fn pause_requires_prior_activity_and_does_not_reset_elapsed_time() {
        let inactive = NodeState {
            active_history: vec![StateCheckpoint {
                timepoint: 150,
                value: true,
            }],
            ..node()
        };
        let paused = AdmissionPolicy {
            admissions_paused: true,
            pause_timepoint: 100,
            pause_cooldown_enabled: true,
            pause_cooldown_duration: 10,
            ..Default::default()
        };
        assert!(!allowed(50, 300, &paused, &inactive));
        assert!(allowed(50, 300, &paused, &node()));
        assert!(!allowed(95, 300, &paused, &node()));
        assert!(!allowed(101, 300, &paused, &node()));
        assert!(allowed(
            95,
            300,
            &AdmissionPolicy {
                cooldown_enabled: true,
                cooldown_duration: 10,
                ..Default::default()
            },
            &node()
        ));
    }

    #[test]
    fn waiting_owners_cannot_fill_the_shortlist_or_hide_ready_backups() {
        let mut state = AdmissionState::default();
        policy(
            &mut state,
            2,
            AdmissionPolicy {
                cooldown_enabled: true,
                cooldown_duration: 100,
                ..Default::default()
            },
        );
        let mut backend = SortitionBackend::default();
        let mut nodes = NodeStateStore::default();
        let mut owners = BondOwnerState::default();
        for i in 1..=50 {
            let operator = Address::repeat_byte(i);
            backend.add(operator.to_string());
            nodes.nodes.insert(operator.to_string(), node());
            started(&mut state, operator, if i <= 28 { 100 } else { 10 });
            owners
                .record(
                    &BondOwnerSet {
                        chain_id: 1,
                        operator: operator.to_string(),
                        bond_owner: operator.to_string(),
                    },
                    1,
                )
                .unwrap();
        }
        let filtered = state.filter(1, 150, &nodes);
        assert_eq!(filtered.nodes.len(), 22);
        let snapshot = SortitionSnapshot {
            request_block: 151,
            ticket_price: U256::from(1),
        };
        let mut ranks = vec![];
        for i in 1..=50 {
            let rank = backend
                .get_submission_index(
                    E3id::new("1", 1),
                    Seed([1; 32]),
                    Address::repeat_byte(i).to_string(),
                    1,
                    &filtered,
                    snapshot,
                    19,
                    &owners,
                )
                .unwrap();
            if i <= 28 {
                assert!(rank.is_none());
            }
            if let Some((rank, _)) = rank {
                ranks.push(rank);
            }
        }
        ranks.sort();
        assert_eq!(ranks, (0..19).collect::<Vec<_>>());
    }
}
