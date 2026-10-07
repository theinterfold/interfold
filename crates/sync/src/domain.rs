// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Compatibility view of pure planning and state stored in the sync capability.

#[path = "sync/collect_history.rs"]
mod historical_evm_collector;
#[path = "sync/node_role.rs"]
mod node_role;
#[path = "sync/schema_version.rs"]
mod schema_version;
#[path = "sync/state.rs"]
mod snapshot_meta;
#[path = "sync/workflow.rs"]
mod sync_planner;

pub use node_role::{decide_node_role, NodeRole, NodeRoleDecision};
pub use schema_version::{decide_schema_version, SchemaVersionDecision, SCHEMA_VERSION};
pub use snapshot_meta::{AggregateState, SnapshotMeta};

pub(crate) use historical_evm_collector::{CollectOutcome, HistoricalEvmCollector};
pub(crate) use sync_planner::{ReplayDecision, SyncPlanner};
