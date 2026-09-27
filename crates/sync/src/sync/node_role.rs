// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use serde::{Deserialize, Serialize};
use std::fmt;

/// What a node does, which also decides what its data directory holds.
///
/// A bootstrap node reads only the Interfold contract, yet it advances the same per-chain block
/// cursor that a full node's registry readers resume from. A full node started on a bootstrap
/// node's directory would therefore skip every earlier registry event. A bootstrap node started on
/// a full node's directory would restore that node's committees. The role is stamped on first boot
/// so that neither switch can happen silently.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeRole {
    /// Joins committees, generates proofs, and sends transactions.
    Full,
    /// Serves peer discovery and relays gossip. It holds no keyshares and signs no protocol
    /// messages.
    Bootstrap,
}

impl fmt::Display for NodeRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeRole::Full => f.write_str("full"),
            NodeRole::Bootstrap => f.write_str("bootstrap"),
        }
    }
}

/// The action a node takes after reading the role stamped on its data directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeRoleDecision {
    /// The directory has no role yet: stamp the requested role.
    Write,
    /// The directory belongs to the requested role.
    Proceed,
    /// The directory belongs to another role; halt with this reason.
    Halt(String),
}

/// Pure decision: given the stamped role (if any), the requested role, and whether the directory
/// already holds events, decide whether to proceed, stamp the role, or halt.
///
/// Data directories that predate the role marker come from full nodes, because a bootstrap node
/// stamps its role before it writes any event. An unmarked directory that holds events is
/// therefore a full node's.
pub fn decide_node_role(
    persisted: Option<NodeRole>,
    requested: NodeRole,
    has_existing_events: bool,
) -> NodeRoleDecision {
    let owner = match persisted {
        Some(role) => role,
        None if has_existing_events => NodeRole::Full,
        None => return NodeRoleDecision::Write,
    };
    if owner != requested {
        return NodeRoleDecision::Halt(format!(
            "This data directory belongs to a {owner} node and cannot start a {requested} node. \
             Give the {requested} node its own data directory, or clear this one with \
             `interfold node reset-data`, which keeps the operator identity."
        ));
    }
    if persisted.is_none() {
        NodeRoleDecision::Write
    } else {
        NodeRoleDecision::Proceed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_directory_takes_the_requested_role() {
        for role in [NodeRole::Full, NodeRole::Bootstrap] {
            assert_eq!(decide_node_role(None, role, false), NodeRoleDecision::Write);
        }
    }

    #[test]
    fn a_directory_proceeds_with_its_own_role() {
        for role in [NodeRole::Full, NodeRole::Bootstrap] {
            assert_eq!(
                decide_node_role(Some(role), role, true),
                NodeRoleDecision::Proceed
            );
        }
    }

    #[test]
    fn a_directory_refuses_the_other_role() {
        for (owner, requested) in [
            (NodeRole::Full, NodeRole::Bootstrap),
            (NodeRole::Bootstrap, NodeRole::Full),
        ] {
            let NodeRoleDecision::Halt(reason) = decide_node_role(Some(owner), requested, true)
            else {
                panic!("{requested} must not start on a {owner} node's directory");
            };
            assert!(reason.contains(&format!("belongs to a {owner} node")));
        }
    }

    #[test]
    fn the_stamped_role_keeps_its_stored_bytes() -> anyhow::Result<()> {
        // The store keeps the role as positional bincode. Reordering the variants would make every
        // stamped directory read as the other role.
        assert_eq!(bincode::serialize(&NodeRole::Full)?, [0, 0, 0, 0]);
        assert_eq!(bincode::serialize(&NodeRole::Bootstrap)?, [1, 0, 0, 0]);
        Ok(())
    }

    #[test]
    fn an_unmarked_directory_with_events_belongs_to_a_full_node() {
        assert_eq!(
            decide_node_role(None, NodeRole::Full, true),
            NodeRoleDecision::Write
        );
        assert!(matches!(
            decide_node_role(None, NodeRole::Bootstrap, true),
            NodeRoleDecision::Halt(_)
        ));
    }
}
