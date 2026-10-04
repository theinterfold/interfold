// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/// The on-disk schema version understood by this binary.
///
/// All persisted state (Sled snapshots + commitlog) is bincode with no
/// per-struct version tag, so a breaking change to any persisted struct or
/// event-variant layout is undetectable at the byte level. This single global
/// marker is the guardrail: bump it whenever a persisted format changes in a
/// non-additive way. On boot the persisted value is compared against this
/// constant (see `decide_schema_version`).
// Schema 6 can contain sortition checkpoints derived from the merged event clock. A schema-6 node
// clears its state with `interfold node reset-data`, and the resync from chain history rebuilds
// those checkpoints from source timestamps.
// Schema 7 also adds durable decryption backup shares and batch-bound C6 results.
// Schema 8 authenticates complete DKG share and C4 bundles before slot admission.
pub const SCHEMA_VERSION: u32 = 8;

/// The action a node should take after reading the persisted schema version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaVersionDecision {
    /// First boot (or a store that predates versioning): stamp the current version.
    WriteCurrent,
    /// On-disk version matches the binary; proceed.
    Proceed,
    /// On-disk version is incompatible with the binary; halt with this reason.
    Halt(String),
}

/// The supported path for state that is older than this binary. It clears the state and keeps the
/// node identity.
const RESET_HINT: &str = "Stop the node. Then run `interfold node reset-data --name <node>`, which \
     keeps the operator key and the libp2p keypair. That command refuses while the node holds a key \
     share for an E3 that the node has not seen complete.";

/// Pure decision: given the persisted schema version (if any) and the version
/// this binary supports, decide whether to proceed, stamp a fresh marker, or
/// halt loudly (H19 upgrade / H20 downgrade).
///
/// Policy: only an exact match is accepted. Because the codebase supports only
/// additive evolution and removed the previous `#[serde(default)]` shims, any
/// version mismatch implies a breaking change with no migration path, so both
/// older on-disk data (upgrade) and newer on-disk data (downgrade) halt.
pub fn decide_schema_version(
    persisted: Option<u32>,
    current: u32,
    has_existing_state: bool,
) -> SchemaVersionDecision {
    match persisted {
        None if !has_existing_state => SchemaVersionDecision::WriteCurrent,
        None => SchemaVersionDecision::Halt(format!(
            "On-disk state has no schema marker, so compatibility with schema version {current} \
             cannot be proven. Halting. Restore the backup of the stopped node. Without a backup, \
             run `interfold node reset-data --name <node>`. It keeps the operator key and the \
             libp2p keypair only if the key/value store still holds them."
        )),
        Some(v) if v == current => SchemaVersionDecision::Proceed,
        Some(v) if v > current => SchemaVersionDecision::Halt(format!(
            "On-disk schema version {v} is newer than this binary's supported version {current}. \
             This is a downgrade across an incompatible format change. Halting. Run a binary at \
             schema version {v} or newer, or restore the backup taken before the upgrade."
        )),
        Some(v) => SchemaVersionDecision::Halt(format!(
            "On-disk schema version {v} is older than this binary's supported version {current}, \
             and no migration exists. Halting. {RESET_HINT}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_store_writes_current() {
        assert_eq!(
            decide_schema_version(None, 4, false),
            SchemaVersionDecision::WriteCurrent
        );
    }

    #[test]
    fn exact_match_proceeds() {
        assert_eq!(
            decide_schema_version(Some(4), 4, true),
            SchemaVersionDecision::Proceed
        );
    }

    #[test]
    fn older_on_disk_halts_as_upgrade() {
        let d = decide_schema_version(Some(3), 4, true);
        match d {
            SchemaVersionDecision::Halt(msg) => {
                assert!(msg.contains("older"));
                assert!(msg.contains("interfold node reset-data --name <node>"));
            }
            other => panic!("expected Halt, got {other:?}"),
        }
    }

    #[test]
    fn newer_on_disk_halts_as_downgrade() {
        let d = decide_schema_version(Some(5), 4, true);
        match d {
            SchemaVersionDecision::Halt(msg) => {
                assert!(msg.contains("newer"));
                assert!(msg.contains("downgrade"));
                assert!(msg.contains("backup"));
                // The reset guard of an older binary cannot read a newer store reliably.
                assert!(!msg.contains("reset-data"));
            }
            other => panic!("expected Halt, got {other:?}"),
        }
    }

    #[test]
    fn missing_marker_on_existing_state_halts() {
        let d = decide_schema_version(None, 4, true);
        match d {
            SchemaVersionDecision::Halt(message) => {
                assert!(message.contains("no schema marker"));
                assert!(message.contains("backup"));
                assert!(message.contains("interfold node reset-data --name <node>"));
            }
            other => panic!("expected Halt, got {other:?}"),
        }
    }
}
