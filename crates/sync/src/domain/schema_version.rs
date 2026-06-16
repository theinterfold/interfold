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
pub const SCHEMA_VERSION: u32 = 1;

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

/// Pure decision: given the persisted schema version (if any) and the version
/// this binary supports, decide whether to proceed, stamp a fresh marker, or
/// halt loudly (H19 upgrade / H20 downgrade).
///
/// Policy: only an exact match is accepted. Because the codebase supports only
/// additive evolution and removed the previous `#[serde(default)]` shims, any
/// version mismatch implies a breaking change with no migration path, so both
/// older on-disk data (upgrade) and newer on-disk data (downgrade) halt.
pub fn decide_schema_version(persisted: Option<u32>, current: u32) -> SchemaVersionDecision {
    match persisted {
        None => SchemaVersionDecision::WriteCurrent,
        Some(v) if v == current => SchemaVersionDecision::Proceed,
        Some(v) if v > current => SchemaVersionDecision::Halt(format!(
            "On-disk schema version {v} is newer than this binary's supported version {current}. \
             This is a downgrade across an incompatible format change. Halting; run a binary at \
             schema version {v} or newer, or wipe and resync this node."
        )),
        Some(v) => SchemaVersionDecision::Halt(format!(
            "On-disk schema version {v} is older than this binary's supported version {current}. \
             This is an upgrade across an incompatible format change with no migration. Halting; \
             a migration is required before this binary can load the existing data."
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_store_writes_current() {
        assert_eq!(
            decide_schema_version(None, 3),
            SchemaVersionDecision::WriteCurrent
        );
    }

    #[test]
    fn exact_match_proceeds() {
        assert_eq!(
            decide_schema_version(Some(3), 3),
            SchemaVersionDecision::Proceed
        );
    }

    #[test]
    fn older_on_disk_halts_as_upgrade() {
        let d = decide_schema_version(Some(2), 3);
        match d {
            SchemaVersionDecision::Halt(msg) => {
                assert!(msg.contains("older"));
                assert!(msg.contains("upgrade"));
            }
            other => panic!("expected Halt, got {other:?}"),
        }
    }

    #[test]
    fn newer_on_disk_halts_as_downgrade() {
        let d = decide_schema_version(Some(4), 3);
        match d {
            SchemaVersionDecision::Halt(msg) => {
                assert!(msg.contains("newer"));
                assert!(msg.contains("downgrade"));
            }
            other => panic!("expected Halt, got {other:?}"),
        }
    }
}
