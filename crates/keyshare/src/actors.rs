// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Compatibility view of the actors stored in `threshold_keyshare`.
//!
//! These actors own mailboxes, timers, persistence and bus I/O. All
//! business/decision logic lives beside them in the capability directory.

#[path = "threshold_keyshare/decryption_key_collector.rs"]
pub(crate) mod decryption_key_shared_collector;
#[path = "threshold_keyshare/encryption_key_collector.rs"]
pub(crate) mod encryption_key_collector;
#[path = "threshold_keyshare/actor.rs"]
pub(crate) mod threshold_keyshare;
#[path = "threshold_keyshare/threshold_share_collector.rs"]
pub(crate) mod threshold_share_collector;

pub use encryption_key_collector::{
    AllEncryptionKeysCollected, EncryptionKeyCollector, ExpelPartyFromKeyCollection,
};
pub use threshold_keyshare::{
    AllThresholdSharesCollected, CkksCeremonyRecovery, GenEsiSss, GenPkShareAndSkSss,
    ThresholdKeyshare, ThresholdKeyshareParams, ThresholdKeyshareRecoveryState,
    THRESHOLD_KEYSHARE_RECOVERY_SCHEMA_VERSION,
};
