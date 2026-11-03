// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::sync::OnceLock;

use e3_data::DataStore;

// Hold shared data store - this is for production only - for testing we can create new stores per
// routine
static CACHED_STORE: OnceLock<DataStore> = OnceLock::new();

/// Save the store to a cache for use by socket commands. This solves the problem of reusing a
/// database connection while the node is running in start mode. We can use this during node start.
/// Only the first call to this is satisfied.
pub fn share_store(store: &DataStore) {
    CACHED_STORE.get_or_init(|| store.clone());
}

pub fn get_cached_store() -> Option<DataStore> {
    CACHED_STORE.get().cloned()
}
