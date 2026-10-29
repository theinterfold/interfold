// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

#[cfg(feature = "bfv")]
pub use e3_bfv_client as bfv_client;
#[cfg(feature = "bfv")]
pub use e3_fhe_params as bfv_params;

#[cfg(feature = "evm")]
pub use e3_evm_client as evm;

/// Compatibility alias for the 0.20 migration; use [`evm`] in new code.
#[cfg(feature = "evm")]
#[deprecated(note = "Use e3_sdk::evm; evm_helpers will be removed in 0.21.")]
pub use e3_evm_client as evm_helpers;

#[cfg(feature = "indexer")]
pub use e3_indexer as indexer;
