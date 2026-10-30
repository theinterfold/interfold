// SPDX-License-Identifier: LGPL-3.0-only

//! Compatibility view of concrete EVM provider adapters stored by capability.

#[path = "chain_reader/progress.rs"]
pub mod ingestion_progress;
#[path = "log_fetching/adapter.rs"]
pub(crate) mod log_fetcher;
