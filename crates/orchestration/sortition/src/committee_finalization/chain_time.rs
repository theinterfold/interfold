// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use std::{future::Future, pin::Pin, sync::Arc};

pub type CommitteeChainTimeFuture = Pin<Box<dyn Future<Output = Result<u64>> + Send>>;

/// Read a chain's latest block timestamp in Unix seconds. Scheduling and retries belong to the
/// finalizer; the adapter must create a fresh read provider for every attempt.
pub type CommitteeChainTimeReader = Arc<dyn Fn(u64) -> CommitteeChainTimeFuture + Send + Sync>;
