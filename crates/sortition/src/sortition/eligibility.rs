// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::primitives::Address;
use anyhow::Result;
use std::{collections::HashSet, future::Future, pin::Pin, sync::Arc};

pub type EligibilityFuture = Pin<Box<dyn Future<Output = Result<HashSet<Address>>> + Send>>;

/// Reads which of `operators` `BondingRegistry.eligibilityAt` finds active at `timepoint` on
/// `chain_id`. Under a required identity policy, that includes a verified bond owner, so the owner
/// shortlist can rank only those operators.
pub type EligibilityReader = Arc<dyn Fn(u64, Vec<Address>, u64) -> EligibilityFuture + Send + Sync>;
