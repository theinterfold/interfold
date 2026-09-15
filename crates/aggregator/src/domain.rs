// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Compatibility view of pure aggregation modules stored by capability.

#[path = "committee.rs"]
pub mod committee;
#[path = "committee_hash.rs"]
pub mod committee_hash;
#[path = "public_key_aggregation/lbfv_contribution_collection.rs"]
pub mod lbfv_contribution_collection;
