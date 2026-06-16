// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure, synchronous domain logic for aggregation. These modules contain no
//! actix, persistence, or event-bus dependencies and are unit-tested in
//! isolation. The actors in [`crate::actors`] drive them and perform all I/O.

pub mod committee;
pub mod committee_hash;
pub mod failover;
pub mod publickey_aggregation;
pub mod threshold_plaintext_aggregation;
