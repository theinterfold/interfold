// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Compatibility view of aggregation workflows stored by capability.
//!
//! These modules own protocol progress but perform no Actix, persistence, or bus I/O. The actor
//! shells commit their state transitions and execute the resulting effects.

#[path = "public_key_aggregation/workflow.rs"]
pub mod publickey_aggregation;
#[path = "plaintext_aggregation/workflow.rs"]
pub mod threshold_plaintext_aggregation;
