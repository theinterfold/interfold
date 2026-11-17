// SPDX-License-Identifier: LGPL-3.0-only

//! Bounded network effects and lifecycle coordination.

use super::*;

mod admission;
#[path = "fetch_history.rs"]
pub(super) mod historical_sync;
pub(super) mod history_source;
mod readiness;
mod rebroadcast;
