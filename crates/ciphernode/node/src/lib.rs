// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The v2 node's composition root: one engine, fed by the chain reader, the network, the job
//! runner, the operator key and the availability layer, whose effects it hands back to them.

mod heartbeat;
pub mod launch;
mod memory;
mod runtime;
