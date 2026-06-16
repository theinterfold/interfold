// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Circuit registry and metadata.
//!
//! The registry maps circuit names (e.g. `pk`) to [`CircuitMetadata`]. Use
//! [`CircuitRegistry`] to register and look up circuits by name.

#[allow(clippy::module_inception)]
pub mod registry;

pub use registry::*;
