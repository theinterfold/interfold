// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Compatibility view of pure request modules stored by capability.

#[path = "routing/event_buffer.rs"]
mod event_buffer;
#[path = "lifecycle/workflow.rs"]
mod lifecycle;
#[path = "routing/workflow.rs"]
mod routing;
#[path = "routing/unadmitted_inputs.rs"]
mod unadmitted_inputs;

pub use event_buffer::*;
pub use lifecycle::*;
pub use routing::*;
pub use unadmitted_inputs::*;
