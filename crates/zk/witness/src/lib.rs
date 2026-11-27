// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! BFV witness preparation, commitments, and canonical Noir JSON.

pub mod commitments;
pub mod dkg;
pub mod encoding;
pub mod errors;
mod negacyclic;
pub mod packing;
pub mod synchronized;
pub mod threshold;
mod validation;

pub use commitments::*;
pub use e3_zk_config::output_layout;
pub use e3_zk_config::output_layout::*;
pub use e3_zk_config::DkgInputType;
pub use encoding::*;
pub use errors::WitnessError;
