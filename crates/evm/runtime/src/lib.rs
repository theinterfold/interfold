// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! What the CLI's chain commands share: providers with the operator's RPC settings, the scan of
//! the committees that hold an operator's collateral, and readable contract errors.

mod adapters;
mod domain;
pub mod helpers;
mod operator_status;

use e3_evm_contracts as contracts;

pub use domain::error_decoder;
pub use helpers::*;
pub use operator_status::*;
