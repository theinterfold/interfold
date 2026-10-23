// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Share-verification effect execution grouped by business action.

use super::*;

mod complete_verification;
mod consistency;
mod dispatch;
mod ecdsa;
mod results;
