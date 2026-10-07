// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use interfold_lib::configs::default::MAX_MSG_NON_ZERO_COEFFS;

/// Maximum number of options for a vote.
/// We need this value because we need a compile-time bound value
/// for looping.
pub global MAX_OPTIONS: u32 = 10;

/// The widest option segment, in binary coefficients. A ballot has at least two options, so one
/// option holds at most half of the message region.
pub global MAX_VOTE_BITS: u32 = MAX_MSG_NON_ZERO_COEFFS / 2;
