// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Effect execution for threshold-plaintext aggregation.

use super::*;

mod prove_plaintext;
mod publish_result;
mod recovery;
mod validate_decryption_share;
mod verify_decryption_shares;
