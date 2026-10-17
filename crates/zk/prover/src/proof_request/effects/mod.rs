// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Proof-request effect execution grouped by business action.

use super::*;

mod aggregation_proofs;
mod decryption_key_proofs;
mod decryption_share_proofs;
mod dkg_proofs;
mod encryption_key_result;
mod failures;
mod publish_threshold_shares;
mod signing;
