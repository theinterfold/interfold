// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Deliberately noncanonical compatible dummy inner circuit for the `nodes_fold` adversarial tests.
//!
//! It exposes the exact public ABI of `node_fold` — `NODE_FOLD_PUBLIC_LEN` public fields — so its
//! proof is verifiable inside `nodes_fold`'s `verify_honk_proof_non_zk` call, but its VK hash
//! differs from the canonical `node_fold` VK hash. `nodes_fold` must reject a proof minted under
//! this VK.

use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::{H, N_PARTIES};

/// Must match `node_fold::NODE_FOLD_PUBLIC_LEN`.
pub global NODE_FOLD_PUBLIC_LEN: u32 = 14 + N_PARTIES + (2 * (N_PARTIES + H) * L_THRESHOLD);

fn main(
    node_fold_public_inputs: [Field; NODE_FOLD_PUBLIC_LEN],
) -> pub [Field; NODE_FOLD_PUBLIC_LEN] {
    // Identity circuit: no constraints beyond the public ABI shape.
    node_fold_public_inputs
}
